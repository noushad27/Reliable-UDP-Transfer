"""
Network Simulator Layer for Reliable UDP (Milestone 12).
Simulates real-world network impairments:
  - Packet loss (probabilistic or deterministic datagram drop)
  - Artificial latency / jitter (propagation delay)
  - Packet corruption (bit-flipping / payload mutation)
Operates entirely within the application layer without modifying OS networking or drivers.
"""

from __future__ import annotations

import logging
import random
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional, Tuple

from app.config import TransferConfig


@dataclass
class SimulationStats:
    """Collects real-time telemetry of simulated network impairments."""
    packets_attempted: int = 0
    packets_dropped: int = 0
    packets_corrupted: int = 0
    packets_delayed: int = 0

    def format_summary(self) -> str:
        """Format metrics into a clean human-readable report."""
        att = self.packets_attempted
        drop_pct = (self.packets_dropped / att * 100) if att > 0 else 0.0
        corrupt_pct = (self.packets_corrupted / att * 100) if att > 0 else 0.0
        delay_pct = (self.packets_delayed / att * 100) if att > 0 else 0.0

        return (
            f"========================================================\n"
            f"  NETWORK SIMULATION TELEMETRY\n"
            f"========================================================\n"
            f"  * Total Datagrams Attempted: {self.packets_attempted}\n"
            f"  * Packets Dropped (Loss):    {self.packets_dropped} ({drop_pct:.1f}%)\n"
            f"  * Packets Corrupted:         {self.packets_corrupted} ({corrupt_pct:.1f}%)\n"
            f"  * Packets Delayed (Latency): {self.packets_delayed} ({delay_pct:.1f}%)\n"
            f"========================================================"
        )


class NetworkSimulator:
    """
    Simulation engine that decides whether to drop, corrupt, or delay packets.
    """

    def __init__(
        self,
        loss_rate: float = 0.0,
        latency: float = 0.0,
        corruption_rate: float = 0.0,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.loss_rate = max(0.0, min(1.0, float(loss_rate)))
        self.latency = max(0.0, float(latency))
        self.corruption_rate = max(0.0, min(1.0, float(corruption_rate)))
        self.logger = logger or logging.getLogger("reliable_udp.simulator")
        self.stats = SimulationStats()
        self._lock = threading.Lock()

    def should_drop(self) -> bool:
        """Determine whether the current packet should be dropped based on loss_rate."""
        if self.loss_rate <= 0.0:
            return False
        return random.random() < self.loss_rate

    def should_corrupt(self) -> bool:
        """Determine whether the current packet should be corrupted."""
        if self.corruption_rate <= 0.0:
            return False
        return random.random() < self.corruption_rate

    def corrupt_bytes(self, data: bytes) -> bytes:
        """
        Corrupt bytes by inverting bits at random byte positions.
        Guarantees that the corrupted byte sequence differs from the original.
        """
        if not data:
            return data

        buf = bytearray(data)
        # Corrupt 1 to min(3, len(buf)) bytes
        num_mutations = random.randint(1, min(3, len(buf)))
        for _ in range(num_mutations):
            idx = random.randint(0, len(buf) - 1)
            # Invert random bitmask (at least one bit flipped)
            buf[idx] ^= random.choice([0x01, 0x02, 0x04, 0x80, 0xFF])

        return bytes(buf)


class SimulatedSocket:
    """
    Transparent wrapper around a standard socket.socket that injects simulated impairments
    on outbound datagrams (loss, latency, corruption) while recording accurate metrics.
    """

    def __init__(
        self,
        sock: socket.socket,
        config: TransferConfig,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._sock = sock
        self._config = config
        self._logger = logger or logging.getLogger("reliable_udp.simulator")
        self.simulator = NetworkSimulator(
            loss_rate=config.loss_rate,
            latency=config.latency,
            corruption_rate=config.corruption_rate,
            logger=self._logger,
        )
        self._active_timers: list[threading.Timer] = []
        self._lock = threading.Lock()

    @property
    def stats(self) -> SimulationStats:
        return self.simulator.stats

    def sendto(self, data: bytes, addr: Tuple[str, int]) -> int:
        """
        Intercept outbound UDP datagram and apply simulation impairments:
        1. Loss: Silently drop datagram without sending to wire.
        2. Corruption: Invert bits before transmission so receiver detects CRC mismatch.
        3. Latency: Schedule delivery after propagation delay.
        """
        with self._lock:
            self.simulator.stats.packets_attempted += 1

            # 1. Packet Loss Simulation
            if self.simulator.should_drop():
                self.simulator.stats.packets_dropped += 1
                self._logger.warning(
                    f"[SIMULATOR:DROP] Dropped outbound datagram to {addr[0]}:{addr[1]} "
                    f"({len(data)} bytes) [Loss Rate: {self._config.loss_rate * 100:.1f}%]"
                )
                # Return len(data) so caller assumes socket transmission completed
                return len(data)

            # 2. Packet Corruption Simulation
            outbound_data = data
            if self.simulator.should_corrupt():
                self.simulator.stats.packets_corrupted += 1
                outbound_data = self.simulator.corrupt_bytes(data)
                self._logger.warning(
                    f"[SIMULATOR:CORRUPT] Corrupted outbound datagram to {addr[0]}:{addr[1]} "
                    f"({len(data)} bytes) [Corruption Rate: {self._config.corruption_rate * 100:.1f}%]"
                )

            # 3. Artificial Latency Simulation
            if self._config.latency > 0:
                self.simulator.stats.packets_delayed += 1
                self._logger.debug(
                    f"[SIMULATOR:LATENCY] Delaying datagram to {addr[0]}:{addr[1]} "
                    f"by {self._config.latency * 1000:.1f} ms"
                )

                # Asynchronous propagation delay using daemon timer
                timer_cell: list[Optional[threading.Timer]] = [None]

                def delayed_emit(d: bytes, a: Tuple[str, int]):
                    try:
                        self._sock.sendto(d, a)
                    except OSError:
                        pass
                    finally:
                        with self._lock:
                            if timer_cell[0] in self._active_timers:
                                self._active_timers.remove(timer_cell[0])

                t = threading.Timer(self._config.latency, delayed_emit, args=(outbound_data, addr))
                t.daemon = True
                timer_cell[0] = t
                self._active_timers.append(t)
                t.start()
                return len(data)

            # Normal immediate transmission
            return self._sock.sendto(outbound_data, addr)

    def recvfrom(self, bufsize: int) -> Tuple[bytes, Tuple[str, int]]:
        return self._sock.recvfrom(bufsize)

    def bind(self, addr: Tuple[str, int]) -> None:
        self._sock.bind(addr)

    def settimeout(self, timeout: Optional[float]) -> None:
        self._sock.settimeout(timeout)

    def gettimeout(self) -> Optional[float]:
        return self._sock.gettimeout()

    def setblocking(self, flag: bool) -> None:
        self._sock.setblocking(flag)

    def getsockname(self) -> Tuple[str, int]:
        return self._sock.getsockname()

    def fileno(self) -> int:
        return self._sock.fileno()

    def ioctl(self, *args, **kwargs) -> Any:
        if hasattr(self._sock, "ioctl"):
            return self._sock.ioctl(*args, **kwargs)
        return None

    def close(self) -> None:
        with self._lock:
            pending = list(self._active_timers)
        # Flush active delayed packets before closing socket
        for t in pending:
            t.join(timeout=max(0.1, self._config.latency * 2))
        with self._lock:
            self._active_timers.clear()
        try:
            self._sock.close()
        except OSError:
            pass


def wrap_simulated_socket(
    sock: socket.socket,
    config: TransferConfig,
    logger: Optional[logging.Logger] = None,
) -> socket.socket | SimulatedSocket:
    """
    Factory function: Wraps a socket in SimulatedSocket if any simulation rate > 0.
    Otherwise returns original socket directly for zero-overhead transmission.
    """
    if config.loss_rate > 0.0 or config.latency > 0.0 or config.corruption_rate > 0.0:
        return SimulatedSocket(sock, config, logger)
    return sock
