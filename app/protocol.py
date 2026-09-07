"""
Reliable transport protocol implementation using Stop-and-Wait ARQ over UDP.
Implements connection handshake, sequence numbering, synchronous ACKs,
timeout-driven retransmission, and cryptographic transfer teardown.
"""

from __future__ import annotations

import logging
import random
import socket
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Iterable, Optional, Tuple

from app.checksum import calculate_checksum, calculate_file_sha256, verify_checksum
from app.config import (
    DEFAULT_TIMEOUT,
    MAX_BUFFER_BYTES,
    MAX_BUFFERED_PACKETS,
    PacketType,
    TransferConfig,
)
from app.packet import (
    ChecksumMismatchError,
    InvalidHeaderError,
    Packet,
    PacketError,
    PacketTruncatedError,
)
from app.simulator import SimulationStats, wrap_simulated_socket
from app.transfer import FileMetadata, inspect_file, read_file_chunks
from app.utils import format_bytes, format_duration, format_throughput, sanitize_filename


class ProtocolError(Exception):
    """Base exception for reliable protocol failures."""
    pass


class HandshakeError(ProtocolError):
    """Raised when transfer handshake fails to complete."""
    pass


class RetransmissionLimitExceeded(ProtocolError):
    """Raised when a packet exceeds maximum retry attempts."""
    pass


class ReceiverUnavailableError(ProtocolError):
    """Raised when target receiver endpoint is offline, unreachable, or firewalled."""
    pass


class StopAndWaitSender:
    """
    Stop-and-Wait ARQ sender protocol engine.
    Transmits one DATA packet at a time and strictly waits for matching ACK
    before advancing sequence number.
    """

    def __init__(
        self,
        config: TransferConfig,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.config = config
        self.logger = logger or logging.getLogger("reliable_udp.sender")
        self.session_id = random.randint(100000, 999999)
        self.sock: Optional[socket.socket] = None
        self.target_addr = (self.config.host, self.config.port)

        # Telemetry metrics
        self.packets_sent = 0
        self.retransmissions = 0
        self.acks_received = 0

    def _get_socket(self) -> socket.socket:
        """Create and configure underlying UDP socket with timeout and OS error suppression."""
        if self.sock is None:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            raw_sock.settimeout(self.config.timeout)
            # Suppress WSAECONNRESET (WinError 10054) on Windows from ICMP Port Unreachable
            if hasattr(socket, "SIO_UDP_CONNRESET"):
                try:
                    raw_sock.ioctl(socket.SIO_UDP_CONNRESET, False)
                except OSError:
                    pass
            self.sock = wrap_simulated_socket(raw_sock, self.config, self.logger)
        return self.sock

    def get_simulation_stats(self) -> Optional[SimulationStats]:
        """Return simulation metrics if simulator was active on this socket."""
        if self.sock and hasattr(self.sock, "stats"):
            return self.sock.stats
        return getattr(self, "_saved_sim_stats", None)

    def close(self) -> None:
        """Close socket handle."""
        if self.sock:
            if hasattr(self.sock, "stats"):
                self._saved_sim_stats = self.sock.stats
            self.sock.close()
            self.sock = None

    def send_handshake(self, metadata: FileMetadata) -> bool:
        """
        Initiate transfer by sending START packet and awaiting START_ACK.

        Args:
            metadata: Metadata of the file to transfer.

        Returns:
            True if handshake succeeded.
        """
        sock = self._get_socket()
        start_pkt = Packet.create_start(
            session_id=self.session_id,
            filename=metadata.filename,
            filesize=metadata.filesize,
            total_packets=metadata.total_chunks,
            file_sha256=metadata.sha256_hash,
            window_size=1,  # Stop-and-wait window size is 1
            arq_mode="stop_and_wait",
        )
        raw_start = start_pkt.encode()

        for attempt in range(1, self.config.max_retries + 1):
            try:
                self.logger.info(
                    f"[HANDSHAKE] Sending START (session={self.session_id}, "
                    f"file='{metadata.filename}', size={format_bytes(metadata.filesize)}, "
                    f"chunks={metadata.total_chunks}) [Attempt {attempt}/{self.config.max_retries}]"
                )
                sock.sendto(raw_start, self.target_addr)
                self.packets_sent += 1

                resp_data, _ = sock.recvfrom(65535)
                resp_pkt = Packet.decode(resp_data)

                if (
                    resp_pkt.pkt_type == PacketType.START_ACK
                    and resp_pkt.session_id == self.session_id
                ):
                    self.logger.info(f"[HANDSHAKE] START_ACK received from {self.target_addr}. Connection established.")
                    return True

            except (socket.timeout, ConnectionResetError):
                self.logger.warning(
                    f"[HANDSHAKE] START timed out after {self.config.timeout}s. Retrying..."
                )
                self.retransmissions += 1
            except PacketError as e:
                self.logger.warning(f"[HANDSHAKE] Received corrupted packet during handshake: {e}")

        raise HandshakeError(
            f"Handshake failed: Target {self.target_addr} did not reply after {self.config.max_retries} attempts."
        )

    def send_chunk(self, seq_num: int, chunk: bytes) -> None:
        """
        Send a single DATA packet and wait synchronously for its matching ACK.

        Args:
            seq_num: Sequence number of the chunk.
            chunk: Binary payload data.
        """
        sock = self._get_socket()
        data_pkt = Packet.create_data(
            session_id=self.session_id,
            seq_num=seq_num,
            payload=chunk,
        )
        raw_data = data_pkt.encode()

        for attempt in range(1, self.config.max_retries + 1):
            try:
                if attempt > 1:
                    self.logger.warning(
                        f"[RETRANSMIT] DATA #{seq_num} ({len(chunk)} B) [Attempt {attempt}/{self.config.max_retries}]"
                    )
                    self.retransmissions += 1
                else:
                    self.logger.debug(f"[SEND] DATA #{seq_num} ({len(chunk)} B) to {self.target_addr}")

                sock.sendto(raw_data, self.target_addr)
                self.packets_sent += 1

                # Wait for matching ACK
                while True:
                    resp_bytes, _ = sock.recvfrom(65535)
                    ack_pkt = Packet.decode(resp_bytes)

                    # Validate that this is an ACK for our session and current sequence number
                    if ack_pkt.pkt_type == PacketType.ACK and ack_pkt.session_id == self.session_id:
                        if ack_pkt.ack_num == seq_num:
                            self.acks_received += 1
                            self.logger.debug(f"[RECV] ACK #{seq_num} confirmed.")
                            return
                        elif ack_pkt.ack_num < seq_num:
                            self.logger.warning(
                                f"[DUPLICATE ACK] Received stale ACK #{ack_pkt.ack_num} (waiting for #{seq_num}). Ignoring."
                            )
                            continue

                    # Handle case where receiver sent START_ACK late
                    if ack_pkt.pkt_type == PacketType.START_ACK and ack_pkt.session_id == self.session_id:
                        continue

                    self.logger.debug(
                        f"[IGNORE] Received unexpected packet {ack_pkt.pkt_type.name} (ack={ack_pkt.ack_num}) "
                        f"while waiting for ACK #{seq_num}"
                    )

            except (socket.timeout, ConnectionResetError):
                self.logger.warning(
                    f"[TIMEOUT] DATA #{seq_num} timed out after {self.config.timeout}s."
                )
            except PacketError as e:
                self.logger.warning(f"[CORRUPT] Packet error while waiting for ACK #{seq_num}: {e}")

        raise RetransmissionLimitExceeded(
            f"Failed to deliver DATA #{seq_num} after {self.config.max_retries} attempts."
        )

    def send_teardown(self, file_sha256: str) -> bool:
        """
        Send FIN packet signaling end of transfer and verify receiver's FIN_ACK.

        Args:
            file_sha256: Hex-encoded SHA-256 hash of the complete sent file.

        Returns:
            True if receiver verified the file integrity successfully.
        """
        sock = self._get_socket()
        fin_pkt = Packet.create_fin(session_id=self.session_id, file_sha256=file_sha256)
        raw_fin = fin_pkt.encode()

        for attempt in range(1, self.config.max_retries + 1):
            try:
                self.logger.info(
                    f"[TEARDOWN] Sending FIN (session={self.session_id}) [Attempt {attempt}/{self.config.max_retries}]"
                )
                sock.sendto(raw_fin, self.target_addr)
                self.packets_sent += 1

                while True:
                    resp_data, _ = sock.recvfrom(65535)
                    resp_pkt = Packet.decode(resp_data)

                    if (
                        resp_pkt.pkt_type == PacketType.FIN_ACK
                        and resp_pkt.session_id == self.session_id
                    ):
                        payload = resp_pkt.get_json_payload()
                        verified = payload.get("verified", False)
                        receiver_sha = payload.get("receiver_sha256", "")

                        if verified:
                            self.logger.info(
                                f"[TEARDOWN] Transfer completed successfully! Receiver SHA-256 verified: {receiver_sha}"
                            )
                            return True
                        else:
                            self.logger.error(
                                f"[TEARDOWN] Transfer failed integrity check! Receiver SHA-256: {receiver_sha} != {file_sha256}"
                            )
                            return False
                    elif resp_pkt.pkt_type == PacketType.ACK and resp_pkt.session_id == self.session_id:
                        continue

            except (socket.timeout, ConnectionResetError):
                self.logger.warning(f"[TEARDOWN] FIN timed out after {self.config.timeout}s. Retrying...")
                self.retransmissions += 1
            except PacketError as e:
                self.logger.warning(f"[TEARDOWN] Error receiving FIN_ACK: {e}")

        self.logger.error(f"[TEARDOWN] FIN_ACK not received after {self.config.max_retries} retries.")
        return False


@dataclass
class InFlightPacket:
    """Represents a DATA packet currently in flight awaiting acknowledgment."""
    seq_num: int
    raw_packet: bytes
    send_time: float
    retries: int = 0


class SlidingWindowSender:
    """
    Sliding Window ARQ Sender Protocol Engine (Milestone 10).
    Allows up to `window_size` unacknowledged packets in flight concurrently.

    Tracks:
      - base_seq: Oldest unacknowledged sequence number (base of window)
      - next_seq: Sequence number of next packet to send
      - acknowledged_packets: Set of confirmed packet sequence numbers
      - outstanding_packets: Map of seq_num -> InFlightPacket currently in flight
    """

    def __init__(
        self,
        config: TransferConfig,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.config = config
        self.logger = logger or logging.getLogger("reliable_udp.sender")
        self.session_id = random.randint(100000, 999999)
        self.sock: Optional[socket.socket] = None
        self.target_addr = (self.config.host, self.config.port)

        # Sliding Window tracking state
        self.base_seq: int = 0
        self.next_seq: int = 0
        self.window_size: int = config.window_size
        self.acknowledged_packets: set[int] = set()
        self.outstanding_packets: dict[int, InFlightPacket] = {}

        # Telemetry metrics
        self.packets_sent = 0
        self.retransmissions = 0
        self.acks_received = 0

    def _get_socket(self) -> socket.socket:
        """Create and configure underlying UDP socket with timeout and OS error suppression."""
        if self.sock is None:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            raw_sock.settimeout(self.config.timeout)
            if hasattr(socket, "SIO_UDP_CONNRESET"):
                try:
                    raw_sock.ioctl(socket.SIO_UDP_CONNRESET, False)
                except OSError:
                    pass
            self.sock = wrap_simulated_socket(raw_sock, self.config, self.logger)
        return self.sock

    def get_simulation_stats(self) -> Optional[SimulationStats]:
        """Return simulation metrics if simulator was active on this socket."""
        if self.sock and hasattr(self.sock, "stats"):
            return self.sock.stats
        return getattr(self, "_saved_sim_stats", None)

    def close(self) -> None:
        """Close socket handle."""
        if self.sock:
            if hasattr(self.sock, "stats"):
                self._saved_sim_stats = self.sock.stats
            self.sock.close()
            self.sock = None

    def send_handshake(self, metadata: FileMetadata) -> bool:
        """
        Initiate transfer by sending START packet and awaiting START_ACK.
        Advertises sliding window mode and window size.
        """
        sock = self._get_socket()
        start_pkt = Packet.create_start(
            session_id=self.session_id,
            filename=metadata.filename,
            filesize=metadata.filesize,
            total_packets=metadata.total_chunks,
            file_sha256=metadata.sha256_hash,
            window_size=self.window_size,
            arq_mode="sliding_window",
        )
        raw_start = start_pkt.encode()

        for attempt in range(1, self.config.max_retries + 1):
            try:
                self.logger.info(
                    f"[HANDSHAKE] Sending START (session={self.session_id}, "
                    f"file='{metadata.filename}', size={format_bytes(metadata.filesize)}, "
                    f"chunks={metadata.total_chunks}, window={self.window_size}) "
                    f"[Attempt {attempt}/{self.config.max_retries}]"
                )
                sock.sendto(raw_start, self.target_addr)
                self.packets_sent += 1

                resp_data, _ = sock.recvfrom(65535)
                resp_pkt = Packet.decode(resp_data)

                if (
                    resp_pkt.pkt_type == PacketType.START_ACK
                    and resp_pkt.session_id == self.session_id
                ):
                    self.logger.info(
                        f"[HANDSHAKE] START_ACK received from {self.target_addr}. "
                        f"Sliding Window (N={self.window_size}) connection established."
                    )
                    return True

            except (socket.timeout, ConnectionResetError):
                self.logger.warning(
                    f"[HANDSHAKE] START timed out after {self.config.timeout}s. Retrying..."
                )
                self.retransmissions += 1
            except PacketError as e:
                self.logger.warning(f"[HANDSHAKE] Received corrupted packet during handshake: {e}")

        raise HandshakeError(
            f"Handshake failed: Target {self.target_addr} did not reply after {self.config.max_retries} attempts."
        )

    def send_file_stream(
        self,
        chunk_generator: Iterable[bytes],
        total_chunks: int,
    ) -> None:
        """
        Transmit all file chunks using a Sliding Window protocol.
        Maintains up to `window_size` packets in flight simultaneously.

        Tracks:
          - base_seq: Oldest unacknowledged sequence number
          - next_seq: Sequence number of next packet to send
          - acknowledged_packets: Set of sequence numbers confirmed by receiver
          - outstanding_packets: In-flight packets currently awaiting ACK
        """
        if total_chunks == 0:
            return

        sock = self._get_socket()
        chunk_iter = iter(chunk_generator)
        chunk_cache: dict[int, bytes] = {}

        self.base_seq = 0
        self.next_seq = 0
        self.acknowledged_packets.clear()
        self.outstanding_packets.clear()

        self.logger.info(
            f"[WINDOW-START] Beginning sliding window transmission (total_chunks={total_chunks}, window_size={self.window_size})"
        )

        while self.base_seq < total_chunks:
            # 1. Pipeline: Send packets while within window bounds
            while self.next_seq < self.base_seq + self.window_size and self.next_seq < total_chunks:
                if self.next_seq not in chunk_cache:
                    try:
                        chunk_cache[self.next_seq] = next(chunk_iter)
                    except StopIteration:
                        break

                chunk_payload = chunk_cache[self.next_seq]
                data_pkt = Packet.create_data(
                    session_id=self.session_id,
                    seq_num=self.next_seq,
                    payload=chunk_payload,
                )
                raw_pkt = data_pkt.encode()

                sock.sendto(raw_pkt, self.target_addr)
                self.packets_sent += 1
                now = time.monotonic()
                self.outstanding_packets[self.next_seq] = InFlightPacket(
                    seq_num=self.next_seq,
                    raw_packet=raw_pkt,
                    send_time=now,
                    retries=0,
                )
                self.logger.debug(
                    f"[PIPELINE-SEND] Sent DATA #{self.next_seq} | Base: {self.base_seq}, "
                    f"Next: {self.next_seq + 1}, Outstanding: {len(self.outstanding_packets)}"
                )
                self.next_seq += 1

            # 2. Dynamic socket timeout: wait until oldest unacknowledged packet would time out
            if self.outstanding_packets:
                oldest_seq = min(self.outstanding_packets.keys())
                elapsed = time.monotonic() - self.outstanding_packets[oldest_seq].send_time
                remaining_timeout = max(0.005, self.config.timeout - elapsed)
                sock.settimeout(min(remaining_timeout, self.config.timeout))
            else:
                sock.settimeout(self.config.timeout)

            # 3. Receive ACKs and drain any queued incoming ACKs
            try:
                ack_data, _ = sock.recvfrom(65535)
                self._process_ack(ack_data, chunk_cache, total_chunks)

                # Greedily drain any additional ACKs queued in the socket receive buffer
                sock.setblocking(False)
                try:
                    while True:
                        ack_data, _ = sock.recvfrom(65535)
                        self._process_ack(ack_data, chunk_cache, total_chunks)
                except (BlockingIOError, socket.error):
                    pass
                finally:
                    sock.setblocking(True)

            except (socket.timeout, ConnectionResetError):
                # 4. Retransmit timed-out in-flight packets
                now = time.monotonic()
                timed_out = [
                    pkt for pkt in self.outstanding_packets.values()
                    if (now - pkt.send_time) >= self.config.timeout
                ]
                # If socket timed out and elapsed check is on threshold boundary, target oldest
                if not timed_out and self.outstanding_packets:
                    oldest_seq = min(self.outstanding_packets.keys())
                    timed_out = [self.outstanding_packets[oldest_seq]]

                for in_flight in timed_out:
                    if in_flight.retries >= self.config.max_retries:
                        raise RetransmissionLimitExceeded(
                            f"Packet #{in_flight.seq_num} exceeded maximum retries ({self.config.max_retries})."
                        )
                    self.logger.warning(
                        f"[TIMEOUT-RETRANSMIT] Packet #{in_flight.seq_num} timed out. "
                        f"Retransmitting [Attempt {in_flight.retries + 1}/{self.config.max_retries}]"
                    )
                    sock.sendto(in_flight.raw_packet, self.target_addr)
                    self.packets_sent += 1
                    self.retransmissions += 1
                    in_flight.send_time = time.monotonic()
                    in_flight.retries += 1

            except PacketError as e:
                self.logger.warning(f"[CORRUPT-ACK] Corrupted packet received: {e}")

        self.logger.info(
            f"[WINDOW-COMPLETE] All {total_chunks} packets acknowledged. Final base_seq: {self.base_seq}"
        )

    def _process_ack(
        self,
        ack_data: bytes,
        chunk_cache: dict[int, bytes],
        total_chunks: int,
    ) -> None:
        """Decode and process an incoming ACK packet, sliding the window forward."""
        try:
            ack_pkt = Packet.decode(ack_data)
        except PacketError as e:
            self.logger.warning(f"[DECODE-FAIL] Invalid ACK: {e}")
            return

        if ack_pkt.session_id != self.session_id or ack_pkt.pkt_type != PacketType.ACK:
            self.logger.debug(
                f"[IGNORE-ACK] Received packet type {ack_pkt.pkt_type} for session {ack_pkt.session_id}"
            )
            return

        ack_num = ack_pkt.ack_num
        self.acks_received += 1

        if ack_num not in self.acknowledged_packets:
            self.acknowledged_packets.add(ack_num)
            self.outstanding_packets.pop(ack_num, None)
            self.logger.debug(
                f"[ACK] Confirmed #{ack_num} | Outstanding remaining: {len(self.outstanding_packets)}"
            )

            # Slide window forward as long as the base packet has been acknowledged
            prev_base = self.base_seq
            while self.base_seq in self.acknowledged_packets:
                chunk_cache.pop(self.base_seq, None)
                self.base_seq += 1

            if self.base_seq > prev_base:
                self.logger.debug(
                    f"[SLIDE] Window slid forward {prev_base} -> {self.base_seq} / {total_chunks}"
                )
        else:
            self.logger.debug(f"[DUP-ACK] Already acknowledged #{ack_num}")

    def send_teardown(self, file_sha256: str) -> bool:
        """
        Send FIN packet signaling completion and verify receiver's FIN_ACK.
        """
        sock = self._get_socket()
        fin_pkt = Packet.create_fin(session_id=self.session_id, file_sha256=file_sha256)
        raw_fin = fin_pkt.encode()

        for attempt in range(1, self.config.max_retries + 1):
            try:
                self.logger.info(
                    f"[TEARDOWN] Sending FIN (session={self.session_id}) [Attempt {attempt}/{self.config.max_retries}]"
                )
                sock.sendto(raw_fin, self.target_addr)
                self.packets_sent += 1

                while True:
                    resp_data, _ = sock.recvfrom(65535)
                    resp_pkt = Packet.decode(resp_data)

                    if (
                        resp_pkt.pkt_type == PacketType.FIN_ACK
                        and resp_pkt.session_id == self.session_id
                    ):
                        payload = resp_pkt.get_json_payload()
                        verified = payload.get("verified", False)
                        receiver_sha = payload.get("receiver_sha256", "")

                        if verified:
                            self.logger.info(
                                f"[TEARDOWN] Transfer verified! Receiver SHA-256: {receiver_sha}"
                            )
                            return True
                        else:
                            self.logger.error(
                                f"[TEARDOWN] Integrity mismatch! Receiver SHA-256: {receiver_sha} != {file_sha256}"
                            )
                            return False
                    elif resp_pkt.pkt_type == PacketType.ACK and resp_pkt.session_id == self.session_id:
                        continue

            except (socket.timeout, ConnectionResetError):
                self.logger.warning(f"[TEARDOWN] FIN timed out after {self.config.timeout}s. Retrying...")
                self.retransmissions += 1
            except PacketError as e:
                self.logger.warning(f"[TEARDOWN] Error receiving FIN_ACK: {e}")

        self.logger.error(f"[TEARDOWN] FIN_ACK not received after {self.config.max_retries} retries.")
        return False


class PacketState(StrEnum):
    """Lifecycle states of a packet in Selective Repeat ARQ."""
    UNSENT = "unsent"
    IN_FLIGHT = "in_flight"
    ACKED = "acked"
    TIMED_OUT = "timed_out"


@dataclass
class SelectiveRepeatPacket:
    """Descriptor tracking per-packet state, payload, individual timer, and retry counter."""
    seq_num: int
    payload: bytes
    raw_packet: bytes
    state: PacketState = PacketState.UNSENT
    send_time: float = 0.0
    retry_count: int = 0


class SelectiveRepeatSender:
    """
    Selective Repeat ARQ Sender Protocol Engine (Milestone 11).
    Transmits packets within a sender window of size W.
    Maintains per-packet acknowledgment state and individual timers.
    Retransmits ONLY packets that were lost/timed out, never already-ACKed packets.

    State:
      - base_seq: Lowest unacknowledged sequence number
      - next_seq: Sequence number of next packet to send
      - window_size: Size of transmission window (default 8)
      - window_packets: Map of seq_num -> SelectiveRepeatPacket currently in the active window
      - packet_retransmissions: Map of seq_num -> count of retransmissions
    """

    def __init__(
        self,
        config: TransferConfig,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.config = config
        self.logger = logger or logging.getLogger("reliable_udp.sender")
        self.session_id = random.randint(100000, 999999)
        self.sock: Optional[socket.socket] = None
        self.target_addr = (self.config.host, self.config.port)

        # Selective Repeat Window State
        self.base_seq: int = 0
        self.next_seq: int = 0
        self.window_size: int = config.window_size
        self.window_packets: dict[int, SelectiveRepeatPacket] = {}
        self.packet_retransmissions: dict[int, int] = {}

        # Telemetry metrics
        self.packets_sent = 0
        self.retransmissions = 0
        self.acks_received = 0

    def _get_socket(self) -> socket.socket:
        """Create and configure underlying UDP socket with timeout and OS error suppression."""
        if self.sock is None:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            raw_sock.settimeout(self.config.timeout)
            if hasattr(socket, "SIO_UDP_CONNRESET"):
                try:
                    raw_sock.ioctl(socket.SIO_UDP_CONNRESET, False)
                except OSError:
                    pass
            self.sock = wrap_simulated_socket(raw_sock, self.config, self.logger)
        return self.sock

    def get_simulation_stats(self) -> Optional[SimulationStats]:
        """Return simulation metrics if simulator was active on this socket."""
        if self.sock and hasattr(self.sock, "stats"):
            return self.sock.stats
        return getattr(self, "_saved_sim_stats", None)

    def close(self) -> None:
        """Close socket handle."""
        if self.sock:
            if hasattr(self.sock, "stats"):
                self._saved_sim_stats = self.sock.stats
            self.sock.close()
            self.sock = None

    def send_handshake(self, metadata: FileMetadata) -> bool:
        """
        Initiate transfer by sending START packet and awaiting START_ACK.
        Advertises Selective Repeat mode and window size.
        """
        sock = self._get_socket()
        start_pkt = Packet.create_start(
            session_id=self.session_id,
            filename=metadata.filename,
            filesize=metadata.filesize,
            total_packets=metadata.total_chunks,
            file_sha256=metadata.sha256_hash,
            window_size=self.window_size,
            arq_mode="selective_repeat",
        )
        raw_start = start_pkt.encode()

        for attempt in range(1, self.config.max_retries + 1):
            try:
                self.logger.info(
                    f"[SR-HANDSHAKE] Sending START (session={self.session_id}, "
                    f"file='{metadata.filename}', size={format_bytes(metadata.filesize)}, "
                    f"chunks={metadata.total_chunks}, window={self.window_size}) "
                    f"[Attempt {attempt}/{self.config.max_retries}]"
                )
                sock.sendto(raw_start, self.target_addr)
                self.packets_sent += 1

                resp_data, _ = sock.recvfrom(65535)
                resp_pkt = Packet.decode(resp_data)

                if (
                    resp_pkt.pkt_type == PacketType.START_ACK
                    and resp_pkt.session_id == self.session_id
                ):
                    self.logger.info(
                        f"[SR-HANDSHAKE] START_ACK received from {self.target_addr}. "
                        f"Selective Repeat (W={self.window_size}) connection established."
                    )
                    return True

            except (socket.timeout, ConnectionResetError):
                self.logger.warning(
                    f"[SR-HANDSHAKE] START timed out after {self.config.timeout}s. Retrying..."
                )
                self.retransmissions += 1
            except PacketError as e:
                self.logger.warning(f"[SR-HANDSHAKE] Corrupted packet during handshake: {e}")

        raise HandshakeError(
            f"Handshake failed: Target {self.target_addr} did not reply after {self.config.max_retries} attempts."
        )

    def send_file_stream(
        self,
        chunk_generator: Iterable[bytes],
        total_chunks: int,
    ) -> None:
        """
        Transmit all chunks using Selective Repeat ARQ.
        Maintains per-packet acknowledgment state and selective retransmission.
        """
        if total_chunks == 0:
            return

        sock = self._get_socket()
        chunk_iter = iter(chunk_generator)

        self.base_seq = 0
        self.next_seq = 0
        self.window_packets.clear()
        self.packet_retransmissions.clear()

        self.logger.info(
            f"[SR-START] Beginning Selective Repeat transmission (total_chunks={total_chunks}, window={self.window_size})"
        )

        while self.base_seq < total_chunks:
            now = time.monotonic()

            # 1. Pipeline: Send new packets within the sender window [base_seq, base_seq + window_size - 1]
            while self.next_seq < self.base_seq + self.window_size and self.next_seq < total_chunks:
                try:
                    payload = next(chunk_iter)
                except StopIteration:
                    break

                pkt = Packet.create_data(
                    session_id=self.session_id,
                    seq_num=self.next_seq,
                    payload=payload,
                )
                raw_pkt = pkt.encode()

                sr_pkt = SelectiveRepeatPacket(
                    seq_num=self.next_seq,
                    payload=payload,
                    raw_packet=raw_pkt,
                    state=PacketState.IN_FLIGHT,
                    send_time=now,
                    retry_count=0,
                )
                self.window_packets[self.next_seq] = sr_pkt
                self.packet_retransmissions[self.next_seq] = 0

                sock.sendto(raw_pkt, self.target_addr)
                self.packets_sent += 1
                self.logger.debug(
                    f"[SR-SEND] Sent DATA #{self.next_seq} (State: {sr_pkt.state.value}) | "
                    f"Base: {self.base_seq}, Window: [{self.base_seq}..{self.base_seq + self.window_size - 1}]"
                )
                self.next_seq += 1

            # 2. Check individual timeouts: Retransmit ONLY expired unacknowledged packets
            now = time.monotonic()
            for seq, sr_pkt in list(self.window_packets.items()):
                if sr_pkt.state in (PacketState.IN_FLIGHT, PacketState.TIMED_OUT):
                    if (now - sr_pkt.send_time) >= self.config.timeout:
                        if sr_pkt.retry_count >= self.config.max_retries:
                            raise RetransmissionLimitExceeded(
                                f"Packet #{seq} exceeded max retries ({self.config.max_retries}) in Selective Repeat."
                            )
                        sr_pkt.state = PacketState.TIMED_OUT
                        self.logger.warning(
                            f"[SR-TIMEOUT] DATA #{seq} timed out after {self.config.timeout}s. "
                            f"SELECTIVELY retransmitting #{seq} only [Attempt {sr_pkt.retry_count + 1}/{self.config.max_retries}]"
                        )
                        sock.sendto(sr_pkt.raw_packet, self.target_addr)
                        self.packets_sent += 1
                        self.retransmissions += 1
                        self.packet_retransmissions[seq] += 1
                        sr_pkt.send_time = time.monotonic()
                        sr_pkt.retry_count += 1
                        sr_pkt.state = PacketState.IN_FLIGHT

            # 3. Dynamic socket timeout: wait until the earliest expiring in-flight packet
            in_flight = [p for p in self.window_packets.values() if p.state == PacketState.IN_FLIGHT]
            if in_flight:
                now = time.monotonic()
                earliest_expiry = min(p.send_time + self.config.timeout for p in in_flight)
                remaining = max(0.005, earliest_expiry - now)
                sock.settimeout(min(remaining, self.config.timeout))
            else:
                sock.settimeout(self.config.timeout)

            # 4. Receive and process ACKs
            try:
                ack_data, _ = sock.recvfrom(65535)
                self._process_ack(ack_data, total_chunks)

                # Greedily drain queued ACKs
                sock.setblocking(False)
                try:
                    while True:
                        ack_data, _ = sock.recvfrom(65535)
                        self._process_ack(ack_data, total_chunks)
                except (BlockingIOError, socket.error):
                    pass
                finally:
                    sock.setblocking(True)

            except (socket.timeout, ConnectionResetError):
                pass
            except PacketError as e:
                self.logger.warning(f"[SR-CORRUPT] Packet error while receiving ACK: {e}")

        self.logger.info(
            f"[SR-COMPLETE] Selective Repeat transfer complete. All {total_chunks} chunks acknowledged."
        )

    def _process_ack(self, ack_data: bytes, total_chunks: int) -> None:
        """Decode incoming ACK, update per-packet state, and slide window base."""
        try:
            ack_pkt = Packet.decode(ack_data)
        except PacketError as e:
            self.logger.warning(f"[SR-DECODE-FAIL] Invalid ACK: {e}")
            return

        if ack_pkt.session_id != self.session_id or ack_pkt.pkt_type != PacketType.ACK:
            return

        ack_num = ack_pkt.ack_num
        self.acks_received += 1

        if ack_num in self.window_packets:
            sr_pkt = self.window_packets[ack_num]
            if sr_pkt.state != PacketState.ACKED:
                sr_pkt.state = PacketState.ACKED
                self.logger.debug(
                    f"[SR-ACK] Confirmed DATA #{ack_num} (State -> {sr_pkt.state.value})"
                )

                # Slide window forward while base_seq is ACKED
                prev_base = self.base_seq
                while self.base_seq in self.window_packets and self.window_packets[self.base_seq].state == PacketState.ACKED:
                    del self.window_packets[self.base_seq]
                    self.base_seq += 1

                if self.base_seq > prev_base:
                    self.logger.debug(
                        f"[SR-SLIDE] Window slid forward {prev_base} -> {self.base_seq} / {total_chunks}"
                    )
        else:
            self.logger.debug(f"[SR-DUP-ACK] Received ACK #{ack_num} for already retired packet.")

    def send_teardown(self, file_sha256: str) -> bool:
        """Send FIN and verify FIN_ACK."""
        sock = self._get_socket()
        fin_pkt = Packet.create_fin(session_id=self.session_id, file_sha256=file_sha256)
        raw_fin = fin_pkt.encode()

        for attempt in range(1, self.config.max_retries + 1):
            try:
                self.logger.info(
                    f"[SR-TEARDOWN] Sending FIN (session={self.session_id}) [Attempt {attempt}/{self.config.max_retries}]"
                )
                sock.sendto(raw_fin, self.target_addr)
                self.packets_sent += 1

                while True:
                    resp_data, _ = sock.recvfrom(65535)
                    resp_pkt = Packet.decode(resp_data)

                    if (
                        resp_pkt.pkt_type == PacketType.FIN_ACK
                        and resp_pkt.session_id == self.session_id
                    ):
                        payload = resp_pkt.get_json_payload()
                        verified = payload.get("verified", False)
                        receiver_sha = payload.get("receiver_sha256", "")

                        if verified:
                            self.logger.info(
                                f"[SR-TEARDOWN] Transfer verified! Receiver SHA-256: {receiver_sha}"
                            )
                            return True
                        else:
                            self.logger.error(
                                f"[SR-TEARDOWN] Integrity mismatch! Receiver SHA-256: {receiver_sha} != {file_sha256}"
                            )
                            return False
                    elif resp_pkt.pkt_type == PacketType.ACK and resp_pkt.session_id == self.session_id:
                        continue

            except (socket.timeout, ConnectionResetError):
                self.logger.warning(f"[SR-TEARDOWN] FIN timed out after {self.config.timeout}s. Retrying...")
                self.retransmissions += 1
            except PacketError as e:
                self.logger.warning(f"[SR-TEARDOWN] Error receiving FIN_ACK: {e}")

        self.logger.error(f"[SR-TEARDOWN] FIN_ACK not received after {self.config.max_retries} retries.")
        return False


class StopAndWaitReceiver:
    """
    Stop-and-Wait ARQ receiver protocol engine.
    Listens on local UDP port, accepts START, processes DATA sequentially,
    issues immediate ACKs, rejects/discards duplicates, and confirms SHA-256 on FIN.
    """

    def __init__(
        self,
        config: TransferConfig,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.config = config
        self.logger = logger or logging.getLogger("reliable_udp.receiver")
        self.sock: Optional[socket.socket] = None

        # Telemetry metrics
        self.packets_received = 0
        self.acks_sent = 0
        self.duplicates_detected = 0
        self.corrupted_packets = 0
        self.out_of_order_packets = 0
        self.out_of_order_buffer: dict[int, bytes] = {}
        self.current_buffer_bytes: int = 0

    def _get_bound_socket(self) -> socket.socket:
        """Create, bind, and return local receiver socket."""
        if self.sock is None:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            raw_sock.bind((self.config.host, self.config.port))
            raw_sock.settimeout(None)
            self.sock = wrap_simulated_socket(raw_sock, self.config, self.logger)
        return self.sock

    def get_simulation_stats(self) -> Optional[SimulationStats]:
        """Return simulation metrics if simulator was active on this socket."""
        if self.sock and hasattr(self.sock, "stats"):
            return self.sock.stats
        return getattr(self, "_saved_sim_stats", None)

    def close(self) -> None:
        """Close socket handle."""
        if self.sock:
            if hasattr(self.sock, "stats"):
                self._saved_sim_stats = self.sock.stats
            self.sock.close()
            self.sock = None

    def wait_for_handshake(self) -> Tuple[dict, Tuple[str, int]]:
        """
        Block until a valid START packet is received and acknowledge it with START_ACK.

        Returns:
            Tuple of (metadata_dict, sender_address).
        """
        sock = self._get_bound_socket()
        self.logger.info(f"Receiver listening for transfer sessions on {self.config.host}:{self.config.port}...")

        while True:
            try:
                data, addr = sock.recvfrom(65535)
                pkt = Packet.decode(data)

                if pkt.pkt_type == PacketType.START:
                    metadata = pkt.get_json_payload()
                    session_id = pkt.session_id
                    filename = sanitize_filename(metadata.get("filename", "received_file"))
                    filesize = metadata.get("filesize", 0)
                    total_packets = metadata.get("total_packets", 0)

                    self.logger.info(
                        f"[HANDSHAKE] Received START from {addr[0]}:{addr[1]}: session={session_id}, "
                        f"file='{filename}', size={format_bytes(filesize)}, total_chunks={total_packets}"
                    )

                    # Store session ID and normalized metadata
                    metadata["session_id"] = session_id
                    metadata["filename"] = filename
                    metadata["filesize"] = filesize
                    metadata["total_packets"] = total_packets

                    # Send START_ACK
                    start_ack = Packet.create_start_ack(session_id=session_id, window_size=self.config.window_size)
                    sock.sendto(start_ack.encode(), addr)
                    self.acks_sent += 1
                    self.logger.info(f"[HANDSHAKE] Sent START_ACK for session={session_id} to {addr}")

                    return metadata, addr

            except ChecksumMismatchError as e:
                self.corrupted_packets += 1
                self.logger.warning(f"[DROP] Checksum corrupted packet received: {e}")
            except PacketError as e:
                self.logger.warning(f"[DROP] Malformed packet received: {e}")

    def receive_file_data(
        self,
        metadata: dict,
        sender_addr: Tuple[str, int],
        output_path: Path,
    ) -> bool:
        """
        Receive DATA packets using Stop-and-Wait ARQ and write sequentially to disk.

        Args:
            metadata: File metadata dictionary from START packet.
            sender_addr: Address of the sender.
            output_path: Destination path on local disk.

        Returns:
            True if entire file was received and SHA-256 verified.
        """
        sock = self._get_bound_socket()
        session_id = metadata.get("session_id", 0)
        total_packets = metadata.get("total_packets", 0)
        expected_seq = 0
        file_sha256 = metadata.get("file_sha256", "")
        rcv_window_size = metadata.get("window_size") or self.config.window_size

        # Set a session timeout (e.g. 15 seconds of inactivity terminates transfer)
        sock.settimeout(15.0)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger.info(f"[TRANSFER] Writing incoming chunks to: {output_path}")

        with open(output_path, "wb") as f:
            while expected_seq < total_packets:
                try:
                    data, addr = sock.recvfrom(65535)
                    self.packets_received += 1
                    pkt = Packet.decode(data)

                    # Ensure packet belongs to this active session
                    if pkt.session_id != session_id:
                        self.logger.debug(f"[IGNORE] Packet session {pkt.session_id} != active {session_id}")
                        continue

                    # Handle DATA packets
                    if pkt.pkt_type == PacketType.DATA:
                        if pkt.seq_num == expected_seq:
                            # 1. In-order expected packet: write to disk and ACK
                            f.write(pkt.payload)
                            ack_pkt = Packet.create_ack(session_id=session_id, ack_num=pkt.seq_num)
                            sock.sendto(ack_pkt.encode(), addr)
                            self.acks_sent += 1
                            self.logger.debug(f"[RECV] Accepted DATA #{pkt.seq_num} ({len(pkt.payload)} B). Sent ACK #{pkt.seq_num}")
                            expected_seq += 1

                            # Drain contiguous buffered out-of-order packets
                            while expected_seq in self.out_of_order_buffer:
                                buffered_payload = self.out_of_order_buffer.pop(expected_seq)
                                self.current_buffer_bytes = max(0, self.current_buffer_bytes - len(buffered_payload))
                                f.write(buffered_payload)
                                ack_pkt = Packet.create_ack(session_id=session_id, ack_num=expected_seq)
                                sock.sendto(ack_pkt.encode(), addr)
                                self.acks_sent += 1
                                self.logger.info(
                                    f"[DRAIN] Committed buffered DATA #{expected_seq} ({len(buffered_payload)} B) to file. "
                                    f"Buffer remaining: {len(self.out_of_order_buffer)} ({self.current_buffer_bytes} B)"
                                )
                                expected_seq += 1

                        elif pkt.seq_num < expected_seq:
                            # 2. Duplicate packet: already written to disk. Re-send ACK to unblock sender without writing
                            self.duplicates_detected += 1
                            self.logger.warning(
                                f"[DUPLICATE] DATA #{pkt.seq_num} already processed (expected #{expected_seq}). "
                                f"Re-sending ACK #{pkt.seq_num} to unblock sender without writing to disk."
                            )
                            ack_pkt = Packet.create_ack(session_id=session_id, ack_num=pkt.seq_num)
                            sock.sendto(ack_pkt.encode(), addr)
                            self.acks_sent += 1

                        elif pkt.seq_num < expected_seq + rcv_window_size:
                            # 3. Out-of-order packet within receiver window [expected_seq, expected_seq + rcv_window_size - 1]
                            self.out_of_order_packets += 1
                            payload_len = len(pkt.payload)
                            if pkt.seq_num in self.out_of_order_buffer:
                                self.duplicates_detected += 1
                                self.logger.debug(
                                    f"[BUFFER-DUP] DATA #{pkt.seq_num} already buffered. Re-sending ACK #{pkt.seq_num}."
                                )
                            elif (
                                len(self.out_of_order_buffer) >= MAX_BUFFERED_PACKETS
                                or self.current_buffer_bytes + payload_len > MAX_BUFFER_BYTES
                            ):
                                self.logger.warning(
                                    f"[BUFFER-OVERFLOW] Maximum buffer limit reached ({len(self.out_of_order_buffer)} pkts, {self.current_buffer_bytes} B). "
                                    f"Dropping DATA #{pkt.seq_num} to prevent memory exhaustion."
                                )
                            else:
                                self.out_of_order_buffer[pkt.seq_num] = pkt.payload
                                self.current_buffer_bytes += payload_len
                                self.logger.info(
                                    f"[BUFFERED] Out-of-order DATA #{pkt.seq_num} buffered (expected #{expected_seq}). "
                                    f"Current buffer size: {len(self.out_of_order_buffer)} ({self.current_buffer_bytes} B)"
                                )

                            # Send individual selective ACK for received packet
                            ack_pkt = Packet.create_ack(session_id=session_id, ack_num=pkt.seq_num)
                            sock.sendto(ack_pkt.encode(), addr)
                            self.acks_sent += 1
                        else:
                            # 4. Outside receiver window
                            self.logger.warning(
                                f"[OUT-OF-WINDOW] DATA #{pkt.seq_num} outside receiver window "
                                f"[{expected_seq}..{expected_seq + rcv_window_size - 1}]. Dropping."
                            )

                    elif pkt.pkt_type == PacketType.START:
                        # Sender re-transmitted START; re-acknowledge
                        start_ack = Packet.create_start_ack(session_id=session_id, window_size=1)
                        sock.sendto(start_ack.encode(), addr)
                        self.acks_sent += 1

                except socket.timeout:
                    self.logger.error(f"[TIMEOUT] Transfer stalled: No packets received for 15 seconds.")
                    if output_path.exists():
                        output_path.unlink(missing_ok=True)
                        self.logger.warning(f"[CLEANUP] Deleted incomplete file: {output_path}")
                    return False
                except ChecksumMismatchError as e:
                    self.corrupted_packets += 1
                    self.logger.warning(f"[CORRUPT] Discarded corrupted datagram: {e}")
                except PacketError as e:
                    self.logger.warning(f"[ERROR] Malformed packet received: {e}")

            f.flush()

        # Handle FIN packet and SHA-256 verification
        self.logger.info("[TEARDOWN] All data chunks written. Waiting for FIN packet...")
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                pkt = Packet.decode(data)

                if pkt.pkt_type == PacketType.FIN and pkt.session_id == session_id:
                    computed_sha256 = calculate_file_sha256(output_path)
                    fin_payload = pkt.get_json_payload()
                    expected_sha256 = fin_payload.get("file_sha256") or file_sha256
                    is_verified = (computed_sha256.lower() == expected_sha256.lower())

                    fin_ack = Packet.create_fin_ack(
                        session_id=session_id,
                        verified=is_verified,
                        receiver_sha256=computed_sha256,
                    )
                    sock.sendto(fin_ack.encode(), addr)
                    self.acks_sent += 1

                    if is_verified:
                        self.logger.info(
                            f"[SUCCESS] File verified! SHA-256 match: {computed_sha256}"
                        )
                        # Non-blocking check to absorb any immediately queued duplicate FINs
                        sock.settimeout(0.0)
                        try:
                            while True:
                                extra_data, extra_addr = sock.recvfrom(65535)
                                extra_pkt = Packet.decode(extra_data)
                                if extra_pkt.pkt_type == PacketType.FIN and extra_pkt.session_id == session_id:
                                    sock.sendto(fin_ack.encode(), extra_addr)
                                    self.acks_sent += 1
                        except (BlockingIOError, socket.timeout, OSError):
                            pass
                        return True
                    else:
                        self.logger.error(
                            f"[CORRUPTION] SHA-256 mismatch! Expected {file_sha256}, got {computed_sha256}"
                        )
                        if output_path.exists():
                            output_path.unlink(missing_ok=True)
                            self.logger.warning(f"[CLEANUP] Deleted corrupted file: {output_path}")
                        return False

                elif pkt.pkt_type == PacketType.DATA:
                    # Re-send ACK for final data packet in case sender missed it
                    ack_pkt = Packet.create_ack(session_id=session_id, ack_num=pkt.seq_num)
                    sock.sendto(ack_pkt.encode(), addr)

            except socket.timeout:
                self.logger.error("[TIMEOUT] Timed out waiting for FIN packet.")
                if output_path.exists():
                    output_path.unlink(missing_ok=True)
                    self.logger.warning(f"[CLEANUP] Deleted incomplete file: {output_path}")
                return False
            except PacketError as e:
                self.logger.warning(f"[TEARDOWN] Packet error during FIN: {e}")


# Protocol aliases for Milestone 11
SelectiveRepeatReceiver = StopAndWaitReceiver
ReliableReceiver = StopAndWaitReceiver
