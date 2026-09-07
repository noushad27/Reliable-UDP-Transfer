"""
Configuration, protocol constants, and dataclasses for the Reliable UDP transfer protocol.
Defines protocol header layout, default networking parameters, and runtime configurations.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Any


# ============================================================================
# Protocol Header Constants (Wire Format)
# ============================================================================
PROTOCOL_MAGIC: bytes = b"RD"  # 'Reliable Data' magic identifier (0x5244)
PROTOCOL_VERSION: int = 1
HEADER_SIZE: int = 22  # Exact size of struct format: '!2sBBIIIHI'
HEADER_STRUCT_FORMAT: str = "!2sBBIIIHI"

# ============================================================================
# Default Network & Transfer Parameters
# ============================================================================
DEFAULT_HOST: str = "127.0.0.1"
DEFAULT_PORT: int = 9000
DEFAULT_PAYLOAD_SIZE: int = 1024  # 1 KB chunk per DATA packet
DEFAULT_WINDOW_SIZE: int = 8  # Window size for Sliding Window & Selective Repeat (Milestone 10 default)
DEFAULT_TIMEOUT: float = 1.0  # Retransmission timeout in seconds (Milestone 7 default)
DEFAULT_MAX_RETRIES: int = 5   # Maximum retransmission attempts per packet
MAX_PAYLOAD_SIZE: int = 65507 - HEADER_SIZE  # Maximum safe UDP payload (65,485 bytes)
MAX_BUFFERED_PACKETS: int = 8192  # Memory safety limit for out-of-order buffer (packet count)
MAX_BUFFER_BYTES: int = 16 * 1024 * 1024  # Memory safety limit for out-of-order buffer (16 MB total payload)


class PacketType(IntEnum):
    """Supported protocol packet types."""
    START = 1
    START_ACK = 2
    DATA = 3
    ACK = 4
    FIN = 5
    FIN_ACK = 6
    ERROR = 7

    def __str__(self) -> str:
        return self.name


class ARQMode(StrEnum):
    """Reliability ARQ transmission modes."""
    STOP_AND_WAIT = "stop_and_wait"
    SLIDING_WINDOW = "sliding_window"
    SELECTIVE_REPEAT = "selective_repeat"


VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


@dataclass
class TransferConfig:
    """
    Runtime configuration for sender and receiver.
    
    Encapsulates network endpoints, ARQ protocol tuning parameters,
    simulation injection rates, and filesystem/logging preferences.
    """
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    payload_size: int = DEFAULT_PAYLOAD_SIZE
    window_size: int = DEFAULT_WINDOW_SIZE
    timeout: float = DEFAULT_TIMEOUT
    max_retries: int = DEFAULT_MAX_RETRIES
    loss_rate: float = 0.0
    latency: float = 0.0  # Latency in seconds (e.g. 0.1 for 100ms)
    corruption_rate: float = 0.0
    output_dir: Path = Path("./received_files")
    log_level: str = "INFO"
    arq_mode: ARQMode = ARQMode.SELECTIVE_REPEAT

    def __post_init__(self) -> None:
        """Validate all configuration attributes to prevent runtime failure."""
        if not isinstance(self.host, str) or not self.host.strip():
            raise ValueError(f"Invalid host '{self.host}': Host must be a non-empty string.")

        if not isinstance(self.port, int) or not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid port {self.port}: Port must be an integer between 1 and 65535.")

        if not isinstance(self.payload_size, int) or not (1 <= self.payload_size <= MAX_PAYLOAD_SIZE):
            raise ValueError(
                f"Invalid payload size {self.payload_size}: Must be between 1 and {MAX_PAYLOAD_SIZE} bytes."
            )

        if not isinstance(self.window_size, int) or self.window_size < 1:
            raise ValueError(f"Invalid window size {self.window_size}: Window size must be at least 1.")

        if not isinstance(self.timeout, (int, float)) or self.timeout <= 0.0:
            raise ValueError(f"Invalid timeout {self.timeout}: Timeout must be a positive number greater than 0.")

        if not isinstance(self.max_retries, int) or self.max_retries < 0:
            raise ValueError(f"Invalid max_retries {self.max_retries}: Max retries cannot be negative.")

        if not isinstance(self.loss_rate, (int, float)) or not (0.0 <= self.loss_rate <= 1.0):
            raise ValueError(f"Invalid loss_rate {self.loss_rate}: Loss rate must be between 0.0 and 1.0.")

        if not isinstance(self.latency, (int, float)) or self.latency < 0.0:
            raise ValueError(f"Invalid latency {self.latency}: Latency cannot be negative.")

        if not isinstance(self.corruption_rate, (int, float)) or not (0.0 <= self.corruption_rate <= 1.0):
            raise ValueError(
                f"Invalid corruption_rate {self.corruption_rate}: Corruption rate must be between 0.0 and 1.0."
            )

        if isinstance(self.output_dir, str):
            self.output_dir = Path(self.output_dir)

        if not isinstance(self.log_level, str) or self.log_level.upper() not in VALID_LOG_LEVELS:
            raise ValueError(
                f"Invalid log_level '{self.log_level}': Must be one of {sorted(VALID_LOG_LEVELS)}."
            )
        self.log_level = self.log_level.upper()

    @property
    def packet_loss_rate(self) -> float:
        """Alias for loss_rate for backward compatibility."""
        return self.loss_rate

    @packet_loss_rate.setter
    def packet_loss_rate(self, value: float) -> None:
        self.loss_rate = value
        self.__post_init__()

    @property
    def latency_ms(self) -> float:
        """Latency in milliseconds."""
        return self.latency * 1000.0

    @latency_ms.setter
    def latency_ms(self, value_ms: float) -> None:
        self.latency = value_ms / 1000.0
        self.__post_init__()

    @property
    def output_directory(self) -> Path:
        """Alias for output_dir."""
        return self.output_dir

    @output_directory.setter
    def output_directory(self, path: Path | str) -> None:
        self.output_dir = Path(path)
        self.__post_init__()
