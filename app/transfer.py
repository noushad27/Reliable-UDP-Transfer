"""
File handling, binary chunking, metadata extraction, and streaming utilities.
Coordinates high-level FileSender and FileReceiver transfer managers over reliable UDP.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generator, Optional, Tuple

from app.checksum import calculate_file_sha256
from app.config import DEFAULT_PAYLOAD_SIZE, TransferConfig
from app.utils import (
    PathTraversalError,
    format_bytes,
    format_duration,
    format_throughput,
    safe_join_path,
    sanitize_filename,
)


@dataclass(frozen=True)
class FileMetadata:
    """
    Immutable metadata describing a file to be transferred.
    """
    file_path: Path
    filename: str
    filesize: int
    sha256_hash: str
    total_chunks: int
    payload_size: int

    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to a serializable dictionary."""
        return {
            "filename": self.filename,
            "filesize": self.filesize,
            "sha256_hash": self.sha256_hash,
            "total_chunks": self.total_chunks,
            "total_packets": self.total_chunks,
            "payload_size": self.payload_size,
        }


@dataclass
class TransferStats:
    """
    Summary performance and reliability metrics of a file transfer.
    """
    filename: str
    filesize: int
    duration_seconds: float
    throughput_bytes_per_sec: float
    total_packets_sent: int
    retransmissions: int
    success: bool
    sha256_hash: str
    simulation_stats: Optional[Any] = None

    def format_summary(self) -> str:
        """Format metrics into a clean human-readable summary."""
        status = "SUCCESS" if self.success else "FAILED"
        throughput_str = (
            format_throughput(self.filesize, self.duration_seconds)
            if self.success
            else "0.00 B/s (Incomplete)"
        )
        base_summary = (
            f"\n{'='*60}\n"
            f"Transfer Result: {status}\n"
            f"File:            {self.filename} ({format_bytes(self.filesize)})\n"
            f"Duration:        {format_duration(self.duration_seconds)}\n"
            f"Throughput:      {throughput_str}\n"
            f"Packets Sent:    {self.total_packets_sent} (Retransmissions: {self.retransmissions})\n"
            f"SHA-256:         {self.sha256_hash}\n"
            f"{'='*60}"
        )
        if self.simulation_stats:
            if hasattr(self.simulation_stats, "format_summary"):
                base_summary += f"\n{self.simulation_stats.format_summary()}"
            else:
                base_summary += f"\nSimulation Stats: {self.simulation_stats}"
        return base_summary


def validate_file(file_path: Path | str) -> Path:
    """
    Validate that the target file exists, is a regular file, and is readable.

    Args:
        file_path: Path to the target file.

    Returns:
        Resolved Path object.

    Raises:
        FileNotFoundError: If the file does not exist.
        IsADirectoryError: If the path is a directory.
        ValueError: If the path is not a regular file.
        PermissionError: If the file cannot be read.
    """
    path = Path(file_path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if path.is_dir():
        raise IsADirectoryError(f"Path is a directory, not a regular file: {path}")

    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {path}")

    if not os.access(path, os.R_OK):
        raise PermissionError(f"File exists but is not readable: {path}")

    return path


def calculate_total_chunks(filesize: int, chunk_size: int = DEFAULT_PAYLOAD_SIZE) -> int:
    """
    Calculate the total number of chunks required to partition a file of given size.

    Args:
        filesize: Total file size in bytes.
        chunk_size: Size in bytes of each chunk (payload).

    Returns:
        Integer chunk count. An empty file (0 bytes) returns 0 chunks.

    Raises:
        TypeError: If filesize or chunk_size is not an integer.
        ValueError: If filesize is negative or chunk_size <= 0.
    """
    if not isinstance(filesize, int) or isinstance(filesize, bool):
        raise TypeError(f"File size must be an integer, got {type(filesize).__name__}")
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool):
        raise TypeError(f"Chunk size must be an integer, got {type(chunk_size).__name__}")

    if filesize < 0:
        raise ValueError(f"File size cannot be negative: {filesize}")
    if chunk_size <= 0:
        raise ValueError(f"Chunk size must be greater than zero: {chunk_size}")

    if filesize == 0:
        return 0

    return (filesize + chunk_size - 1) // chunk_size


def read_file_chunks(
    file_path: Path | str,
    chunk_size: int = DEFAULT_PAYLOAD_SIZE,
) -> Generator[bytes, None, None]:
    """
    Stream a file from disk in binary chunks without loading the whole file into memory.

    Args:
        file_path: Path to the target file.
        chunk_size: Maximum bytes to read per iteration.

    Yields:
        Bytes chunk of length <= chunk_size.

    Raises:
        FileNotFoundError: If file does not exist.
        TypeError: If chunk_size is not an integer.
        ValueError: If chunk_size <= 0.
    """
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool):
        raise TypeError(f"Chunk size must be an integer, got {type(chunk_size).__name__}")
    if chunk_size <= 0:
        raise ValueError(f"Chunk size must be positive: {chunk_size}")

    valid_path = validate_file(file_path)

    # Open exclusively in binary read mode ('rb')
    with open(valid_path, "rb") as f:
        while chunk := f.read(chunk_size):
            yield chunk


def inspect_file(
    file_path: Path | str,
    chunk_size: int = DEFAULT_PAYLOAD_SIZE,
) -> FileMetadata:
    """
    Inspect a file and compute its transfer metadata, including size, chunk count, and SHA-256.

    Args:
        file_path: Path to the file.
        chunk_size: Payload chunk size in bytes.

    Returns:
        FileMetadata dataclass instance.
    """
    path = validate_file(file_path)
    filesize = path.stat().st_size
    filename = sanitize_filename(path.name)
    sha256_hash = calculate_file_sha256(path)
    total_chunks = calculate_total_chunks(filesize, chunk_size)

    return FileMetadata(
        file_path=path,
        filename=filename,
        filesize=filesize,
        sha256_hash=sha256_hash,
        total_chunks=total_chunks,
        payload_size=chunk_size,
    )


class FileSender:
    """
    High-level File Sender Manager.
    Orchestrates file chunking, reliable protocol lifecycle, and performance reporting.
    """

    def __init__(
        self,
        config: TransferConfig,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.config = config
        self.logger = logger or logging.getLogger("reliable_udp.sender")
        self._active_sender: Optional[Any] = None

    def close(self) -> None:
        """Close any active underlying sender socket."""
        if self._active_sender:
            try:
                self._active_sender.close()
            except Exception as e:
                self.logger.debug(f"Error closing underlying sender: {e}")
            self._active_sender = None

    def send_file(self, file_path: Path | str) -> TransferStats:
        """
        Execute reliable transfer of the given file.

        Args:
            file_path: Local path to the file to send.

        Returns:
            TransferStats dataclass with outcome metrics.
        """
        from app.config import ARQMode
        from app.protocol import (
            HandshakeError,
            ReceiverUnavailableError,
            RetransmissionLimitExceeded,
            SelectiveRepeatSender,
            SlidingWindowSender,
            StopAndWaitSender,
        )

        start_time = time.perf_counter()
        success = False
        sender: Optional[StopAndWaitSender | SlidingWindowSender | SelectiveRepeatSender] = None
        metadata: Optional[FileMetadata] = None

        try:
            metadata = inspect_file(file_path, self.config.payload_size)
            if self.config.arq_mode == ARQMode.STOP_AND_WAIT:
                sender = StopAndWaitSender(self.config, self.logger)
                mode_str = "Stop-and-Wait ARQ"
            elif self.config.arq_mode == ARQMode.SLIDING_WINDOW:
                sender = SlidingWindowSender(self.config, self.logger)
                mode_str = f"Sliding Window ARQ (window_size={self.config.window_size})"
            else:
                sender = SelectiveRepeatSender(self.config, self.logger)
                mode_str = f"Selective Repeat ARQ (window_size={self.config.window_size})"

            self._active_sender = sender
            self.logger.info(
                f"Starting transfer of '{metadata.filename}' ({format_bytes(metadata.filesize)}) "
                f"to {self.config.host}:{self.config.port} via {mode_str}"
            )

            # 1. Handshake (START / START_ACK)
            sender.send_handshake(metadata)

            # 2. Chunk Transmission
            if isinstance(sender, StopAndWaitSender):
                for seq_num, chunk in enumerate(read_file_chunks(metadata.file_path, self.config.payload_size)):
                    sender.send_chunk(seq_num, chunk)
            else:
                sender.send_file_stream(
                    read_file_chunks(metadata.file_path, self.config.payload_size),
                    metadata.total_chunks,
                )

            # 3. Teardown & Integrity Verification (FIN / FIN_ACK)
            success = sender.send_teardown(metadata.sha256_hash)

        except (HandshakeError, ReceiverUnavailableError) as e:
            self.logger.error(f"[OFFLINE/HANDSHAKE] Connection failed: {e}")
            success = False
        except RetransmissionLimitExceeded as e:
            self.logger.error(f"[TIMEOUT/RETRY] Retransmission limit exhausted: {e}")
            success = False
        except FileNotFoundError as e:
            self.logger.error(f"[ERROR] Source file missing: {e}")
            success = False
        except PermissionError as e:
            self.logger.error(f"[ERROR] Permission denied reading source file: {e}")
            success = False
        except IsADirectoryError as e:
            self.logger.error(f"[ERROR] Target path is a directory, not a file: {e}")
            success = False
        except Exception as e:
            self.logger.error(f"Transfer error during transmission: {e}")
            success = False
        finally:
            duration = max(time.perf_counter() - start_time, 0.0001)
            sim_stats = None
            if sender:
                sim_stats = getattr(sender, "get_simulation_stats", lambda: None)()
                sender.close()
            self._active_sender = None

        if metadata:
            filesize = metadata.filesize
            filename = metadata.filename
            sha256 = metadata.sha256_hash
        else:
            filesize = 0
            try:
                filename = sanitize_filename(Path(str(file_path)).name) if file_path else "unknown"
            except Exception:
                filename = "unknown"
            sha256 = ""

        total_sent = getattr(sender, "packets_sent", 0) if sender else 0
        retrans = getattr(sender, "retransmissions", 0) if sender else 0

        bps = (filesize / duration) if (success and duration > 0) else 0.0
        stats = TransferStats(
            filename=filename,
            filesize=filesize,
            duration_seconds=duration,
            throughput_bytes_per_sec=bps,
            total_packets_sent=total_sent,
            retransmissions=retrans,
            success=success,
            sha256_hash=sha256,
            simulation_stats=sim_stats,
        )

        self.logger.info(stats.format_summary())
        return stats


class FileReceiver:
    """
    High-level File Receiver Manager.
    Coordinates socket listening, file reception, chunk reassembly, and verification.
    """

    def __init__(
        self,
        config: TransferConfig,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.config = config
        self.logger = logger or logging.getLogger("reliable_udp.receiver")
        self._active_receiver: Optional[Any] = None
        self.last_receiver_stats: dict[str, int] = {
            "packets_received": 0,
            "duplicates_detected": 0,
            "corrupted_packets": 0,
            "out_of_order_packets": 0,
        }

    def close(self) -> None:
        """Explicitly close any currently active underlying receiver socket."""
        if self._active_receiver:
            try:
                self._active_receiver.close()
            except Exception as e:
                self.logger.debug(f"Error closing underlying receiver: {e}")
            self._active_receiver = None

    def receive_file(self, output_dir: Optional[Path | str] = None) -> Tuple[Path, bool]:
        """
        Listen for a transfer, receive all data chunks, and verify integrity.

        Args:
            output_dir: Optional override of destination directory.

        Returns:
            Tuple of (output_file_path, verification_success_boolean).
        """
        from app.protocol import StopAndWaitReceiver

        dest_dir = Path(output_dir or self.config.output_dir).resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)
        if not os.access(dest_dir, os.W_OK):
            raise PermissionError(f"Destination directory is not writable: {dest_dir}")

        receiver = StopAndWaitReceiver(self.config, self.logger)
        self._active_receiver = receiver
        try:
            metadata, sender_addr = receiver.wait_for_handshake()
            try:
                raw_filename = metadata.get("filename") or "received_file"
                output_path = safe_join_path(dest_dir, raw_filename)
            except PathTraversalError as e:
                self.logger.error(f"[SECURITY] Path traversal attack prevented: {e}")
                output_path = dest_dir / "safe_received_file"

            success = receiver.receive_file_data(metadata, sender_addr, output_path)
            self.last_receiver_stats = {
                "packets_received": receiver.packets_received,
                "duplicates_detected": receiver.duplicates_detected,
                "corrupted_packets": receiver.corrupted_packets,
                "out_of_order_packets": receiver.out_of_order_packets,
            }
            return output_path, success
        finally:
            if not self.last_receiver_stats or self.last_receiver_stats.get("packets_received", 0) == 0:
                self.last_receiver_stats = {
                    "packets_received": getattr(receiver, "packets_received", 0),
                    "duplicates_detected": getattr(receiver, "duplicates_detected", 0),
                    "corrupted_packets": getattr(receiver, "corrupted_packets", 0),
                    "out_of_order_packets": getattr(receiver, "out_of_order_packets", 0),
                }
            receiver.close()
            self._active_receiver = None
