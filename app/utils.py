"""
Utility functions for logging, metric formatting, security validation, and path handling.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Optional


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[Path | str] = None,
    log_to_console: bool = True,
    logger_name: str = "reliable_udp",
) -> logging.Logger:
    """
    Configure structured logging for the application.

    Args:
        log_level: String log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Optional file path to persist logs.
        log_to_console: Whether to attach a stdout StreamHandler.
        logger_name: Name of the root or module logger to configure.

    Returns:
        Configured logging.Logger instance.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)
    logger = logging.getLogger(logger_name)
    logger.setLevel(level)

    # Clear existing handlers to prevent duplicate lines if reconfigured
    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    if log_file:
        file_path = Path(log_file)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(file_path), encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def format_bytes(num_bytes: int) -> str:
    """
    Format raw byte counts into human-readable representations (B, KB, MB, GB).

    Args:
        num_bytes: Total number of bytes.

    Returns:
        Formatted string (e.g. '1.50 MB', '512 B').
    """
    if num_bytes < 0:
        return f"{num_bytes} B"

    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    unit_idx = 0

    while size >= 1024.0 and unit_idx < len(units) - 1:
        size /= 1024.0
        unit_idx += 1

    if unit_idx == 0:
        return f"{int(size)} {units[unit_idx]}"
    return f"{size:.2f} {units[unit_idx]}"


def format_throughput(bytes_transferred: int, duration_seconds: float) -> str:
    """
    Calculate and format transfer throughput.

    Args:
        bytes_transferred: Total bytes successfully transferred.
        duration_seconds: Elapsed time in seconds.

    Returns:
        Throughput string (e.g. '4.20 MB/s', '120.50 KB/s').
    """
    if duration_seconds <= 0:
        return "0.00 B/s"

    bytes_per_sec = bytes_transferred / duration_seconds
    return f"{format_bytes(int(bytes_per_sec))}/s"


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable form.

    Args:
        seconds: Elapsed seconds.

    Returns:
        Formatted string (e.g., '120 ms', '4.25 s').
    """
    if seconds < 0:
        return "0.00 s"
    if seconds < 1.0:
        return f"{seconds * 1000.0:.1f} ms"
    return f"{seconds:.2f} s"


class PathTraversalError(ValueError):
    """Raised when an untrusted path attempts to escape the allowed base directory."""
    pass


WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}


def sanitize_filename(filename: str) -> str:
    """
    Sanitize incoming filenames from untrusted peers to prevent directory traversal
    and filesystem exploitation.

    Strips null bytes, normalizes path separators, extracts base name, filters illegal
    characters, and neutralizes Windows reserved device names.

    Args:
        filename: Raw filename received from network peer.

    Returns:
        Safe base filename string.
    """
    if not filename or not isinstance(filename, str):
        return "unnamed_received_file"

    # 1. Remove null bytes and non-printable control characters
    cleaned = "".join(c for c in filename if c not in "\x00\r\n\t" and ord(c) >= 32)

    # 2. Normalize backslashes to forward slashes for cross-platform processing
    cleaned = cleaned.replace("\\", "/")

    # 3. Strip slashes and extract basename
    segments = [s.strip() for s in cleaned.split("/") if s.strip()]
    if not segments:
        return "unnamed_received_file"

    base_name = segments[-1]

    # 4. Filter illegal filesystem characters (: * ? " < > |)
    for illegal in (':', '*', '?', '"', '<', '>', '|'):
        base_name = base_name.replace(illegal, "_")

    # 5. Check traversal tokens
    if base_name in (".", ".."):
        return "unnamed_received_file"

    # 6. Neutralize Windows reserved device names (e.g. CON, NUL, COM1, AUX)
    stem = Path(base_name).stem.upper()
    if stem in WINDOWS_RESERVED_NAMES:
        base_name = f"safe_{base_name}"

    base_name = base_name.strip(" .")
    if not base_name:
        return "unnamed_received_file"

    return base_name


def safe_join_path(base_dir: Path | str, untrusted_filename: str) -> Path:
    """
    Safely resolve a destination path ensuring it is strictly contained within base_dir.
    Guarantees that directory traversal (e.g. '../../etc/passwd' or absolute paths) cannot escape base_dir.

    Args:
        base_dir: Authorized target directory on local filesystem.
        untrusted_filename: Raw filename provided by remote peer.

    Returns:
        Resolved Path inside base_dir.

    Raises:
        PathTraversalError: If the resolved path attempts to escape base_dir.
    """
    base = Path(base_dir).resolve()
    clean_name = sanitize_filename(untrusted_filename)
    target = (base / clean_name).resolve()

    try:
        target.relative_to(base)
    except ValueError:
        raise PathTraversalError(
            f"Path traversal detected: '{untrusted_filename}' resolves to '{target}' which is outside '{base}'."
        )

    return target


def validate_file_path(file_path: Path | str, must_exist: bool = True) -> Path:
    """
    Validate that a file path is accessible and well-formed.

    Args:
        file_path: Target path to validate.
        must_exist: Whether the file must exist on the local filesystem.

    Returns:
        Resolved Path object.

    Raises:
        FileNotFoundError: If must_exist is True and file does not exist.
        IsADirectoryError: If the path points to a directory instead of a regular file.
    """
    path = Path(file_path).resolve()
    if must_exist:
        if not path.exists():
            raise FileNotFoundError(f"File does not exist: {path}")
        if path.is_dir():
            raise IsADirectoryError(f"Target path is a directory, not a regular file: {path}")
    return path
