"""
Checksum and integrity calculation utilities for packets and files.
Implements per-packet CRC32 error detection and streaming SHA-256 for cryptographic file verification.
"""

from __future__ import annotations

import hashlib
import zlib
from pathlib import Path


def calculate_checksum(data: bytes) -> int:
    """
    Calculate an unsigned 32-bit CRC32 checksum for the given byte buffer.

    CRC32 (Cyclic Redundancy Check 32) treats data as a binary polynomial,
    dividing it by a fixed generator polynomial (IEEE 802.3 standard).
    Provides fast, hardware-accelerated detection of burst bit-errors,
    transposition errors, and transmission corruption.

    Args:
        data: Raw byte buffer to calculate checksum over.

    Returns:
        32-bit unsigned integer checksum (0 to 0xFFFFFFFF).
    """
    return zlib.crc32(data) & 0xFFFFFFFF


def verify_checksum(data: bytes, expected_checksum: int) -> bool:
    """
    Verify whether the calculated checksum of data matches the expected 32-bit checksum.

    Args:
        data: Raw byte buffer.
        expected_checksum: Unsigned 32-bit integer checksum.

    Returns:
        True if checksums match exactly, False otherwise.
    """
    return calculate_checksum(data) == (expected_checksum & 0xFFFFFFFF)


# Aliases for explicit CRC32 naming
calculate_crc32 = calculate_checksum
verify_crc32 = verify_checksum


def calculate_bytes_sha256(data: bytes) -> str:
    """
    Compute hex-encoded SHA-256 digest of in-memory bytes.

    Args:
        data: Raw byte buffer.

    Returns:
        Hex-encoded SHA-256 string (64 characters).
    """
    return hashlib.sha256(data).hexdigest()


def calculate_file_sha256(file_path: Path | str, chunk_size: int = 65536) -> str:
    """
    Compute hex-encoded SHA-256 hash of a file by streaming in chunks.

    Args:
        file_path: Path to the target file.
        chunk_size: Block size in bytes for reading (default 64 KB).

    Returns:
        Hex-encoded SHA-256 digest.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If file access is restricted.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found for SHA-256 computation: {path}")

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_file_sha256(file_path: Path | str, expected_hash: str) -> bool:
    """
    Verify that a file's computed SHA-256 matches the expected hash.

    Args:
        file_path: Target file.
        expected_hash: Hex-encoded SHA-256 string to compare against.

    Returns:
        True if hashes match exactly, False otherwise.
    """
    try:
        actual_hash = calculate_file_sha256(file_path)
        return actual_hash.lower() == expected_hash.strip().lower()
    except (FileNotFoundError, PermissionError):
        return False
