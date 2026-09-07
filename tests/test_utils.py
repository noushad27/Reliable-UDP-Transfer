"""
Unit tests for app/utils.py.
Validates logging setup, formatting utilities, and security path sanitization.
"""

import logging
import tempfile
import unittest
from pathlib import Path

from app.utils import (
    format_bytes,
    format_duration,
    format_throughput,
    sanitize_filename,
    setup_logging,
    validate_file_path,
)


class TestUtils(unittest.TestCase):
    """Test suite for helper and utility functions."""

    def test_setup_logging(self):
        """Test logging configuration with console and file output."""
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
            log_path = Path(tmp.name)

        try:
            logger = setup_logging(log_level="DEBUG", log_file=log_path, logger_name="test_logger")
            self.assertEqual(logger.level, logging.DEBUG)
            logger.info("Test message for reliable UDP")

            # Flush and verify log file has content
            with open(log_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Test message for reliable UDP", content)
        finally:
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)
            if log_path.exists():
                try:
                    log_path.unlink()
                except PermissionError:
                    pass

    def test_format_bytes(self):
        """Test formatting of byte counts into human-readable units."""
        self.assertEqual(format_bytes(500), "500 B")
        self.assertEqual(format_bytes(1024), "1.00 KB")
        self.assertEqual(format_bytes(1048576), "1.00 MB")
        self.assertEqual(format_bytes(1073741824), "1.00 GB")
        self.assertEqual(format_bytes(-10), "-10 B")

    def test_format_throughput(self):
        """Test formatting throughput."""
        self.assertEqual(format_throughput(1048576, 1.0), "1.00 MB/s")
        self.assertEqual(format_throughput(0, 1.0), "0 B/s")
        self.assertEqual(format_throughput(1024, 0.0), "0.00 B/s")

    def test_format_duration(self):
        """Test formatting elapsed time."""
        self.assertEqual(format_duration(0.05), "50.0 ms")
        self.assertEqual(format_duration(2.5), "2.50 s")
        self.assertEqual(format_duration(-1.0), "0.00 s")

    def test_sanitize_filename(self):
        """Test filename sanitization against path traversal attacks."""
        self.assertEqual(sanitize_filename("document.pdf"), "document.pdf")
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename(r"..\..\Windows\System32\cmd.exe"), "cmd.exe")
        self.assertEqual(sanitize_filename("/var/log/app.log"), "app.log")
        self.assertEqual(sanitize_filename("image\x00.png"), "image.png")
        self.assertEqual(sanitize_filename(""), "unnamed_received_file")
        self.assertEqual(sanitize_filename(".."), "unnamed_received_file")

    def test_validate_file_path(self):
        """Test file path validation."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            valid_path = validate_file_path(tmp_path, must_exist=True)
            self.assertEqual(valid_path, tmp_path.resolve())

            with self.assertRaises(FileNotFoundError):
                validate_file_path("nonexistent_path_xyz.bin", must_exist=True)

            with self.assertRaises(IsADirectoryError):
                validate_file_path(tmp_path.parent, must_exist=True)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


if __name__ == "__main__":
    unittest.main()
