"""
Unit and integration tests for app/transfer.py.
Validates file validation, binary chunk streaming, metadata extraction,
and chunk count calculations across various file sizes and formats.
"""

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from app.config import TransferConfig
from app.transfer import (
    FileMetadata,
    FileReceiver,
    FileSender,
    TransferStats,
    calculate_total_chunks,
    inspect_file,
    read_file_chunks,
    validate_file,
)


class TestFileChunking(unittest.TestCase):
    """Test suite for binary file handling and chunking."""

    def test_small_file(self):
        """Test chunking of a small file smaller than the 1024-byte payload size."""
        content = b"Small file transfer test content."
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            meta = inspect_file(tmp_path, chunk_size=1024)
            self.assertEqual(meta.filesize, len(content))
            self.assertEqual(meta.total_chunks, 1)
            self.assertEqual(meta.payload_size, 1024)

            chunks = list(read_file_chunks(tmp_path, chunk_size=1024))
            self.assertEqual(len(chunks), 1)
            self.assertEqual(chunks[0], content)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_binary_file(self):
        """Test chunking with non-text binary data containing null bytes and full 0xFF bytes."""
        # Non-ASCII, arbitrary binary pattern
        content = bytes(range(256)) * 4  # 1024 bytes
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            meta = inspect_file(tmp_path, chunk_size=512)
            self.assertEqual(meta.filesize, 1024)
            self.assertEqual(meta.total_chunks, 2)
            self.assertEqual(meta.sha256_hash, hashlib.sha256(content).hexdigest())

            chunks = list(read_file_chunks(tmp_path, chunk_size=512))
            self.assertEqual(len(chunks), 2)
            self.assertEqual(len(chunks[0]), 512)
            self.assertEqual(len(chunks[1]), 512)
            self.assertEqual(b"".join(chunks), content)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_empty_file(self):
        """Test handling of an empty (0-byte) file."""
        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            meta = inspect_file(tmp_path, chunk_size=1024)
            self.assertEqual(meta.filesize, 0)
            self.assertEqual(meta.total_chunks, 0)
            self.assertEqual(meta.sha256_hash, hashlib.sha256(b"").hexdigest())

            chunks = list(read_file_chunks(tmp_path, chunk_size=1024))
            self.assertEqual(len(chunks), 0)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_file_larger_than_payload(self):
        """Test file significantly larger than chunk size to verify multi-chunk partitioning."""
        total_size = 3500  # 3500 bytes with 1024 chunk size = 4 chunks (1024, 1024, 1024, 428)
        content = os.urandom(total_size)
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            meta = inspect_file(tmp_path, chunk_size=1024)
            self.assertEqual(meta.filesize, 3500)
            self.assertEqual(meta.total_chunks, 4)

            chunks = list(read_file_chunks(tmp_path, chunk_size=1024))
            self.assertEqual(len(chunks), 4)
            self.assertEqual(len(chunks[0]), 1024)
            self.assertEqual(len(chunks[1]), 1024)
            self.assertEqual(len(chunks[2]), 1024)
            self.assertEqual(len(chunks[3]), 428)

            # Ensure byte-for-byte reassembly matches original
            self.assertEqual(b"".join(chunks), content)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_missing_file(self):
        """Test that attempting to validate or chunk a missing file raises FileNotFoundError."""
        fake_path = Path("this_file_does_not_exist_xyz_987654.pdf")
        with self.assertRaises(FileNotFoundError):
            validate_file(fake_path)

        with self.assertRaises(FileNotFoundError):
            list(read_file_chunks(fake_path))

        with self.assertRaises(FileNotFoundError):
            inspect_file(fake_path)

    def test_directory_raises_error(self):
        """Test that passing a directory instead of a regular file raises IsADirectoryError."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            dir_path = Path(tmp_dir)
            with self.assertRaises(IsADirectoryError):
                validate_file(dir_path)

    def test_chunk_calculation_edge_cases(self):
        """Test chunk calculation boundary cases."""
        self.assertEqual(calculate_total_chunks(0, 1024), 0)
        self.assertEqual(calculate_total_chunks(1, 1024), 1)
        self.assertEqual(calculate_total_chunks(1024, 1024), 1)
        self.assertEqual(calculate_total_chunks(1025, 1024), 2)
        self.assertEqual(calculate_total_chunks(2048, 1024), 2)
        self.assertEqual(calculate_total_chunks(2049, 1024), 3)

        with self.assertRaises(ValueError):
            calculate_total_chunks(-5, 1024)
        with self.assertRaises(ValueError):
            calculate_total_chunks(100, 0)
        with self.assertRaises(ValueError):
            calculate_total_chunks(100, -10)

    def test_sample_files_reading_and_integrity(self):
        """Test inspecting and chunking all generated sample files (TXT, PDF, JPG, PNG, ZIP)."""
        samples_dir = Path("sample_files")
        if not samples_dir.exists():
            self.skipTest("sample_files directory does not exist")

        expected_extensions = {".txt", ".pdf", ".jpg", ".png", ".zip"}
        found_extensions = set()

        for sample_file in samples_dir.iterdir():
            if sample_file.is_file() and sample_file.suffix in expected_extensions:
                found_extensions.add(sample_file.suffix)
                meta = inspect_file(sample_file, chunk_size=1024)
                self.assertGreater(meta.filesize, 0)
                self.assertGreaterEqual(meta.total_chunks, 1)

                # Read and reassemble
                reassembled = b"".join(read_file_chunks(sample_file, chunk_size=1024))
                self.assertEqual(len(reassembled), meta.filesize)
                self.assertEqual(hashlib.sha256(reassembled).hexdigest(), meta.sha256_hash)

        # Confirm all 5 target formats were found and tested
        self.assertTrue(expected_extensions.issubset(found_extensions))

    def test_file_metadata_to_dict(self):
        """Test FileMetadata dictionary serialization."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp.write(b"metadata test")
            tmp_path = Path(tmp.name)

        try:
            meta = inspect_file(tmp_path, chunk_size=512)
            d = meta.to_dict()
            self.assertEqual(d["filename"], tmp_path.name)
            self.assertEqual(d["filesize"], 13)
            self.assertEqual(d["total_chunks"], 1)
            self.assertEqual(d["total_packets"], 1)
            self.assertEqual(d["payload_size"], 512)
            self.assertIn("sha256_hash", d)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_transfer_stats_summary_formatting(self):
        """Test TransferStats format_summary for success and failure."""
        stats_ok = TransferStats(
            filename="data.bin",
            filesize=1000,
            duration_seconds=2.0,
            throughput_bytes_per_sec=500.0,
            total_packets_sent=2,
            retransmissions=0,
            success=True,
            sha256_hash="deadbeef" * 8,
        )
        summary_ok = stats_ok.format_summary()
        self.assertIn("Transfer Result: SUCCESS", summary_ok)
        self.assertIn("data.bin", summary_ok)
        self.assertIn("deadbeef", summary_ok)

        stats_fail = TransferStats(
            filename="corrupt.bin",
            filesize=5000,
            duration_seconds=1.0,
            throughput_bytes_per_sec=0.0,
            total_packets_sent=5,
            retransmissions=5,
            success=False,
            sha256_hash="",
        )
        summary_fail = stats_fail.format_summary()
        self.assertIn("Transfer Result: FAILED", summary_fail)
        self.assertIn("Incomplete", summary_fail)

    def test_calculate_total_chunks_type_validation(self):
        """Test that non-integer arguments to calculate_total_chunks raise TypeError."""
        with self.assertRaises(TypeError):
            calculate_total_chunks("100", 1024)  # type: ignore
        with self.assertRaises(TypeError):
            calculate_total_chunks(100, "1024")  # type: ignore
        with self.assertRaises(TypeError):
            calculate_total_chunks(True, 1024)  # type: ignore
        with self.assertRaises(TypeError):
            calculate_total_chunks(100, False)  # type: ignore

    def test_read_file_chunks_invalid_chunk_size(self):
        """Test that read_file_chunks validates chunk size properly."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"data")
            tmp_path = Path(tmp.name)

        try:
            with self.assertRaises(TypeError):
                list(read_file_chunks(tmp_path, chunk_size="512"))  # type: ignore
            with self.assertRaises(ValueError):
                list(read_file_chunks(tmp_path, chunk_size=0))
            with self.assertRaises(ValueError):
                list(read_file_chunks(tmp_path, chunk_size=-10))
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_sender_receiver_close_lifecycle(self):
        """Test that FileSender and FileReceiver can be safely closed without errors."""
        config = TransferConfig(host="127.0.0.1", port=9999)
        sender = FileSender(config)
        receiver = FileReceiver(config)

        # Calling close when no socket is active should be a no-op and not raise
        sender.close()
        receiver.close()
        self.assertIsNone(sender._active_sender)
        self.assertIsNone(receiver._active_receiver)


if __name__ == "__main__":
    unittest.main()
