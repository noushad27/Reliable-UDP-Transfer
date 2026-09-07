"""
Unit and integration tests for SHA-256 file integrity verification (Milestone 9).
Validates streaming hash calculation, sender/receiver hash matching,
and deterministic failure when file corruption/tampering occurs.
"""

import hashlib
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from app.checksum import (
    calculate_bytes_sha256,
    calculate_file_sha256,
    verify_file_sha256,
)
from app.config import TransferConfig
from app.transfer import FileReceiver, FileSender, inspect_file


class TestFileIntegrity(unittest.TestCase):
    """Test suite for complete-file SHA-256 integrity verification."""

    def setUp(self):
        self.test_port = 9890

    def test_incremental_streaming_sha256(self):
        """
        Verify that calculate_file_sha256 reads and hashes files in incremental chunks
        rather than buffering the entire file in RAM, matching standard hashlib digest.
        """
        # Create a 256 KB file
        size = 256 * 1024
        test_bytes = os.urandom(size)
        expected_hash = hashlib.sha256(test_bytes).hexdigest()

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
            tmp.write(test_bytes)
            tmp_path = Path(tmp.name)

        try:
            # Stream with tiny 4 KB blocks to test multiple iteration cycles
            streamed_hash = calculate_file_sha256(tmp_path, chunk_size=4096)
            self.assertEqual(streamed_hash, expected_hash)
            self.assertTrue(verify_file_sha256(tmp_path, expected_hash))

            # One-byte mutation on disk must completely break the hash
            with open(tmp_path, "r+b") as f:
                f.seek(size // 2)
                original_byte = f.read(1)[0]
                f.seek(size // 2)
                f.write(bytes([original_byte ^ 0xFF]))

            corrupted_hash = calculate_file_sha256(tmp_path, chunk_size=4096)
            self.assertNotEqual(corrupted_hash, expected_hash)
            self.assertFalse(verify_file_sha256(tmp_path, expected_hash))
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_end_to_end_binary_transfer_sha256_match(self):
        """
        Verify that transferring binary formats (PDF, ZIP, PNG, JPG) produces
        an exact SHA-256 match and confirms SUCCESS.
        """
        samples_dir = Path("sample_files")
        if not samples_dir.exists():
            self.skipTest("sample_files directory not present")

        port = self.test_port
        for sample in ("sample.pdf", "sample.zip", "sample.png", "sample.jpg"):
            sample_path = samples_dir / sample
            if not sample_path.exists():
                continue

            with tempfile.TemporaryDirectory() as recv_dir:
                config_rcv = TransferConfig(host="127.0.0.1", port=port, output_dir=Path(recv_dir))
                config_snd = TransferConfig(host="127.0.0.1", port=port)

                recv_result = []
                ready = threading.Event()

                def receiver_worker():
                    receiver = FileReceiver(config_rcv)
                    ready.set()
                    out_p, ok = receiver.receive_file()
                    recv_result.append((out_p, ok))

                t = threading.Thread(target=receiver_worker, daemon=True)
                t.start()
                self.assertTrue(ready.wait(timeout=2.0))
                time.sleep(0.05)

                sender = FileSender(config_snd)
                stats = sender.send_file(sample_path)
                t.join(timeout=5.0)

                self.assertTrue(stats.success)
                self.assertEqual(len(recv_result), 1)
                out_file, verified = recv_result[0]
                self.assertTrue(verified)

                # Verify receiver hash matches sender hash
                expected_sha = calculate_file_sha256(sample_path)
                actual_sha = calculate_file_sha256(out_file)
                self.assertEqual(actual_sha, expected_sha)
                self.assertEqual(stats.sha256_hash, actual_sha)

            port += 1

    def test_sha256_mismatch_detected_and_fails_transfer(self):
        """
        Simulate disk corruption or in-transit mutation that bypassed packet layer.
        Verify receiver detects SHA-256 mismatch upon FIN and reports FAILURE.
        """
        port = self.test_port + 10
        content = b"Integrity tamper verification payload block " * 50
        fake_sha256 = "0" * 64  # An incorrect SHA-256

        with tempfile.TemporaryDirectory() as sender_dir, tempfile.TemporaryDirectory() as recv_dir:
            src_file = Path(sender_dir) / "tamper_test.txt"
            src_file.write_bytes(content)

            config_rcv = TransferConfig(host="127.0.0.1", port=port, output_dir=Path(recv_dir))
            receiver = FileReceiver(config_rcv)

            ready = threading.Event()
            recv_outcome = []

            def receiver_worker():
                ready.set()
                out_p, ok = receiver.receive_file()
                recv_outcome.append((out_p, ok))

            t = threading.Thread(target=receiver_worker, daemon=True)
            t.start()
            self.assertTrue(ready.wait(timeout=2.0))
            time.sleep(0.05)

            # Use sender but artificially provide fake SHA-256 during teardown
            from app.protocol import StopAndWaitSender
            meta = inspect_file(src_file, chunk_size=1024)

            config_snd = TransferConfig(host="127.0.0.1", port=port)
            proto_sender = StopAndWaitSender(config_snd)

            proto_sender.send_handshake(meta)
            from app.transfer import read_file_chunks
            for seq, chunk in enumerate(read_file_chunks(src_file, 1024)):
                proto_sender.send_chunk(seq, chunk)

            # Send FIN with incorrect SHA-256
            fin_verified = proto_sender.send_teardown(file_sha256=fake_sha256)
            proto_sender.close()

            t.join(timeout=5.0)

            # Sender teardown must fail
            self.assertFalse(fin_verified)
            # Receiver must report failure
            self.assertEqual(len(recv_outcome), 1)
            _, receiver_ok = recv_outcome[0]
            self.assertFalse(receiver_ok)


if __name__ == "__main__":
    unittest.main()
