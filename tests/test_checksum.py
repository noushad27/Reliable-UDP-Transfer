"""
Unit tests for app/checksum.py.
Validates CRC32 checksum calculation, verification, packet-level integrity,
rejection of modified headers, payloads, and invalid checksum values.
"""

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from app.checksum import (
    calculate_bytes_sha256,
    calculate_checksum,
    calculate_crc32,
    calculate_file_sha256,
    verify_checksum,
    verify_crc32,
    verify_file_sha256,
)
from app.config import (
    HEADER_SIZE,
    HEADER_STRUCT_FORMAT,
    PROTOCOL_MAGIC,
    PROTOCOL_VERSION,
    PacketType,
)
from app.packet import ChecksumMismatchError, Packet


class TestChecksum(unittest.TestCase):
    """Test suite for checksum routines and per-packet integrity enforcement."""

    def test_checksum_calculation(self):
        """Test basic CRC32 checksum calculation and repeatability."""
        data = b"Reliable UDP transport packet payload"
        cksum = calculate_checksum(data)

        self.assertIsInstance(cksum, int)
        self.assertGreaterEqual(cksum, 0)
        self.assertLessEqual(cksum, 0xFFFFFFFF)
        # Consistent re-calculation
        self.assertEqual(cksum, calculate_checksum(data))
        # Alias consistency
        self.assertEqual(cksum, calculate_crc32(data))

    def test_checksum_verification(self):
        """Test verify_checksum returns True for intact data and False for corrupted data."""
        data = b"Critical telemetry and communication state"
        cksum = calculate_checksum(data)

        self.assertTrue(verify_checksum(data, cksum))
        self.assertTrue(verify_crc32(data, cksum))

        # Modifying a single byte should fail verification
        corrupted = bytearray(data)
        corrupted[0] ^= 0x01
        self.assertFalse(verify_checksum(bytes(corrupted), cksum))
        self.assertFalse(verify_crc32(bytes(corrupted), cksum))

    def test_valid_packet_checksum(self):
        """Test that a normally created and encoded packet passes checksum validation."""
        pkt = Packet.create_data(session_id=101, seq_num=5, payload=b"Payload data for packet test")
        raw = pkt.encode()

        # Packet should decode cleanly without ChecksumMismatchError
        decoded = Packet.decode(raw)
        self.assertEqual(decoded.seq_num, 5)
        self.assertEqual(decoded.payload, b"Payload data for packet test")
        self.assertEqual(decoded.checksum, pkt.checksum)

    def test_modified_payload_rejected(self):
        """Test that modifying even a single bit in the payload triggers ChecksumMismatchError."""
        pkt = Packet.create_data(session_id=202, seq_num=12, payload=b"Untampered binary payload block")
        raw = bytearray(pkt.encode())

        # Flip a bit in the payload (last byte)
        raw[-1] ^= 0x01

        with self.assertRaises(ChecksumMismatchError):
            Packet.decode(bytes(raw))

    def test_modified_header_rejected(self):
        """Test that modifying fields in the header causes checksum verification failure."""
        pkt = Packet.create_data(session_id=303, seq_num=20, payload=b"Header tampering verification")
        raw = bytearray(pkt.encode())

        # Sequence number is located at bytes 8..11.
        # Alter sequence number from 20 to 21
        raw[11] ^= 0x01

        with self.assertRaises(ChecksumMismatchError):
            Packet.decode(bytes(raw))

        # Also test altering session_id at bytes 4..7
        raw_session = bytearray(pkt.encode())
        raw_session[4] ^= 0xFF
        with self.assertRaises(ChecksumMismatchError):
            Packet.decode(bytes(raw_session))

    def test_invalid_checksum_value(self):
        """Test that replacing the checksum field itself with an invalid value raises ChecksumMismatchError."""
        pkt = Packet.create_ack(session_id=404, ack_num=99)
        raw = bytearray(pkt.encode())

        # Checksum is located at offsets 18..21. Overwrite with 0x00000000 or arbitrary value
        raw[18:22] = b"\x00\x00\x00\x00"

        with self.assertRaises(ChecksumMismatchError):
            Packet.decode(bytes(raw))

        raw[18:22] = b"\xff\xff\xff\xff"
        with self.assertRaises(ChecksumMismatchError):
            Packet.decode(bytes(raw))

    def test_checksum_bit_flip_sensitivity(self):
        """Test that every single bit flip in a block produces a different checksum."""
        original = b"High-precision network bit error rate detection"
        base_cksum = calculate_checksum(original)

        for byte_idx in range(len(original)):
            for bit_offset in range(8):
                mutated = bytearray(original)
                mutated[byte_idx] ^= (1 << bit_offset)
                mutated_cksum = calculate_checksum(bytes(mutated))
                self.assertNotEqual(
                    base_cksum,
                    mutated_cksum,
                    f"Collision on byte {byte_idx}, bit {bit_offset}",
                )

    def test_sha256_utilities(self):
        """Verify streaming SHA-256 computation utility functions."""
        data = b"Streamed payload chunk " * 50
        expected = hashlib.sha256(data).hexdigest()
        self.assertEqual(calculate_bytes_sha256(data), expected)

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)

        try:
            self.assertEqual(calculate_file_sha256(tmp_path), expected)
            self.assertTrue(verify_file_sha256(tmp_path, expected))
            self.assertFalse(verify_file_sha256(tmp_path, "wrong_hash"))
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


if __name__ == "__main__":
    unittest.main()
