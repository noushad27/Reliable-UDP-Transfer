"""
Unit tests for app/packet.py.
Validates binary struct serialization (encode/decode), CRC32 integrity enforcement,
header layout constraints, and error handling on corrupted/truncated/oversized packets.
"""

import struct
import unittest

from app.config import (
    HEADER_SIZE,
    HEADER_STRUCT_FORMAT,
    MAX_PAYLOAD_SIZE,
    PROTOCOL_MAGIC,
    PROTOCOL_VERSION,
    PacketType,
)
from app.packet import (
    ChecksumMismatchError,
    InvalidHeaderError,
    InvalidPayloadLengthError,
    Packet,
    PacketError,
    PacketTruncatedError,
)


class TestPacket(unittest.TestCase):
    """Test suite for Packet class binary serialization and parsing."""

    def test_packet_header_size(self):
        """Ensure empty packet serialization exactly equals HEADER_SIZE (22 bytes)."""
        pkt = Packet(pkt_type=PacketType.ACK, session_id=1001, ack_num=42)
        raw = pkt.encode()
        self.assertEqual(len(raw), HEADER_SIZE)
        self.assertEqual(pkt.to_bytes(), raw)

    def test_data_packet_encode_decode_roundtrip(self):
        """Test packing and unpacking of a DATA packet using encode() and decode()."""
        payload = b"\x00\xff\xfe\x01\x42" * 100
        pkt = Packet.create_data(session_id=5555, seq_num=128, payload=payload)
        raw = pkt.encode()

        self.assertEqual(len(raw), HEADER_SIZE + len(payload))

        unpacked = Packet.decode(raw)
        self.assertEqual(unpacked.magic, PROTOCOL_MAGIC)
        self.assertEqual(unpacked.version, PROTOCOL_VERSION)
        self.assertEqual(unpacked.pkt_type, PacketType.DATA)
        self.assertEqual(unpacked.session_id, 5555)
        self.assertEqual(unpacked.seq_num, 128)
        self.assertEqual(unpacked.ack_num, 0)
        self.assertEqual(unpacked.payload_len, len(payload))
        self.assertEqual(unpacked.payload, payload)
        self.assertEqual(unpacked.checksum, pkt.checksum)

    def test_all_packet_types_wire_representation(self):
        """Verify that all defined packet types serialize and deserialize accurately."""
        types_to_test = [
            PacketType.START,
            PacketType.START_ACK,
            PacketType.DATA,
            PacketType.ACK,
            PacketType.FIN,
            PacketType.FIN_ACK,
            PacketType.ERROR,
        ]
        for idx, ptype in enumerate(types_to_test):
            pkt = Packet(pkt_type=ptype, session_id=100 + idx, seq_num=idx, ack_num=idx * 2)
            raw = pkt.encode()
            decoded = Packet.decode(raw)
            self.assertEqual(decoded.pkt_type, ptype)
            self.assertEqual(decoded.session_id, 100 + idx)
            self.assertEqual(decoded.seq_num, idx)
            self.assertEqual(decoded.ack_num, idx * 2)

    def test_start_packet_metadata(self):
        """Test START packet with metadata payload."""
        pkt = Packet.create_start(
            session_id=1234,
            filename="document.pdf",
            filesize=1048576,
            total_packets=1024,
            file_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            window_size=32,
            arq_mode="selective_repeat",
        )
        raw = pkt.encode()
        unpacked = Packet.decode(raw)

        self.assertEqual(unpacked.pkt_type, PacketType.START)
        meta = unpacked.get_json_payload()
        self.assertEqual(meta["filename"], "document.pdf")
        self.assertEqual(meta["filesize"], 1048576)
        self.assertEqual(meta["total_packets"], 1024)
        self.assertEqual(meta["window_size"], 32)
        self.assertEqual(meta["arq_mode"], "selective_repeat")

    def test_ack_packet_roundtrip(self):
        """Test ACK packet generation and deserialization."""
        pkt = Packet.create_ack(session_id=987, ack_num=255)
        raw = pkt.encode()
        unpacked = Packet.decode(raw)

        self.assertEqual(unpacked.pkt_type, PacketType.ACK)
        self.assertEqual(unpacked.session_id, 987)
        self.assertEqual(unpacked.ack_num, 255)
        self.assertEqual(unpacked.payload, b"")

    def test_fin_and_fin_ack_roundtrip(self):
        """Test FIN and FIN_ACK packets."""
        fin = Packet.create_fin(session_id=77, file_sha256="abc123hash")
        unpacked_fin = Packet.decode(fin.encode())
        self.assertEqual(unpacked_fin.pkt_type, PacketType.FIN)
        self.assertEqual(unpacked_fin.get_json_payload()["file_sha256"], "abc123hash")

        fin_ack = Packet.create_fin_ack(session_id=77, verified=True, receiver_sha256="abc123hash")
        unpacked_fin_ack = Packet.decode(fin_ack.encode())
        self.assertEqual(unpacked_fin_ack.pkt_type, PacketType.FIN_ACK)
        self.assertTrue(unpacked_fin_ack.get_json_payload()["verified"])

    def test_error_packet_roundtrip(self):
        """Test ERROR packet creation and decoding."""
        err_pkt = Packet.create_error(session_id=42, message="Transfer aborted by peer", code=404)
        unpacked = Packet.decode(err_pkt.encode())
        self.assertEqual(unpacked.pkt_type, PacketType.ERROR)
        payload = unpacked.get_json_payload()
        self.assertEqual(payload["code"], 404)
        self.assertEqual(payload["message"], "Transfer aborted by peer")

    def test_corrupted_payload_checksum_rejection(self):
        """Verify that any single byte corruption in payload raises ChecksumMismatchError."""
        pkt = Packet.create_data(session_id=1, seq_num=10, payload=b"Sensory network telemetry stream")
        raw = bytearray(pkt.encode())

        # Corrupt one payload byte
        raw[-1] ^= 0xFF
        with self.assertRaises(ChecksumMismatchError):
            Packet.decode(bytes(raw))

    def test_corrupted_header_checksum_rejection(self):
        """Verify that altering sequence number in header causes ChecksumMismatchError."""
        pkt = Packet.create_data(session_id=1, seq_num=10, payload=b"Payload data")
        raw = bytearray(pkt.encode())

        # Sequence number is at bytes 8:12. Alter one byte.
        raw[10] ^= 0x01
        with self.assertRaises(ChecksumMismatchError):
            Packet.decode(bytes(raw))

    def test_invalid_magic_bytes(self):
        """Verify that invalid magic identifier raises InvalidHeaderError."""
        pkt = Packet.create_ack(session_id=1, ack_num=1)
        raw = bytearray(pkt.encode())
        raw[0:2] = b"XX"  # Bad magic

        with self.assertRaises(InvalidHeaderError):
            Packet.decode(bytes(raw))

    def test_invalid_version(self):
        """Verify that unknown protocol version raises InvalidHeaderError."""
        pkt = Packet.create_ack(session_id=1, ack_num=1)
        raw = bytearray(pkt.encode())
        raw[0:2] = PROTOCOL_MAGIC
        raw[2] = 99  # Invalid version

        with self.assertRaises(InvalidHeaderError):
            Packet.decode(bytes(raw))

    def test_invalid_packet_type(self):
        """Verify that unknown packet type raises InvalidHeaderError."""
        pkt = Packet.create_ack(session_id=1, ack_num=1)
        raw = bytearray(pkt.encode())
        raw[0:2] = PROTOCOL_MAGIC
        raw[2] = PROTOCOL_VERSION
        raw[3] = 250  # Unknown type

        with self.assertRaises(InvalidHeaderError):
            Packet.decode(bytes(raw))

    def test_truncated_header(self):
        """Verify that raw bytes shorter than 22 bytes raise PacketTruncatedError."""
        with self.assertRaises(PacketTruncatedError):
            Packet.decode(b"RD\x01\x01\x00\x00")

    def test_truncated_payload(self):
        """Verify that buffer shorter than declared payload_len raises PacketTruncatedError."""
        pkt = Packet.create_data(session_id=1, seq_num=1, payload=b"A" * 100)
        raw = pkt.encode()
        # Truncate 20 bytes from payload
        truncated_raw = raw[:-20]

        with self.assertRaises(PacketTruncatedError):
            Packet.decode(truncated_raw)

    def test_oversized_payload_on_encode(self):
        """Verify that encoding payload larger than MAX_PAYLOAD_SIZE raises InvalidPayloadLengthError."""
        huge_payload = b"X" * (MAX_PAYLOAD_SIZE + 1)
        pkt = Packet(pkt_type=PacketType.DATA, session_id=1, payload=huge_payload)
        with self.assertRaises(InvalidPayloadLengthError):
            pkt.encode()

    def test_oversized_declared_payload_on_decode(self):
        """Verify that decode raises InvalidPayloadLengthError when declared length exceeds limit."""
        # Craft a header declaring 65500 bytes payload (limit is 65485)
        bad_header = struct.pack(
            HEADER_STRUCT_FORMAT,
            PROTOCOL_MAGIC,
            PROTOCOL_VERSION,
            int(PacketType.DATA),
            1,     # session_id
            0,     # seq_num
            0,     # ack_num
            65500, # payload_len > MAX_PAYLOAD_SIZE
            0,     # checksum
        )
        with self.assertRaises(InvalidPayloadLengthError):
            Packet.decode(bad_header + (b"A" * 100))

    def test_malformed_random_packet(self):
        """Verify that random garbage bytes raise appropriate PacketError."""
        garbage = b"\xde\xad\xbe\xef" * 8
        with self.assertRaises(PacketError):
            Packet.decode(garbage)


if __name__ == "__main__":
    unittest.main()
