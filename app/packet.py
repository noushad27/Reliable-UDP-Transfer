"""
Packet structure, binary serialization, deserialization, and header validation.

Wire Format Specification (22-Byte Fixed Header, Network Byte Order '!'):
========================================================================================
Offset | Field        | Struct Format | Type   | Size | Description
========================================================================================
0..1   | magic        | 2s            | bytes  | 2 B  | Protocol Identifier b"RD" (0x5244)
2      | version      | B             | uint8  | 1 B  | Protocol Version (default: 1)
3      | pkt_type     | B             | uint8  | 1 B  | PacketType (1=START..7=ERROR)
4..7   | session_id   | I             | uint32 | 4 B  | Transfer Session Identifier
8..11  | seq_num      | I             | uint32 | 4 B  | Packet Sequence Number
12..15 | ack_num      | I             | uint32 | 4 B  | Acknowledgment Number
16..17 | payload_len  | H             | uint16 | 2 B  | Payload size in bytes (0..65485)
18..21 | checksum     | I             | uint32 | 4 B  | CRC32 (Header with cksum=0 + Payload)
22..N  | payload      | bytes         | bytes  | var  | Raw binary chunk or control payload
========================================================================================
Total Header Size: 22 bytes. Format string: '!2sBBIIIHI'
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from typing import Any, Optional

from app.checksum import (
    calculate_checksum,
    calculate_crc32,
    verify_checksum,
    verify_crc32,
)
from app.config import (
    HEADER_SIZE,
    HEADER_STRUCT_FORMAT,
    MAX_PAYLOAD_SIZE,
    PROTOCOL_MAGIC,
    PROTOCOL_VERSION,
    PacketType,
)


class PacketError(Exception):
    """Base exception for all packet-level errors."""
    pass


class InvalidHeaderError(PacketError):
    """Raised when header contains invalid magic, version, or unknown type."""
    pass


class InvalidVersionError(InvalidHeaderError):
    """Raised when packet protocol version does not match PROTOCOL_VERSION."""
    pass


class InvalidPacketTypeError(InvalidHeaderError):
    """Raised when packet type ID is unknown or outside PacketType enum."""
    pass


class InvalidSessionIdError(InvalidHeaderError):
    """Raised when session ID is zero or outside permissible uint32 range."""
    pass


class InvalidSequenceNumberError(PacketError):
    """Raised when sequence number or ack number is outside valid uint32 range."""
    pass


class ChecksumMismatchError(PacketError):
    """Raised when received packet fails CRC32 integrity verification."""
    pass


class PacketTruncatedError(PacketError):
    """Raised when raw packet buffer is shorter than header or declared payload."""
    pass


class InvalidPayloadLengthError(PacketError):
    """Raised when payload length exceeds permissible limits or is invalid."""
    pass


class OversizedPacketError(PacketError):
    """Raised when raw datagram exceeds maximum allowable UDP datagram size."""
    pass


@dataclass
class Packet:
    """
    Representation of a custom binary reliable UDP packet.

    Contains a 22-byte fixed header serialized via Python's struct module
    in network byte order (Big-Endian '!'), followed by variable-length binary payload.
    """
    pkt_type: PacketType
    session_id: int
    seq_num: int = 0
    ack_num: int = 0
    payload: bytes = field(default_factory=bytes)
    magic: bytes = PROTOCOL_MAGIC
    version: int = PROTOCOL_VERSION
    checksum: int = 0

    @property
    def payload_len(self) -> int:
        """Calculate payload length dynamically."""
        return len(self.payload)

    def encode(self) -> bytes:
        """
        Serialize packet into binary format using struct in network byte order.
        Calculates and inserts a 32-bit CRC32 checksum over the header (with checksum=0)
        concatenated with the payload.

        Returns:
            bytes: Complete binary datagram wire format.

        Raises:
            InvalidPayloadLengthError: If payload exceeds MAX_PAYLOAD_SIZE.
        """
        if not (1 <= self.session_id <= 0xFFFFFFFF):
            raise InvalidSessionIdError(
                f"Session ID {self.session_id} is invalid. Must be in range [1, 4294967295]."
            )
        if not (0 <= self.seq_num <= 0xFFFFFFFF):
            raise InvalidSequenceNumberError(
                f"Sequence number {self.seq_num} is invalid. Must be in range [0, 4294967295]."
            )
        if not (0 <= self.ack_num <= 0xFFFFFFFF):
            raise InvalidSequenceNumberError(
                f"ACK number {self.ack_num} is invalid. Must be in range [0, 4294967295]."
            )
        if len(self.payload) > MAX_PAYLOAD_SIZE:
            raise InvalidPayloadLengthError(
                f"Payload size {len(self.payload)} bytes exceeds maximum allowed {MAX_PAYLOAD_SIZE} bytes."
            )

        # 1. Pack header with checksum set to 0 to compute CRC32 over entire packet
        header_zero_cksum = struct.pack(
            HEADER_STRUCT_FORMAT,
            self.magic,
            self.version,
            int(self.pkt_type),
            self.session_id,
            self.seq_num,
            self.ack_num,
            len(self.payload),
            0,
        )

        # 2. Compute CRC32 checksum
        computed_checksum = calculate_checksum(header_zero_cksum + self.payload)
        self.checksum = computed_checksum

        # 3. Pack final header with the actual checksum in network byte order
        header_final = struct.pack(
            HEADER_STRUCT_FORMAT,
            self.magic,
            self.version,
            int(self.pkt_type),
            self.session_id,
            self.seq_num,
            self.ack_num,
            len(self.payload),
            computed_checksum,
        )

        return header_final + self.payload

    def to_bytes(self) -> bytes:
        """Alias for encode() for backward compatibility."""
        return self.encode()

    @classmethod
    def decode(cls, raw_data: bytes) -> Packet:
        """
        Parse and validate raw binary bytes received from UDP socket into a Packet instance.

        Args:
            raw_data: Raw byte array received over the network.

        Returns:
            Packet: Validated packet instance.

        Raises:
            PacketTruncatedError: If buffer length is smaller than header or declared payload.
            OversizedPacketError: If buffer exceeds max datagram size or contains trailing bytes.
            InvalidHeaderError: If magic is invalid.
            InvalidVersionError: If protocol version does not match.
            InvalidPacketTypeError: If packet type is unrecognized.
            InvalidSessionIdError: If session ID is zero or outside uint32 range.
            InvalidSequenceNumberError: If seq_num or ack_num is outside uint32 range.
            InvalidPayloadLengthError: If declared payload exceeds maximum permitted.
            ChecksumMismatchError: If computed CRC32 does not match the packet checksum.
        """
        # 1. Validate minimum header length
        if len(raw_data) < HEADER_SIZE:
            raise PacketTruncatedError(
                f"Packet data too short ({len(raw_data)} bytes). Expected at least {HEADER_SIZE} bytes."
            )

        # 2. Validate maximum packet length
        max_datagram_size = HEADER_SIZE + MAX_PAYLOAD_SIZE
        if len(raw_data) > max_datagram_size:
            raise OversizedPacketError(
                f"Packet size {len(raw_data)} bytes exceeds maximum allowed datagram size {max_datagram_size} bytes."
            )

        # 3. Unpack binary header
        header_bytes = raw_data[:HEADER_SIZE]
        try:
            (
                magic,
                version,
                pkt_type_val,
                session_id,
                seq_num,
                ack_num,
                payload_len,
                received_checksum,
            ) = struct.unpack(HEADER_STRUCT_FORMAT, header_bytes)
        except struct.error as e:
            raise InvalidHeaderError(f"Failed to unpack header with format '{HEADER_STRUCT_FORMAT}': {e}") from e

        # 4. Validate Magic bytes
        if magic != PROTOCOL_MAGIC:
            raise InvalidHeaderError(f"Invalid magic bytes {magic!r}. Expected {PROTOCOL_MAGIC!r}.")

        # 5. Validate Protocol Version
        if version != PROTOCOL_VERSION:
            raise InvalidVersionError(f"Unsupported protocol version {version}. Expected {PROTOCOL_VERSION}.")

        # 6. Validate Packet Type
        try:
            pkt_type = PacketType(pkt_type_val)
        except ValueError:
            raise InvalidPacketTypeError(f"Unknown or invalid packet type ID: {pkt_type_val}.")

        # 7. Validate Session ID
        if not (1 <= session_id <= 0xFFFFFFFF):
            raise InvalidSessionIdError(f"Invalid session ID {session_id}. Must be in range [1, 4294967295].")

        # 8. Validate Sequence and ACK numbers
        if not (0 <= seq_num <= 0xFFFFFFFF):
            raise InvalidSequenceNumberError(f"Invalid sequence number {seq_num}.")
        if not (0 <= ack_num <= 0xFFFFFFFF):
            raise InvalidSequenceNumberError(f"Invalid ACK number {ack_num}.")

        # 9. Validate Maximum Payload
        if payload_len > MAX_PAYLOAD_SIZE:
            raise InvalidPayloadLengthError(
                f"Declared payload length {payload_len} exceeds maximum allowed {MAX_PAYLOAD_SIZE} bytes."
            )

        # 10. Validate Declared Payload Length against Actual Buffer
        expected_total_len = HEADER_SIZE + payload_len
        if len(raw_data) < expected_total_len:
            raise PacketTruncatedError(
                f"Packet payload truncated: received {len(raw_data) - HEADER_SIZE} bytes, "
                f"expected {payload_len} bytes."
            )
        if len(raw_data) > expected_total_len:
            raise OversizedPacketError(
                f"Packet contains {len(raw_data) - expected_total_len} unauthenticated trailing bytes beyond declared payload."
            )

        payload = raw_data[HEADER_SIZE:expected_total_len]

        # 8. Verify CRC32 Checksum Integrity
        header_zero_cksum = struct.pack(
            HEADER_STRUCT_FORMAT,
            magic,
            version,
            pkt_type_val,
            session_id,
            seq_num,
            ack_num,
            payload_len,
            0,
        )
        packet_content_for_checksum = header_zero_cksum + payload
        if not verify_checksum(packet_content_for_checksum, received_checksum):
            computed_checksum = calculate_checksum(packet_content_for_checksum)
            raise ChecksumMismatchError(
                f"Checksum mismatch for packet type {pkt_type.name} (seq={seq_num}, ack={ack_num}): "
                f"expected {computed_checksum:#010x}, received {received_checksum:#010x}."
            )

        return cls(
            magic=magic,
            version=version,
            pkt_type=pkt_type,
            session_id=session_id,
            seq_num=seq_num,
            ack_num=ack_num,
            payload=payload,
            checksum=received_checksum,
        )

    @classmethod
    def from_bytes(cls, raw_data: bytes) -> Packet:
        """Alias for decode() for backward compatibility."""
        return cls.decode(raw_data)

    def get_json_payload(self) -> dict[str, Any]:
        """Decode and parse payload as UTF-8 JSON dictionary for control packets."""
        if not self.payload:
            return {}
        try:
            return json.loads(self.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise PacketError(f"Failed to decode JSON payload: {e}") from e

    def set_json_payload(self, data: dict[str, Any]) -> None:
        """Encode dictionary as UTF-8 JSON bytes into payload for control packets."""
        self.payload = json.dumps(data).encode("utf-8")

    # =========================================================================
    # Factory Constructors
    # =========================================================================
    @classmethod
    def create_start(
        cls,
        session_id: int,
        filename: str,
        filesize: int,
        total_packets: int,
        file_sha256: str,
        window_size: int = 16,
        arq_mode: str = "selective_repeat",
    ) -> Packet:
        """Create a START packet containing file and session metadata."""
        pkt = cls(pkt_type=PacketType.START, session_id=session_id, seq_num=0, ack_num=0)
        pkt.set_json_payload({
            "filename": filename,
            "filesize": filesize,
            "total_packets": total_packets,
            "file_sha256": file_sha256,
            "window_size": window_size,
            "arq_mode": arq_mode,
        })
        return pkt

    @classmethod
    def create_start_ack(cls, session_id: int, window_size: int = 16) -> Packet:
        """Create a START_ACK packet accepting transfer session."""
        pkt = cls(pkt_type=PacketType.START_ACK, session_id=session_id, seq_num=0, ack_num=0)
        pkt.set_json_payload({"status": "READY", "window_size": window_size})
        return pkt

    @classmethod
    def create_data(cls, session_id: int, seq_num: int, payload: bytes) -> Packet:
        """Create a pure binary DATA packet with payload chunk."""
        return cls(
            pkt_type=PacketType.DATA,
            session_id=session_id,
            seq_num=seq_num,
            ack_num=0,
            payload=payload,
        )

    @classmethod
    def create_ack(cls, session_id: int, ack_num: int) -> Packet:
        """Create an ACK packet acknowledging a sequence number."""
        return cls(
            pkt_type=PacketType.ACK,
            session_id=session_id,
            seq_num=0,
            ack_num=ack_num,
            payload=b"",
        )

    @classmethod
    def create_fin(cls, session_id: int, file_sha256: str) -> Packet:
        """Create a FIN packet signaling end of data transmission."""
        pkt = cls(pkt_type=PacketType.FIN, session_id=session_id, seq_num=0, ack_num=0)
        pkt.set_json_payload({"file_sha256": file_sha256})
        return pkt

    @classmethod
    def create_fin_ack(cls, session_id: int, verified: bool, receiver_sha256: str) -> Packet:
        """Create a FIN_ACK packet confirming final integrity check."""
        pkt = cls(pkt_type=PacketType.FIN_ACK, session_id=session_id, seq_num=0, ack_num=0)
        pkt.set_json_payload({
            "status": "SUCCESS" if verified else "CORRUPTED",
            "verified": verified,
            "receiver_sha256": receiver_sha256,
        })
        return pkt

    @classmethod
    def create_error(cls, session_id: int, message: str, code: int = 400) -> Packet:
        """Create an ERROR packet signaling a session error."""
        pkt = cls(pkt_type=PacketType.ERROR, session_id=session_id, seq_num=0, ack_num=0)
        pkt.set_json_payload({"code": code, "message": message})
        return pkt
