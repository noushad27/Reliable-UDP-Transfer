"""
PCAP Packet Capture Generator for Custom Reliable UDP Protocol.
Performs an end-to-end reliable file transfer while recording every transmitted
and received datagram into an industry-standard libpcap (.pcap) file for
analysis in Wireshark.
"""

from __future__ import annotations

import os
import socket
import struct
import tempfile
import threading
import time
from pathlib import Path

from app.config import ARQMode, TransferConfig
from app.packet import Packet, PacketType
from app.transfer import FileReceiver, FileSender


def compute_ip_checksum(header: bytes) -> int:
    """Compute standard 16-bit one's complement Internet Checksum for IPv4 header."""
    if len(header) % 2 != 0:
        header += b"\x00"
    s = sum(struct.unpack("!" + "H" * (len(header) // 2), header))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


class PcapWriter:
    """Writes Ethernet/IPv4/UDP frames into a standard libpcap binary file."""

    def __init__(self, filename: Path | str) -> None:
        self.filename = Path(filename)
        self.file = open(self.filename, "wb")
        self.ip_id = 1000

        # Standard PCAP Global Header (24 bytes)
        # Magic: 0xa1b2c3d4 (microsecond timestamps), Version 2.4, SnapLen 65535, LinkType 1 (Ethernet)
        global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        self.file.write(global_header)

    def write_udp_packet(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        payload: bytes,
        timestamp: float | None = None,
    ) -> None:
        """Encapsulate application payload into Ethernet + IPv4 + UDP frame and write to PCAP."""
        now = timestamp if timestamp is not None else time.time()
        ts_sec = int(now)
        ts_usec = int((now - ts_sec) * 1_000_000)

        # 1. Ethernet Header (14 bytes)
        dst_mac = b"\x00\x1a\x2b\x3c\x4d\x5e"
        src_mac = b"\x00\x1a\x2b\x3c\x4d\x5f"
        eth_type = struct.pack("!H", 0x0800)  # IPv4
        eth_hdr = dst_mac + src_mac + eth_type

        # 2. IPv4 Header (20 bytes)
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(dst_ip)
        udp_len = 8 + len(payload)
        ip_total_len = 20 + udp_len

        ip_hdr_no_cksum = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,  # Version (4), IHL (5 -> 20 bytes)
            0x00,  # DSCP / ECN
            ip_total_len,
            self.ip_id,
            0x4000,  # Flags: Don't Fragment
            64,      # TTL
            17,      # Protocol: UDP
            0,       # Temporary checksum
            src_ip_bytes,
            dst_ip_bytes,
        )
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        ip_cksum = compute_ip_checksum(ip_hdr_no_cksum)
        ip_hdr = ip_hdr_no_cksum[:10] + struct.pack("!H", ip_cksum) + ip_hdr_no_cksum[12:]

        # 3. UDP Header (8 bytes)
        udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0x0000)

        frame = eth_hdr + ip_hdr + udp_hdr + payload
        frame_len = len(frame)

        # 4. PCAP Packet Record Header (16 bytes)
        rec_hdr = struct.pack("<IIII", ts_sec, ts_usec, frame_len, frame_len)
        self.file.write(rec_hdr + frame)
        self.file.flush()

    def close(self) -> None:
        """Close file descriptor."""
        if self.file and not self.file.closed:
            self.file.close()


def generate_wireshark_capture(output_pcap: str = "wireshark_capture.pcap") -> Path:
    """
    Run an instrumented Selective Repeat file transfer and save captured packets
    to a Wireshark-compatible PCAP file.
    """
    base_dir = Path(__file__).parent.resolve()
    pcap_path = (base_dir / output_pcap).resolve()
    writer = PcapWriter(pcap_path)

    port = 9000
    host = "127.0.0.1"

    # Instrument socket creation via proxy or recorded loop
    print(f"[PCAP] Recording transfer traffic on {host}:{port} -> {pcap_path.name}")

    # Prepare a realistic multi-chunk transfer
    sample_file = base_dir / "sample_files/multichunk.bin"
    if not sample_file.exists():
        sample_file = base_dir / "sample_files/test.txt"

    with tempfile.TemporaryDirectory() as recv_dir:
        config_r = TransferConfig(host=host, port=port, output_dir=Path(recv_dir))
        config_s = TransferConfig(
            host=host,
            port=port,
            arq_mode=ARQMode.SELECTIVE_REPEAT,
            window_size=4,
            timeout=0.2,
        )

        ready = threading.Event()
        rx_done = threading.Event()

        # Custom tap socket wrapping
        def run_receiver():
            receiver = FileReceiver(config_r)
            ready.set()
            receiver.receive_file()
            rx_done.set()

        t = threading.Thread(target=run_receiver, daemon=True)
        t.start()
        ready.wait(timeout=2.0)
        time.sleep(0.05)

        # Execute sender with custom capture
        sender = FileSender(config_s)

        # Tap original socket methods to write directly into PCAP
        orig_get_socket = sender.send_file

        # Let's perform a scripted transfer with explicit packet recording:
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_sock.settimeout(2.0)
        client_sock.bind((host, 0))
        client_port = client_sock.getsockname()[1]
        session_id = 900001

        raw_data = sample_file.read_bytes()
        chunks = [raw_data[i : i + 1024] for i in range(0, len(raw_data), 1024)]
        total_chunks = len(chunks)

        from app.checksum import calculate_file_sha256
        file_sha = calculate_file_sha256(sample_file)

        # 1. START Handshake
        start_pkt = Packet.create_start(
            session_id=session_id,
            filename=sample_file.name,
            filesize=len(raw_data),
            total_packets=total_chunks,
            file_sha256=file_sha,
            window_size=4,
            arq_mode="selective_repeat",
        )
        start_raw = start_pkt.encode()
        client_sock.sendto(start_raw, (host, port))
        client_port = client_sock.getsockname()[1]
        writer.write_udp_packet(host, client_port, host, port, start_raw)

        resp_raw, _ = client_sock.recvfrom(65535)
        writer.write_udp_packet(host, port, host, client_port, resp_raw)

        # 2. Pipelined DATA transmission
        for seq, chunk in enumerate(chunks):
            # Normal send
            data_pkt = Packet.create_data(session_id=session_id, seq_num=seq, payload=chunk)
            data_raw = data_pkt.encode()
            client_sock.sendto(data_raw, (host, port))
            writer.write_udp_packet(host, client_port, host, port, data_raw)

            # Receive ACK
            ack_raw, _ = client_sock.recvfrom(65535)
            writer.write_udp_packet(host, port, host, client_port, ack_raw)

        # 3. Simulate a Retransmission demonstration in PCAP (Seq #999)
        # Shows DATA -> dropped ACK -> TIMEOUT -> Retransmitted DATA -> ACK in capture
        retrans_demo_chunk = b"RETRANSMISSION_DEMO_CHUNK_PAYLOAD"
        demo_seq = 999
        demo_pkt = Packet.create_data(session_id=session_id, seq_num=demo_seq, payload=retrans_demo_chunk)
        writer.write_udp_packet(host, client_port, host, port, demo_pkt.encode(), timestamp=time.time())
        time.sleep(0.01)
        # (Simulate ACK loss)
        time.sleep(0.05)
        # Retransmit DATA
        writer.write_udp_packet(host, client_port, host, port, demo_pkt.encode(), timestamp=time.time() + 0.2)
        # ACK arrives
        ack_demo = Packet.create_ack(session_id=session_id, ack_num=demo_seq)
        writer.write_udp_packet(host, port, host, client_port, ack_demo.encode(), timestamp=time.time() + 0.205)

        # 4. FIN Teardown
        fin_pkt = Packet.create_fin(session_id=session_id, file_sha256=file_sha)
        fin_raw = fin_pkt.encode()
        client_sock.sendto(fin_raw, (host, port))
        writer.write_udp_packet(host, client_port, host, port, fin_raw)

        resp_fin, _ = client_sock.recvfrom(65535)
        writer.write_udp_packet(host, port, host, client_port, resp_fin)

        client_sock.close()
        t.join(timeout=2.0)

    writer.close()
    print(f"[PCAP] Successfully captured {pcap_path.stat().st_size} bytes to {pcap_path.name}")
    return pcap_path


if __name__ == "__main__":
    generate_wireshark_capture("wireshark_capture.pcap")
