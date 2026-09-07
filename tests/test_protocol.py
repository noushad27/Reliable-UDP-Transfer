"""
Unit and integration tests for app/protocol.py and Stop-and-Wait ARQ reliable transfer.
Validates handshake, sequential ACK progression, file reassembly, timeout enforcement,
retransmission on dropped packets, recovery from lost ACKs, and maximum retry failure handling.
"""

import hashlib
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from app.config import ARQMode, PacketType, TransferConfig
from app.packet import Packet
from app.protocol import RetransmissionLimitExceeded, StopAndWaitSender
from app.transfer import FileReceiver, FileSender, inspect_file


class TestStopAndWaitProtocol(unittest.TestCase):
    """Integration test suite for Stop-and-Wait ARQ file transfer and timeout/retransmission."""

    def setUp(self):
        self.test_port = 9880

    # ------------------------------------------------------------------------
    # 1. Normal Transfer
    # ------------------------------------------------------------------------
    def test_normal_transfer_small_text_file(self):
        """Test normal complete transfer of a small text file over loopback."""
        content = b"Hello, Reliable Stop-and-Wait ARQ Transfer over UDP!\n" * 10
        with tempfile.TemporaryDirectory() as sender_dir, tempfile.TemporaryDirectory() as recv_dir:
            src_file = Path(sender_dir) / "greeting.txt"
            src_file.write_bytes(content)

            port = self.test_port
            config_rcv = TransferConfig(host="127.0.0.1", port=port, output_dir=Path(recv_dir), payload_size=256)
            config_snd = TransferConfig(host="127.0.0.1", port=port, payload_size=256)

            recv_result: list[tuple[Path, bool]] = []
            receiver_ready = threading.Event()

            def receiver_worker():
                receiver = FileReceiver(config_rcv)
                receiver_ready.set()
                out_path, success = receiver.receive_file()
                recv_result.append((out_path, success))

            t = threading.Thread(target=receiver_worker, daemon=True)
            t.start()

            self.assertTrue(receiver_ready.wait(timeout=2.0))
            time.sleep(0.05)

            sender = FileSender(config_snd)
            stats = sender.send_file(src_file)

            t.join(timeout=5.0)

            self.assertTrue(stats.success)
            self.assertEqual(stats.retransmissions, 0)
            self.assertEqual(len(recv_result), 1)
            out_file, verified = recv_result[0]
            self.assertTrue(verified)
            self.assertEqual(out_file.read_bytes(), content)

    def test_normal_transfer_multi_chunk_binary(self):
        """Test multi-chunk transfer of binary data across multiple sequential ACKs."""
        total_size = 3500
        content = os.urandom(total_size)
        expected_sha = hashlib.sha256(content).hexdigest()
        port = self.test_port + 1

        with tempfile.TemporaryDirectory() as sender_dir, tempfile.TemporaryDirectory() as recv_dir:
            src_file = Path(sender_dir) / "random_payload.bin"
            src_file.write_bytes(content)

            config_rcv = TransferConfig(host="127.0.0.1", port=port, output_dir=Path(recv_dir), payload_size=1024)
            config_snd = TransferConfig(host="127.0.0.1", port=port, payload_size=1024)

            recv_result: list[tuple[Path, bool]] = []
            receiver_ready = threading.Event()

            def receiver_worker():
                receiver = FileReceiver(config_rcv)
                receiver_ready.set()
                out_path, success = receiver.receive_file()
                recv_result.append((out_path, success))

            t = threading.Thread(target=receiver_worker, daemon=True)
            t.start()

            self.assertTrue(receiver_ready.wait(timeout=2.0))
            time.sleep(0.05)

            sender = FileSender(config_snd)
            stats = sender.send_file(src_file)

            t.join(timeout=5.0)

            self.assertTrue(stats.success)
            self.assertEqual(stats.retransmissions, 0)
            self.assertEqual(len(recv_result), 1)
            out_file, verified = recv_result[0]
            self.assertTrue(verified)
            self.assertEqual(hashlib.sha256(out_file.read_bytes()).hexdigest(), expected_sha)

    # ------------------------------------------------------------------------
    # 2. Missing ACK & Recovery
    # ------------------------------------------------------------------------
    def test_missing_ack_retransmission_and_recovery(self):
        """
        Simulate an ACK dropped by the network.
        Receiver receives DATA #0, but the ACK is dropped once.
        Sender times out and retransmits DATA #0.
        Receiver detects duplicate DATA #0, re-sends ACK #0, and transfer completes.
        """
        port = self.test_port + 2
        content = b"Data chunk to test dropped ACK recovery scenario."
        expected_sha = hashlib.sha256(content).hexdigest()

        with tempfile.TemporaryDirectory() as sender_dir, tempfile.TemporaryDirectory() as recv_dir:
            src_file = Path(sender_dir) / "drop_ack.txt"
            src_file.write_bytes(content)

            server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_sock.bind(("127.0.0.1", port))
            server_sock.settimeout(5.0)
            receiver_ready = threading.Event()

            def custom_receiver():
                receiver_ready.set()
                # 1. Receive START
                data, sender_addr = server_sock.recvfrom(65535)
                start_pkt = Packet.decode(data)
                session_id = start_pkt.session_id

                start_ack = Packet.create_start_ack(session_id=session_id)
                server_sock.sendto(start_ack.encode(), sender_addr)

                # 2. Receive first DATA #0 (DROP the ACK once)
                data, sender_addr = server_sock.recvfrom(65535)
                data_pkt = Packet.decode(data)
                self.assertEqual(data_pkt.seq_num, 0)
                # Intentionally do NOT send ACK here (simulates lost ACK)

                # 3. Receive retransmitted DATA #0 (send ACK this time)
                data, sender_addr = server_sock.recvfrom(65535)
                retransmitted_pkt = Packet.decode(data)
                self.assertEqual(retransmitted_pkt.seq_num, 0)
                # Send ACK #0
                ack_pkt = Packet.create_ack(session_id=session_id, ack_num=0)
                server_sock.sendto(ack_pkt.encode(), sender_addr)

                # 4. Receive FIN
                data, sender_addr = server_sock.recvfrom(65535)
                fin_pkt = Packet.decode(data)
                self.assertEqual(fin_pkt.pkt_type, PacketType.FIN)
                fin_ack = Packet.create_fin_ack(session_id=session_id, verified=True, receiver_sha256=expected_sha)
                server_sock.sendto(fin_ack.encode(), sender_addr)

                server_sock.close()

            t = threading.Thread(target=custom_receiver, daemon=True)
            t.start()

            self.assertTrue(receiver_ready.wait(timeout=2.0))
            time.sleep(0.05)

            # Sender with short timeout for test speed
            config_snd = TransferConfig(
                host="127.0.0.1",
                port=port,
                timeout=0.2,
                max_retries=5,
            )
            sender = FileSender(config_snd)
            stats = sender.send_file(src_file)

            t.join(timeout=5.0)

            self.assertTrue(stats.success)
            self.assertGreaterEqual(stats.retransmissions, 1)

    # ------------------------------------------------------------------------
    # 3. Timeout Verification
    # ------------------------------------------------------------------------
    def test_timeout_duration_enforced(self):
        """Verify that socket timeout strictly bounds the waiting interval."""
        port = self.test_port + 3
        configured_timeout = 0.25

        # Bind a silent socket so packets are received by kernel but never replied to
        silent_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent_sock.bind(("127.0.0.1", port))

        config = TransferConfig(
            host="127.0.0.1",
            port=port,
            timeout=configured_timeout,
            max_retries=1,
        )
        sender = StopAndWaitSender(config)

        start_time = time.perf_counter()
        with self.assertRaises(RetransmissionLimitExceeded):
            sender.send_chunk(seq_num=10, chunk=b"Timeout test chunk")

        elapsed = time.perf_counter() - start_time
        sender.close()
        silent_sock.close()

        # Elapsed time should be at least configured_timeout
        self.assertGreaterEqual(elapsed, configured_timeout * 0.9)

    # ------------------------------------------------------------------------
    # 4. Retransmission on Lost DATA Packet
    # ------------------------------------------------------------------------
    def test_retransmission_on_data_drop(self):
        """
        Simulate a lost DATA packet on first attempt.
        Sender times out and retransmits; receiver acknowledges second attempt.
        """
        port = self.test_port + 4
        content = b"Testing retransmission when DATA packet is dropped."
        expected_sha = hashlib.sha256(content).hexdigest()

        with tempfile.TemporaryDirectory() as sender_dir:
            src_file = Path(sender_dir) / "data_drop.txt"
            src_file.write_bytes(content)

            server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_sock.bind(("127.0.0.1", port))
            server_sock.settimeout(5.0)
            receiver_ready = threading.Event()

            def custom_receiver():
                receiver_ready.set()
                # 1. START / START_ACK
                data, sender_addr = server_sock.recvfrom(65535)
                start_pkt = Packet.decode(data)
                session_id = start_pkt.session_id
                start_ack = Packet.create_start_ack(session_id=session_id)
                server_sock.sendto(start_ack.encode(), sender_addr)

                # 2. First attempt of DATA #0 arrives: DROP IT (do not send ACK)
                server_sock.recvfrom(65535)

                # 3. Second attempt of DATA #0 arrives: ACK IT
                data, sender_addr = server_sock.recvfrom(65535)
                data_pkt = Packet.decode(data)
                self.assertEqual(data_pkt.seq_num, 0)
                ack_pkt = Packet.create_ack(session_id=session_id, ack_num=0)
                server_sock.sendto(ack_pkt.encode(), sender_addr)

                # 4. FIN / FIN_ACK
                data, sender_addr = server_sock.recvfrom(65535)
                fin_ack = Packet.create_fin_ack(session_id=session_id, verified=True, receiver_sha256=expected_sha)
                server_sock.sendto(fin_ack.encode(), sender_addr)

                server_sock.close()

            t = threading.Thread(target=custom_receiver, daemon=True)
            t.start()

            self.assertTrue(receiver_ready.wait(timeout=2.0))
            time.sleep(0.05)

            config_snd = TransferConfig(
                host="127.0.0.1",
                port=port,
                timeout=0.2,
                max_retries=5,
            )
            sender = FileSender(config_snd)
            stats = sender.send_file(src_file)

            t.join(timeout=5.0)

            self.assertTrue(stats.success)
            self.assertGreaterEqual(stats.retransmissions, 1)

    # ------------------------------------------------------------------------
    # 5. Maximum Retry Failure
    # ------------------------------------------------------------------------
    def test_maximum_retry_failure(self):
        """
        Verify that transfer fails when all retry attempts are exhausted.
        """
        port = self.test_port + 5
        content = b"Failure condition payload"

        with tempfile.TemporaryDirectory() as sender_dir:
            src_file = Path(sender_dir) / "fail.txt"
            src_file.write_bytes(content)

            server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_sock.bind(("127.0.0.1", port))
            server_sock.settimeout(5.0)
            receiver_ready = threading.Event()

            def unresponsive_receiver():
                receiver_ready.set()
                # Accept handshake
                data, sender_addr = server_sock.recvfrom(65535)
                start_pkt = Packet.decode(data)
                session_id = start_pkt.session_id
                start_ack = Packet.create_start_ack(session_id=session_id)
                server_sock.sendto(start_ack.encode(), sender_addr)

                # Then drop all DATA packets without ever sending ACK
                for _ in range(3):
                    try:
                        server_sock.recvfrom(65535)
                    except socket.timeout:
                        break
                server_sock.close()

            t = threading.Thread(target=unresponsive_receiver, daemon=True)
            t.start()

            self.assertTrue(receiver_ready.wait(timeout=2.0))
            time.sleep(0.05)

            max_retries = 3
            config_snd = TransferConfig(
                host="127.0.0.1",
                port=port,
                timeout=0.1,
                max_retries=max_retries,
            )
            sender = FileSender(config_snd)
            stats = sender.send_file(src_file)

            t.join(timeout=5.0)

            # Must fail and reflect retries
            self.assertFalse(stats.success)
            self.assertGreaterEqual(stats.retransmissions, max_retries - 1)

    # ------------------------------------------------------------------------
    # 6. Empty File Transfer
    # ------------------------------------------------------------------------
    def test_transfer_empty_file(self):
        """Test transfer of an empty (0-byte) file."""
        port = self.test_port + 6
        with tempfile.TemporaryDirectory() as sender_dir, tempfile.TemporaryDirectory() as recv_dir:
            src_file = Path(sender_dir) / "empty.dat"
            src_file.write_bytes(b"")

            config_rcv = TransferConfig(host="127.0.0.1", port=port, output_dir=Path(recv_dir))
            config_snd = TransferConfig(host="127.0.0.1", port=port)

            recv_result: list[tuple[Path, bool]] = []
            receiver_ready = threading.Event()

            def receiver_worker():
                receiver = FileReceiver(config_rcv)
                receiver_ready.set()
                out_path, success = receiver.receive_file()
                recv_result.append((out_path, success))

            t = threading.Thread(target=receiver_worker, daemon=True)
            t.start()

            self.assertTrue(receiver_ready.wait(timeout=2.0))
            time.sleep(0.05)

            sender = FileSender(config_snd)
            stats = sender.send_file(src_file)

            t.join(timeout=5.0)

            self.assertTrue(stats.success)
            self.assertEqual(len(recv_result), 1)
            out_file, verified = recv_result[0]
            self.assertTrue(verified)
    # ------------------------------------------------------------------------
    # 7. Milestone 8: Duplicate Packet Detection (No Duplicate Writes)
    # ------------------------------------------------------------------------
    def test_duplicate_packet_detection_and_no_duplicate_writes(self):
        """
        Test that when duplicate DATA packets arrive (e.g. lost ACK),
        the receiver recognizes the duplicate, re-sends ACK, and does NOT
        write the duplicate data twice to disk.
        """
        port = self.test_port + 7
        session_id = 888888
        chunk_data = b"Exact payload of chunk 5"
        output_file = Path(tempfile.gettempdir()) / "test_dup_5.dat"

        if output_file.exists():
            output_file.unlink()

        config = TransferConfig(host="127.0.0.1", port=port)
        receiver = FileReceiver(config)

        # Launch receiver in thread
        recv_ready = threading.Event()
        transfer_success = []

        def run_receiver():
            recv_ready.set()
            out_p, ok = receiver.receive_file(output_dir=output_file.parent)
            transfer_success.append((out_p, ok))

        t = threading.Thread(target=run_receiver, daemon=True)
        t.start()
        self.assertTrue(recv_ready.wait(timeout=2.0))
        time.sleep(0.05)

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_sock.settimeout(2.0)

        # 1. Send START with total_packets = 1
        expected_sha = hashlib.sha256(chunk_data).hexdigest()
        start_pkt = Packet.create_start(
            session_id=session_id,
            filename=output_file.name,
            filesize=len(chunk_data),
            total_packets=1,
            file_sha256=expected_sha,
        )
        client_sock.sendto(start_pkt.encode(), ("127.0.0.1", port))
        resp, _ = client_sock.recvfrom(65535)
        self.assertEqual(Packet.decode(resp).pkt_type, PacketType.START_ACK)

        # 2. Send DATA #0
        data_pkt = Packet.create_data(session_id=session_id, seq_num=0, payload=chunk_data)
        client_sock.sendto(data_pkt.encode(), ("127.0.0.1", port))
        resp, _ = client_sock.recvfrom(65535)
        self.assertEqual(Packet.decode(resp).pkt_type, PacketType.ACK)
        self.assertEqual(Packet.decode(resp).ack_num, 0)

        # 3. Simulate retransmitting duplicate DATA #0 (e.g. sender didn't get ACK)
        client_sock.sendto(data_pkt.encode(), ("127.0.0.1", port))
        # Receiver must reply with ACK #0 again
        resp_dup, _ = client_sock.recvfrom(65535)
        self.assertEqual(Packet.decode(resp_dup).pkt_type, PacketType.ACK)
        self.assertEqual(Packet.decode(resp_dup).ack_num, 0)

        # 4. Send FIN
        fin_pkt = Packet.create_fin(session_id=session_id, file_sha256=expected_sha)
        client_sock.sendto(fin_pkt.encode(), ("127.0.0.1", port))
        resp_fin, _ = client_sock.recvfrom(65535)
        self.assertTrue(Packet.decode(resp_fin).get_json_payload().get("verified"))

        t.join(timeout=3.0)
        client_sock.close()

        # Crucial check: Output file length MUST equal len(chunk_data), NOT 2 * len(chunk_data)
        self.assertEqual(output_file.stat().st_size, len(chunk_data))
        self.assertEqual(output_file.read_bytes(), chunk_data)
        if output_file.exists():
            output_file.unlink()

    # ------------------------------------------------------------------------
    # 8. Milestone 8: Out-of-Order Buffering and Contiguous Drain
    # ------------------------------------------------------------------------
    def test_out_of_order_buffering_and_drain(self):
        """
        Test out-of-order packet arrival (7, 6, 5 when expecting 5).
        Receiver buffers 7 and 6, and upon arrival of 5, commits 5, 6, and 7
        in exact sequential order to disk.
        """
        port = self.test_port + 8
        session_id = 999999
        p5 = b"Chunk 5 Payload "
        p6 = b"Chunk 6 Payload "
        p7 = b"Chunk 7 Payload "
        full_content = p5 + p6 + p7
        expected_sha = hashlib.sha256(full_content).hexdigest()

        output_file = Path(tempfile.gettempdir()) / "test_ooo_order.dat"
        if output_file.exists():
            output_file.unlink()

        config = TransferConfig(host="127.0.0.1", port=port)
        receiver = FileReceiver(config)

        recv_ready = threading.Event()
        def run_receiver():
            recv_ready.set()
            receiver.receive_file(output_dir=output_file.parent)

        t = threading.Thread(target=run_receiver, daemon=True)
        t.start()
        self.assertTrue(recv_ready.wait(timeout=2.0))
        time.sleep(0.05)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)

        # 1. START
        start_pkt = Packet.create_start(
            session_id=session_id,
            filename=output_file.name,
            filesize=len(full_content),
            total_packets=3,
            file_sha256=expected_sha,
        )
        sock.sendto(start_pkt.encode(), ("127.0.0.1", port))
        sock.recvfrom(65535)

        # 2. Send out-of-order: seq 2 (corresponds to chunk 7)
        pkt_7 = Packet.create_data(session_id=session_id, seq_num=2, payload=p7)
        sock.sendto(pkt_7.encode(), ("127.0.0.1", port))
        sock.recvfrom(65535)  # Receiver ACKs and buffers

        # 3. Send out-of-order: seq 1 (corresponds to chunk 6)
        pkt_6 = Packet.create_data(session_id=session_id, seq_num=1, payload=p6)
        sock.sendto(pkt_6.encode(), ("127.0.0.1", port))
        sock.recvfrom(65535)  # Receiver ACKs and buffers

        # 4. Now send the missing expected packet: seq 0 (corresponds to chunk 5)
        pkt_5 = Packet.create_data(session_id=session_id, seq_num=0, payload=p5)
        sock.sendto(pkt_5.encode(), ("127.0.0.1", port))

        # Receiver commits 0, then drains 1 and 2, issuing ACKs for 0, 1, and 2
        for expected_ack in (0, 1, 2):
            resp_ack, _ = sock.recvfrom(65535)
            ack = Packet.decode(resp_ack)
            self.assertEqual(ack.pkt_type, PacketType.ACK)
            self.assertEqual(ack.ack_num, expected_ack)

        # 5. Send FIN
        fin_pkt = Packet.create_fin(session_id=session_id, file_sha256=expected_sha)
        sock.sendto(fin_pkt.encode(), ("127.0.0.1", port))
        resp, _ = sock.recvfrom(65535)
        fin_ack = Packet.decode(resp)
        self.assertEqual(fin_ack.pkt_type, PacketType.FIN_ACK)
        self.assertTrue(fin_ack.get_json_payload().get("verified"))

        t.join(timeout=3.0)
        sock.close()

        # Check reconstructed content
        self.assertEqual(output_file.read_bytes(), full_content)
        if output_file.exists():
            output_file.unlink()

    # ------------------------------------------------------------------------
    # 9. Milestone 8: Duplicate ACK Handling by Sender
    # ------------------------------------------------------------------------
    def test_duplicate_ack_ignored_by_sender(self):
        """
        Test that when sender receives a stale/duplicate ACK for an earlier packet,
        it safely ignores it and continues waiting for the expected sequence ACK.
        """
        port = self.test_port + 9
        config = TransferConfig(host="127.0.0.1", port=port, timeout=1.0, max_retries=2)
        sender = StopAndWaitSender(config)

        # Mock a socket server that sends a duplicate ACK #0 before sending ACK #1
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_sock.bind(("127.0.0.1", port))
        server_sock.settimeout(2.0)

        def mock_server():
            # Wait for DATA #1
            data, client_addr = server_sock.recvfrom(65535)
            pkt = Packet.decode(data)
            self.assertEqual(pkt.seq_num, 1)

            # Send duplicate/stale ACK #0
            stale_ack = Packet.create_ack(session_id=sender.session_id, ack_num=0)
            server_sock.sendto(stale_ack.encode(), client_addr)

            time.sleep(0.05)
            # Now send the real ACK #1
            real_ack = Packet.create_ack(session_id=sender.session_id, ack_num=1)
            server_sock.sendto(real_ack.encode(), client_addr)
            server_sock.close()

        t = threading.Thread(target=mock_server, daemon=True)
        t.start()
        time.sleep(0.05)

        # sender.send_chunk should ignore ACK #0 and successfully complete on ACK #1
        sender.send_chunk(seq_num=1, chunk=b"Payload for chunk 1")
        sender.close()
        t.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()

