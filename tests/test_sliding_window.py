"""
Unit and integration tests for the Sliding Window ARQ protocol (Milestone 10).
Tests window state tracking, pipelined transmission, in-order and out-of-order ACK processing,
window sliding, retransmission on lost packets, and end-to-end binary transfer.
"""

import hashlib
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from app.checksum import calculate_file_sha256
from app.config import ARQMode, PacketType, TransferConfig
from app.packet import Packet
from app.protocol import InFlightPacket, RetransmissionLimitExceeded, SlidingWindowSender, StopAndWaitReceiver
from app.transfer import FileReceiver, FileSender, inspect_file


class TestSlidingWindowProtocol(unittest.TestCase):
    """Test suite for Sliding Window Sender and pipeline reliability."""

    def setUp(self):
        self.base_port = 9200

    def test_window_state_tracking_and_pipeline(self):
        """
        Verify that SlidingWindowSender tracks base_seq, next_seq,
        acknowledged_packets, and outstanding_packets as window_size (8) packets are pipelined.
        """
        port = self.base_port
        config = TransferConfig(host="127.0.0.1", port=port, window_size=8, timeout=0.5)
        sender = SlidingWindowSender(config)

        # Mock server that records received sequence numbers and answers START and ACKs
        received_seqs = []
        ready = threading.Event()
        stop_server = threading.Event()

        def mock_receiver():
            srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv.bind(("127.0.0.1", port))
            srv.settimeout(1.5)
            ready.set()

            # 1. Answer START
            try:
                data, addr = srv.recvfrom(65535)
                pkt = Packet.decode(data)
                if pkt.pkt_type == PacketType.START:
                    start_ack = Packet.create_start_ack(session_id=pkt.session_id, window_size=8)
                    srv.sendto(start_ack.encode(), addr)

                # 2. Collect packets up to window limit without ACKing immediately
                while not stop_server.is_set():
                    try:
                        data, addr = srv.recvfrom(65535)
                        p = Packet.decode(data)
                        if p.pkt_type == PacketType.DATA:
                            received_seqs.append(p.seq_num)
                            # ACK immediately to allow pipeline to progress
                            ack = Packet.create_ack(session_id=p.session_id, ack_num=p.seq_num)
                            srv.sendto(ack.encode(), addr)
                        elif p.pkt_type == PacketType.FIN:
                            fin_ack = Packet.create_fin_ack(session_id=p.session_id, verified=True)
                            srv.sendto(fin_ack.encode(), addr)
                            break
                    except socket.timeout:
                        break
            finally:
                srv.close()

        t = threading.Thread(target=mock_receiver, daemon=True)
        t.start()
        self.assertTrue(ready.wait(timeout=2.0))
        time.sleep(0.05)

        try:
            # 10 test chunks
            total_chunks = 10
            chunks = [f"chunk-data-{i:03d}".encode("utf-8") for i in range(total_chunks)]

            # Initial state
            self.assertEqual(sender.base_seq, 0)
            self.assertEqual(sender.next_seq, 0)
            self.assertEqual(len(sender.acknowledged_packets), 0)
            self.assertEqual(len(sender.outstanding_packets), 0)

            # Transmit stream
            sender.send_file_stream(chunks, total_chunks)

            # After complete transfer
            self.assertEqual(sender.base_seq, total_chunks)
            self.assertEqual(sender.next_seq, total_chunks)
            self.assertEqual(len(sender.acknowledged_packets), total_chunks)
            self.assertEqual(len(sender.outstanding_packets), 0)
            self.assertEqual(sorted(received_seqs), list(range(total_chunks)))
        finally:
            stop_server.set()
            sender.close()
            t.join(timeout=2.0)

    def test_window_slides_on_in_order_and_out_of_order_acks(self):
        """
        Verify that _process_ack accurately advances base_seq when receiving
        in-order ACKs and handles out-of-order ACKs without skipping.
        """
        config = TransferConfig(window_size=8)
        sender = SlidingWindowSender(config)
        sender.session_id = 55555

        chunk_cache = {i: f"chunk-{i}".encode() for i in range(8)}
        for i in range(8):
            sender.outstanding_packets[i] = InFlightPacket(
                seq_num=i,
                raw_packet=b"",
                send_time=time.monotonic(),
            )
        sender.next_seq = 8

        # 1. In-order ACK #0 -> base_seq slides to 1
        ack0 = Packet.create_ack(session_id=55555, ack_num=0).encode()
        sender._process_ack(ack0, chunk_cache, total_chunks=8)
        self.assertEqual(sender.base_seq, 1)
        self.assertIn(0, sender.acknowledged_packets)
        self.assertNotIn(0, sender.outstanding_packets)
        self.assertNotIn(0, chunk_cache)

        # 2. Out-of-order ACK #3 arrives before ACK #1 and #2 -> base_seq stays at 1
        ack3 = Packet.create_ack(session_id=55555, ack_num=3).encode()
        sender._process_ack(ack3, chunk_cache, total_chunks=8)
        self.assertEqual(sender.base_seq, 1)
        self.assertIn(3, sender.acknowledged_packets)
        self.assertNotIn(3, sender.outstanding_packets)

        # 3. ACK #2 arrives -> base_seq still stays at 1
        ack2 = Packet.create_ack(session_id=55555, ack_num=2).encode()
        sender._process_ack(ack2, chunk_cache, total_chunks=8)
        self.assertEqual(sender.base_seq, 1)

        # 4. ACK #1 arrives -> completes gap, base_seq slides past 1, 2, 3 to 4!
        ack1 = Packet.create_ack(session_id=55555, ack_num=1).encode()
        sender._process_ack(ack1, chunk_cache, total_chunks=8)
        self.assertEqual(sender.base_seq, 4)
        self.assertEqual(len(sender.outstanding_packets), 4)  # 4, 5, 6, 7 remain

        sender.close()

    def test_retransmission_on_window_packet_loss(self):
        """
        Verify that if an in-flight packet is dropped, the sender detects timeout,
        retransmits the missing packet, and the transfer recovers successfully.
        """
        port = self.base_port + 20
        config = TransferConfig(
            host="127.0.0.1",
            port=port,
            window_size=4,
            timeout=0.2,
            max_retries=3,
        )

        dropped_seq = 2
        dropped_once = False
        received_seqs = []
        ready = threading.Event()

        def flaky_receiver():
            nonlocal dropped_once
            srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv.bind(("127.0.0.1", port))
            srv.settimeout(2.5)
            ready.set()

            try:
                while True:
                    data, addr = srv.recvfrom(65535)
                    pkt = Packet.decode(data)

                    if pkt.pkt_type == PacketType.DATA:
                        if pkt.seq_num == dropped_seq and not dropped_once:
                            # Drop packet #2 exactly once
                            dropped_once = True
                            continue

                        received_seqs.append(pkt.seq_num)
                        ack = Packet.create_ack(session_id=pkt.session_id, ack_num=pkt.seq_num)
                        srv.sendto(ack.encode(), addr)
                        if len(set(received_seqs)) == 5:
                            break
            finally:
                srv.close()

        t = threading.Thread(target=flaky_receiver, daemon=True)
        t.start()
        self.assertTrue(ready.wait(timeout=2.0))
        time.sleep(0.05)

        sender = SlidingWindowSender(config)
        chunks = [f"data-chunk-{i}".encode() for i in range(5)]

        try:
            sender.send_file_stream(chunks, total_chunks=5)
            self.assertTrue(dropped_once, "Packet was not dropped as intended")
            self.assertGreater(sender.retransmissions, 0, "No retransmission recorded")
            self.assertEqual(sender.base_seq, 5)
            self.assertEqual(len(sender.acknowledged_packets), 5)
        finally:
            sender.close()
            t.join(timeout=3.0)

    def test_sliding_window_full_binary_transfer_with_sha256(self):
        """
        End-to-end transfer of a real binary file using Sliding Window (window_size=8).
        Validates complete pipelining, chunk reassembly, and SHA-256 verification.
        """
        port = self.base_port + 40
        sample_path = Path("sample_files/multichunk.bin")
        if not sample_path.exists():
            self.skipTest("sample_files/multichunk.bin does not exist")

        with tempfile.TemporaryDirectory() as recv_dir:
            config_r = TransferConfig(
                host="127.0.0.1",
                port=port,
                window_size=8,
                output_dir=Path(recv_dir),
            )
            config_s = TransferConfig(
                host="127.0.0.1",
                port=port,
                window_size=8,
                arq_mode=ARQMode.SLIDING_WINDOW,
            )

            ready = threading.Event()
            recv_outcome = []

            def rx_worker():
                rx = FileReceiver(config_r)
                ready.set()
                out_path, ok = rx.receive_file()
                recv_outcome.append((out_path, ok))

            t = threading.Thread(target=rx_worker, daemon=True)
            t.start()
            self.assertTrue(ready.wait(timeout=2.0))
            time.sleep(0.05)

            sender = FileSender(config_s)
            stats = sender.send_file(sample_path)
            t.join(timeout=5.0)

            self.assertTrue(stats.success)
            self.assertEqual(len(recv_outcome), 1)
            out_file, verified = recv_outcome[0]
            self.assertTrue(verified)

            # Verify hashes match
            src_sha = calculate_file_sha256(sample_path)
            dst_sha = calculate_file_sha256(out_file)
            self.assertEqual(src_sha, dst_sha)
            self.assertEqual(stats.sha256_hash, dst_sha)

    def test_max_retry_failure_sliding_window(self):
        """
        Verify that when a packet fails to be acknowledged after max_retries,
        SlidingWindowSender raises RetransmissionLimitExceeded.
        """
        port = self.base_port + 60
        config = TransferConfig(
            host="127.0.0.1",
            port=port,
            window_size=4,
            timeout=0.05,
            max_retries=2,
        )
        sender = SlidingWindowSender(config)

        # No receiver running on port -> every packet will time out
        chunks = [b"unreachable-chunk-1", b"unreachable-chunk-2"]
        with self.assertRaises(RetransmissionLimitExceeded):
            sender.send_file_stream(chunks, total_chunks=2)
        sender.close()


if __name__ == "__main__":
    unittest.main()
