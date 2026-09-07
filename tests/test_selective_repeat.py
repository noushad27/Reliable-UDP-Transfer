"""
Unit and integration tests for Selective Repeat ARQ (Milestone 11).
Tests per-packet acknowledgment states, selective retransmission of only lost packets,
receiver out-of-order buffering, independent timers, and end-to-end binary transfer.
"""

import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from app.checksum import calculate_file_sha256
from app.config import ARQMode, PacketType, TransferConfig
from app.packet import Packet
from app.protocol import (
    PacketState,
    RetransmissionLimitExceeded,
    SelectiveRepeatPacket,
    SelectiveRepeatReceiver,
    SelectiveRepeatSender,
)
from app.transfer import FileReceiver, FileSender


class TestSelectiveRepeatProtocol(unittest.TestCase):
    """Test suite for Selective Repeat ARQ."""

    def setUp(self):
        self.base_port = 9300

    def test_exact_selective_retransmission_scenario(self):
        """
        Verify the prompt scenario:
        DATA #0 -> ACK
        DATA #1 -> ACK
        DATA #2 -> LOST
        DATA #3 -> ACK
        DATA #4 -> ACK
        
        Assert: ONLY DATA #2 is retransmitted.
        Retransmissions for 0, 1, 3, 4 MUST be 0.
        Retransmission for 2 MUST be 1.
        """
        port = self.base_port
        config = TransferConfig(
            host="127.0.0.1",
            port=port,
            window_size=5,
            timeout=0.25,
            max_retries=3,
        )

        dropped_seq = 2
        dropped_count = 0
        received_packets = []
        ready = threading.Event()

        def flaky_sr_receiver():
            nonlocal dropped_count
            srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv.bind(("127.0.0.1", port))
            srv.settimeout(3.0)
            ready.set()

            try:
                while True:
                    data, addr = srv.recvfrom(65535)
                    pkt = Packet.decode(data)

                    if pkt.pkt_type == PacketType.DATA:
                        # Drop packet #2 exactly once
                        if pkt.seq_num == dropped_seq and dropped_count == 0:
                            dropped_count += 1
                            continue

                        received_packets.append(pkt.seq_num)
                        ack = Packet.create_ack(session_id=pkt.session_id, ack_num=pkt.seq_num)
                        srv.sendto(ack.encode(), addr)

                        # Once all 5 packets are acknowledged (0, 1, 2, 3, 4)
                        if set(received_packets) == {0, 1, 2, 3, 4}:
                            break
            finally:
                srv.close()

        t = threading.Thread(target=flaky_sr_receiver, daemon=True)
        t.start()
        self.assertTrue(ready.wait(timeout=2.0))
        time.sleep(0.05)

        sender = SelectiveRepeatSender(config)
        chunks = [f"selective-chunk-{i}".encode() for i in range(5)]

        try:
            sender.send_file_stream(chunks, total_chunks=5)

            # Assertions on exact Selective Repeat behavior
            self.assertEqual(dropped_count, 1, "Packet 2 was not dropped")
            self.assertEqual(sender.base_seq, 5, "Window did not slide to completion")

            # Retransmission verification: ONLY packet 2 was retransmitted
            self.assertEqual(sender.packet_retransmissions.get(0, 0), 0, "Packet 0 was unnecessarily retransmitted")
            self.assertEqual(sender.packet_retransmissions.get(1, 0), 0, "Packet 1 was unnecessarily retransmitted")
            self.assertEqual(sender.packet_retransmissions.get(2, 0), 1, "Packet 2 was not retransmitted exactly once")
            self.assertEqual(sender.packet_retransmissions.get(3, 0), 0, "Packet 3 was unnecessarily retransmitted")
            self.assertEqual(sender.packet_retransmissions.get(4, 0), 0, "Packet 4 was unnecessarily retransmitted")
            self.assertEqual(sender.retransmissions, 1, "Total retransmission count must be exactly 1")

        finally:
            sender.close()
            t.join(timeout=3.0)

    def test_per_packet_acknowledgement_state_transitions(self):
        """
        Verify that SelectiveRepeatPacket transitions through states:
        UNSENT -> IN_FLIGHT -> ACKED, and handles out-of-order ACK processing.
        """
        config = TransferConfig(window_size=5)
        sender = SelectiveRepeatSender(config)
        sender.session_id = 77777

        # Simulate 4 packets in flight
        for i in range(4):
            sender.window_packets[i] = SelectiveRepeatPacket(
                seq_num=i,
                payload=b"payload",
                raw_packet=b"",
                state=PacketState.IN_FLIGHT,
                send_time=time.monotonic(),
            )
        sender.next_seq = 4

        # 1. ACK #1 arrives (out-of-order, before ACK #0)
        ack1 = Packet.create_ack(session_id=77777, ack_num=1).encode()
        sender._process_ack(ack1, total_chunks=4)
        self.assertEqual(sender.window_packets[1].state, PacketState.ACKED)
        self.assertEqual(sender.window_packets[0].state, PacketState.IN_FLIGHT)
        self.assertEqual(sender.base_seq, 0, "Base cannot slide past unacked packet 0")

        # 2. ACK #3 arrives
        ack3 = Packet.create_ack(session_id=77777, ack_num=3).encode()
        sender._process_ack(ack3, total_chunks=4)
        self.assertEqual(sender.window_packets[3].state, PacketState.ACKED)
        self.assertEqual(sender.base_seq, 0)

        # 3. ACK #0 arrives -> Base slides forward to 2 (since 0 and 1 are ACKED, but 2 is still IN_FLIGHT)
        ack0 = Packet.create_ack(session_id=77777, ack_num=0).encode()
        sender._process_ack(ack0, total_chunks=4)
        self.assertEqual(sender.base_seq, 2, "Base should slide past 0 and 1 to 2")
        self.assertNotIn(0, sender.window_packets)
        self.assertNotIn(1, sender.window_packets)
        self.assertIn(2, sender.window_packets)
        self.assertIn(3, sender.window_packets)

        # 4. ACK #2 arrives -> Base slides through 2 and 3 to 4!
        ack2 = Packet.create_ack(session_id=77777, ack_num=2).encode()
        sender._process_ack(ack2, total_chunks=4)
        self.assertEqual(sender.base_seq, 4, "Base should slide through all contiguous acked packets to 4")
        self.assertEqual(len(sender.window_packets), 0)

        sender.close()

    def test_full_binary_transfer_selective_repeat_with_sha256(self):
        """
        End-to-end file transfer using Selective Repeat ARQ with SHA-256 verification.
        """
        port = self.base_port + 20
        sample_path = Path("sample_files/multichunk.bin")
        if not sample_path.exists():
            self.skipTest("sample_files/multichunk.bin does not exist")

        with tempfile.TemporaryDirectory() as recv_dir:
            config_r = TransferConfig(
                host="127.0.0.1",
                port=port,
                window_size=8,
                output_dir=Path(recv_dir),
                arq_mode=ARQMode.SELECTIVE_REPEAT,
            )
            config_s = TransferConfig(
                host="127.0.0.1",
                port=port,
                window_size=8,
                arq_mode=ARQMode.SELECTIVE_REPEAT,
            )

            ready = threading.Event()
            rx_outcome = []

            def rx_worker():
                rx = FileReceiver(config_r)
                ready.set()
                out_path, ok = rx.receive_file()
                rx_outcome.append((out_path, ok))

            t = threading.Thread(target=rx_worker, daemon=True)
            t.start()
            self.assertTrue(ready.wait(timeout=2.0))
            time.sleep(0.05)

            sender = FileSender(config_s)
            stats = sender.send_file(sample_path)
            t.join(timeout=5.0)

            self.assertTrue(stats.success)
            self.assertEqual(len(rx_outcome), 1)
            out_file, verified = rx_outcome[0]
            self.assertTrue(verified)

            # Validate SHA-256 hash match
            src_sha = calculate_file_sha256(sample_path)
            dst_sha = calculate_file_sha256(out_file)
            self.assertEqual(src_sha, dst_sha)
            self.assertEqual(stats.sha256_hash, dst_sha)

    def test_max_retry_failure_selective_repeat(self):
        """
        Verify that if an individual packet in the Selective Repeat window exceeds
        max_retries without being acknowledged, RetransmissionLimitExceeded is raised.
        """
        port = self.base_port + 40
        config = TransferConfig(
            host="127.0.0.1",
            port=port,
            window_size=4,
            timeout=0.05,
            max_retries=2,
            arq_mode=ARQMode.SELECTIVE_REPEAT,
        )
        sender = SelectiveRepeatSender(config)

        chunks = [b"chunk-sr-fail-1", b"chunk-sr-fail-2"]
        with self.assertRaises(RetransmissionLimitExceeded):
            sender.send_file_stream(chunks, total_chunks=2)
        sender.close()


if __name__ == "__main__":
    unittest.main()
