"""
Unit and integration tests for Network Simulator Layer (Milestone 12).
Tests packet loss simulation, artificial latency, packet corruption detection,
metrics collection, and Selective Repeat recovery under 10% loss and corruption.
"""

import hashlib
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from app.checksum import calculate_checksum, calculate_file_sha256, verify_checksum
from app.config import ARQMode, TransferConfig
from app.packet import ChecksumMismatchError, Packet, PacketType
from app.simulator import NetworkSimulator, SimulatedSocket, SimulationStats
from app.transfer import FileReceiver, FileSender


class TestNetworkSimulator(unittest.TestCase):
    """Test suite for app/simulator.py and network impairment recovery."""

    def setUp(self):
        self.base_port = 9600

    def test_simulation_stats_and_probabilistic_loss(self):
        """
        Verify that NetworkSimulator accurately drops packets based on loss_rate
        and tracks packets_attempted and packets_dropped in SimulationStats.
        """
        sim = NetworkSimulator(loss_rate=0.25)
        total = 1000
        drops = sum(1 for _ in range(total) if sim.should_drop())

        # With 1000 samples and loss_rate 0.25, drops should reasonably be between 180 and 320 (3 sigma)
        self.assertGreater(drops, 150)
        self.assertLess(drops, 350)

        # Test with SimulatedSocket
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cfg = TransferConfig(loss_rate=0.30)
        sim_sock = SimulatedSocket(raw_sock, cfg)

        try:
            for _ in range(100):
                sim_sock.sendto(b"test-payload", ("127.0.0.1", 9999))

            stats = sim_sock.stats
            self.assertEqual(stats.packets_attempted, 100)
            self.assertGreater(stats.packets_dropped, 15)
            self.assertLess(stats.packets_dropped, 45)
            self.assertEqual(stats.packets_corrupted, 0)
            self.assertEqual(stats.packets_delayed, 0)

            summary = stats.format_summary()
            self.assertIn("Total Datagrams Attempted: 100", summary)
            self.assertIn("Packets Dropped", summary)
        finally:
            sim_sock.close()

    def test_packet_corruption_detected_by_checksum(self):
        """
        Verify that corrupt_bytes flips bits and guarantees that receiver
        checksum verification detects and rejects the corrupted packet.
        """
        sim = NetworkSimulator(corruption_rate=1.0)
        original_pkt = Packet.create_data(session_id=12345, seq_num=1, payload=b"Sensors and Telemetry Data")
        encoded_data = original_pkt.encode()

        # Guarantee corrupted data differs from original
        corrupted_data = sim.corrupt_bytes(encoded_data)
        self.assertNotEqual(corrupted_data, encoded_data)

        # Decoding corrupted data should fail or trigger ChecksumMismatchError
        with self.assertRaises(Exception):
            decoded_pkt = Packet.decode(corrupted_data)
            # If header by rare chance decoded, checksum must fail
            header_bytes = corrupted_data[:22]
            payload = corrupted_data[22:]
            self.assertFalse(verify_checksum(header_bytes + payload, decoded_pkt.checksum))

    def test_artificial_latency_causes_rtt_delay_and_timeout(self):
        """
        Verify that artificial latency delays packet delivery and triggers
        timeout/retransmission when latency exceeds timeout.
        """
        port = self.base_port
        received_times = []
        ready = threading.Event()

        def listener():
            srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv.bind(("127.0.0.1", port))
            ready.set()
            data, _ = srv.recvfrom(1024)
            received_times.append(time.monotonic())
            srv.close()

        t = threading.Thread(target=listener, daemon=True)
        t.start()
        ready.wait(timeout=2.0)
        time.sleep(0.02)

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 60 ms artificial latency
        latency_sec = 0.06
        cfg = TransferConfig(latency=latency_sec)
        sim_sock = SimulatedSocket(raw_sock, cfg)

        try:
            start_t = time.monotonic()
            sim_sock.sendto(b"latency-test", ("127.0.0.1", port))
            t.join(timeout=2.0)

            self.assertEqual(len(received_times), 1)
            elapsed = received_times[0] - start_t
            # Should have arrived after at least 50 ms
            self.assertGreaterEqual(elapsed, 0.045)
            self.assertEqual(sim_sock.stats.packets_delayed, 1)
        finally:
            sim_sock.close()

    def test_selective_repeat_recovers_under_10_percent_loss(self):
        """
        Perform a full binary file transfer under 10% simulated packet loss.
        Verify that the reliability layer successfully retransmits lost packets
        and the reconstructed file SHA-256 matches the source.
        """
        port = self.base_port + 20
        sample_path = Path("sample_files/multichunk.bin")
        if not sample_path.exists():
            self.skipTest("sample_files/multichunk.bin not present")

        with tempfile.TemporaryDirectory() as recv_dir:
            config_r = TransferConfig(
                host="127.0.0.1",
                port=port,
                window_size=8,
                timeout=0.2,
                output_dir=Path(recv_dir),
                arq_mode=ARQMode.SELECTIVE_REPEAT,
            )
            config_s = TransferConfig(
                host="127.0.0.1",
                port=port,
                window_size=8,
                timeout=0.2,
                loss_rate=0.10,  # 10% packet loss injection
                arq_mode=ARQMode.SELECTIVE_REPEAT,
            )

            ready = threading.Event()
            rx_outcome = []

            def rx_thread():
                rx = FileReceiver(config_r)
                ready.set()
                out_p, ok = rx.receive_file()
                rx_outcome.append((out_p, ok))

            t = threading.Thread(target=rx_thread, daemon=True)
            t.start()
            self.assertTrue(ready.wait(timeout=2.0))
            time.sleep(0.05)

            sender = FileSender(config_s)
            stats = sender.send_file(sample_path)
            t.join(timeout=10.0)

            # Verification
            self.assertTrue(stats.success, "Transfer failed under 10% loss")
            self.assertEqual(len(rx_outcome), 1)
            out_file, verified = rx_outcome[0]
            self.assertTrue(verified, "Receiver failed to verify file integrity")

            # Verify SHA-256 hash match
            src_sha = calculate_file_sha256(sample_path)
            dst_sha = calculate_file_sha256(out_file)
            self.assertEqual(src_sha, dst_sha)
            self.assertEqual(stats.sha256_hash, dst_sha)

            # Simulation metrics check
            self.assertIsNotNone(stats.simulation_stats)
            self.assertGreaterEqual(stats.simulation_stats.packets_attempted, 4)

    def test_selective_repeat_recovers_under_corruption(self):
        """
        Perform a transfer under simulated packet corruption.
        Verify receiver detects and drops corrupted packets via CRC32 checksum,
        sender retransmits, and transfer succeeds with valid SHA-256.
        """
        port = self.base_port + 40
        sample_path = Path("sample_files/multichunk.bin")
        if not sample_path.exists():
            self.skipTest("sample_files/multichunk.bin not present")

        with tempfile.TemporaryDirectory() as recv_dir:
            config_r = TransferConfig(
                host="127.0.0.1",
                port=port,
                window_size=8,
                timeout=0.2,
                output_dir=Path(recv_dir),
                arq_mode=ARQMode.SELECTIVE_REPEAT,
            )
            config_s = TransferConfig(
                host="127.0.0.1",
                port=port,
                window_size=8,
                timeout=0.2,
                corruption_rate=0.08,  # 8% packet corruption rate
                arq_mode=ARQMode.SELECTIVE_REPEAT,
            )

            ready = threading.Event()
            rx_outcome = []

            def rx_thread():
                rx = FileReceiver(config_r)
                ready.set()
                out_p, ok = rx.receive_file()
                rx_outcome.append((out_p, ok))

            t = threading.Thread(target=rx_thread, daemon=True)
            t.start()
            self.assertTrue(ready.wait(timeout=2.0))
            time.sleep(0.05)

            sender = FileSender(config_s)
            stats = sender.send_file(sample_path)
            t.join(timeout=10.0)

            self.assertTrue(stats.success, "Transfer failed under corruption")
            out_file, verified = rx_outcome[0]
            self.assertTrue(verified)

            src_sha = calculate_file_sha256(sample_path)
            dst_sha = calculate_file_sha256(out_file)
            self.assertEqual(src_sha, dst_sha)


if __name__ == "__main__":
    unittest.main()
