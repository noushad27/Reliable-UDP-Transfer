"""
Integration tests for app/sender.py and app/receiver.py.
Validates basic connectionless UDP datagram transmission and reception.
"""

import socket
import threading
import time
import unittest

from app.receiver import run_receiver
from app.sender import send_message


class TestBasicUDP(unittest.TestCase):
    """Test suite for basic UDP socket communication."""

    def test_udp_send_and_receive_hello(self):
        """Test sending 'HELLO' over loopback interface using basic UDP sockets."""
        test_port = 9876
        received_data: list[tuple[bytes, tuple[str, int]]] = []
        receiver_ready = threading.Event()
        stop_receiver = threading.Event()

        def receiver_worker():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            try:
                sock.bind(("127.0.0.1", test_port))
                receiver_ready.set()
                data, addr = sock.recvfrom(1024)
                received_data.append((data, addr))
            except socket.timeout:
                pass
            finally:
                sock.close()

        thread = threading.Thread(target=receiver_worker, daemon=True)
        thread.start()

        # Wait for receiver to bind
        self.assertTrue(receiver_ready.wait(timeout=2.0))
        time.sleep(0.05)  # brief settle time

        # Sender sends HELLO
        bytes_sent = send_message(host="127.0.0.1", port=test_port, message="HELLO")
        self.assertEqual(bytes_sent, 5)

        thread.join(timeout=2.0)
        self.assertEqual(len(received_data), 1)
        data, addr = received_data[0]
        self.assertEqual(data.decode("utf-8"), "HELLO")
        self.assertEqual(addr[0], "127.0.0.1")

    def test_run_receiver_with_once_flag(self):
        """Test run_receiver terminates cleanly when once=True."""
        test_port = 9877
        receiver_ready = threading.Event()

        def receiver_thread():
            # Mock bind by running receiver with timeout
            run_receiver(
                host="127.0.0.1",
                port=test_port,
                buffer_size=1024,
                once=True,
                timeout=2.0,
            )

        t = threading.Thread(target=receiver_thread, daemon=True)
        t.start()
        time.sleep(0.1)

        # Send test packet
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"HELLO", ("127.0.0.1", test_port))
        sock.close()

        t.join(timeout=2.0)
        self.assertFalse(t.is_alive())


if __name__ == "__main__":
    unittest.main()
