"""
Unit tests for app/config.py.
Validates default parameters, custom options, dataclass properties, and defensive bounds checking.
"""

import unittest
from pathlib import Path

from app.config import (
    DEFAULT_HOST,
    DEFAULT_MAX_RETRIES,
    DEFAULT_PAYLOAD_SIZE,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    DEFAULT_WINDOW_SIZE,
    MAX_PAYLOAD_SIZE,
    ARQMode,
    TransferConfig,
)


class TestConfig(unittest.TestCase):
    """Test suite for TransferConfig dataclass and validation."""

    def test_default_config(self):
        """Test default values of TransferConfig."""
        config = TransferConfig()
        self.assertEqual(config.host, DEFAULT_HOST)
        self.assertEqual(config.port, DEFAULT_PORT)
        self.assertEqual(config.payload_size, DEFAULT_PAYLOAD_SIZE)
        self.assertEqual(config.window_size, DEFAULT_WINDOW_SIZE)
        self.assertEqual(config.timeout, DEFAULT_TIMEOUT)
        self.assertEqual(config.max_retries, DEFAULT_MAX_RETRIES)
        self.assertEqual(config.loss_rate, 0.0)
        self.assertEqual(config.latency, 0.0)
        self.assertEqual(config.corruption_rate, 0.0)
        self.assertEqual(config.output_dir, Path("./received_files"))
        self.assertEqual(config.log_level, "INFO")
        self.assertEqual(config.arq_mode, ARQMode.SELECTIVE_REPEAT)

    def test_custom_valid_config(self):
        """Test creating TransferConfig with valid custom parameters."""
        config = TransferConfig(
            host="192.168.1.50",
            port=9999,
            payload_size=2048,
            window_size=32,
            timeout=1.2,
            max_retries=5,
            loss_rate=0.1,
            latency=0.05,
            corruption_rate=0.01,
            output_dir="/tmp/transfers",
            log_level="debug",
            arq_mode=ARQMode.SELECTIVE_REPEAT,
        )
        self.assertEqual(config.host, "192.168.1.50")
        self.assertEqual(config.port, 9999)
        self.assertEqual(config.payload_size, 2048)
        self.assertEqual(config.window_size, 32)
        self.assertEqual(config.timeout, 1.2)
        self.assertEqual(config.max_retries, 5)
        self.assertEqual(config.loss_rate, 0.1)
        self.assertEqual(config.latency, 0.05)
        self.assertEqual(config.corruption_rate, 0.01)
        self.assertEqual(config.output_dir, Path("/tmp/transfers"))
        self.assertEqual(config.log_level, "DEBUG")
        self.assertEqual(config.arq_mode, ARQMode.SELECTIVE_REPEAT)

    def test_property_aliases(self):
        """Test aliases like packet_loss_rate, latency_ms, and output_directory."""
        config = TransferConfig(loss_rate=0.15, latency=0.05)
        self.assertEqual(config.packet_loss_rate, 0.15)
        self.assertEqual(config.latency_ms, 50.0)
        self.assertEqual(config.output_directory, Path("./received_files"))

        # Test setters
        config.packet_loss_rate = 0.25
        self.assertEqual(config.loss_rate, 0.25)

        config.latency_ms = 100.0
        self.assertEqual(config.latency, 0.1)

        config.output_directory = "custom_dir"
        self.assertEqual(config.output_dir, Path("custom_dir"))

    def test_invalid_host(self):
        """Test that invalid host names raise ValueError."""
        with self.assertRaises(ValueError):
            TransferConfig(host="")
        with self.assertRaises(ValueError):
            TransferConfig(host="   ")

    def test_invalid_port(self):
        """Test that out-of-range port numbers raise ValueError."""
        with self.assertRaises(ValueError):
            TransferConfig(port=0)
        with self.assertRaises(ValueError):
            TransferConfig(port=-1)
        with self.assertRaises(ValueError):
            TransferConfig(port=65536)

    def test_invalid_payload_size(self):
        """Test that invalid payload sizes raise ValueError."""
        with self.assertRaises(ValueError):
            TransferConfig(payload_size=0)
        with self.assertRaises(ValueError):
            TransferConfig(payload_size=-100)
        with self.assertRaises(ValueError):
            TransferConfig(payload_size=MAX_PAYLOAD_SIZE + 1)

    def test_invalid_window_size(self):
        """Test that window size < 1 raises ValueError."""
        with self.assertRaises(ValueError):
            TransferConfig(window_size=0)
        with self.assertRaises(ValueError):
            TransferConfig(window_size=-5)

    def test_invalid_timeout(self):
        """Test that timeout <= 0 raises ValueError."""
        with self.assertRaises(ValueError):
            TransferConfig(timeout=0)
        with self.assertRaises(ValueError):
            TransferConfig(timeout=-0.5)

    def test_invalid_max_retries(self):
        """Test that negative retries raise ValueError."""
        with self.assertRaises(ValueError):
            TransferConfig(max_retries=-1)

    def test_invalid_rates(self):
        """Test that out-of-bound loss and corruption rates raise ValueError."""
        with self.assertRaises(ValueError):
            TransferConfig(loss_rate=-0.1)
        with self.assertRaises(ValueError):
            TransferConfig(loss_rate=1.1)

        with self.assertRaises(ValueError):
            TransferConfig(corruption_rate=-0.01)
        with self.assertRaises(ValueError):
            TransferConfig(corruption_rate=1.05)

        with self.assertRaises(ValueError):
            TransferConfig(latency=-1.0)

    def test_invalid_log_level(self):
        """Test that unknown log level strings raise ValueError."""
        with self.assertRaises(ValueError):
            TransferConfig(log_level="VERBOSE")


if __name__ == "__main__":
    unittest.main()
