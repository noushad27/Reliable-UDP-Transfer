"""
Sender CLI and socket utilities.
Supports both basic UDP message sending and reliable Stop-and-Wait file transmission.
"""

from __future__ import annotations

import argparse
import logging
import socket
import sys
from pathlib import Path

from app.config import (
    DEFAULT_HOST,
    DEFAULT_MAX_RETRIES,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT,
    TransferConfig,
)
from app.transfer import FileSender
from app.utils import setup_logging


def send_message(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    message: str = "HELLO",
    logger: logging.Logger | None = None,
) -> int:
    """
    Send a single raw unacknowledged UDP datagram (Milestone 2).
    """
    if logger is None:
        logger = setup_logging(log_level="INFO", logger_name="udp_sender")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        payload = message.encode("utf-8")
        bytes_sent = sock.sendto(payload, (host, port))
        logger.info(f"Sent {bytes_sent} bytes to {host}:{port}: '{message}'")
        print(f"Sent: {message}")
        return bytes_sent
    finally:
        sock.close()


def main() -> None:
    """CLI entry point for reliable file sender."""
    parser = argparse.ArgumentParser(description="Reliable UDP File Sender (Stop-and-Wait ARQ)")
    parser.add_argument(
        "--host",
        type=str,
        default=DEFAULT_HOST,
        help=f"Receiver host address (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Receiver port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Path to file to transmit",
    )
    parser.add_argument(
        "--message",
        type=str,
        default=None,
        help="Send a single raw UDP datagram (Milestone 2 basic mode)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Retransmission timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=DEFAULT_MAX_RETRIES,
        help=f"Maximum retry attempts per packet (default: {DEFAULT_MAX_RETRIES})",
    )
    parser.add_argument(
        "--payload-size",
        type=int,
        default=1024,
        help="Chunk payload size in bytes (default: 1024)",
    )
    parser.add_argument(
        "--loss-rate",
        type=float,
        default=0.0,
        help="Simulated packet drop rate between 0.0 and 1.0 (default: 0.0)",
    )
    parser.add_argument(
        "--latency",
        type=float,
        default=0.0,
        help="Simulated one-way propagation latency in milliseconds (e.g. 100) or seconds (default: 0.0)",
    )
    parser.add_argument(
        "--corruption-rate",
        type=float,
        default=0.0,
        help="Simulated packet corruption rate between 0.0 and 1.0 (default: 0.0)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )

    args = parser.parse_args()
    logger = setup_logging(log_level=args.log_level, logger_name="reliable_udp.sender")

    if args.message and not args.file:
        send_message(host=args.host, port=args.port, message=args.message, logger=logger)
        return

    if not args.file:
        logger.error("Must specify either --file <path> or --message <text>")
        parser.print_help()
        sys.exit(1)

    latency_sec = args.latency / 1000.0 if args.latency > 1.0 else args.latency
    config = TransferConfig(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        max_retries=args.max_retries,
        payload_size=args.payload_size,
        loss_rate=args.loss_rate,
        latency=latency_sec,
        corruption_rate=args.corruption_rate,
        log_level=args.log_level,
    )

    file_path = Path(args.file)
    if not file_path.exists():
        logger.error(f"Target file does not exist: {file_path}")
        sys.exit(1)

    sender = FileSender(config, logger)
    stats = sender.send_file(file_path)

    if not stats.success:
        logger.error("File transfer failed or was unconfirmed by receiver.")
        sys.exit(1)

    logger.info("File transfer completed and verified.")


if __name__ == "__main__":
    main()
