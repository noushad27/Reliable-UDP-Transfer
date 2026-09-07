"""
Receiver CLI and socket listeners.
Supports both basic UDP datagram reception and reliable Stop-and-Wait file reception.
"""

from __future__ import annotations

import argparse
import logging
import socket
import sys
from pathlib import Path
from typing import Optional

from app.config import DEFAULT_PORT, TransferConfig
from app.transfer import FileReceiver
from app.utils import setup_logging


def run_receiver(
    host: str = "0.0.0.0",
    port: int = DEFAULT_PORT,
    buffer_size: int = 1024,
    once: bool = False,
    timeout: float | None = None,
    logger: logging.Logger | None = None,
) -> None:
    """
    Bind a raw UDP socket and receive incoming unacknowledged datagrams (Milestone 2).
    """
    if logger is None:
        logger = setup_logging(log_level="INFO", logger_name="udp_receiver")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if timeout is not None:
        sock.settimeout(timeout)

    try:
        sock.bind((host, port))
        logger.info(f"UDP Receiver bound and listening on {host}:{port}")

        while True:
            try:
                data, addr = sock.recvfrom(buffer_size)
                message = data.decode("utf-8", errors="replace")
                logger.info(f"Received {len(data)} bytes from {addr[0]}:{addr[1]}: '{message}'")
                print(f"Received: {message}")
                if once:
                    break
            except socket.timeout:
                logger.warning(f"Socket timed out after {timeout}s.")
                break
    except KeyboardInterrupt:
        logger.info("Receiver stopped by user.")
    finally:
        sock.close()


def main() -> None:
    """CLI entry point for reliable file receiver."""
    parser = argparse.ArgumentParser(description="Reliable UDP File Receiver (Stop-and-Wait ARQ)")
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Interface address to bind (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port to bind (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./received_files",
        help="Directory where received files will be saved (default: ./received_files)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Exit after receiving a single file transfer",
    )
    parser.add_argument(
        "--basic",
        action="store_true",
        help="Run simple unacknowledged UDP datagram receiver (Milestone 2 mode)",
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
    logger = setup_logging(log_level=args.log_level, logger_name="reliable_udp.receiver")

    if args.basic:
        run_receiver(host=args.host, port=args.port, once=args.once, logger=logger)
        return

    latency_sec = args.latency / 1000.0 if args.latency > 1.0 else args.latency
    config = TransferConfig(
        host=args.host,
        port=args.port,
        output_dir=Path(args.output_dir),
        loss_rate=args.loss_rate,
        latency=latency_sec,
        corruption_rate=args.corruption_rate,
        log_level=args.log_level,
    )

    receiver = FileReceiver(config, logger)
    logger.info(f"Receiver ready on {args.host}:{args.port}. Saving files to: {args.output_dir}")

    while True:
        try:
            output_file, success = receiver.receive_file()
            if success:
                logger.info(f"Successfully received and verified file: {output_file}")
            else:
                logger.error(f"File reception failed for: {output_file}")

            if args.once:
                break
        except KeyboardInterrupt:
            logger.info("Receiver shutting down on user request.")
            break
        except Exception as e:
            logger.error(f"Transfer error: {e}", exc_info=True)
            if args.once:
                sys.exit(1)


if __name__ == "__main__":
    main()
