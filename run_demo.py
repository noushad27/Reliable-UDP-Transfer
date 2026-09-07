"""
Reliable File Transfer over UDP - Demonstration Entry Point.

This script demonstrates and orchestrates the reliable file transfer protocol
across various network conditions and ARQ reliability modes.
"""

import sys
from app.config import TransferConfig, ARQMode, PROTOCOL_VERSION, HEADER_SIZE
from app.utils import setup_logging, format_bytes

def main() -> None:
    logger = setup_logging(log_level="INFO")
    logger.info("==================================================================")
    logger.info("Custom Reliable File Transfer over UDP -- Project Framework")
    logger.info(f"Protocol Version: {PROTOCOL_VERSION} | Header Size: {HEADER_SIZE} bytes")
    logger.info("==================================================================")

    config = TransferConfig()
    logger.info("Default Configuration initialized:")
    logger.info(f"  * Endpoint:       {config.host}:{config.port}")
    logger.info(f"  * Payload Size:   {config.payload_size} bytes ({format_bytes(config.payload_size)})")
    logger.info(f"  * Window Size:    {config.window_size}")
    logger.info(f"  * Timeout:        {config.timeout}s")
    logger.info(f"  * Max Retries:    {config.max_retries}")
    logger.info(f"  * ARQ Mode:       {config.arq_mode}")
    logger.info(f"  * Output Dir:     {config.output_dir}")
    logger.info("==================================================================")
    logger.info("Status: Milestone 1 (Project Setup & Configuration) Complete.")
    logger.info("Run 'pytest tests' to execute the test suite.")

if __name__ == "__main__":
    main()
