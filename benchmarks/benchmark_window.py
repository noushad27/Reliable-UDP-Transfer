"""
Milestone 10 Benchmark: Stop-and-Wait vs Sliding Window (window_size = 8).

Measures and compares elapsed transfer time, throughput, and protocol behavior
between Stop-and-Wait ARQ (N=1) and Sliding Window ARQ (N=8).
"""

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.checksum import calculate_file_sha256
from app.config import ARQMode, TransferConfig
from app.transfer import FileReceiver, FileSender
from app.utils import format_bytes, format_throughput, setup_logging


def run_single_benchmark(
    file_path: Path,
    port: int,
    arq_mode: ARQMode,
    window_size: int,
) -> dict:
    """Execute a single transfer run under specified ARQ mode and window size."""
    with tempfile.TemporaryDirectory() as recv_dir:
        config_rcv = TransferConfig(
            host="127.0.0.1",
            port=port,
            output_dir=Path(recv_dir),
            window_size=window_size,
            log_level="WARNING",
        )
        config_snd = TransferConfig(
            host="127.0.0.1",
            port=port,
            arq_mode=arq_mode,
            window_size=window_size,
            log_level="WARNING",
        )

        ready = threading.Event()
        rx_result = []

        def rx_thread():
            receiver = FileReceiver(config_rcv)
            ready.set()
            out_file, verified = receiver.receive_file()
            rx_result.append((out_file, verified))

        t = threading.Thread(target=rx_thread, daemon=True)
        t.start()
        ready.wait(timeout=2.0)
        time.sleep(0.05)

        sender = FileSender(config_snd)
        stats = sender.send_file(file_path)
        t.join(timeout=10.0)

        out_file, verified = rx_result[0]
        src_sha = calculate_file_sha256(file_path)
        dst_sha = calculate_file_sha256(out_file)

        return {
            "mode": arq_mode.value,
            "window_size": window_size,
            "filesize": stats.filesize,
            "duration": stats.duration_seconds,
            "throughput": stats.throughput_bytes_per_sec,
            "packets_sent": stats.total_packets_sent,
            "retransmissions": stats.retransmissions,
            "sha_match": (src_sha == dst_sha) and verified,
        }


def main():
    logger = setup_logging(log_level="INFO", logger_name="benchmark")
    print("=" * 75)
    print("  RELIABLE UDP BENCHMARK: Stop-and-Wait vs Sliding Window (Milestone 10)")
    print("=" * 75)

    # Prepare a benchmark payload file (256 KB -> 256 chunks of 1024 bytes)
    bench_dir = Path("sample_files")
    bench_dir.mkdir(exist_ok=True)
    bench_file = bench_dir / "bench_256kb.bin"
    if not bench_file.exists():
        bench_file.write_bytes(os.urandom(256 * 1024))

    file_size = bench_file.stat().st_size
    print(f"Benchmark File: {bench_file} ({format_bytes(file_size)}, ~{file_size // 1024} chunks)")
    print("-" * 75)

    # 1. Run Stop-and-Wait (N=1)
    print("Running Run 1: Stop-and-Wait ARQ (window_size=1)...")
    res_sw = run_single_benchmark(
        file_path=bench_file,
        port=9501,
        arq_mode=ARQMode.STOP_AND_WAIT,
        window_size=1,
    )

    # 2. Run Sliding Window (N=8)
    print("Running Run 2: Sliding Window ARQ (window_size=8)...")
    res_win = run_single_benchmark(
        file_path=bench_file,
        port=9502,
        arq_mode=ARQMode.SLIDING_WINDOW,
        window_size=8,
    )

    # Display results
    print("=" * 75)
    print(f"{'Metric':<30} | {'Stop-and-Wait (N=1)':<18} | {'Sliding Window (N=8)':<18}")
    print("-" * 75)
    print(f"{'Protocol Window Size':<30} | {res_sw['window_size']:<18} | {res_win['window_size']:<18}")
    print(f"{'Max Packets in Flight':<30} | {'1':<18} | {'8':<18}")
    print(f"{'Elapsed Transfer Time':<30} | {res_sw['duration']:.4f} s           | {res_win['duration']:.4f} s")
    print(f"{'Effective Throughput':<30} | {format_throughput(res_sw['filesize'], res_sw['duration']):<18} | {format_throughput(res_win['filesize'], res_win['duration']):<18}")
    print(f"{'Packets Sent':<30} | {res_sw['packets_sent']:<18} | {res_win['packets_sent']:<18}")
    print(f"{'Retransmissions':<30} | {res_sw['retransmissions']:<18} | {res_win['retransmissions']:<18}")
    print(f"{'SHA-256 Integrity Verified':<30} | {str(res_sw['sha_match']):<18} | {str(res_win['sha_match']):<18}")
    print("=" * 75)

    speedup = res_sw["duration"] / res_win["duration"] if res_win["duration"] > 0 else 1.0
    time_saved = ((res_sw["duration"] - res_win["duration"]) / res_sw["duration"]) * 100
    print(f"Speedup Factor: {speedup:.2f}x")
    print(f"Time Reduction: {time_saved:.1f}% reduction in transfer duration")
    print("=" * 75)

    # Theoretical throughput scaling across realistic network RTTs
    print("\n" + "=" * 75)
    print("  THEORETICAL NETWORK SCALING OVER RTT (Bandwidth-Delay Product)")
    print("=" * 75)
    print(f"{'Network RTT':<16} | {'Stop-and-Wait Throughput':<26} | {'Sliding Window (N=8) Throughput':<30}")
    print("-" * 75)
    payload_bits = 1024 * 8
    for rtt_ms in [5, 10, 25, 50, 100]:
        rtt_sec = rtt_ms / 1000.0
        sw_bps = payload_bits / rtt_sec
        win_bps = (payload_bits * 8) / rtt_sec
        sw_str = f"{sw_bps / 1e6:.2f} Mbps ({format_throughput(int(sw_bps / 8), 1.0)})"
        win_str = f"{win_bps / 1e6:.2f} Mbps ({format_throughput(int(win_bps / 8), 1.0)})"
        print(f"{f'{rtt_ms} ms':<16} | {sw_str:<26} | {win_str:<30}")
    print("=" * 75)


if __name__ == "__main__":
    main()
