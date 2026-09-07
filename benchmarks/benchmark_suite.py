"""
Performance Benchmarking Suite for Reliable UDP (Milestone 13).
Executes live empirical benchmarks comparing:
  - Stop-and-Wait ARQ
  - Sliding Window ARQ
  - Selective Repeat ARQ

Measures actual metrics across multiple real tests:
  - transfer time
  - throughput
  - packets sent
  - packets received
  - retransmissions
  - duplicate packets
  - corrupted packets
  - success rate

Saves measured results to benchmarks/benchmark_results.json and benchmarks/benchmark_report.md.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.checksum import calculate_file_sha256
from app.config import ARQMode, TransferConfig
from app.transfer import FileReceiver, FileSender
from app.utils import format_bytes, format_duration, format_throughput, setup_logging


@dataclass
class BenchmarkTrialResult:
    scenario: str
    protocol: str
    window_size: int
    loss_rate: float
    latency_ms: float
    corruption_rate: float
    filesize_bytes: int
    duration_seconds: float
    throughput_mbps: float
    throughput_formatted: str
    packets_sent: int
    packets_received: int
    retransmissions: int
    duplicate_packets: int
    corrupted_packets: int
    sha_verified: bool
    success_rate_percent: float


def run_single_trial(
    scenario_name: str,
    file_path: Path,
    port: int,
    arq_mode: ARQMode,
    window_size: int = 8,
    loss_rate: float = 0.0,
    latency_ms: float = 0.0,
    corruption_rate: float = 0.0,
    timeout: float = 0.25,
    max_retries: int = 5,
) -> BenchmarkTrialResult:
    """Execute an empirical trial of a file transfer under specific network conditions."""
    latency_sec = latency_ms / 1000.0 if latency_ms > 0 else 0.0

    with tempfile.TemporaryDirectory() as recv_dir:
        config_rcv = TransferConfig(
            host="127.0.0.1",
            port=port,
            output_dir=Path(recv_dir),
            window_size=window_size,
            timeout=timeout,
            max_retries=max_retries,
            loss_rate=loss_rate,
            latency=latency_sec,
            corruption_rate=corruption_rate,
            arq_mode=arq_mode,
            log_level="WARNING",
        )
        config_snd = TransferConfig(
            host="127.0.0.1",
            port=port,
            window_size=window_size,
            timeout=timeout,
            max_retries=max_retries,
            loss_rate=loss_rate,
            latency=latency_sec,
            corruption_rate=corruption_rate,
            arq_mode=arq_mode,
            log_level="WARNING",
        )

        ready = threading.Event()
        rx_outcomes = []
        receiver = FileReceiver(config_rcv)

        def rx_worker():
            ready.set()
            out_path, ok = receiver.receive_file()
            rx_outcomes.append((out_path, ok))

        t = threading.Thread(target=rx_worker, daemon=True)
        t.start()
        ready.wait(timeout=2.0)
        time.sleep(0.04)

        sender = FileSender(config_snd)
        stats = sender.send_file(file_path)
        t.join(timeout=30.0)

        if rx_outcomes:
            out_file, verified = rx_outcomes[0]
            src_sha = calculate_file_sha256(file_path)
            dst_sha = calculate_file_sha256(out_file) if out_file and out_file.exists() else ""
            is_valid = verified and (src_sha == dst_sha) and stats.success
        else:
            is_valid = False

        rcv_stats = getattr(receiver, "last_receiver_stats", {})
        packets_rcvd = rcv_stats.get("packets_received", 0)
        duplicates = rcv_stats.get("duplicates_detected", 0)
        corrupted = rcv_stats.get("corrupted_packets", 0)

        mbps = (stats.filesize * 8) / (stats.duration_seconds * 1e6) if stats.duration_seconds > 0 else 0.0

        protocol_name = {
            ARQMode.STOP_AND_WAIT: "Stop-and-Wait",
            ARQMode.SLIDING_WINDOW: "Sliding Window",
            ARQMode.SELECTIVE_REPEAT: "Selective Repeat",
        }[arq_mode]

        return BenchmarkTrialResult(
            scenario=scenario_name,
            protocol=protocol_name,
            window_size=window_size,
            loss_rate=loss_rate,
            latency_ms=latency_ms,
            corruption_rate=corruption_rate,
            filesize_bytes=stats.filesize,
            duration_seconds=round(stats.duration_seconds, 4),
            throughput_mbps=round(mbps, 2),
            throughput_formatted=format_throughput(stats.filesize, stats.duration_seconds),
            packets_sent=stats.total_packets_sent,
            packets_received=packets_rcvd,
            retransmissions=stats.retransmissions,
            duplicate_packets=duplicates,
            corrupted_packets=corrupted,
            sha_verified=is_valid,
            success_rate_percent=100.0 if is_valid else 0.0,
        )


def generate_markdown_report(results: List[BenchmarkTrialResult], output_path: Path) -> None:
    """Generate a clean, professional GitHub-flavored Markdown benchmark report."""
    md = []
    md.append("# Milestone 13 — Performance Benchmark Report\n")
    md.append("**Generated**: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
    md.append("All metrics represent **actual measured empirical results** over real UDP sockets.\n\n")

    # Group by scenario
    scenarios: Dict[str, List[BenchmarkTrialResult]] = {}
    for r in results:
        scenarios.setdefault(r.scenario, []).append(r)

    for sc_name, trials in scenarios.items():
        md.append(f"## {sc_name}\n\n")
        md.append("| Protocol | Window ($W$) | Duration | Throughput | Pkts Sent | Pkts Recv | Retrans | Dups | Corrupt | Success Rate |")
        md.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
        for t in trials:
            md.append(
                f"| **{t.protocol}** | {t.window_size} | {t.duration_seconds:.4f} s | {t.throughput_formatted} ({t.throughput_mbps:.1f} Mbps) | "
                f"{t.packets_sent} | {t.packets_received} | {t.retransmissions} | {t.duplicate_packets} | {t.corrupted_packets} | "
                f"{'100% (Verified)' if t.sha_verified else '0% (Failed)'} |"
            )
        md.append("\n")

    md.append("## Architectural Analysis & Principles\n\n")
    md.append("### 1. Why Stop-and-Wait is Slower\n")
    md.append(
        "Stop-and-Wait enforces a strictly synchronous cycle: transmit packet $i$, block, and wait for $ACK(i)$ before packet $i+1$ can be sent. "
        "The transmission rate is fundamentally capped by the round-trip time: $\\text{Rate} \\le \\text{MSS} / \\text{RTT}$. "
        "Regardless of network bandwidth, the channel sits idle for nearly 100% of the duration on links with non-negligible propagation delay.\n\n"
    )
    md.append("### 2. Why Multiple Packets in Flight Improve Throughput\n")
    md.append(
        "Allowing up to $W$ packets in flight simultaneously keeps the network pipe continuously filled during the round-trip time. "
        "Instead of stalling for an entire RTT after every 1024 bytes, the sender pipelines $W \\times 1024$ bytes into transit, "
        "scaling channel utilization directly with window size: $U \\approx \\min(1, (W \\times T_{\\text{trans}}) / \\text{RTT})$.\n\n"
    )
    md.append("### 3. How Packet Loss Affects Performance\n")
    md.append(
        "- **Stop-and-Wait**: Halts the entire pipeline upon any loss; wait duration is $1.0 \\times \\text{RTO}$ per dropped packet.\n"
        "- **Sliding Window (Go-Back-N)**: When packet $k$ is dropped, the receiver discards all subsequent packets $k+1..k+W-1$. The sender must retransmit the entire window, wasting bandwidth on already delivered packets.\n"
        "- **Selective Repeat**: When packet $k$ is dropped, out-of-order packets $k+1..k+W-1$ are buffered in receiver RAM and individually ACKed. **Only packet $k$ is retransmitted**, preserving maximum throughput even under heavy packet drop rates.\n\n"
    )
    md.append("### 4. How Window Size Affects Performance\n")
    md.append(
        "- **When $W < \\text{BDP}$**: The window is the bottleneck; the sender exhausts window credits before the first ACK returns, causing pipeline underflow.\n"
        "- **When $W \\approx \\text{BDP}$**: Optimal network operating point; 100% link utilization with minimal queuing delay.\n"
        "- **When $W \\gg \\text{BDP}$**: Diminishing throughput returns; excessive bursts overflow socket and switch buffers, causing bufferbloat, increased jitter, and drop cascades without congestion control.\n"
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(md), encoding="utf-8")


def run_all_benchmarks() -> List[BenchmarkTrialResult]:
    """Execute the complete suite of performance benchmarks."""
    bench_dir = Path("benchmarks")
    bench_dir.mkdir(exist_ok=True)

    test_file = Path("sample_files/bench_256kb.bin")
    if not test_file.exists():
        test_file.parent.mkdir(exist_ok=True)
        test_file.write_bytes(os.urandom(256 * 1024))

    print("=" * 80)
    print("  RELIABLE UDP PERFORMANCE BENCHMARK SUITE (Milestone 13)")
    print(f"  Test Artifact: {test_file} ({format_bytes(test_file.stat().st_size)})")
    print("=" * 80)

    results: List[BenchmarkTrialResult] = []
    port = 9710

    # -------------------------------------------------------------------------
    # Experiment 1: Clean Channel Baseline (0% loss, 0ms latency)
    # -------------------------------------------------------------------------
    print("\n[EXPERIMENT 1] Clean Network Baseline (0% loss, 0ms latency)...")
    for mode, w in [
        (ARQMode.STOP_AND_WAIT, 1),
        (ARQMode.SLIDING_WINDOW, 8),
        (ARQMode.SELECTIVE_REPEAT, 8),
    ]:
        print(f"  * Running {mode.value} (W={w})...")
        r = run_single_trial("1. Clean Network Baseline", test_file, port, mode, window_size=w)
        results.append(r)
        port += 1

    # -------------------------------------------------------------------------
    # Experiment 2: High-Latency Channel (10ms latency -> ~20ms RTT)
    # -------------------------------------------------------------------------
    print("\n[EXPERIMENT 2] High-Latency Channel (10ms one-way latency)...")
    for mode, w in [
        (ARQMode.STOP_AND_WAIT, 1),
        (ARQMode.SLIDING_WINDOW, 8),
        (ARQMode.SELECTIVE_REPEAT, 8),
    ]:
        print(f"  * Running {mode.value} (W={w})...")
        r = run_single_trial("2. High-Latency Channel (10ms)", test_file, port, mode, window_size=w, latency_ms=10)
        results.append(r)
        port += 1

    # -------------------------------------------------------------------------
    # Experiment 3: Lossy Channel (5% Packet Loss)
    # -------------------------------------------------------------------------
    print("\n[EXPERIMENT 3] Lossy Channel (5% packet loss)...")
    for mode, w in [
        (ARQMode.STOP_AND_WAIT, 1),
        (ARQMode.SLIDING_WINDOW, 8),
        (ARQMode.SELECTIVE_REPEAT, 8),
    ]:
        print(f"  * Running {mode.value} (W={w})...")
        r = run_single_trial("3. Lossy Channel (5% Loss)", test_file, port, mode, window_size=w, loss_rate=0.05)
        results.append(r)
        port += 1

    # -------------------------------------------------------------------------
    # Experiment 4: Window Size Scaling (Selective Repeat)
    # -------------------------------------------------------------------------
    print("\n[EXPERIMENT 4] Window Size Scaling (Selective Repeat)...")
    for w in [1, 2, 4, 8, 16]:
        print(f"  * Running Selective Repeat with Window Size W={w}...")
        r = run_single_trial("4. Window Size Scaling (Selective Repeat)", test_file, port, ARQMode.SELECTIVE_REPEAT, window_size=w)
        results.append(r)
        port += 1

    # -------------------------------------------------------------------------
    # Save Results
    # -------------------------------------------------------------------------
    json_path = bench_dir / "benchmark_results.json"
    report_path = bench_dir / "benchmark_report.md"

    print("\n" + "=" * 80)
    print(f"Saving raw benchmark telemetry to: {json_path}")
    raw_dicts = [asdict(r) for r in results]
    json_path.write_text(json.dumps(raw_dicts, indent=2), encoding="utf-8")

    print(f"Saving formatted markdown report to: {report_path}")
    generate_markdown_report(results, report_path)
    print("=" * 80)

    # Print summary table to console
    print(f"\n{'Scenario':<32} | {'Protocol':<18} | {'W':<3} | {'Time (s)':<9} | {'Throughput':<12} | {'Retrans':<7} | {'Success':<8}")
    print("-" * 105)
    for r in results:
        print(
            f"{r.scenario:<32} | {r.protocol:<18} | {r.window_size:<3} | {r.duration_seconds:<9.4f} | "
            f"{r.throughput_formatted:<12} | {r.retransmissions:<7} | {'100%' if r.sha_verified else '0%'}"
        )
    print("=" * 105)

    return results


if __name__ == "__main__":
    setup_logging(log_level="WARNING")
    run_all_benchmarks()
