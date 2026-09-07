# Milestone 13 — Performance Benchmark Report

**Generated**: 2026-09-04 23:24:39

All metrics represent **actual measured empirical results** over real UDP sockets.


## 1. Clean Network Baseline


| Protocol | Window ($W$) | Duration | Throughput | Pkts Sent | Pkts Recv | Retrans | Dups | Corrupt | Success Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Stop-and-Wait** | 1 | 0.0309 s | 8.10 MB/s (68.0 Mbps) | 258 | 256 | 0 | 0 | 0 | 100% (Verified) |
| **Sliding Window** | 8 | 0.0287 s | 8.70 MB/s (73.0 Mbps) | 258 | 256 | 0 | 0 | 0 | 100% (Verified) |
| **Selective Repeat** | 8 | 0.0284 s | 8.79 MB/s (73.7 Mbps) | 258 | 256 | 0 | 0 | 0 | 100% (Verified) |


## 2. High-Latency Channel (10ms)


| Protocol | Window ($W$) | Duration | Throughput | Pkts Sent | Pkts Recv | Retrans | Dups | Corrupt | Success Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Stop-and-Wait** | 1 | 8.0996 s | 31.61 KB/s (0.3 Mbps) | 258 | 256 | 0 | 0 | 0 | 100% (Verified) |
| **Sliding Window** | 8 | 1.0720 s | 238.81 KB/s (2.0 Mbps) | 258 | 256 | 0 | 0 | 0 | 100% (Verified) |
| **Selective Repeat** | 8 | 1.0715 s | 238.92 KB/s (2.0 Mbps) | 258 | 256 | 0 | 0 | 0 | 100% (Verified) |


## 3. Lossy Channel (5% Loss)


| Protocol | Window ($W$) | Duration | Throughput | Pkts Sent | Pkts Recv | Retrans | Dups | Corrupt | Success Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Stop-and-Wait** | 1 | 10.1758 s | 25.16 KB/s (0.2 Mbps) | 297 | 274 | 39 | 18 | 0 | 100% (Verified) |
| **Sliding Window** | 8 | 4.1825 s | 61.21 KB/s (0.5 Mbps) | 283 | 268 | 25 | 12 | 0 | 100% (Verified) |
| **Selective Repeat** | 8 | 4.6772 s | 54.73 KB/s (0.5 Mbps) | 281 | 270 | 23 | 14 | 0 | 100% (Verified) |


## 4. Window Size Scaling (Selective Repeat)


| Protocol | Window ($W$) | Duration | Throughput | Pkts Sent | Pkts Recv | Retrans | Dups | Corrupt | Success Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Selective Repeat** | 1 | 0.0397 s | 6.30 MB/s (52.8 Mbps) | 258 | 256 | 0 | 0 | 0 | 100% (Verified) |
| **Selective Repeat** | 2 | 0.0344 s | 7.26 MB/s (60.9 Mbps) | 258 | 256 | 0 | 0 | 0 | 100% (Verified) |
| **Selective Repeat** | 4 | 0.0335 s | 7.46 MB/s (62.6 Mbps) | 258 | 256 | 0 | 0 | 0 | 100% (Verified) |
| **Selective Repeat** | 8 | 0.0327 s | 7.65 MB/s (64.2 Mbps) | 258 | 256 | 0 | 0 | 0 | 100% (Verified) |
| **Selective Repeat** | 16 | 0.0305 s | 8.19 MB/s (68.7 Mbps) | 258 | 256 | 0 | 0 | 0 | 100% (Verified) |


## Architectural Analysis & Principles


### 1. Why Stop-and-Wait is Slower

Stop-and-Wait enforces a strictly synchronous cycle: transmit packet $i$, block, and wait for $ACK(i)$ before packet $i+1$ can be sent. The transmission rate is fundamentally capped by the round-trip time: $\text{Rate} \le \text{MSS} / \text{RTT}$. Regardless of network bandwidth, the channel sits idle for nearly 100% of the duration on links with non-negligible propagation delay.


### 2. Why Multiple Packets in Flight Improve Throughput

Allowing up to $W$ packets in flight simultaneously keeps the network pipe continuously filled during the round-trip time. Instead of stalling for an entire RTT after every 1024 bytes, the sender pipelines $W \times 1024$ bytes into transit, scaling channel utilization directly with window size: $U \approx \min(1, (W \times T_{\text{trans}}) / \text{RTT})$.


### 3. How Packet Loss Affects Performance

- **Stop-and-Wait**: Halts the entire pipeline upon any loss; wait duration is $1.0 \times \text{RTO}$ per dropped packet.
- **Sliding Window (Go-Back-N)**: When packet $k$ is dropped, the receiver discards all subsequent packets $k+1..k+W-1$. The sender must retransmit the entire window, wasting bandwidth on already delivered packets.
- **Selective Repeat**: When packet $k$ is dropped, out-of-order packets $k+1..k+W-1$ are buffered in receiver RAM and individually ACKed. **Only packet $k$ is retransmitted**, preserving maximum throughput even under heavy packet drop rates.


### 4. How Window Size Affects Performance

- **When $W < \text{BDP}$**: The window is the bottleneck; the sender exhausts window credits before the first ACK returns, causing pipeline underflow.
- **When $W \approx \text{BDP}$**: Optimal network operating point; 100% link utilization with minimal queuing delay.
- **When $W \gg \text{BDP}$**: Diminishing throughput returns; excessive bursts overflow socket and switch buffers, causing bufferbloat, increased jitter, and drop cascades without congestion control.
