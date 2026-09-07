# Networking, Transport Protocols & Systems Engineering Interview Guide

This guide provides structured interview explanations and 25 comprehensive technical questions covering reliable transport protocol engineering, socket programming, security, and systems architecture.

---

## 1. Project Explanations (By Time Limit)

### 30-Second Elevator Pitch
> *"I designed and built a reliable, high-throughput file transfer protocol from scratch directly on top of raw UDP in Python. Because standard UDP provides zero delivery or ordering guarantees, I engineered a 22-byte binary packet wire format with CRC32 checksums, bidirectional sequence numbers and acknowledgments, dynamic retransmission timeouts, out-of-order packet buffering, and Selective Repeat ARQ. It pipelines multi-megabyte binary transfers across simulated lossy and high-latency networks while enforcing incremental SHA-256 cryptographic verification and path-traversal sandboxing."*

---

### 60-Second Summary
> *"When building network applications like real-time gaming, VoIP, or high-speed data synchronization, TCP's head-of-line blocking and kernel-level congestion backoff can severely degrade throughput. To understand transport engineering from first principles, I implemented a portfolio-grade reliable UDP protocol. 
>
> The system implements a three-phase lifecycle: a three-way metadata handshake (`START`/`START_ACK`), pipelined chunk streaming with Selective Repeat ARQ, and an integrity-verified teardown (`FIN`/`FIN_ACK`). The receiver buffers out-of-order chunks in a ring buffer, while the sender tracks per-packet timers to selectively retransmit only dropped datagrams rather than discarding the entire window. I also built an in-process network simulation layer to inject packet loss, artificial jitter, and bit corruption, an empirical benchmarking suite, and full Wireshark dissection support."*

---

### 2-Minute Architectural Deep-Dive
> *"The project is structured into five distinct, decoupled layers:
>
> 1. **Application & Storage Layer**: Handles chunk streaming using Python generators to read large files in fixed-size buffers (default 1024 bytes) without exhausting memory. It computes 64-character SHA-256 hashes incrementally and validates filesystem paths to prevent path traversal attacks like `../../etc/passwd`.
> 2. **Session & Transfer Manager (`FileSender` / `FileReceiver`)**: Coordinates connection establishment, session state transitions, performance telemetry, and graceful error teardowns.
> 3. **Reliability & ARQ Engine**: Implements three configurable ARQ strategies: Stop-and-Wait, Sliding Window (Go-Back-N), and Selective Repeat. In Selective Repeat, the sender maintains individual packet states (`IN_FLIGHT`, `ACKED`, `TIMED_OUT`) and individual monotonic timers. The receiver buffers out-of-order packets and drains them sequentially into disk files upon receiving missing sequence numbers.
> 4. **Binary Serialization & Packet Layer**: Serializes headers into an exact 22-byte big-endian binary struct containing magic identifier `RD`, protocol version, packet type, session ID, sequence number, ACK number, payload length, and a CRC32 checksum computed over the header and payload.
> 5. **Network Simulation & Socket Layer**: Intercepts `sendto` and `recvfrom` calls to probabilistically simulate packet drops, microsecond latency delays, and bit-level corruption without requiring root privileges or OS kernel routing changes.
>
> In our empirical benchmarks across high-latency links, pipelining multiple packets in flight boosted throughput by over 7.5x compared to Stop-and-Wait, while Selective Repeat eliminated wasted retransmissions under loss."*

---

### 5-Minute Comprehensive Presentation
> *"The motivation behind this project was to master the fundamentals of transport-layer protocol engineering by solving the exact challenges modern protocols like QUIC, SCTP, and HTTP/3 face.
>
> **The Problem with Standard UDP**:
> Raw UDP is connectionless and best-effort. It offers no delivery confirmation, no ordering guarantees, no duplicate suppression, and no flow control.
>
> **The Protocol State Machine**:
> 1. **Handshake**: The sender initiates with a `START` packet containing JSON metadata (filename, file size, total chunk count, expected SHA-256, and advertised window size). The receiver validates the parameters, sandboxes the destination filename inside a dedicated directory, allocates state, and replies with `START_ACK`.
> 2. **Pipelined Transfer**: Under Selective Repeat, the sender maintains a window of $W$ packets (e.g., $W=8$). Up to 8 packets are in flight simultaneously. As ACKs arrive, the lower window boundary (`base_seq`) slides forward. If an ACK is lost or a packet is dropped, only the unacknowledged packet's timer expires. The sender selectively retransmits only that single missing sequence number.
> 3. **Teardown & Verification**: Once all chunks are transmitted, the sender issues a `FIN` datagram carrying its computed SHA-256 hash. The receiver streams the reassembled file through `hashlib.sha256()`, validates that the hashes match byte-for-byte, commits the file, and replies with `FIN_ACK`. If a mismatch or incomplete transfer is detected, the corrupted partial file is quarantined and wiped from disk.
>
> **Engineering Challenges & Key Decisions**:
> - **Zero-Memory Chunk Streaming**: Reading large files into memory at once causes out-of-memory crashes on resource-constrained systems. I designed binary chunk generators that stream slices directly from disk to socket.
> - **Race Conditions in Multi-Packet ACKs**: Under high network latency or out-of-order delivery, late ACKs from earlier sessions or stale sequence numbers could corrupt sender state. I implemented session ID isolation and sequence filters that discard stale ACKs (`ack_num < base_seq`).
> - **Defensive Security Validation**: The protocol rejects malformed packets, invalid magic bytes, truncated headers, and oversized payloads exceeding MTU limits. Filename sanitization strips null bytes, directory separators, and reserved Windows device names (`CON`, `NUL`, `COM1`).
> - **Benchmarking & Wireshark Dissection**: I authored a complete Wireshark Lua dissector (`reliable_udp.lua`) and a pure-Python PCAP generator, enabling engineers to inspect packet headers, sequence numbers, and retransmission events under the display filter `udp.port == 9000`."*

---

## 2. Technical Interview Questions & Answers

---

### Question 1: UDP (User Datagram Protocol)
- **Simple Answer**: UDP is a lightweight, connectionless transport protocol that sends independent packets without establishing a connection or guaranteeing delivery.
- **Technical Answer**: UDP is defined in RFC 768. It is a minimal, stateless transport layer protocol operating above IP. It adds only an 8-byte header consisting of Source Port, Destination Port, Length, and an optional Checksum. It does not perform handshakes, sequence tracking, acknowledgment, retransmission, or flow/congestion control.
- **Project Example**: We bind a `socket.socket(socket.AF_INET, socket.SOCK_DGRAM)` to send discrete datagrams up to the MTU size without stream overhead or connection establishment latency.
- **Common Mistake**: Assuming UDP packets will arrive in the order they were sent, or that a successful `sendto()` return means the remote receiver accepted or received the packet.

---

### Question 2: TCP (Transmission Control Protocol)
- **Simple Answer**: TCP is a connection-oriented, reliable protocol that guarantees in-order, error-checked delivery of byte streams between hosts.
- **Technical Answer**: Defined in RFC 793 and subsequent standards, TCP establishes a virtual circuit via a three-way handshake (`SYN`, `SYN-ACK`, `ACK`). It numbers every byte of data, tracks acknowledgments, estimates round-trip time (RTT), performs Go-Back-N or SACK retransmissions, and dynamically throttles send rates via congestion control algorithms (Reno, Cubic, BBR).
- **Project Example**: We deliberately avoided TCP streams so that we could implement our own application-layer reliability primitives (sequence numbers, timeouts, out-of-order buffering) on top of raw datagrams.
- **Common Mistake**: Confusing packet boundaries with stream boundaries; TCP is a continuous stream with no inherent message delimiters, whereas UDP preserves datagram boundaries.

---

### Question 3: TCP/IP Model
- **Simple Answer**: A 4-layer architectural model that standardizes how computers communicate over the Internet: Link, Internet, Transport, and Application layers.
- **Technical Answer**: The TCP/IP stack organizes network functions into:
  1. *Link Layer* (Ethernet, Wi-Fi; framing, MAC addresses).
  2. *Internet Layer* (IPv4, IPv6; logical addressing, routing, fragmentation).
  3. *Transport Layer* (TCP, UDP; process-to-process multiplexing via ports).
  4. *Application Layer* (HTTP, DNS, custom protocols; application data framing).
- **Project Example**: Our custom protocol resides at the Application Layer (Layer 7/4 application-transport hybrid) while transmitting over UDP (Layer 4) and IPv4 (Layer 3).
- **Common Mistake**: Believing that reliable delivery can only be implemented at the Transport Layer; application-layer protocols (like our protocol or QUIC over UDP) frequently implement their own reliability.

---

### Question 4: HTTP (Hypertext Transfer Protocol)
- **Simple Answer**: An application-layer protocol used for transmitting hypermedia documents, traditionally running over TCP and TLS.
- **Technical Answer**: HTTP/1.1 and HTTP/2 operate over TCP, where head-of-line blocking at the transport layer can stall all multiplexed streams if a single packet is lost. HTTP/3 solves this by migrating from TCP to QUIC, which runs entirely over UDP with independent stream recovery.
- **Project Example**: Our protocol's architecture mirrors the design philosophy of HTTP/3 and QUIC: building customized reliability, multiplexing, and cryptographic validation directly over UDP datagrams.
- **Common Mistake**: Assuming HTTP is inherently tied to TCP; HTTP/3 proves that modern Web transport is moving towards UDP-based application-level framing.

---

### Question 5: Sockets
- **Simple Answer**: An OS abstraction and software endpoint for sending and receiving data across a network.
- **Technical Answer**: A network socket is a file descriptor managed by the operating system kernel. It binds an application process to a specific transport protocol, IP address, and port number tuple. On POSIX and Windows (`Winsock`), sockets support blocking, non-blocking, and multiplexed I/O (`select`, `poll`, `epoll`, `kqueue`).
- **Project Example**: In `StopAndWaitReceiver`, we instantiate a non-blocking UDP socket and use `sock.settimeout(0.2)` to prevent thread deadlocks while awaiting client handshakes.
- **Common Mistake**: Forgetting to close socket handles in `finally` blocks, resulting in OS descriptor leaks and port binding errors (`WSAEADDRINUSE` or `EADDRINUSE`).

---

### Question 6: Ports
- **Simple Answer**: A 16-bit numerical identifier (0 to 65,535) used to direct network traffic to a specific process on a host.
- **Technical Answer**: Ports enable transport-layer multiplexing. Ports 0–1023 are Well-Known (system/root), 1024–49151 are Registered, and 49152–65535 are Dynamic/Ephemeral. Both TCP and UDP headers allocate exactly 16 bits for source and destination port numbers.
- **Project Example**: Our receiver listens on default UDP port `9000`, while client senders bind to an ephemeral OS port (e.g. `54321`) to transmit datagrams.
- **Common Mistake**: Assuming a TCP port and UDP port with the same number conflict; TCP port 9000 and UDP port 9000 are distinct kernel endpoints and can be bound simultaneously.

---

### Question 7: Datagrams
- **Simple Answer**: A self-contained, independent network packet that contains enough routing information to reach its destination without relying on prior exchanges.
- **Technical Answer**: A datagram carries its own source and destination headers and preserves discrete message boundaries. Unlike stream protocols where multiple writes may be combined into a single read, one `sendto()` call on a datagram socket corresponds to exactly one `recvfrom()` call on the receiving socket.
- **Project Example**: Each file chunk (up to 1024 bytes) is packed into a standalone datagram with its own 22-byte header and CRC32 checksum.
- **Common Mistake**: Calling `recvfrom()` with a buffer smaller than the datagram payload, which on Windows results in `WSAEMSGSIZE` and truncates the packet.

---

### Question 8: Packet Structure & Binary Serialization
- **Simple Answer**: The fixed layout and binary encoding of fields in a network packet.
- **Technical Answer**: Network packet serialization formats data into contiguous bytes using big-endian (network byte order). Struct padding must be eliminated to ensure cross-platform compatibility across architectures (x86, ARM, RISC-V).
- **Project Example**: We use `struct.pack("!2sBBIIIHI", b"RD", 1, pkt_type, session_id, seq_num, ack_num, payload_len, checksum)` to build an exact 22-byte wire header.
- **Common Mistake**: Using platform-native byte ordering or variable-length text formats (like JSON) for low-level packet headers, which introduces endianness bugs and massive serialization overhead.

---

### Question 9: Sequence Numbers
- **Simple Answer**: An integer assigned to each packet that identifies its order in the transmission stream.
- **Technical Answer**: Sequence numbers allow receivers to detect lost packets, reconstruct original byte ordering, eliminate duplicate transmissions, and enforce flow control. In our protocol, sequence numbers are 0-indexed integer identifiers assigned to each discrete payload chunk.
- **Project Example**: Chunk 0 has `seq_num=0`, Chunk 1 has `seq_num=1`, up to `total_chunks - 1`.
- **Common Mistake**: Treating sequence numbers as byte offsets without accounting for integer overflow, or failing to pair sequence numbers with unique session IDs.

---

### Question 10: Acknowledgments (ACK)
- **Simple Answer**: A return message sent by the receiver confirming that a specific packet arrived successfully.
- **Technical Answer**: ACKs can be cumulative (acknowledging all bytes/packets up to $N$) or selective (acknowledging only packet $N$). In our Selective Repeat implementation, ACKs carry the exact `ack_num` of the chunk received, enabling the sender to retire individual in-flight timers.
- **Project Example**: Upon receiving `DATA #5` with valid CRC32, the receiver immediately replies with `ACK #5` back to the sender's source address.
- **Common Mistake**: Assuming ACKs never get lost; if an ACK is dropped in transit, the sender will time out and retransmit even though the receiver already stored the chunk.

---

### Question 11: Timeout & RTO (Retransmission Timeout)
- **Simple Answer**: A timer that triggers a retransmission if an acknowledgment is not received within a specified duration.
- **Technical Answer**: Retransmission Timeout (RTO) must exceed the Round-Trip Time (RTT) plus safety variance: $\text{RTO} > \text{RTT} + 4 \times \text{RTTVAR}$. Setting RTO too low causes spurious retransmissions; setting it too high causes idle pipeline stalling.
- **Project Example**: Our sender tracks per-packet timestamps with high-resolution `time.monotonic()`. If `now - packet.send_time >= config.timeout` (default 1.0s, configurable down to 0.1s for tests), timeout triggers.
- **Common Mistake**: Using wall-clock time (`time.time()`), which can jump backwards during NTP synchronization, corrupting timeout intervals.

---

### Question 12: Retransmission
- **Simple Answer**: Resending a copy of a packet when the original packet or its ACK was lost or corrupted in transit.
- **Technical Answer**: When a packet's ACK does not arrive before the RTO expires, the sender enters retransmission. It increments `retry_count` and resends the cached binary packet. If `retry_count >= max_retries`, the connection terminates with `RetransmissionLimitExceeded`.
- **Project Example**: If `DATA #3` times out, the sender selectively re-emits `DATA #3` without retransmitting already-acknowledged packets `#1`, `#2`, or `#4`.
- **Common Mistake**: Modifying the sequence number or payload of a retransmitted packet, which breaks receiver duplicate detection.

---

### Question 13: Duplicate Handling
- **Simple Answer**: Detecting when the same packet arrives more than once and ignoring it so data is not duplicated on disk.
- **Technical Answer**: Duplicates occur when a data packet is delayed and retransmitted, or when an ACK is lost. The receiver tracks received sequence numbers in a set or bitmap. When a duplicate `seq_num` arrives, the receiver re-sends the matching ACK (to clear the sender's state) but does NOT write the payload to disk again.
- **Project Example**: `StopAndWaitReceiver` checks `if seq_num in self.received_chunks: self._send_ack(seq_num); return`.
- **Common Mistake**: Dropping duplicate packets silently without re-sending the ACK, which traps the sender in an endless retransmission loop until timeout exhaustion.

---

### Question 14: Out-of-Order Packets
- **Simple Answer**: Packets that arrive at the receiver in a different order than the sender transmitted them due to network path routing differences.
- **Technical Answer**: In IP networks, routing changes or multipath forwarding can cause packet #7 to arrive before packet #6. The receiver must maintain a temporary buffer to hold future packets until missing gaps arrive, after which the buffered chunks are written to storage in order.
- **Project Example**: If receiver expects `#0` but receives `#1` and `#2`, it stores `#1` and `#2` in `out_of_order_buffer = {}`. When `#0` finally arrives, it writes `#0`, `#1`, and `#2` contiguously.
- **Common Mistake**: Discarding out-of-order packets immediately, which severely degrades throughput by forcing redundant retransmissions of packets that already arrived safely.

---

### Question 15: Sliding Window Protocol (Go-Back-N)
- **Simple Answer**: A technique allowing multiple packets to be in flight simultaneously without waiting for an individual ACK after each one.
- **Technical Answer**: The sender maintains a window of size $W$ defined by $[base, base + W - 1]$. It sends packets up to $base + W - 1$. Under standard Go-Back-N, if packet $base$ is lost, all packets from $base$ onward must be retransmitted, even if the receiver received them.
- **Project Example**: `SlidingWindowSender` pipelines up to 8 packets simultaneously, tracking `base_seq` and advancing whenever `base_seq` is acknowledged.
- **Common Mistake**: Expanding window size without bounding it, which leads to buffer overflows on the receiver and drops inside network routers.

---

### Question 16: Selective Repeat ARQ
- **Simple Answer**: An advanced reliability protocol where the receiver buffers out-of-order packets and the sender only retransmits the specific packets that were lost.
- **Technical Answer**: Both sender and receiver maintain active windows of size $W$. The sender tracks individual state for every packet in the window (`IN_FLIGHT`, `ACKED`, `TIMED_OUT`). The receiver accepts any packet within its receive window $[rcv\_base, rcv\_base + W - 1]$, buffers it, and ACKs it individually. Only timed-out packets are re-sent.
- **Project Example**: `SelectiveRepeatSender` maintains `window_packets: dict[int, SelectiveRepeatPacket]`. When packet #2 is lost but #0, #1, #3 arrive, only packet #2 is re-sent.
- **Common Mistake**: Allowing the window size $W$ to exceed half the sequence number space ($W > 2^{N-1}$), which causes ambiguity between new packets and delayed duplicates under wrapping sequence numbers.

---

### Question 17: Per-Packet Checksum (CRC32)
- **Simple Answer**: A 32-bit mathematical check value included in every packet header to detect data corruption during transit.
- **Technical Answer**: Cyclic Redundancy Check (CRC32, IEEE 802.3) treats binary data as a polynomial and divides it by a generator polynomial (`0xEDB88320`), storing the 32-bit remainder. When received, the calculation is repeated; if the checksums differ, corruption occurred and the packet is discarded.
- **Project Example**: In `app/checksum.py`, `calculate_crc32()` computes the checksum over the 22-byte header (with checksum zeroed) concatenated with the payload.
- **Common Mistake**: Calculating the checksum over a header that already contains the checksum, creating a chicken-and-egg validation mismatch.

---

### Question 18: File Integrity Verification (SHA-256)
- **Simple Answer**: A cryptographic hash function that produces a unique 256-bit fingerprint of the entire file to verify byte-for-byte correctness after reassembly.
- **Technical Answer**: While CRC32 detects single-burst bit flips per packet, SHA-256 provides collision-resistant cryptographic integrity across the entire concatenated file. The receiver independently computes the hash of the assembled file and verifies it against the hash sent in the handshake.
- **Project Example**: In `app/checksum.py`, `calculate_file_sha256()` streams 64 KB blocks into `hashlib.sha256()` so multi-gigabyte files can be hashed in constant memory.
- **Common Mistake**: Confusing hashing with encryption; SHA-256 provides integrity verification (tamper evidence), not confidentiality (privacy).

---

### Question 19: In-Process Network Simulation
- **Simple Answer**: Software logic inside the application that artificially drops, delays, or corrupts packets to test reliability without needing physical network hardware.
- **Technical Answer**: Using `SimulatedSocket` wrapper over `socket.socket`, outgoing and incoming datagrams are intercepted. The simulator evaluates random probabilities: `random.random() < loss_rate` drops the packet; `random.random() < corruption_rate` flips bits in the payload; and `time.sleep(latency)` injects RTT delay.
- **Project Example**: In `app/simulator.py`, `SimulatedSocket` tracks telemetry counters (`packets_dropped`, `packets_corrupted`, `packets_delayed`) and returns them in `SimulationStats`.
- **Common Mistake**: Modifying OS firewall rules (like `iptables` or Windows Firewall) for unit testing, which requires admin privileges and interferes with system-wide networking.

---

### Question 20: Wireshark & Packet Inspection
- **Simple Answer**: An open-source network protocol analyzer used to capture, inspect, and dissect network traffic at the packet level.
- **Technical Answer**: Wireshark decodes packet capture files (`.pcap`, `.pcapng`) using protocol dissectors. By writing a custom Lua dissector, engineers can register custom ports (e.g. UDP port 9000) and parse proprietary binary headers into interactive trees in the Wireshark GUI.
- **Project Example**: We developed `docs/reliable_udp.lua` and `generate_pcap.py` to inspect our custom 22-byte headers and analyze retransmission sequences under `udp.port == 9000`.
- **Common Mistake**: Filtering by IP address only, which captures background DNS and OS broadcast noise; combining `udp.port == 9000` isolates protocol traffic cleanly.

---

### Question 21: Troubleshooting Network Protocols
- **Simple Answer**: A methodical process of identifying whether connection failures stem from firewalls, binding errors, timeouts, or data corruption.
- **Technical Answer**: Troubleshooting begins at Layer 1/2 (interface connectivity), Layer 3 (IP reachability via ICMP/ping), Layer 4 (UDP port bind errors, `WSAECONNRESET` on Windows, firewall blocking), and Layer 7 (protocol handshake failure, CRC mismatch, sequence stalls).
- **Project Example**: Our `docs/troubleshooting.md` outlines diagnosis steps for unreachable receivers, missing ACKs, firewall packet drops, and infinite retry loops.
- **Common Mistake**: Assuming that a socket timeout always means network packet loss; an overloaded receiver process or blocked disk write will also fail to return ACKs in time.

---

### Question 22: API & Architecture Design
- **Simple Answer**: Structuring software into clean, decoupled modules with clear interfaces so that components can be tested and swapped independently.
- **Technical Answer**: Following the Single Responsibility Principle and Layered Architecture, transport mechanics (socket I/O, packet serialization) are decoupled from transfer management (file reading, stats reporting) and reliability logic (ARQ state machines).
- **Project Example**: `FileSender` delegates chunk transmission to any class implementing the ARQ interface (`StopAndWaitSender`, `SlidingWindowSender`, `SelectiveRepeatSender`) via dependency injection.
- **Common Mistake**: Hardcoding socket calls directly into file I/O loops, which makes mocking, network simulation, and unit testing nearly impossible.

---

### Question 23: Memory Management & Streaming
- **Simple Answer**: Handling file data in small, fixed-size chunks so that transferring huge files doesn't exhaust system RAM.
- **Technical Answer**: Reading a 10 GB file into memory with `f.read()` causes immediate memory exhaustion (OOM). By leveraging Python generator functions (`yield chunk`), memory consumption remains bounded at $O(\text{chunk\_size})$ regardless of total file size.
- **Project Example**: `read_file_chunks()` streams binary chunks of default size 1024 bytes directly to the sender pipeline, keeping resident memory usage under 25 MB throughout transfers.
- **Common Mistake**: Using `f.readlines()` or accumulating all chunks into a list before transmission, which defeats chunk streaming.

---

### Question 24: Defensive Security & Sandboxing
- **Simple Answer**: Validating all incoming data from the network to protect the host against crashes, unauthorized file overwrites, and directory traversal attacks.
- **Technical Answer**: Network inputs must be treated as untrusted. Attackers can embed `../../` in filenames or send corrupted lengths. Defensive measures include enforcing maximum payload bounds, verifying magic bytes, neutralizing Windows reserved device names, and asserting that resolved output paths remain strictly inside an authorized base directory.
- **Project Example**: `safe_join_path()` resolves incoming filenames against the destination directory and raises `PathTraversalError` if `target.relative_to(base)` fails.
- **Common Mistake**: Relying solely on `os.path.basename(filename)`, which fails to neutralize Windows alternate data streams (e.g. `file.txt:evil.exe`) or reserved device names (`CON`, `PRN`, `NUL`).

---

### Question 25: Performance Optimization & Bottlenecks
- **Simple Answer**: Identifying and eliminating factors that slow down data transfer, such as lock contention, socket buffer underflow, and blocking I/O.
- **Technical Answer**: Throughput is bounded by the Bandwidth-Delay Product ($\text{BDP} = \text{Bandwidth} \times \text{RTT}$). If the window size $W \times \text{MSS} < \text{BDP}$, the pipeline underflows. Additionally, context switching and syscall overhead can be minimized by greedily draining socket queues using non-blocking I/O.
- **Project Example**: Replacing blocking `TIME_WAIT` delays on post-FIN socket cleanup with non-blocking socket drains dropped test suite execution time from 9.2s down to 4.3s.
- **Common Mistake**: Adding arbitrary `time.sleep()` statements to "fix" race conditions instead of using deterministic synchronization primitives like `threading.Event`.
