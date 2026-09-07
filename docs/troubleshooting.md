# Reliable UDP Transfer Protocol — Troubleshooting & Diagnostic Guide

This guide provides exhaustive troubleshooting procedures, common root causes, observable symptoms, and remediation workflows for transport issues encountered when transferring files over our custom Reliable UDP protocol.

---

## Quick Diagnostic Checklist

| Symptom | Probable Root Cause | Primary Remedy |
| :--- | :--- | :--- |
| `Handshake failed: Target did not reply` | Receiver not running, wrong IP/port, or firewall block | Verify receiver is listening on `0.0.0.0` or target IP, check port number, disable local firewall rule |
| `ConnectionResetError` (WSAECONNRESET 10054) | Receiver closed port or host returned ICMP Port Unreachable | Start the receiver before launching the sender |
| Rapid `[TIMEOUT]` warnings on every chunk | Configured timeout is lower than link Round-Trip Time (RTT) | Increase `--timeout` (e.g. `--timeout 1.5`) to exceed network RTT |
| `Checksum mismatch` / `[CORRUPT]` logs | In-flight physical bit flips, NIC corruption, or simulator rate | Verify checksum integrity; ARQ will automatically retransmit corrupted chunks |
| `SHA-256 mismatch` during teardown | Disk I/O corruption, memory race condition, or truncated writes | Re-run transfer; check receiver storage health |
| `Path traversal detected` in receiver logs | Remote peer sent relative `..` path or absolute system path | Malicious or buggy client; `safe_join_path` safely sandboxes files to destination dir |
| `[BUFFER-OVERFLOW]` warnings | Out-of-order packet flood exceeded memory limits ($16\text{ MB}$) | Receiver dropped unbuffered chunks; sender selective repeat will retransmit |

---

## 1. Wrong IP Address

### Symptoms
- Sender repeatedly logs:
  ```text
  [HANDSHAKE] START timed out after 1.0s. Retrying... [Attempt 1/5]
  [HANDSHAKE] START timed out after 1.0s. Retrying... [Attempt 2/5]
  HandshakeError: Handshake failed: Target ('192.168.1.50', 9000) did not reply after 5 attempts.
  ```
- No packets appear in the receiver terminal or Wireshark capture on the destination machine.

### Root Cause
- The sender was targeted at an incorrect IP, an unassigned DHCP lease, or an interface not routed to the receiver.
- The receiver bound strictly to `127.0.0.1` (loopback), but the sender is attempting to connect over LAN (`192.168.x.x`).

### Remediation
1. **Find Receiver IP**:
   - Windows: `ipconfig` (look for IPv4 Address on active Ethernet or Wi-Fi adapter).
   - Linux/macOS: `ip addr show` or `ifconfig`.
2. **Bind Receiver to All Interfaces**:
   - Ensure the receiver is started with `--host 0.0.0.0` so it accepts packets on both loopback and LAN interfaces:
     ```bash
     python -m app.receiver --host 0.0.0.0 --port 9000
     ```
3. **Verify Routing**:
   - Ping the receiver IP: `ping <receiver-ip>`. If ping fails, check that both machines are on the same subnet.

---

## 2. Wrong Port

### Symptoms
- On Windows: Sender immediately receives:
  ```text
  ConnectionResetError: [WinError 10054] An existing connection was forcibly closed by the remote host
  ```
- On Linux: Sender logs timeouts or ICMP "Port Unreachable" in Wireshark (`Type 3, Code 3`).
- Receiver console reports `Address already in use` upon startup:
  ```text
  OSError: [Errno 10048] Only one usage of each socket address is normally permitted
  ```

### Root Cause
- The sender specified `--port 9001` while the receiver is listening on `--port 9000`.
- Another process is already holding a lock on the requested UDP port.

### Remediation
1. **Check Listening UDP Ports**:
   - Windows:
     ```powershell
     Get-NetUDPEndpoint -LocalPort 9000
     ```
   - Linux:
     ```bash
     ss -ulnp | grep 9000
     ```
2. **Align Sender & Receiver Ports**:
   ```bash
   # Terminal 1 (Receiver)
   python -m app.receiver --port 9000
   
   # Terminal 2 (Sender)
   python -m app.sender sample_files/test.txt --port 9000
   ```

---

## 3. Receiver Not Running

### Symptoms
- Sender fails after exhausting retries:
  ```text
  [HANDSHAKE] START timed out after 1.0s. Retrying...
  HandshakeError: Target receiver at 127.0.0.1:9000 did not reply after 5 attempts. Receiver is likely offline or firewalled.
  ```
- Immediate `ConnectionResetError` if OS sends back ICMP port unreachable.

### Remediation
1. Always start the receiver process **first** before initiating `app.sender`.
2. Keep the receiver running in `--listen` mode to accept multiple sequential transfer sessions.

---

## 4. Firewall & OS Restrictions

### Symptoms
- Packets can be seen leaving the sender in Wireshark, but never appear in Wireshark on the receiver machine.
- Local loopback works (`127.0.0.1`), but cross-machine LAN transfers fail on handshake.

### Root Cause
- Windows Defender Firewall, macOS Application Firewall, or Linux `iptables`/`ufw` silently drops unsolicited incoming UDP datagrams on non-standard ports.

### Remediation
1. **Windows Firewall Rule**:
   Allow inbound UDP on port 9000:
   ```powershell
   New-NetFirewallRule -DisplayName "Reliable UDP Transfer" -Direction Inbound -LocalPort 9000 -Protocol UDP -Action Allow
   ```
2. **Linux ufw**:
   ```bash
   sudo ufw allow 9000/udp
   ```
3. **Public Network Profile**:
   Ensure Windows Network Profile is set to **Private** instead of **Public**, as Public profile blocks unsolicited inbound UDP.

---

## 5. Packet Loss & Network Impairments

### Symptoms
- Sender logs occasional retransmissions:
  ```text
  [SR-TIMEOUT] DATA #42 timed out after 0.25s. SELECTIVELY retransmitting #42 only [Attempt 1/5]
  [DRAIN] Committed buffered DATA #42 (1024 B) to file. Buffer remaining: 3 (3072 B)
  ```
- Receiver logs `[BUFFERED]` out-of-order packets.
- Transfer duration increases proportionally to packet loss rate.

### Root Cause
- Congested Wi-Fi links, buffer overflow at intermediate routers, or artificial simulation flags (`--loss-rate 0.10`).

### Remediation
- **Protocol Resiliency**: Selective Repeat ARQ will automatically detect missing sequence numbers and retransmit only the lost datagrams without restarting the window.
- **Tuning Parameters**:
  - For lossy links ($> 5\%$ loss), increase `--max-retries` from `5` to `10`:
    ```bash
    python -m app.sender large_file.bin --max-retries 10 --timeout 1.0
    ```

---

## 6. Repeated Timeouts & Jitter

### Symptoms
- Sender continually logs:
  ```text
  [TIMEOUT] DATA #12 timed out after 0.25s.
  [RETRANSMIT] DATA #12 (1024 B) [Attempt 2/5]
  ```
- Receiver logs:
  ```text
  [DUPLICATE] DATA #12 already processed (expected #13). Re-sending ACK #12 to unblock sender without writing to disk.
  ```

### Root Cause
- **Premature Timeout**: Link RTT is higher than the sender's configured timeout (e.g. RTT is 350ms on a satellite or cross-continental link, but `--timeout` is set to `0.25s`). The sender retransmits before the original ACK has time to return, causing spurious retransmissions.

### Remediation
- Set timeout to at least $2 \times \text{RTT}$:
  ```bash
  # Check ping RTT
  ping <target-host>
  
  # If average ping is 150ms, set timeout to >= 0.5s
  python -m app.sender file.bin --timeout 0.50
  ```

---

## 7. Checksum Failures & Packet Corruption

### Symptoms
- Receiver logs:
  ```text
  [CORRUPT] Discarded corrupted datagram: Checksum mismatch for packet type DATA (seq=15, ack=0): expected 0x8a92f01c, received 0x1234abcd.
  ```
- Sender detects missing ACK and retransmits the corrupted packet.

### Root Cause
- Physical cable noise, memory bit rot, malfunctioning router hardware, or simulated corruption (`--corruption-rate 0.05`).

### Remediation
- The receiver's CRC32 validation rejects the corrupted packet before it can be written to disk. The sender's ARQ layer automatically retransmits the chunk.
- If checksum failures occur continually on physical networks, inspect Ethernet cabling and network card hardware.
