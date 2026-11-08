# PARIS-AC: Cyber-Physical Smart-HVAC Canary & Active Deception Engine

> **Project Code:** PARIS-AC  
> **Domain:** Cyber-Physical Systems (CPS) / Smart Building & HVAC Security / Active Deception  
> **Target Alignment:** Daikin Applied & Smart Connected HVAC Systems  

---

## 1. Executive Summary & Context

During recent cyberattacks targeting retail chains across Europe (including major stores in Paris), threat actors compromised Building Management Systems (BMS) and smart HVAC controllers. Instead of stealing data or encrypting hard drives, the attackers **artificially spiked indoor temperatures to 35°C–40°C** during business hours.

The consequences were direct and physical:
* **Perishable inventory spoilage** (refrigerated goods, produce, temperature-sensitive pharmaceuticals).
* **Forced evacuation** of retail stores and offices due to hazardous heat.
* **Severe electrical grid penalties** and equipment compressor damage from simultaneous peak power spikes.

**PARIS-AC** is a lightweight, active deception honeypot designed specifically for **Daikin VRV/BACnet intelligent controllers**. It mimics real-world HVAC equipment, traps attackers who attempt unauthorized temperature setpoint manipulation, deceives them into believing the attack succeeded with real-time thermodynamic simulation, and generates an automated AI incident triage report with one-click firewall remediation.

---

## 2. Architecture & Working Principles

```
   [ Attacker / Rogue Device ]
                │
                │ 1. Probe & Force 38.5°C Override
                ▼
  ┌──────────────────────────────────────────────────────────────┐
  │                   PARIS-AC CANARY ENGINE                    │
  │                                                              │
  │  ┌────────────────────────┐    ┌──────────────────────────┐  │
  │  │  Virtual Daikin Gateway│    │ Thermodynamic Simulator  │  │
  │  │  - BACnet/IP & REST    │◄───┤ - Compressor load curve  │  │
  │  │  - Emulated Firmware   │    │ - Temperature ramp rate  │  │
  │  └───────────┬────────────┘    └─────────────┬────────────┘  │
  │              │                               │               │
  │  2. Returns Deceptive Fake                   │ 3. Flags      │
  │     Confirmation ("Success")                 │    Anomaly    │
  │              ▼                               ▼               │
  │  ┌────────────────────────────────────────────────────────┐  │
  │  │           AI Threat Triage & Incident Engine           │  │
  │  │   - MITRE ATT&CK for ICS (T0836, T0855)                │  │
  │  │   - Automated Risk Calibration & Threat Narrative      │  │
  │  │   - Auto-Generated Firewall Isolation Rules (netsh)    │  │
  │  └───────────────────────────┬────────────────────────────┘  │
  └──────────────────────────────┼───────────────────────────────┘
                                 │
                                 ▼
                 ┌───────────────────────────────┐
                 │       Live SOC Dashboard      │
                 │     http://localhost:8080     │
                 └───────────────────────────────┘
```

---

## 3. How to Run the Live Demo (In 2 Minutes)

### Step 1: Start the PARIS-AC Canary Server
In your first terminal:
```bash
cd C:\Users\rajde\.gemini\antigravity\scratch\paris-ac
python server.py
```
* The server starts listening on port `8080`.
* Open your browser to **`http://localhost:8080`** to view the live Security Operations Center (SOC) dashboard.

### Step 2: Launch the Paris Store Exploit
In a second terminal window:
```bash
python attacker.py
```

### What You Will Observe:
1. **In the Attacker Terminal:** The exploit script receives a `200 OK` confirmation showing that the setpoint was adjusted to `38.5°C`. The attacker is convinced their attack went through.
2. **On the Web Dashboard:**
   * The status switches to flashing red: `ATTACK DETECTED`.
   * The indoor temperature and compressor strain dynamically spike according to the physics simulator.
   * An AI incident card appears instantly with:
     * **Incident ID & Client IP**
     * **MITRE ATT&CK for ICS mapping** (`T0836: Modify Parameter`, `T0855: Unauthorized Command`)
     * **Automated incident summary and immediate firewall block commands**.

---

## 4. Why This Project Matters to Daikin

1. **Focuses on Cyber-Physical Security:** Proves that you understand how cyber threats impact physical machines (thermodynamics, compressors, power draw), not just standard web apps.
2. **Active Deception Strategy:** Rather than simple passive logging, deception forces the attacker to waste time on a decoy while giving security teams early warning.
3. **Zero Heavy Dependencies:** Runs entirely on standard Python 3 with no bloated installations or external dependencies.

