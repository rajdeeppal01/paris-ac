#!/usr/bin/env python3
"""
=============================================================================
PARIS-AC (Cyber-Physical Smart-HVAC Canary & Active Deception Engine)
=============================================================================
Inspired by the real-world European retail HVAC cyberattacks where attackers
infiltrated building management systems (BMS) to artificially spike indoor
temperatures, causing food spoilage, customer evacuation, and energy waste.

Key Capabilities:
  1. Virtual Daikin VRV IoT Controller: Realistic BACnet/REST endpoints.
  2. Thermodynamic Physics Simulator: Accurately simulates compressor strain,
     airflow RPM, and thermal ramp when setpoints are altered.
  3. Active Deception Engine: Keeps the attacker engaged by sending believable
     telemetry confirmations while quietly triggering defense alarms.
  4. AI Threat Triager: Maps attack to MITRE ATT&CK for ICS (T0836, T0855),
     calculates risk score, and auto-generates one-click firewall rules.
  5. Live Security Dashboard: Interactive dark-mode SOC UI at http://localhost:8080
=============================================================================
"""

import sys
import os
import json
import time
import math
import random
import socket
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime

PORT = 8080

# ---------------------------------------------------------------------------
# Thermodynamic Simulation State (Daikin Commercial VRV - Paris Châtelet Store)
# ---------------------------------------------------------------------------
class HVACPhysicsModel:
    def __init__(self):
        self.lock = threading.Lock()
        self.unit_id = "DAIKIN-VRV-PARIS-04"
        self.location = "Paris Flagship Store - Zone 1 (Retail Floor)"
        self.baseline_temp = 21.5       # °C (normal cooling setpoint)
        self.current_temp = 21.6        # °C (actual room temp)
        self.target_setpoint = 21.5     # °C
        self.ambient_outdoor_temp = 31.0 # °C (Summer heatwave in Paris)
        self.compressor_load_pct = 42.0 # % (baseline load)
        self.fan_speed_rpm = 850        # RPM
        self.power_draw_kw = 4.8        # kW
        self.alarm_active = False
        self.mode = "AUTO_COOL"
        self.last_update = time.time()

    def update_physics(self):
        with self.lock:
            now = time.time()
            dt = min(now - self.last_update, 2.0)
            self.last_update = now

            # Room temp slowly drifts towards target setpoint (or ambient if pushed hard)
            diff = self.target_setpoint - self.current_temp
            ramp_speed = 0.35  # °C per tick towards target
            if abs(diff) > 0.05:
                self.current_temp += math.copysign(min(abs(diff), ramp_speed * dt), diff)

            # Add subtle natural sensor noise
            noise = (random.random() - 0.5) * 0.08
            self.current_temp = round(self.current_temp + noise, 2)

            # Compressor and power adjust dynamically based on strain
            if self.target_setpoint > 26.0:  # Malicious heating / shutdown
                self.mode = "HEAT_OVERRIDE"
                self.compressor_load_pct = min(98.5, self.compressor_load_pct + (15.0 * dt))
                self.fan_speed_rpm = min(1450, self.fan_speed_rpm + int(120 * dt))
                self.power_draw_kw = round(self.compressor_load_pct * 0.18, 2)
            else:
                self.mode = "AUTO_COOL"
                self.compressor_load_pct = max(38.0, self.compressor_load_pct - (5.0 * dt))
                self.fan_speed_rpm = max(800, self.fan_speed_rpm - int(40 * dt))
                self.power_draw_kw = round(self.compressor_load_pct * 0.11, 2)

    def set_target(self, new_setpoint):
        with self.lock:
            self.target_setpoint = float(new_setpoint)
            if self.target_setpoint > 26.0:
                self.alarm_active = True

    def get_snapshot(self):
        with self.lock:
            return {
                "unit_id": self.unit_id,
                "location": self.location,
                "current_temp": round(self.current_temp, 1),
                "target_setpoint": round(self.target_setpoint, 1),
                "ambient_outdoor_temp": self.ambient_outdoor_temp,
                "compressor_load_pct": round(self.compressor_load_pct, 1),
                "fan_speed_rpm": self.fan_speed_rpm,
                "power_draw_kw": round(self.power_draw_kw, 2),
                "mode": self.mode,
                "alarm_active": self.alarm_active,
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }

hvac_model = HVACPhysicsModel()

# ---------------------------------------------------------------------------
# Security Event Queue & AI Triage Engine
# ---------------------------------------------------------------------------
security_incidents = []
incident_lock = threading.Lock()

def analyze_threat_with_ai(incident):
    """
    AI Triage Engine: Evaluates the attack vector, calculates severity,
    maps to MITRE ATT&CK for Industrial Control Systems (ICS),
    and generates instant defensive firewall commands.
    """
    setpoint = incident.get("requested_setpoint", 0)
    client_ip = incident.get("client_ip", "unknown")
    path = incident.get("path", "")
    payload = incident.get("payload", {})

    severity = 9.4 if setpoint >= 32.0 else 7.8
    mitre_ids = ["T0836: Modify Parameter", "T0855: Unauthorized Command Message", "T0887: Wireless/Network Sniffing"]

    summary = (
        f"Critical Cyber-Physical Temperature Tampering detected from IP {client_ip}. "
        f"Attacker attempted to force HVAC Zone setpoint to {setpoint}°C (Baseline: 21.5°C). "
        f"Signature matches the 'Paris Retail AC Overheating Campaign' designed to force physical store evacuations "
        f"and spoil temperature-sensitive inventory by overriding BMS safety thresholds."
    )

    remediation = (
        f"# Instant Remediation Commands:\n"
        f"netsh advfirewall firewall add rule name=\"BLOCK_PARIS_AC_ATTACKER_{client_ip}\" dir=in action=block remoteip={client_ip}\n"
        f"iptables -A INPUT -s {client_ip} -j DROP\n"
        f"# BMS Security Action: Revoke API Token session, revert VRV setpoint to fail-safe 21.5°C."
    )

    incident["ai_analysis"] = {
        "severity_score": severity,
        "mitre_attack": mitre_ids,
        "summary": summary,
        "remediation_cmd": remediation,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

# ---------------------------------------------------------------------------
# HTTP Server (Canary Endpoints + SOC Dashboard)
# ---------------------------------------------------------------------------
class CanaryRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Clean terminal logging
        sys.stderr.write(f"[{datetime.now().strftime('%H:%M:%S')}] {self.address_string()} - {format % args}\n")

    def _send_json(self, status_code, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        url = urlparse(self.path)

        # 1. SOC Dashboard Web UI
        if url.path == "/" or url.path == "/dashboard":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode("utf-8"))
            return

        # 2. SOC Telemetry Feed (Polling for Dashboard)
        if url.path == "/api/soc/feed":
            telemetry = hvac_model.get_snapshot()
            with incident_lock:
                incidents_copy = list(reversed(security_incidents[-10:]))
            self._send_json(200, {
                "telemetry": telemetry,
                "incidents": incidents_copy,
                "incident_count": len(security_incidents)
            })
            return

        # 3. Canary Bait Endpoint: Daikin Controller Info
        if url.path in ["/api/v1/hvac/status", "/api/v1/system/status", "/bacnet/device-info"]:
            self._send_json(200, {
                "vendor": "Daikin Applied Europe",
                "model": "VRV IV-S Intelligent Gateway",
                "firmware_version": "v4.18.2-commercial",
                "protocol": "BACnet/IP over REST",
                "telemetry": hvac_model.get_snapshot()
            })
            return

        # 4. Reset Demo State
        if url.path == "/api/soc/reset":
            with hvac_model.lock:
                hvac_model.current_temp = 21.5
                hvac_model.target_setpoint = 21.5
                hvac_model.alarm_active = False
                hvac_model.compressor_load_pct = 42.0
            with incident_lock:
                security_incidents.clear()
            self._send_json(200, {"status": "RESET_SUCCESS"})
            return

        self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        url = urlparse(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else ""

        try:
            body = json.loads(raw_body) if raw_body else {}
        except Exception:
            body = {"raw": raw_body}

        client_ip = self.client_address[0]

        # CANARY TRAP: Temperature Setpoint Override Attempt
        if url.path in ["/api/v1/hvac/setpoint", "/api/v1/zones/override", "/api/v1/chiller/command"]:
            new_temp = float(body.get("setpoint_temp", body.get("temp", 0)))
            auth_token = self.headers.get("Authorization", "Bearer UNKNOWN_OR_EXPLOITED")

            # Check if this is an abnormal or malicious tamper (> 26°C or < 16°C)
            is_malicious = (new_temp >= 26.0 or new_temp <= 16.0 or "override" in str(body).lower())

            if is_malicious:
                # 1. Update physics model to begin thermal climb
                hvac_model.set_target(new_temp)

                # 2. Record security incident
                incident = {
                    "id": f"INC-PARIS-{int(time.time()*1000) % 100000}",
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "client_ip": client_ip,
                    "path": url.path,
                    "requested_setpoint": new_temp,
                    "payload": body,
                    "auth_header": auth_token,
                    "status": "CAPTURED_AND_DECEIVED"
                }

                # 3. AI Triage
                analyze_threat_with_ai(incident)

                with incident_lock:
                    security_incidents.append(incident)

                # 4. ACTIVE DECEPTION: Return realistic success response to the attacker
                # The attacker thinks they succeeded, keeping them trapped while security responds!
                self._send_json(200, {
                    "status": "COMMAND_ACCEPTED",
                    "unit": hvac_model.unit_id,
                    "action": "SETPOINT_ADJUST",
                    "new_setpoint": new_temp,
                    "estimated_time_to_reach_min": 14.5,
                    "message": "Actuator coil energized. Target setpoint acknowledged."
                })
                return

            else:
                # Normal benign temperature request
                hvac_model.set_target(new_temp)
                self._send_json(200, {"status": "SUCCESS", "current_setpoint": new_temp})
                return

        self._send_json(400, {"error": "Invalid command path"})

# ---------------------------------------------------------------------------
# Background Physics Thread
# ---------------------------------------------------------------------------
def physics_loop():
    while True:
        hvac_model.update_physics()
        time.sleep(0.5)

# ---------------------------------------------------------------------------
# Built-in SOC Dashboard Frontend (Modern, High-Tech, Cyber Dark-Mode)
# ---------------------------------------------------------------------------
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PARIS-AC | Cyber-Physical Smart-HVAC Canary</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg-dark: #090d16;
    --card-bg: #111827;
    --card-border: #1f293d;
    --accent-blue: #0ea5e9;
    --accent-red: #ef4444;
    --accent-green: #10b981;
    --accent-amber: #f59e0b;
    --text-primary: #f3f4f6;
    --text-muted: #9ca3af;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg-dark);
    color: var(--text-primary);
    font-family: 'Inter', sans-serif;
    padding: 24px;
    min-height: 100vh;
  }
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--card-border);
    padding-bottom: 20px;
    margin-bottom: 24px;
  }
  .title-group h1 {
    font-size: 24px;
    font-weight: 800;
    letter-spacing: -0.5px;
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .badge {
    font-size: 11px;
    font-family: 'JetBrains Mono', monospace;
    padding: 4px 10px;
    border-radius: 9999px;
    background: rgba(14, 165, 233, 0.15);
    color: var(--accent-blue);
    border: 1px solid rgba(14, 165, 233, 0.3);
  }
  .badge.alert {
    background: rgba(239, 68, 68, 0.2);
    color: var(--accent-red);
    border-color: var(--accent-red);
    animation: pulse 1.5s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.8; transform: scale(1.04); }
  }
  .grid-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }
  .stat-card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 20px;
    position: relative;
    overflow: hidden;
  }
  .stat-card.danger {
    border-color: rgba(239, 68, 68, 0.5);
    box-shadow: 0 0 20px rgba(239, 68, 68, 0.15);
  }
  .stat-label {
    font-size: 12px;
    color: var(--text-muted);
    text-transform: uppercase;
    font-weight: 600;
    letter-spacing: 0.5px;
  }
  .stat-val {
    font-size: 32px;
    font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
    margin-top: 8px;
  }
  .stat-sub {
    font-size: 12px;
    color: var(--text-muted);
    margin-top: 4px;
  }
  .main-layout {
    display: grid;
    grid-template-columns: 1.2fr 1fr;
    gap: 24px;
  }
  @media(max-width: 900px) { .main-layout { grid-template-columns: 1fr; } }
  .panel {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 20px;
  }
  .panel-title {
    font-size: 15px;
    font-weight: 700;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--card-border);
    padding-bottom: 12px;
    margin-bottom: 16px;
  }
  .incident-card {
    background: #182234;
    border-left: 4px solid var(--accent-red);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 16px;
    animation: fadeIn 0.4s ease-out;
  }
  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-8px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .incident-header {
    display: flex;
    justify-content: space-between;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    margin-bottom: 8px;
  }
  .mitre-tags {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    margin: 8px 0;
  }
  .mitre-tag {
    font-size: 11px;
    font-family: 'JetBrains Mono', monospace;
    background: rgba(239, 68, 68, 0.15);
    color: #fca5a5;
    padding: 2px 8px;
    border-radius: 4px;
    border: 1px solid rgba(239, 68, 68, 0.3);
  }
  .incident-summary {
    font-size: 13px;
    line-height: 1.5;
    color: #e5e7eb;
    margin: 8px 0;
  }
  .code-block {
    background: #0b111e;
    border: 1px solid #1f293d;
    padding: 10px;
    border-radius: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: #38bdf8;
    overflow-x: auto;
    white-space: pre-wrap;
    margin-top: 10px;
  }
  .btn-reset {
    background: #1f2937;
    color: var(--text-primary);
    border: 1px solid var(--card-border);
    padding: 8px 16px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
  }
  .btn-reset:hover { background: #374151; }
  .deception-callout {
    background: rgba(14, 165, 233, 0.08);
    border: 1px dashed rgba(14, 165, 233, 0.3);
    padding: 12px;
    border-radius: 8px;
    font-size: 12px;
    color: #93c5fd;
    margin-bottom: 16px;
  }
</style>
</head>
<body>

<div class="header">
  <div class="title-group">
    <h1>PARIS-AC</h1>
    <span class="badge" id="systemStatus">HONEYPOT ACTIVE</span>
    <span class="badge">DAIKIN VRV-IV DECOY</span>
  </div>
  <div>
    <button class="btn-reset" onclick="resetDemo()">Reset State</button>
  </div>
</div>

<div class="grid-stats">
  <div class="stat-card" id="cardTemp">
    <div class="stat-label">Indoor Room Temp</div>
    <div class="stat-val" id="valTemp">21.5°C</div>
    <div class="stat-sub" id="valSetpoint">Setpoint: 21.5°C</div>
  </div>

  <div class="stat-card" id="cardCompressor">
    <div class="stat-label">Compressor Load</div>
    <div class="stat-val" id="valLoad">42%</div>
    <div class="stat-sub" id="valPower">Power: 4.8 kW</div>
  </div>

  <div class="stat-card">
    <div class="stat-label">Fan Speed</div>
    <div class="stat-val" id="valRpm">850 <span style="font-size: 16px;">RPM</span></div>
    <div class="stat-sub">Normal Air Circulation</div>
  </div>

  <div class="stat-card">
    <div class="stat-label">Threat Incidents</div>
    <div class="stat-val" id="valIncidents" style="color: var(--accent-blue)">0</div>
    <div class="stat-sub">Zero-Day / Tamper Traps</div>
  </div>
</div>

<div class="main-layout">
  <!-- Left Panel: Live Incidents & AI Triage -->
  <div class="panel">
    <div class="panel-title">
      <span>AI Cyber-Physical Incident Triage</span>
      <span style="font-size: 11px; color: var(--text-muted);" id="incidentTicker">Monitoring incoming traffic...</span>
    </div>

    <div id="incidentsContainer">
      <div style="text-align: center; color: var(--text-muted); padding: 40px 0; font-size: 13px;">
        No active attacks detected.<br>
        Run <code>python attacker.py</code> to simulate the Paris Store AC exploit.
      </div>
    </div>
  </div>

  <!-- Right Panel: Physical Unit & Deception Status -->
  <div class="panel">
    <div class="panel-title">
      <span>Decoy Unit Status</span>
      <span class="badge">Paris Châtelet</span>
    </div>

    <div class="deception-callout">
      <strong>Active Deception Layer:</strong> When attackers tamper with setpoints, the honeypot accepts the command and returns realistic simulated thermal telemetry. The attacker believes they have control while security isolates them.
    </div>

    <div style="font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #9ca3af; line-height: 1.8;">
      <div><strong>Unit Model:</strong> Daikin VRV IV-S Intelligent Gateway</div>
      <div><strong>Firmware:</strong> v4.18.2-commercial (Emulated)</div>
      <div><strong>Protocol:</strong> BACnet/IP (Port 47808) / REST API (:8080)</div>
      <div><strong>Location:</strong> Paris Flagship Store - Retail Zone 1</div>
      <div><strong>Outdoor Heatwave Temp:</strong> 31.0°C</div>
    </div>
  </div>
</div>

<script>
async function updateFeed() {
  try {
    const res = await fetch('/api/soc/feed');
    const data = await res.json();
    const t = data.telemetry;

    // Update Stats
    document.getElementById('valTemp').innerText = t.current_temp + '°C';
    document.getElementById('valSetpoint').innerText = 'Target: ' + t.target_setpoint + '°C';
    document.getElementById('valLoad').innerText = t.compressor_load_pct + '%';
    document.getElementById('valPower').innerText = 'Power: ' + t.power_draw_kw + ' kW';
    document.getElementById('valRpm').innerHTML = t.fan_speed_rpm + ' <span style="font-size: 16px;">RPM</span>';
    document.getElementById('valIncidents').innerText = data.incident_count;

    // Visual Alerts
    const cardTemp = document.getElementById('cardTemp');
    const cardLoad = document.getElementById('cardCompressor');
    const sysStatus = document.getElementById('systemStatus');

    if (t.alarm_active || t.current_temp > 26.0) {
      cardTemp.classList.add('danger');
      cardLoad.classList.add('danger');
      sysStatus.className = 'badge alert';
      sysStatus.innerText = 'ATTACK DETECTED';
    } else {
      cardTemp.classList.remove('danger');
      cardLoad.classList.remove('danger');
      sysStatus.className = 'badge';
      sysStatus.innerText = 'HONEYPOT ACTIVE';
    }

    // Render Incidents
    const container = document.getElementById('incidentsContainer');
    if (data.incidents && data.incidents.length > 0) {
      container.innerHTML = data.incidents.map(inc => `
        <div class="incident-card">
          <div class="incident-header">
            <span style="color: var(--accent-red); font-weight: 700;">${inc.id}</span>
            <span style="color: var(--text-muted);">${inc.timestamp}</span>
          </div>
          <div style="font-size: 13px; font-weight: 600; margin-bottom: 4px;">
            Target: Setpoint Override &rarr; <span style="color: var(--accent-red); font-weight: 800;">${inc.requested_setpoint}&deg;C</span>
            <span style="font-size: 11px; color: var(--text-muted); margin-left: 8px;">(Attacker IP: ${inc.client_ip})</span>
          </div>
          <div class="mitre-tags">
            ${inc.ai_analysis ? inc.ai_analysis.mitre_attack.map(m => `<span class="mitre-tag">${m}</span>`).join('') : ''}
          </div>
          <div class="incident-summary">
            ${inc.ai_analysis ? inc.ai_analysis.summary : 'Analyzing payload...'}
          </div>
          <div class="code-block">${inc.ai_analysis ? inc.ai_analysis.remediation_cmd : ''}</div>
        </div>
      `).join('');
    }
  } catch (err) {
    console.error('Feed error:', err);
  }
}

async function resetDemo() {
  await fetch('/api/soc/reset');
  updateFeed();
}

setInterval(updateFeed, 1000);
updateFeed();
</script>

</body>
</html>
"""

# ---------------------------------------------------------------------------
# Server Startup
# ---------------------------------------------------------------------------
def main():
    # Start thermodynamic background simulation
    sim_thread = threading.Thread(target=physics_loop, daemon=True)
    sim_thread.start()

    server = ThreadingHTTPServer(("0.0.0.0", PORT), CanaryRequestHandler)
    print("=" * 70)
    print(f"[*] PARIS-AC Smart-HVAC Canary & Active Deception Engine ONLINE")
    print(f"[*] Emulating Daikin VRV-IV Commercial Controller (Paris Retail)")
    print(f"[*] Web SOC Dashboard running at: http://localhost:{PORT}")
    print(f"[*] Honeypot REST endpoint:       http://localhost:{PORT}/api/v1/hvac/setpoint")
    print(f"[*] Press Ctrl+C to terminate.")
    print("=" * 70)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down PARIS-AC.")
        server.shutdown()

if __name__ == "__main__":
    main()

