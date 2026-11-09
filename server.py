#!/usr/bin/env python3
"""
=============================================================================
PARIS-AC (Cyber-Physical Smart-HVAC Canary & Active Deception Engine v2.0)
=============================================================================
Dual Protocol Deception Engine:
  1. Industrial BACnet/IP (UDP 47808): Responds as Daikin Industries, Ltd. (Vendor 77)
  2. IoT REST API (TCP 8080): Emulated Daikin Intelligent Touch Manager
  3. Digital Forensics Recorder: Automated Libpcap (.pcap) capture & SHA-256 Chain of Custody
  4. Real-time SOC Dashboard with live telemetry graph & one-click remediation.
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

from forensics import generate_forensic_report, FORENSICS_DIR
from bacnet_engine import BACnetServer

PORT = 8080

# ---------------------------------------------------------------------------
# Thermodynamic Simulation State (Daikin Commercial VRV - Paris Flagship)
# ---------------------------------------------------------------------------
class HVACPhysicsModel:
    def __init__(self):
        self.lock = threading.Lock()
        self.unit_id = "DAIKIN-VRV-PARIS-04"
        self.location = "Paris Flagship Store - Zone 1 (Retail Floor)"
        self.baseline_temp = 21.5       # °C (normal cooling setpoint)
        self.current_temp = 21.5        # °C (actual room temp)
        self.target_setpoint = 21.5     # °C
        self.ambient_outdoor_temp = 31.0 # °C (Summer heatwave in Paris)
        self.compressor_load_pct = 42.0 # % (baseline load)
        self.fan_speed_rpm = 850        # RPM
        self.power_draw_kw = 4.8        # kW
        self.alarm_active = False
        self.mode = "AUTO_COOL"
        self.last_update = time.time()
        self.history = []  # Time-series telemetry for graphs

    def update_physics(self):
        with self.lock:
            now = time.time()
            dt = min(now - self.last_update, 2.0)
            self.last_update = now

            diff = self.target_setpoint - self.current_temp
            ramp_speed = 0.40  # °C per tick
            if abs(diff) > 0.05:
                self.current_temp += math.copysign(min(abs(diff), ramp_speed * dt), diff)

            noise = (random.random() - 0.5) * 0.08
            self.current_temp = round(self.current_temp + noise, 2)

            if self.target_setpoint > 26.0:
                self.mode = "HEAT_OVERRIDE"
                self.compressor_load_pct = min(98.5, self.compressor_load_pct + (18.0 * dt))
                self.fan_speed_rpm = min(1450, self.fan_speed_rpm + int(140 * dt))
                self.power_draw_kw = round(self.compressor_load_pct * 0.18, 2)
                self.alarm_active = True
            else:
                self.mode = "AUTO_COOL"
                self.compressor_load_pct = max(38.0, self.compressor_load_pct - (10.0 * dt))
                self.fan_speed_rpm = max(800, self.fan_speed_rpm - int(80 * dt))
                self.power_draw_kw = round(self.compressor_load_pct * 0.11, 2)
                if self.current_temp < 23.0:
                    self.alarm_active = False

            # Keep 30 data points for live graphs
            self.history.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "temp": round(self.current_temp, 1),
                "power": round(self.power_draw_kw, 2),
                "load": round(self.compressor_load_pct, 1)
            })
            if len(self.history) > 30:
                self.history.pop(0)

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
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "history": list(self.history)
            }

hvac_model = HVACPhysicsModel()

# ---------------------------------------------------------------------------
# Security Event Queue & Incident Response Recorder
# ---------------------------------------------------------------------------
security_incidents = []
incident_lock = threading.Lock()

def record_incident(client_ip, protocol, action_type, requested_setpoint, raw_packet_bytes=None, payload=None):
    """
    Central Incident Processor: updates physics, triggers forensics recording,
    and publishes alerts to the SOC feed.
    """
    # 1. Update physics
    hvac_model.set_target(requested_setpoint)

    case_id = f"CASE-PARIS-{int(time.time()*1000) % 100000}"
    timestamp = datetime.now().strftime("%H:%M:%S")

    # 2. Build Incident Data
    incident = {
        "id": case_id,
        "timestamp": timestamp,
        "client_ip": client_ip,
        "protocol": protocol,
        "action_type": action_type,
        "requested_setpoint": requested_setpoint,
        "payload": payload or {"raw_bytes": len(raw_packet_bytes) if raw_packet_bytes else 0},
        "status": "CAPTURED_AND_DECEIVED"
    }

    # 3. AI Triage & MITRE Attribution
    severity = 9.8 if requested_setpoint >= 35.0 else 8.2
    mitre_ids = [
        "T0836: Modify Parameter",
        "T0855: Unauthorized Command Message",
        "T0887: Wireless/Network Sniffing"
    ]

    summary = (
        f"Critical Cyber-Physical Temperature Tampering detected over {protocol} from {client_ip}. "
        f"Attacker attempted to force HVAC Zone setpoint to {requested_setpoint}°C (Baseline: 21.5°C). "
        f"Target: Daikin VRV-IV Chiller Loop. Forensic packet capture sealed with SHA-256 chain-of-custody."
    )

    remediation = (
        f"# Incident Response Isolation Commands:\n"
        f"netsh advfirewall firewall add rule name=\"BLOCK_DAIKIN_{client_ip}\" dir=in action=block remoteip={client_ip}\n"
        f"iptables -A INPUT -s {client_ip} -j DROP"
    )

    incident["ai_analysis"] = {
        "severity_score": severity,
        "mitre_attack": mitre_ids,
        "summary": summary,
        "remediation_cmd": remediation,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # 4. Generate Formal Forensic Artifacts (PCAP + HTML Dossier)
    packets_to_save = [raw_packet_bytes] if raw_packet_bytes else None
    forensic_res = generate_forensic_report(incident, raw_packets=packets_to_save)
    incident["forensics"] = forensic_res

    with incident_lock:
        security_incidents.append(incident)

    print(f"\n[!] ALERT: Security Incident Recorded: {case_id}")
    print(f"[!] Protocol: {protocol} | Attacker: {client_ip} | Target: {requested_setpoint}°C")
    print(f"[!] Evidence PCAP: {forensic_res['pcap_basename']} (SHA256: {forensic_res['sha256'][:16]}...)")

# ---------------------------------------------------------------------------
# HTTP Server (REST Canary, SOC Dashboard, and Evidence Download)
# ---------------------------------------------------------------------------
class CanaryRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Clean logging
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

        # 2. SOC Telemetry Feed
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

        # 3. Download / View Forensic Dossier HTML
        if url.path == "/api/forensics/dossier":
            params = parse_qs(url.query)
            case_id = params.get("case_id", [""])[0]
            html_file = os.path.join(FORENSICS_DIR, f"{case_id}_DOSSIER.html")
            if os.path.exists(html_file):
                with open(html_file, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            self._send_json(404, {"error": "Dossier not found"})
            return

        # 4. Download Raw Evidence PCAP
        if url.path == "/api/forensics/pcap":
            params = parse_qs(url.query)
            case_id = params.get("case_id", [""])[0]
            pcap_file = os.path.join(FORENSICS_DIR, f"{case_id}.pcap")
            if os.path.exists(pcap_file):
                with open(pcap_file, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
                self.send_header("Content-Disposition", f"attachment; filename=\"{case_id}_EVIDENCE.pcap\"")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            self._send_json(404, {"error": "PCAP not found"})
            return

        # 5. REST Canary Bait Endpoint
        if url.path in ["/api/v1/hvac/status", "/api/v1/system/status"]:
            self._send_json(200, {
                "vendor": "Daikin Applied Europe",
                "model": "VRV IV-S Intelligent Gateway",
                "firmware_version": "v4.18.2-commercial",
                "bacnet_vendor_id": 77,
                "protocol": "BACnet/IP over UDP (47808) + REST API (8080)",
                "telemetry": hvac_model.get_snapshot()
            })
            return

        # 6. Reset Demo State
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

        # One-Click Remediation Execution
        if url.path == "/api/soc/remediate":
            with hvac_model.lock:
                hvac_model.target_setpoint = 21.5
                hvac_model.mode = "AUTO_COOL"
            self._send_json(200, {
                "status": "REMEDIATION_APPLIED",
                "message": "Fail-safe cooling engaged (21.5°C). Attacker traffic dropped."
            })
            return

        # REST Canary Trap: Temperature Override
        if url.path in ["/api/v1/hvac/setpoint", "/api/v1/zones/override"]:
            new_temp = float(body.get("setpoint_temp", body.get("temp", 0)))
            is_malicious = (new_temp >= 26.0 or new_temp <= 16.0 or "override" in str(body).lower())

            if is_malicious:
                record_incident(
                    client_ip=client_ip,
                    protocol="HTTP/REST (Port 8080)",
                    action_type="REST_UNAUTHORIZED_SETPOINT_OVERRIDE",
                    requested_setpoint=new_temp,
                    raw_packet_bytes=raw_body.encode(),
                    payload=body
                )

                # Return realistic deceptive success response
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
# Built-in High-Tech SOC Dashboard Frontend (with Chart.js & Forensics)
# ---------------------------------------------------------------------------
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PARIS-AC v2.0 | Daikin OT Canary & Digital Forensics</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
  .badge.protocol {
    background: rgba(16, 185, 129, 0.15);
    color: var(--accent-green);
    border-color: rgba(16, 185, 129, 0.3);
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
  }
  .stat-val {
    font-size: 32px;
    font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
    margin-top: 8px;
  }
  .stat-sub { font-size: 12px; color: var(--text-muted); margin-top: 4px; }
  .chart-container {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 24px;
    height: 220px;
  }
  .main-layout {
    display: grid;
    grid-template-columns: 1.3fr 1fr;
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
  .incident-summary { font-size: 13px; line-height: 1.5; color: #e5e7eb; margin: 8px 0; }
  .evidence-bar {
    display: flex;
    gap: 10px;
    margin-top: 12px;
    align-items: center;
    flex-wrap: wrap;
  }
  .btn-dossier {
    background: #0284c7;
    color: white;
    text-decoration: none;
    font-size: 12px;
    font-weight: bold;
    padding: 6px 12px;
    border-radius: 4px;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .btn-dossier:hover { background: #0369a1; }
  .btn-pcap {
    background: #059669;
    color: white;
    text-decoration: none;
    font-size: 12px;
    font-weight: bold;
    padding: 6px 12px;
    border-radius: 4px;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .btn-pcap:hover { background: #047857; }
  .btn-remediate {
    background: #dc2626;
    color: white;
    border: none;
    font-size: 12px;
    font-weight: bold;
    padding: 6px 12px;
    border-radius: 4px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .btn-remediate:hover { background: #b91c1c; }
  .sha-pill {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    color: #94a3b8;
    background: #0b111e;
    padding: 4px 8px;
    border-radius: 4px;
    border: 1px solid #1f293d;
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
</style>
</head>
<body>

<div class="header">
  <div class="title-group">
    <h1>PARIS-AC <span style="font-size: 14px; font-weight: normal; color: var(--text-muted);">v2.0</span></h1>
    <span class="badge" id="systemStatus">HONEYPOT ACTIVE</span>
    <span class="badge protocol">BACnet/IP (Port 47808)</span>
    <span class="badge">DAIKIN VENDOR ID: 77</span>
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
    <div class="stat-label">Forensic Cases Sealed</div>
    <div class="stat-val" id="valIncidents" style="color: var(--accent-blue)">0</div>
    <div class="stat-sub">SHA-256 PCAP Artifacts</div>
  </div>
</div>

<!-- Telemetry Chart -->
<div class="chart-container">
  <canvas id="telemetryChart"></canvas>
</div>

<div class="main-layout">
  <!-- Left Panel: Live Incidents & Evidence Dossiers -->
  <div class="panel">
    <div class="panel-title">
      <span>Digital Forensics & Incident Response (DFIR) Evidence</span>
      <span style="font-size: 11px; color: var(--text-muted);">Chain of Custody Enabled</span>
    </div>

    <div id="incidentsContainer">
      <div style="text-align: center; color: var(--text-muted); padding: 40px 0; font-size: 13px;">
        No active attacks detected.<br>
        Run <code>python bacnet_attacker.py</code> to launch the industrial BACnet attack.
      </div>
    </div>
  </div>

  <!-- Right Panel: Physical Unit & Deception Status -->
  <div class="panel">
    <div class="panel-title">
      <span>Decoy OT Infrastructure</span>
      <span class="badge">Paris Châtelet</span>
    </div>

    <div style="background: rgba(14, 165, 233, 0.08); border: 1px dashed rgba(14, 165, 233, 0.3); padding: 12px; border-radius: 8px; font-size: 12px; color: #93c5fd; margin-bottom: 16px;">
      <strong>OT Deception Layer:</strong> Listens on raw BACnet/IP (UDP 47808). Emulates Daikin Industries, Ltd. (Vendor ID 77). Traps Who-Is and WriteProperty requests, records Libpcap byte streams, and calculates SHA-256 evidence integrity.
    </div>

    <div style="font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #9ca3af; line-height: 1.8;">
      <div><strong>Controller:</strong> Daikin Intelligent Touch Manager (iTM)</div>
      <div><strong>BACnet Vendor ID:</strong> 77 (Daikin Industries, Ltd.)</div>
      <div><strong>Device Instance:</strong> 77004</div>
      <div><strong>Firmware:</strong> v4.18.2-commercial</div>
      <div><strong>Active Ports:</strong> UDP 47808 (BACnet), TCP 8080 (REST)</div>
      <div><strong>Facility:</strong> Paris Flagship Store - Retail Zone 1</div>
    </div>
  </div>
</div>

<script>
let chartInstance = null;

function initChart() {
  const ctx = document.getElementById('telemetryChart').getContext('2d');
  chartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Indoor Temp (°C)',
          data: [],
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          yAxisID: 'yTemp',
          tension: 0.3,
          borderWidth: 2,
          pointRadius: 2
        },
        {
          label: 'Power Draw (kW)',
          data: [],
          borderColor: '#0ea5e9',
          backgroundColor: 'rgba(14, 165, 233, 0.1)',
          yAxisID: 'yPower',
          tension: 0.3,
          borderWidth: 2,
          pointRadius: 2
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { grid: { color: '#1f293d' }, ticks: { color: '#9ca3af', font: { family: 'JetBrains Mono' } } },
        yTemp: {
          type: 'linear',
          position: 'left',
          min: 18,
          max: 42,
          grid: { color: '#1f293d' },
          ticks: { color: '#ef4444', callback: v => v + '°C' }
        },
        yPower: {
          type: 'linear',
          position: 'right',
          min: 0,
          max: 20,
          grid: { drawOnChartArea: false },
          ticks: { color: '#0ea5e9', callback: v => v + ' kW' }
        }
      },
      plugins: {
        legend: { labels: { color: '#f3f4f6', font: { family: 'JetBrains Mono' } } }
      }
    }
  });
}

async function updateFeed() {
  try {
    const res = await fetch('/api/soc/feed');
    const data = await res.json();
    const t = data.telemetry;

    document.getElementById('valTemp').innerText = t.current_temp + '°C';
    document.getElementById('valSetpoint').innerText = 'Target: ' + t.target_setpoint + '°C';
    document.getElementById('valLoad').innerText = t.compressor_load_pct + '%';
    document.getElementById('valPower').innerText = 'Power: ' + t.power_draw_kw + ' kW';
    document.getElementById('valRpm').innerHTML = t.fan_speed_rpm + ' <span style="font-size: 16px;">RPM</span>';
    document.getElementById('valIncidents').innerText = data.incident_count;

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

    // Update Chart
    if (chartInstance && t.history) {
      chartInstance.data.labels = t.history.map(h => h.time);
      chartInstance.data.datasets[0].data = t.history.map(h => h.temp);
      chartInstance.data.datasets[1].data = t.history.map(h => h.power);
      chartInstance.update('none');
    }

    // Render Incidents
    const container = document.getElementById('incidentsContainer');
    if (data.incidents && data.incidents.length > 0) {
      container.innerHTML = data.incidents.map(inc => `
        <div class="incident-card">
          <div class="incident-header">
            <span style="color: var(--accent-red); font-weight: 700;">${inc.id}</span>
            <span style="color: var(--accent-green); font-weight: 600;">${inc.protocol}</span>
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

          <div class="evidence-bar">
            ${inc.forensics ? `
              <a class="btn-dossier" href="/api/forensics/dossier?case_id=${inc.id}" target="_blank">
                📄 View Evidence Dossier
              </a>
              <a class="btn-pcap" href="/api/forensics/pcap?case_id=${inc.id}" download>
                📦 Download .PCAP
              </a>
              <span class="sha-pill" title="Evidence Integrity Hash">SHA256: ${inc.forensics.sha256.substring(0, 16)}...</span>
            ` : ''}
            <button class="btn-remediate" onclick="remediateThreat()">
              ⚡ Apply Auto-Remediation
            </button>
          </div>
        </div>
      `).join('');
    }
  } catch (err) {
    console.error('Feed error:', err);
  }
}

async function remediateThreat() {
  await fetch('/api/soc/remediate', { method: 'POST' });
  updateFeed();
}

async function resetDemo() {
  await fetch('/api/soc/reset');
  updateFeed();
}

window.onload = () => {
  initChart();
  setInterval(updateFeed, 1000);
  updateFeed();
};
</script>

</body>
</html>
"""

# ---------------------------------------------------------------------------
# Server Startup
# ---------------------------------------------------------------------------
def main():
    # 1. Thermodynamic simulation background thread
    sim_thread = threading.Thread(target=physics_loop, daemon=True)
    sim_thread.start()

    # 2. BACnet/IP Industrial Honeypot listener (UDP 47808)
    def on_bacnet_attack(client_ip, protocol, action_type, requested_setpoint, raw_packet_bytes):
        record_incident(
            client_ip=client_ip,
            protocol=protocol,
            action_type=action_type,
            requested_setpoint=requested_setpoint,
            raw_packet_bytes=raw_packet_bytes
        )

    bacnet_srv = BACnetServer(on_attack_callback=on_bacnet_attack)
    bacnet_srv.start()

    # 3. HTTP Server (REST Canary + Web SOC Dashboard)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), CanaryRequestHandler)
    print("=" * 70)
    print(f"[*] PARIS-AC v2.0 Smart-HVAC Canary & DFIR Evidence Engine ONLINE")
    print(f"[*] BACnet/IP Industrial Listener: UDP 0.0.0.0:47808 (Daikin Vendor 77)")
    print(f"[*] Web SOC Dashboard:             http://localhost:{PORT}")
    print(f"[*] Forensic Evidence Sealed at:   {FORENSICS_DIR}")
    print("=" * 70)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down PARIS-AC.")
        bacnet_srv.stop()
        server.shutdown()

if __name__ == "__main__":
    main()
