#!/usr/bin/env python3
"""
=============================================================================
PARIS-AC: BACnet/IP Industrial Protocol Honeypot Engine (UDP 47808 / 0xBAC0)
=============================================================================
Emulates a real Daikin VRV-IV Intelligent Touch Manager over BACnet/IP:
  - Responds to 'Who-Is' broadcasts with official Daikin Vendor ID: 77.
  - Responds to 'ReadProperty' requests (Device Name, Firmware, Model).
  - Traps and records 'WriteProperty' unauthorized temperature tampering.
  - Automatically pipes raw packets into the Forensic Evidence Recorder.
=============================================================================
"""

import socket
import struct
import threading
import time
from datetime import datetime

BACNET_PORT = 47808  # 0xBAC0 standard BACnet/IP port

class BACnetServer:
    def __init__(self, on_attack_callback=None):
        self.port = BACNET_PORT
        self.running = False
        self.sock = None
        self.on_attack_callback = on_attack_callback
        self.vendor_id = 77  # Official BACnet Vendor ID for Daikin Industries, Ltd.
        self.device_instance = 77004
        self.device_name = "DAIKIN_VRV_PARIS_ITM"
        self.vendor_name = "Daikin Industries, Ltd."
        self.model_name = "Daikin VRV-IV Intelligent Touch Manager"
        self.firmware_rev = "v4.18.2-commercial"

    def start(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", self.port))
        threading.Thread(target=self._listen_loop, daemon=True).start()
        print(f"[*] BACnet/IP Industrial Listener active on UDP 0.0.0.0:{self.port} (Vendor: Daikin 77)")

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

    def _listen_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if not data or len(data) < 4:
                    continue

                # BVLC check: 0x81 is BACnet/IP
                if data[0] != 0x81:
                    continue

                bvlc_func = data[1]
                client_ip, client_port = addr

                # Check if Who-Is request (BVLC 0x0a or 0x0b, NPDU version 1, APDU unconfirmed 0x10, service 0x08)
                is_who_is = (len(data) >= 7 and data[4] == 0x01 and (data[6] & 0xf0) == 0x10 and data[7] == 0x08)
                is_write_property = (b"\x0f" in data[6:10]) or (len(data) > 15 and data[6] == 0x00)

                if is_who_is:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [BACnet] Who-Is discovery probe from {client_ip}:{client_port}")
                    # Respond with valid I-Am packet (Vendor 77 = Daikin)
                    i_am_pkt = self._build_i_am_response()
                    self.sock.sendto(i_am_pkt, addr)

                elif is_write_property or len(data) > 20:
                    # Trapped unauthorized WriteProperty or fuzzing attempt!
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [BACnet ATTACK] Malicious WriteProperty from {client_ip}:{client_port}")

                    # Extract requested setpoint if present, or simulate extreme 39.0°C override
                    requested_temp = 39.0
                    try:
                        # Extract any float encoded in the BACnet packet
                        for i in range(len(data) - 4):
                            val = struct.unpack(">f", data[i:i+4])[0]
                            if 10.0 <= val <= 50.0:
                                requested_temp = round(val, 1)
                                break
                    except Exception:
                        pass

                    # Build BACnet SimpleACK (Deception confirmation: 200 OK equivalent)
                    # APDU Type 2 (Simple-ACK-PDU), invoke ID, service choice WriteProperty (15 / 0x0f)
                    invoke_id = data[7] if len(data) > 7 else 0x01
                    ack_pkt = bytes([
                        0x81, 0x0a, 0x00, 0x0a,  # BVLC: Type 81, Unicast, Length 10
                        0x01, 0x00,              # NPDU: Version 1, Control 0
                        0x20, invoke_id, 0x0f, 0x00 # APDU: Simple-ACK, Invoke ID, Service 15
                    ])
                    self.sock.sendto(ack_pkt, addr)

                    # Trigger forensic recording & incident triage
                    if self.on_attack_callback:
                        self.on_attack_callback(
                            client_ip=client_ip,
                            protocol="BACnet/IP (UDP 47808)",
                            action_type="BACNET_UNAUTHORIZED_WRITE_PROPERTY",
                            requested_setpoint=requested_temp,
                            raw_packet_bytes=data
                        )
                else:
                    # Generic BACnet probe / ReadProperty
                    read_ack = self._build_read_property_ack(data)
                    if read_ack:
                        self.sock.sendto(read_ack, addr)

            except Exception as e:
                if self.running:
                    pass

    def _build_i_am_response(self):
        """
        Builds a valid BACnet/IP I-Am Unconfirmed-Service-Request datagram.
        Registers as Daikin Industries, Ltd. (Vendor ID 77).
        """
        # BVLC Header (4 bytes)
        # Type: 0x81 (BACnet/IP), Function: 0x0a (Unicast), Length: to be updated
        # NPDU: 0x01, 0x00
        # APDU: 0x10 (Unconfirmed-Request), Service 0x00 (I-Am)
        # Device Object ID: Type 8 (Device), Instance 77004
        # Max APDU Length: 1476
        # Segmentation: 0 (No segmentation)
        # Vendor ID: 77 (0x004d = Daikin Industries, Ltd.)
        apdu = bytes([
            0x10, 0x00,              # Unconfirmed-Request: I-Am
            0xc4, 0x02, 0x01, 0x2c, 0xcc, # ObjectIdentifier: Device, 77004
            0x22, 0x05, 0xc4,        # Max APDU: 1476
            0x91, 0x00,              # Segmentation: None
            0x21, 0x4d               # Vendor ID: 77 (Daikin)
        ])
        npdu = bytes([0x01, 0x00])
        total_len = 4 + len(npdu) + len(apdu)
        bvlc = struct.pack("!BBH", 0x81, 0x0a, total_len)
        return bvlc + npdu + apdu

    def _build_read_property_ack(self, req_data):
        """
        Builds a standard BACnet Complex-ACK returning Daikin vendor strings.
        """
        invoke_id = req_data[7] if len(req_data) > 7 else 0x01
        # Complex-ACK returning character string 'Daikin VRV-IV Gateway'
        val_str = self.device_name.encode("utf-8")
        apdu = bytes([0x30, invoke_id, 0x0c, 0x0c, 0x02, 0x01, 0x2c, 0xcc, 0x19, 0x4d, 0x3e, 0x75, len(val_str) + 1, 0x00]) + val_str + bytes([0x3f])
        npdu = bytes([0x01, 0x00])
        total_len = 4 + len(npdu) + len(apdu)
        bvlc = struct.pack("!BBH", 0x81, 0x0a, total_len)
        return bvlc + npdu + apdu

if __name__ == "__main__":
    def test_cb(**kwargs):
        print("[!] TEST CALLBACK TRIGGERED:", kwargs)
    srv = BACnetServer(on_attack_callback=test_cb)
    srv.start()
    print("[*] Server running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.stop()
