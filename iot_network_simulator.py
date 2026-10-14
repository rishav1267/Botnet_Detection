"""
IoT Network Traffic Simulator & Device Management Module
Simulates authentic IoT network behaviors, botnet attack scenarios, and telemetry.
"""

import random
import time
from typing import Dict, Any, List


class IoTNetworkManager:
    """
    Manages IoT device inventories, live traffic flow generation,
    security alerts, and incident response state.
    """
    def __init__(self, coordinator):
        self.coordinator = coordinator
        self.devices = self._init_device_inventory()
        self.recent_flows = []
        self.alerts = self._init_seed_alerts()
        self.traffic_history = []
        self.max_flow_history = 100
        self.attack_mode = None  # None or specific scenario name
        self.monitoring_active = True
        self.packets_analyzed_total = 148293
        self.bytes_analyzed_total = 89421048

        # Transparent Risk Engine Configuration & Factor Weights
        self.risk_config = {
            "thresholds": {
                "normal_max": 29,
                "suspicious_max": 69,
                "high_risk_min": 70
            },
            "weights": {
                "packet_rate": 25,
                "abnormal_ports": 30,
                "malicious_ips": 35,
                "beaconing": 25,
                "protocol_violations": 20
            }
        }
        self.recalculate_all_risks()
        self._seed_initial_flows(25)

    def _init_device_inventory(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "DEV-101",
                "name": "Hikvision DS-2CD IP Camera",
                "ip": "192.168.1.101",
                "mac": "00:12:17:84:3B:11",
                "category": "Surveillance Camera",
                "firmware": "v5.5.82 build 180302",
                "vendor": "Hikvision Digital",
                "protocol": "RTSP / HTTP",
                "status": "High-Risk",
                "security_classification": "High-Risk",
                "risk_score": 94,
                "first_seen": "2026-10-09 14:20:10",
                "last_seen": "Just now",
                "last_activity": "Just now",
                "pps": 420.5,
                "packet_rate": 420.5,
                "bytes_transferred": "1.24 GB",
                "conn_freq": 24.2,
                "quarantined": False,
                "vulnerabilities": ["CVE-2021-36260 (Command Injection)", "Default Telnet Enabled"],
                "risk_factors": [
                    {"factor": "Port 23/2323 Outbound Scan", "weight": "+35", "detail": "Active dictionary sweep across LAN"},
                    {"factor": "Connection Burst Frequency", "weight": "+25", "detail": "24.2 conn/10s exceeds threshold"},
                    {"factor": "Volumetric PPS Anomaly", "weight": "+20", "detail": "420.5 pps exceeds benign camera baseline"},
                    {"factor": "Known CVE Vulnerability", "weight": "+14", "detail": "CVE-2021-36260 command injection exposure"}
                ],
                "recommended_action": "Isolate camera VLAN port, update firmware, and revoke root Telnet credentials.",
                "anomaly_score": 0.94
            },
            {
                "id": "DEV-102",
                "name": "Philips Hue Bridge v2",
                "ip": "192.168.1.102",
                "mac": "EC:B5:FA:21:49:8C",
                "category": "Smart Lighting Gateway",
                "firmware": "1948086000",
                "vendor": "Signify Netherlands",
                "protocol": "Zigbee / HTTP REST",
                "status": "Normal",
                "security_classification": "Normal",
                "risk_score": 4,
                "first_seen": "2026-10-08 09:15:00",
                "last_seen": "1s ago",
                "last_activity": "1s ago",
                "pps": 4.2,
                "packet_rate": 4.2,
                "bytes_transferred": "48.2 MB",
                "conn_freq": 1.2,
                "quarantined": False,
                "vulnerabilities": [],
                "risk_factors": [
                    {"factor": "Standard Local REST API", "weight": "0", "detail": "Traffic strictly conforms to LAN bridge profile"}
                ],
                "recommended_action": "Maintain routine baseline monitoring.",
                "anomaly_score": 0.04
            },
            {
                "id": "DEV-103",
                "name": "Ecobee Smart Thermostat Pro",
                "ip": "192.168.1.103",
                "mac": "44:61:32:8A:1E:50",
                "category": "HVAC / Environmental",
                "firmware": "4.7.43.186",
                "vendor": "Ecobee Inc.",
                "protocol": "MQTT / TLS",
                "status": "Normal",
                "security_classification": "Normal",
                "risk_score": 2,
                "first_seen": "2026-10-08 10:00:22",
                "last_seen": "2s ago",
                "last_activity": "2s ago",
                "pps": 2.1,
                "packet_rate": 2.1,
                "bytes_transferred": "18.5 MB",
                "conn_freq": 0.8,
                "quarantined": False,
                "vulnerabilities": [],
                "risk_factors": [
                    {"factor": "Encrypted MQTT Telemetry", "weight": "0", "detail": "Valid TLS 1.3 heartbeat to authorized cloud broker"}
                ],
                "recommended_action": "Maintain routine baseline monitoring.",
                "anomaly_score": 0.02
            },
            {
                "id": "DEV-104",
                "name": "TP-Link Kasa Smart Plug HS100",
                "ip": "192.168.1.104",
                "mac": "50:C7:BF:1D:90:3A",
                "category": "Smart Energy Relay",
                "firmware": "1.5.6 Build 191125",
                "vendor": "TP-Link Technologies",
                "protocol": "UDP / Proprietary JSON",
                "status": "Suspicious",
                "security_classification": "Suspicious",
                "risk_score": 58,
                "first_seen": "2026-10-09 18:40:00",
                "last_seen": "Just now",
                "last_activity": "Just now",
                "pps": 68.4,
                "packet_rate": 68.4,
                "bytes_transferred": "142.0 MB",
                "conn_freq": 9.4,
                "quarantined": False,
                "vulnerabilities": ["Weak XOR Token Encryption"],
                "risk_factors": [
                    {"factor": "Atypical UDP Port Queries", "weight": "+28", "detail": "Queried 14 unusual outbound UDP endpoints"},
                    {"factor": "Elevated Burst Frequency", "weight": "+18", "detail": "9.4 conn/10s exceeds normal energy meter rate"},
                    {"factor": "Cleartext XOR Protocol", "weight": "+12", "detail": "Susceptible to local relay spoofing"}
                ],
                "recommended_action": "Inspect destination IPs and verify if vendor cloud firmware check is scheduled.",
                "anomaly_score": 0.58
            },
            {
                "id": "DEV-105",
                "name": "Moxa NPort 5150 Industrial Gateway",
                "ip": "192.168.1.105",
                "mac": "00:90:E8:4A:BC:23",
                "category": "SCADA / Industrial Gateway",
                "firmware": "v3.12 Rev A",
                "vendor": "Moxa Inc.",
                "protocol": "Modbus TCP / Port 502",
                "status": "High-Risk",
                "security_classification": "High-Risk",
                "risk_score": 89,
                "first_seen": "2026-10-07 11:22:15",
                "last_seen": "Quarantined",
                "last_activity": "Quarantined",
                "pps": 0.0,
                "packet_rate": 0.0,
                "bytes_transferred": "890.1 MB",
                "conn_freq": 16.5,
                "quarantined": True,
                "vulnerabilities": ["CVE-2018-8838 (Buffer Overflow)", "Cleartext Modbus"],
                "risk_factors": [
                    {"factor": "C2 Heartbeat Beaconing", "weight": "+40", "detail": "Fixed 120s cadence with high entropy payload"},
                    {"factor": "Known Botnet IP Contact", "weight": "+30", "detail": "Communication with 45.142.213.9 (Gafgyt C2)"},
                    {"factor": "Industrial SCADA Target", "weight": "+19", "detail": "High-consequence critical asset exposure"}
                ],
                "recommended_action": "Maintain switch port quarantine. Perform memory dump and flash clean firmware.",
                "anomaly_score": 0.89
            },
            {
                "id": "DEV-106",
                "name": "B. Braun Infusomat Space Medical Pump",
                "ip": "192.168.1.106",
                "mac": "70:B3:D5:19:62:01",
                "category": "Critical Healthcare",
                "firmware": "v6.08 Build 4",
                "vendor": "B. Braun Melsungen",
                "protocol": "HL7 / TLS 1.3",
                "status": "Normal",
                "security_classification": "Normal",
                "risk_score": 1,
                "first_seen": "2026-10-06 07:10:00",
                "last_seen": "1s ago",
                "last_activity": "1s ago",
                "pps": 1.4,
                "packet_rate": 1.4,
                "bytes_transferred": "6.8 MB",
                "conn_freq": 0.4,
                "quarantined": False,
                "vulnerabilities": [],
                "risk_factors": [
                    {"factor": "Hospital Network Verified", "weight": "0", "detail": "Conforms strictly to HL7 clinical profile"}
                ],
                "recommended_action": "Protected medical device. Retain continuous strict micro-segmentation.",
                "anomaly_score": 0.01
            },
            {
                "id": "DEV-107",
                "name": "Dahua DHI-NVR Surveillance Hub",
                "ip": "192.168.1.107",
                "mac": "3C:EF:8C:72:14:59",
                "category": "DVR / Video Recorder",
                "firmware": "V4.001.0000000.3",
                "vendor": "Dahua Security",
                "protocol": "TCP / Telnet (Port 23)",
                "status": "High-Risk",
                "security_classification": "High-Risk",
                "risk_score": 98,
                "first_seen": "2026-10-09 20:15:30",
                "last_seen": "Just now",
                "last_activity": "Just now",
                "pps": 580.1,
                "packet_rate": 580.1,
                "bytes_transferred": "3.81 GB",
                "conn_freq": 48.0,
                "quarantined": False,
                "vulnerabilities": ["CVE-2021-33044 (Authentication Bypass)"],
                "risk_factors": [
                    {"factor": "Volumetric SYN Flood", "weight": "+45", "detail": "580 pps targeting WAN with SYN ratio 0.96"},
                    {"factor": "Severe Connection Rate", "weight": "+30", "detail": "48 conn/10s indicates automated DoS daemon"},
                    {"factor": "Known C2 Destination", "weight": "+23", "detail": "Exfiltrating telemetry to 185.193.64.12"}
                ],
                "recommended_action": "Immediate device quarantine recommended. Block outbound WAN routing.",
                "anomaly_score": 0.98
            },
            {
                "id": "DEV-108",
                "name": "August Smart Lock Pro 3rd Gen",
                "ip": "192.168.1.108",
                "mac": "D0:73:D5:81:4A:72",
                "category": "Physical Access Control",
                "firmware": "1.1.28-1.5.0",
                "vendor": "August Home Inc.",
                "protocol": "HTTPS / BLE Bridge",
                "status": "Normal",
                "security_classification": "Normal",
                "risk_score": 3,
                "first_seen": "2026-10-10 12:45:00",
                "last_seen": "4s ago",
                "last_activity": "4s ago",
                "pps": 0.8,
                "packet_rate": 0.8,
                "bytes_transferred": "3.2 MB",
                "conn_freq": 0.3,
                "quarantined": False,
                "vulnerabilities": [],
                "risk_factors": [
                    {"factor": "Encrypted Access Control", "weight": "0", "detail": "Standard TLS 1.3 heartbeat token verification"}
                ],
                "recommended_action": "Maintain routine baseline monitoring.",
                "anomaly_score": 0.03
            }
        ]

    def _init_seed_alerts(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "ALT-9042",
                "timestamp": "2026-10-12 10:14:20",
                "device_id": "DEV-107",
                "device_name": "Dahua DHI-NVR Surveillance Hub",
                "source_ip": "192.168.1.107",
                "flow_id": "FLW-94021",
                "severity": "Critical",
                "detection_source": "ML Classifier",
                "classification": "Denial of Service (DoS)",
                "title": "Volumetric SYN Flood Burst Identified",
                "reason": "Machine-learning random forest classifier detected 580.0 pps volumetric burst with 0.96 TCP SYN ratio targeting external cloud host.",
                "details": "High packet volume (580.0 pps) combined with 0.96 SYN ratio matched anomalous botnet flooding signature with 98.4% ML model confidence.",
                "traffic_indicators": {
                    "packet_rate": 580.0,
                    "byte_rate": 74240.0,
                    "dest_port": 80,
                    "dest_ip": "185.193.64.12",
                    "syn_ratio": 0.96,
                    "conn_freq": 34.0,
                    "payload_entropy": 3.90
                },
                "suggested_action": "Isolate device to quarantine VLAN immediately and inspect egress traffic.",
                "status": "New",
                "resolved": False,
                "mitre_technique": "T1499.004 Endpoint DoS: Direct Network Flood",
                "analyst_notes": [
                    {"author": "System AI Sensor", "timestamp": "2026-10-12 10:14:20", "note": "High-confidence ML prediction triggered automated critical escalation."}
                ],
                "action_taken": "Automated Alert Dispatched"
            },
            {
                "id": "ALT-9041",
                "timestamp": "2026-10-12 10:08:12",
                "device_id": "DEV-101",
                "device_name": "Hikvision DS-2CD IP Camera",
                "source_ip": "192.168.1.101",
                "flow_id": "FLW-94018",
                "severity": "Critical",
                "detection_source": "Rule-based Engine",
                "classification": "Credential Access / Scanning",
                "title": "Telnet Brute Force Credential Harvest",
                "reason": "Outbound scanning across 28 distinct LAN/WAN targets on port 23/2323. Connection rate 24.2 conn/10s.",
                "details": "Deterministic rule R01 hit: device initiating rapid credential spraying against external IoT endpoints.",
                "traffic_indicators": {
                    "packet_rate": 84.0,
                    "byte_rate": 10752.0,
                    "dest_port": 23,
                    "dest_ip": "194.26.29.11",
                    "syn_ratio": 0.52,
                    "conn_freq": 24.2,
                    "payload_entropy": 4.15
                },
                "suggested_action": "Revoke default Telnet credentials, block port 23 outbound, and quarantine asset.",
                "status": "In Progress",
                "resolved": False,
                "mitre_technique": "T1110.001 Password Guessing / Brute Force",
                "analyst_notes": [
                    {"author": "SecOps Analyst", "timestamp": "2026-10-12 10:10:02", "note": "Triage started. Device has open CVE-2021-36260 unpatched firmware."}
                ],
                "action_taken": "Traffic Rate Limited"
            },
            {
                "id": "ALT-9040",
                "timestamp": "2026-10-12 09:54:30",
                "device_id": "DEV-105",
                "device_name": "Moxa NPort 5150 Industrial Gateway",
                "source_ip": "192.168.1.105",
                "flow_id": "FLW-93980",
                "severity": "High",
                "detection_source": "Dual-Fused Heuristics",
                "classification": "Command and Control",
                "title": "Known Botnet C2 Beaconing Detected",
                "reason": "Regular interval heartbeat (periodicity 120s) with high entropy payload (7.74) to known Gafgyt/Bashlite C2 IP 45.142.213.9.",
                "details": "Fused correlation: Rule R04 matched encrypted heartbeat, and ML predicted High-Risk C2 beaconing (97.1%).",
                "traffic_indicators": {
                    "packet_rate": 32.0,
                    "byte_rate": 4096.0,
                    "dest_port": 6667,
                    "dest_ip": "45.142.213.9",
                    "syn_ratio": 0.15,
                    "conn_freq": 12.0,
                    "payload_entropy": 7.74
                },
                "suggested_action": "Sever active TCP socket, add 45.142.213.9 to edge firewall blocklist, and isolate gateway.",
                "status": "Acknowledged",
                "resolved": False,
                "mitre_technique": "T1071.001 Web Protocols: Command and Control",
                "analyst_notes": [
                    {"author": "IR Lead", "timestamp": "2026-10-12 09:56:15", "note": "Acknowledged incident. External IP confirmed on AbuseIPDB blocklist."}
                ],
                "action_taken": "Acknowledged by Incident Responder"
            },
            {
                "id": "ALT-9039",
                "timestamp": "2026-10-12 09:30:15",
                "device_id": "DEV-104",
                "device_name": "TP-Link Kasa Smart Plug HS100",
                "source_ip": "192.168.1.104",
                "flow_id": "FLW-93892",
                "severity": "High",
                "detection_source": "Rule-based Engine",
                "classification": "Reconnaissance / Discovery",
                "title": "Anomalous Port Sweep Reconnaissance",
                "reason": "Device queried 14 unusual outbound UDP ports within 60s sampling window.",
                "details": "Rule R05 triggered: Smart plug firmware attempting unauthorized horizontal subnet exploration.",
                "traffic_indicators": {
                    "packet_rate": 48.0,
                    "byte_rate": 6144.0,
                    "dest_port": 37215,
                    "dest_ip": "192.168.1.254",
                    "syn_ratio": 0.40,
                    "conn_freq": 14.0,
                    "payload_entropy": 5.80
                },
                "suggested_action": "Audit device DHCP leases and enforce strict MAC-to-IP binding.",
                "status": "Reopened",
                "resolved": False,
                "mitre_technique": "T1046 Network Service Scanning",
                "analyst_notes": [
                    {"author": "SecOps Senior", "timestamp": "2026-10-12 09:40:00", "note": "Previously closed as benign NTP drift, reopened after secondary sweep detected."}
                ],
                "action_taken": "Reopened for In-Depth Forensics"
            },
            {
                "id": "ALT-9038",
                "timestamp": "2026-10-12 09:12:00",
                "device_id": "DEV-102",
                "device_name": "Philips Hue Smart Bridge",
                "source_ip": "192.168.1.102",
                "flow_id": "FLW-93740",
                "severity": "Medium",
                "detection_source": "Rule-based Engine",
                "classification": "Reflection DoS",
                "title": "UDP Amplification / Blast Probe",
                "reason": "Elevated outbound UDP traffic (110.0 pps) targeting external DNS port 53 with large answer payloads.",
                "details": "Rule R03 hit: Non-standard query volume inconsistent with residential smart home hub profiles.",
                "traffic_indicators": {
                    "packet_rate": 110.0,
                    "byte_rate": 35200.0,
                    "dest_port": 53,
                    "dest_ip": "8.8.8.8",
                    "syn_ratio": 0.0,
                    "conn_freq": 9.5,
                    "payload_entropy": 4.60
                },
                "suggested_action": "Configure DNS forwarder rate limiting and filter reflection ports.",
                "status": "In Progress",
                "resolved": False,
                "mitre_technique": "T1498.002 Network DoS: Reflection Amplification",
                "analyst_notes": [
                    {"author": "Network Admin", "timestamp": "2026-10-12 09:20:10", "note": "Packet capture running on bridge uplink."}
                ],
                "action_taken": "Rate limiting applied at switch port"
            },
            {
                "id": "ALT-9037",
                "timestamp": "2026-10-12 08:55:10",
                "device_id": "DEV-106",
                "device_name": "B. Braun Infusomat Space Medical Pump",
                "source_ip": "192.168.1.106",
                "flow_id": "FLW-93510",
                "severity": "Low",
                "detection_source": "ML Classifier",
                "classification": "Protocol Anomaly",
                "title": "Minor Telemetry Timing Variance",
                "reason": "Supervised ML classifier flagged minor timing jitter outside clinical telemetry baseline (p_suspicious = 0.38).",
                "details": "Packet transmission intervals experienced 350ms delay jitter during scheduled medical bed relocation.",
                "traffic_indicators": {
                    "packet_rate": 8.0,
                    "byte_rate": 1024.0,
                    "dest_port": 8443,
                    "dest_ip": "10.0.10.50",
                    "syn_ratio": 0.05,
                    "conn_freq": 2.1,
                    "payload_entropy": 4.80
                },
                "suggested_action": "Verify Wi-Fi roaming transition across hospital access points.",
                "status": "New",
                "resolved": False,
                "mitre_technique": "T1071 Application Layer Protocol",
                "analyst_notes": [],
                "action_taken": "Logged for telemetry QA"
            },
            {
                "id": "ALT-9036",
                "timestamp": "2026-10-12 08:30:00",
                "device_id": "DEV-103",
                "device_name": "August Wi-Fi Smart Lock Gen 4",
                "source_ip": "192.168.1.103",
                "flow_id": "FLW-93300",
                "severity": "Informational",
                "detection_source": "Rule-based Engine",
                "classification": "System Health",
                "title": "Routine Firmware Baseline Integrity Check",
                "reason": "Cryptographic signature validation succeeded during scheduled 24h health polling.",
                "details": "SHA-256 binary hash verified against cloud vendor trusted release ledger.",
                "traffic_indicators": {
                    "packet_rate": 2.5,
                    "byte_rate": 320.0,
                    "dest_port": 443,
                    "dest_ip": "54.210.12.80",
                    "syn_ratio": 0.02,
                    "conn_freq": 1.0,
                    "payload_entropy": 3.80
                },
                "suggested_action": "No remediation required. Healthy baseline asset.",
                "status": "Resolved",
                "resolved": True,
                "mitre_technique": "N/A - Legitimate Routine Telemetry",
                "analyst_notes": [
                    {"author": "System Monitor", "timestamp": "2026-10-12 08:30:00", "note": "Integrity checksum verified."}
                ],
                "action_taken": "Automated Baseline Archived"
            },
            {
                "id": "ALT-9035",
                "timestamp": "2026-10-12 07:15:40",
                "device_id": "DEV-107",
                "device_name": "Dahua DHI-NVR Surveillance Hub",
                "source_ip": "192.168.1.107",
                "flow_id": "FLW-92890",
                "severity": "Critical",
                "detection_source": "Dual-Fused Heuristics",
                "classification": "Initial Access / Exploit",
                "title": "Torii Modular RAT Payload Stager Ingested",
                "reason": "Anomalous high payload entropy (7.88) combined with port 37215 UPnP exploit probe.",
                "details": "Dual engine matched binary packing shellcode (Rule R06 + ML High-Risk 99.1%).",
                "traffic_indicators": {
                    "packet_rate": 310.0,
                    "byte_rate": 45000.0,
                    "dest_port": 37215,
                    "dest_ip": "185.193.64.12",
                    "syn_ratio": 0.85,
                    "conn_freq": 28.0,
                    "payload_entropy": 7.88
                },
                "suggested_action": "Quarantine device, wipe flash storage, and flash authenticated vendor firmware.",
                "status": "Resolved",
                "resolved": True,
                "mitre_technique": "T1190 Exploit Public-Facing Application",
                "analyst_notes": [
                    {"author": "Incident Response", "timestamp": "2026-10-12 07:45:00", "note": "Asset isolated and re-flashed. Threat neutralised."}
                ],
                "action_taken": "Resolved by SecOps Analyst"
            }
        ]

    def _seed_initial_flows(self, count: int = 25):
        for _ in range(count):
            flow_raw = self.generate_synthetic_flow()
            analyzed = self.coordinator.analyze_flow(flow_raw)
            self.recent_flows.insert(0, analyzed)
        self.recent_flows = self.recent_flows[:self.max_flow_history]

    def calculate_device_risk(self, dev: Dict[str, Any]) -> Dict[str, Any]:
        """Transparent rule-based risk classification engine evaluating 5 factors"""
        weights = self.risk_config["weights"]
        thresholds = self.risk_config["thresholds"]

        score = 0
        factors = []

        # 1. High Packet Rate factor
        pps = dev.get("pps", 0.0)
        w_pps = weights.get("packet_rate", 25)
        if pps > 300:
            score += w_pps
            factors.append({
                "factor": "High packet rate",
                "weight": f"+{w_pps}",
                "detail": f"Volumetric burst: {pps:.1f} pps exceeds baseline threshold (>300 pps)"
            })
        elif pps > 50:
            contrib = int(w_pps * 0.6)
            score += contrib
            factors.append({
                "factor": "High packet rate",
                "weight": f"+{contrib}",
                "detail": f"Elevated throughput: {pps:.1f} pps exceeds baseline threshold (>50 pps)"
            })

        # 2. Abnormal Port Access factor
        w_ports = weights.get("abnormal_ports", 30)
        vulns = dev.get("vulnerabilities", [])
        proto = dev.get("protocol", "")
        if "Telnet" in proto or any("Telnet" in v for v in vulns) or dev["id"] in ["DEV-101", "DEV-107"]:
            score += w_ports
            factors.append({
                "factor": "Abnormal port access",
                "weight": f"+{w_ports}",
                "detail": "Exposed management port 23/2323 observed with external sweep attempts"
            })
        elif "Modbus" in proto or "502" in proto or dev["id"] == "DEV-105":
            contrib = int(w_ports * 0.7)
            score += contrib
            factors.append({
                "factor": "Abnormal port access",
                "weight": f"+{contrib}",
                "detail": "Industrial SCADA Modbus port 502 queried without authentication wrapper"
            })
        elif "UDP" in proto and dev["id"] == "DEV-104":
            contrib = int(w_ports * 0.5)
            score += contrib
            factors.append({
                "factor": "Abnormal port access",
                "weight": f"+{contrib}",
                "detail": "Atypical ephemeral UDP destination port queries detected"
            })

        # 3. Known Malicious IPs factor
        w_ips = weights.get("malicious_ips", 35)
        if dev["id"] in ["DEV-105", "DEV-107"]:
            score += w_ips
            factors.append({
                "factor": "Known malicious IPs",
                "weight": f"+{w_ips}",
                "detail": "Observed outbound communication with flagged C2 endpoint (Gafgyt/Mirai pool)"
            })

        # 4. Beaconing Patterns factor
        w_beacon = weights.get("beaconing", 25)
        conn_freq = dev.get("conn_freq", 0.0)
        if conn_freq > 20:
            score += w_beacon
            factors.append({
                "factor": "Beaconing patterns",
                "weight": f"+{w_beacon}",
                "detail": f"Aggressive burst connection frequency: {conn_freq:.1f} conn/10s"
            })
        elif conn_freq > 8:
            contrib = int(w_beacon * 0.6)
            score += contrib
            factors.append({
                "factor": "Beaconing patterns",
                "weight": f"+{contrib}",
                "detail": f"Periodic synchronization cadence: {conn_freq:.1f} conn/10s exceeds baseline"
            })

        # 5. Protocol Violations & CVEs factor
        w_violations = weights.get("protocol_violations", 20)
        if vulns:
            score += w_violations
            factors.append({
                "factor": "Protocol violations",
                "weight": f"+{w_violations}",
                "detail": f"Known CVE exploitation vector identified: {', '.join(vulns)}"
            })
        elif "XOR" in proto or dev["id"] == "DEV-104":
            contrib = int(w_violations * 0.5)
            score += contrib
            factors.append({
                "factor": "Protocol violations",
                "weight": f"+{contrib}",
                "detail": "Weak unauthenticated XOR cleartext token telemetry observed"
            })

        # Score clamping
        final_score = min(100, max(1, score))
        if not factors:
            factors.append({
                "factor": "Benign baseline telemetry",
                "weight": "0",
                "detail": "Network behavior adheres strictly to device certified functional profile"
            })

        # Classification based on thresholds
        if dev.get("quarantined", False):
            classification = "High-Risk"
        elif final_score >= thresholds["high_risk_min"]:
            classification = "High-Risk"
        elif final_score >= thresholds["normal_max"] + 1:
            classification = "Suspicious"
        else:
            classification = "Normal"

        dev["risk_score"] = final_score
        dev["security_classification"] = classification
        dev["status"] = classification
        dev["risk_factors"] = factors
        dev["anomaly_score"] = round(final_score / 100.0, 2)
        return dev

    def recalculate_all_risks(self) -> List[Dict[str, Any]]:
        """Recalculate risk scores and classifications for all inventory devices"""
        for dev in self.devices:
            self.calculate_device_risk(dev)
        return self.devices

    def ingest_external_flow(self, raw_flow: Dict[str, Any]) -> Dict[str, Any]:
        """External packet collector & ingestion interface for PCAP / NetFlow records"""
        flow_id = raw_flow.get("flow_id") or f"ING-{int(time.time()*1000)%10000000}"
        dev_id = raw_flow.get("device_id") or "DEV-INGEST"
        src_ip = raw_flow.get("source_ip") or "192.168.1.199"
        dev_name = raw_flow.get("device_name")
        if not dev_name:
            matched = next((d for d in self.devices if d["id"] == dev_id or d["ip"] == src_ip), None)
            dev_name = matched["name"] if matched else f"Collector Asset ({src_ip})"

        dest_ip = raw_flow.get("dest_ip", "185.193.64.12")
        dest_port = int(raw_flow.get("dest_port", 23))
        protocol = raw_flow.get("protocol", "TCP")
        pps = float(raw_flow.get("packet_rate", 340.0))
        bps = int(raw_flow.get("byte_rate", pps * 128))
        conn_freq = float(raw_flow.get("conn_freq", 22.0))
        syn_ratio = float(raw_flow.get("syn_ratio", 0.92 if protocol == "TCP" and dest_port in [23, 80] else 0.05))
        entropy = float(raw_flow.get("payload_entropy", 6.9))
        duration = float(raw_flow.get("flow_duration", 1.2))
        unique_ips = int(raw_flow.get("unique_dest_ips", 1))

        flow_obj = {
            "id": flow_id,
            "timestamp": time.strftime("%H:%M:%S"),
            "device_id": dev_id,
            "device_name": dev_name,
            "source_ip": src_ip,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "protocol": protocol,
            "packet_rate": pps,
            "byte_rate": bps,
            "conn_freq": conn_freq,
            "unique_dest_ips": unique_ips,
            "syn_ratio": syn_ratio,
            "payload_entropy": entropy,
            "flow_duration": duration,
            "is_external": not dest_ip.startswith("192.168."),
            "collector_source": raw_flow.get("collector_source", "NetFlow / IPFIX Packet Collector")
        }

        analyzed = self.coordinator.analyze_flow(flow_obj)

        # Update matched device risk state
        matched = next((d for d in self.devices if d["id"] == dev_id or d["ip"] == src_ip), None)
        if matched:
            matched["last_seen"] = "Just now"
            matched["last_activity"] = "Just now"
            matched["pps"] = pps
            matched["packet_rate"] = pps
            if analyzed["status"] in ("High-Risk", "Suspicious"):
                matched["risk_score"] = max(matched.get("risk_score", 0), 85 if analyzed["status"] == "High-Risk" else 50)
                matched["status"] = analyzed["status"]
                matched["security_classification"] = analyzed["status"]

        # Alert generation with deduplication
        if analyzed["status"] in ("High-Risk", "Suspicious"):
            top_rule = analyzed["rule_matches"][0] if len(analyzed["rule_matches"]) > 0 else None
            title = top_rule["name"] if top_rule else "Collector Anomaly Detected"
            existing_active = any(
                a["device_id"] == dev_id and a["title"] == title and not a.get("resolved", False)
                for a in self.alerts
            )
            if not existing_active:
                sev = "Critical" if analyzed["status"] == "High-Risk" else "Medium"
                new_alert = {
                    "id": f"ALT-{random.randint(9100, 9999)}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "device_id": dev_id,
                    "device_name": dev_name,
                    "source_ip": src_ip,
                    "flow_id": flow_id,
                    "severity": sev,
                    "detection_source": "Collector Ingestion Pipeline",
                    "classification": top_rule.get("category", "IoT Botnet Anomaly") if top_rule else "Collector Threat",
                    "title": title,
                    "reason": top_rule.get("reason", "Anomalous telemetry from network collector") if top_rule else "Traffic flow triggered threshold",
                    "details": f"Collector recorded {pps:.1f} pps on port {dest_port}.",
                    "traffic_indicators": {
                        "packet_rate": pps, "byte_rate": bps, "dest_port": dest_port, "dest_ip": dest_ip
                    },
                    "suggested_action": "Audit asset and isolate VLAN port.",
                    "status": "New",
                    "resolved": False,
                    "mitre_technique": "T1499 Denial of Service / T1046 Network Service Scanning",
                    "analyst_notes": [
                        {"author": "Auto Sentinel", "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "note": "Incident generated from collector ingestion."}
                    ],
                    "action_taken": "Automated Alert Dispatched"
                }
                self.alerts.insert(0, new_alert)
                analyzed["new_alert"] = new_alert

        self.recent_flows.insert(0, analyzed)
        if len(self.recent_flows) > self.max_flow_history:
            self.recent_flows.pop()

        self.packets_analyzed_total += int(pps * 1.5)
        self.bytes_analyzed_total += bps
        return analyzed

    def generate_synthetic_flow(self, forced_scenario: str = None) -> Dict[str, Any]:
        """Generate a realistic flow based on current device states or forced attack scenario"""
        scenario = forced_scenario or self.attack_mode
        active_devices = [d for d in self.devices if not d.get("quarantined", False)]
        if not active_devices:
            active_devices = self.devices

        # Route scenario to targeted device
        if scenario == "mirai_telnet":
            target_dev = next((d for d in active_devices if d["id"] == "DEV-101"), active_devices[0])
            chosen_device = target_dev
        elif scenario == "syn_flood":
            target_dev = next((d for d in active_devices if d["id"] == "DEV-107"), active_devices[0])
            chosen_device = target_dev
        elif scenario == "c2_beacon":
            target_dev = next((d for d in active_devices if d["id"] == "DEV-105"), active_devices[0])
            chosen_device = target_dev
        elif scenario == "udp_blast":
            target_dev = next((d for d in active_devices if d["id"] == "DEV-104"), active_devices[0])
            chosen_device = target_dev
        elif scenario == "reset":
            self.attack_mode = None
            chosen_device = random.choice(active_devices)
            scenario = None
        else:
            chosen_device = random.choice(active_devices)

        # Flow feature generation
        if scenario == "mirai_telnet" or (not scenario and chosen_device["status"] == "High-Risk" and chosen_device["id"] == "DEV-101"):
            pps = round(random.uniform(280, 580), 1)
            bps = int(pps * random.uniform(50, 180))
            conn_freq = round(random.uniform(18, 45), 1)
            dest_port = random.choice([23, 2323, 22])
            dest_ip = f"{random.randint(11, 210)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            protocol = "TCP"
            syn_ratio = round(random.uniform(0.65, 0.92), 2)
            unique_ips = random.randint(16, 45)
            entropy = round(random.uniform(6.2, 7.5), 2)
            duration = round(random.uniform(0.1, 0.8), 2)
            is_ext = True

        elif scenario == "syn_flood" or (not scenario and chosen_device["status"] == "High-Risk" and chosen_device["id"] == "DEV-107"):
            pps = round(random.uniform(450, 890), 1)
            bps = int(pps * random.uniform(40, 70))
            conn_freq = round(random.uniform(30, 80), 1)
            dest_port = random.choice([80, 443, 8080])
            dest_ip = "185.193.64.12"
            protocol = "TCP"
            syn_ratio = round(random.uniform(0.88, 0.99), 2)
            unique_ips = 1
            entropy = round(random.uniform(3.0, 4.5), 2)
            duration = round(random.uniform(0.01, 0.2), 2)
            is_ext = True

        elif scenario == "c2_beacon" or (not scenario and chosen_device["status"] == "High-Risk" and chosen_device["id"] == "DEV-105"):
            pps = round(random.uniform(12, 45), 1)
            bps = int(pps * random.uniform(300, 900))
            conn_freq = round(random.uniform(10, 22), 1)
            dest_port = random.choice([4444, 8888, 5555, 37215])
            dest_ip = "45.142.213.9"
            protocol = "TCP"
            syn_ratio = round(random.uniform(0.10, 0.25), 2)
            unique_ips = 1
            entropy = round(random.uniform(7.4, 7.95), 2)
            duration = round(random.uniform(1.2, 5.0), 2)
            is_ext = True

        elif scenario == "udp_blast":
            pps = round(random.uniform(320, 650), 1)
            bps = int(pps * random.uniform(512, 1400))
            conn_freq = round(random.uniform(25, 55), 1)
            dest_port = random.choice([53, 123, 1900])
            dest_ip = f"{random.randint(60, 190)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            protocol = "UDP"
            syn_ratio = 0.0
            unique_ips = random.randint(8, 25)
            entropy = round(random.uniform(4.0, 6.2), 2)
            duration = round(random.uniform(0.05, 0.5), 2)
            is_ext = True

        elif chosen_device["status"] == "Suspicious":
            pps = round(random.uniform(45, 110), 1)
            bps = int(pps * random.uniform(80, 240))
            conn_freq = round(random.uniform(7, 14), 1)
            dest_port = random.choice([8080, 8443, 53, 9999])
            dest_ip = f"192.168.1.{random.choice([1, 10, 20, 30])}"
            protocol = random.choice(["UDP", "TCP"])
            syn_ratio = round(random.uniform(0.25, 0.45), 2)
            unique_ips = random.randint(5, 14)
            entropy = round(random.uniform(5.8, 7.1), 2)
            duration = round(random.uniform(0.8, 3.5), 2)
            is_ext = random.random() > 0.4

        else:
            # Benign / Normal IoT telemetry
            pps = round(random.uniform(0.8, 12.5), 1)
            bps = int(pps * random.uniform(120, 480))
            conn_freq = round(random.uniform(0.3, 2.5), 1)
            if "Camera" in chosen_device["name"]:
                dest_port = 554
                protocol = "RTSP"
            elif "Thermostat" in chosen_device["name"]:
                dest_port = 1883
                protocol = "MQTT"
            elif "Bridge" in chosen_device["name"]:
                dest_port = 443
                protocol = "HTTPS"
            elif "Medical" in chosen_device["name"]:
                dest_port = 8443
                protocol = "TLS"
            else:
                dest_port = random.choice([80, 443, 53])
                protocol = "TCP"
            dest_ip = random.choice(["192.168.1.1", "104.21.32.11", "172.217.16.206", "34.117.59.81"])
            syn_ratio = round(random.uniform(0.01, 0.10), 2)
            unique_ips = 1
            entropy = round(random.uniform(3.2, 5.2), 2)
            duration = round(random.uniform(4.0, 30.0), 2)
            is_ext = not dest_ip.startswith("192.168.")

        self.packets_analyzed_total += int(pps * 1.5)
        self.bytes_analyzed_total += bps

        tot_pkts = max(1, int(pps * duration))
        fwd_pkts = max(1, int(tot_pkts * (0.90 if syn_ratio > 0.6 else 0.65)))
        bwd_pkts = max(0, tot_pkts - fwd_pkts)
        mean_pkt_len = round(bps / max(1.0, pps), 1)

        return {
            "id": f"FLW-{int(time.time()*1000)%10000000}",
            "timestamp": time.strftime("%H:%M:%S"),
            "device_id": chosen_device["id"],
            "device_name": chosen_device["name"],
            "source_ip": chosen_device["ip"],
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "protocol": protocol,
            "packet_rate": pps,
            "byte_rate": bps,
            "conn_freq": conn_freq,
            "unique_dest_ips": unique_ips,
            "syn_ratio": syn_ratio,
            "payload_entropy": entropy,
            "flow_duration": duration,
            "fwd_packets": fwd_pkts,
            "bwd_packets": bwd_pkts,
            "mean_pkt_len": mean_pkt_len,
            "is_external": is_ext
        }

    def tick_stream(self, forced_scenario: str = None) -> Dict[str, Any]:
        """Produce one new analyzed packet flow and check for auto-alerting"""
        raw = self.generate_synthetic_flow(forced_scenario)
        analyzed = self.coordinator.analyze_flow(raw)

        # Update targeted device metric without corrupting others
        for d in self.devices:
            if d["id"] == analyzed["device_id"]:
                if not d.get("quarantined", False):
                    d["pps"] = analyzed["raw_features"]["packet_rate"]
                    d["last_seen"] = "Just now"
                    d["last_activity"] = "Just now"

        # Auto-create alert if High-Risk or Suspicious anomaly and not duplicate
        if analyzed["status"] in ["High-Risk", "Suspicious"]:
            top_rule = analyzed["rule_matches"][0] if len(analyzed["rule_matches"]) > 0 else None
            ml_pred = analyzed.get("ml_prediction", {})
            ml_high = ml_pred.get("prediction") == "High-Risk"

            if top_rule or ml_high:
                title = top_rule["name"] if top_rule else "ML Botnet Incursion Detected"
                existing_active = any(
                    a["device_id"] == analyzed["device_id"] and a["title"] == title and not a.get("resolved", False)
                    for a in self.alerts
                )
                if not existing_active:
                    sev = "Critical" if (top_rule and top_rule.get("severity") == "High-Risk") or ml_high else "Medium"
                    source = "Dual-Fused Heuristics" if (top_rule and ml_high) else ("Rule-based Engine" if top_rule else "ML Classifier")
                    raw_f = analyzed.get("raw_features", {})

                    new_alert = {
                        "id": f"ALT-{random.randint(9100, 9999)}",
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "device_id": analyzed["device_id"],
                        "device_name": analyzed["device_name"],
                        "source_ip": analyzed.get("source_ip", "192.168.1.100"),
                        "flow_id": analyzed.get("flow_id", f"FLW-{random.randint(10000, 99999)}"),
                        "severity": sev,
                        "detection_source": source,
                        "classification": top_rule.get("category", "IoT Botnet Anomaly") if top_rule else "Heuristic Incursion",
                        "title": title,
                        "reason": top_rule.get("reason", "Anomalous packet telemetry exceeded risk baseline") if top_rule else f"ML Classifier predicted {ml_pred.get('prediction')} with score {ml_pred.get('risk_score', 0.9)}",
                        "details": f"Observed {raw_f.get('packet_rate', 0):.1f} pps on port {analyzed.get('dest_port', 80)}. SYN ratio: {raw_f.get('syn_ratio', 0.0):.2f}.",
                        "traffic_indicators": {
                            "packet_rate": raw_f.get("packet_rate", 0),
                            "byte_rate": raw_f.get("byte_rate", 0),
                            "dest_port": analyzed.get("dest_port", 80),
                            "dest_ip": analyzed.get("dest_ip", "104.28.12.9"),
                            "syn_ratio": raw_f.get("syn_ratio", 0.0),
                            "conn_freq": raw_f.get("conn_freq", 0.0),
                            "payload_entropy": raw_f.get("payload_entropy", 4.0)
                        },
                        "suggested_action": "Quarantine affected device and audit port activity." if sev == "Critical" else "Monitor device connection cadence.",
                        "status": "New",
                        "resolved": False,
                        "mitre_technique": "T1499 Denial of Service / T1046 Network Service Scanning",
                        "analyst_notes": [
                            {"author": "Auto Sentinel", "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "note": f"Incident triggered via {source}."}
                        ],
                        "action_taken": "Automated Alert Dispatched"
                    }
                    self.alerts.insert(0, new_alert)
                    analyzed["new_alert"] = new_alert

        self.recent_flows.insert(0, analyzed)
        if len(self.recent_flows) > self.max_flow_history:
            self.recent_flows.pop()

        return analyzed

    def update_alert_status(self, alert_id: str, new_status: str, analyst_comment: str = "") -> Optional[Dict[str, Any]]:
        """Update incident triage status (New, Acknowledged, In Progress, Resolved, Reopened)"""
        for a in self.alerts:
            if a["id"] == alert_id:
                a["status"] = new_status
                a["resolved"] = (new_status == "Resolved")
                if analyst_comment:
                    a.setdefault("analyst_notes", []).append({
                        "author": "SecOps Analyst",
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "note": analyst_comment
                    })
                a["action_taken"] = f"Status updated to {new_status}"
                return a
        return None

    def add_alert_note(self, alert_id: str, author: str, note_text: str) -> Optional[Dict[str, Any]]:
        """Append an analyst investigation comment to the incident forensic trail"""
        for a in self.alerts:
            if a["id"] == alert_id:
                note_entry = {
                    "author": author or "SecOps Analyst",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "note": note_text
                }
                a.setdefault("analyst_notes", []).append(note_entry)
                return a
        return None

    def bulk_update_alerts(self, alert_ids: List[str], action: str) -> Dict[str, Any]:
        """Perform bulk triage on selected incidents"""
        updated = []
        for a in self.alerts:
            if a["id"] in alert_ids:
                if action == "acknowledge":
                    a["status"] = "Acknowledged"
                    a["resolved"] = False
                    a["action_taken"] = "Bulk Acknowledged"
                elif action == "resolve":
                    a["status"] = "Resolved"
                    a["resolved"] = True
                    a["action_taken"] = "Bulk Resolved by SecOps"
                elif action == "reopen":
                    a["status"] = "Reopened"
                    a["resolved"] = False
                    a["action_taken"] = "Bulk Reopened for Investigation"
                elif action == "in_progress":
                    a["status"] = "In Progress"
                    a["resolved"] = False
                    a["action_taken"] = "Investigation Commenced"
                elif action == "isolate":
                    a["action_taken"] = "Associated Device Quarantined / Network Cut"
                updated.append(a["id"])

        if action == "isolate":
            # Isolate all affected devices
            affected_dev_ids = {a["device_id"] for a in self.alerts if a["id"] in alert_ids}
            for d_id in affected_dev_ids:
                self.set_device_quarantine(d_id, True)

        return {"updated_count": len(updated), "alert_ids": updated, "action": action}

    def set_device_quarantine(self, device_id: str, quarantined: bool) -> bool:
        for d in self.devices:
            if d["id"] == device_id:
                d["quarantined"] = quarantined
                if quarantined:
                    d["pps"] = 0.0
                    d["last_seen"] = "Quarantined / Isolated"
                    d["last_activity"] = "Quarantined"
                    d["status"] = "High-Risk"
                    d["security_classification"] = "High-Risk"
                else:
                    self.calculate_device_risk(d)
                    d["last_seen"] = "Re-connected"
                    d["last_activity"] = "Just now"
                return True
        return False

    def get_summary_kpis(self) -> Dict[str, Any]:
        total_devices = len(self.devices)
        high_risk = sum(1 for d in self.devices if d["status"] == "High-Risk" and not d["quarantined"])
        suspicious = sum(1 for d in self.devices if d["status"] == "Suspicious")
        quarantined = sum(1 for d in self.devices if d["quarantined"])
        normal = sum(1 for d in self.devices if d["status"] == "Normal")
        unresolved_alerts = sum(1 for a in self.alerts if not a.get("resolved", False))
        new_alerts = sum(1 for a in self.alerts if a.get("status") == "New")

        health_score = max(18, 100 - (high_risk * 24 + suspicious * 8 + unresolved_alerts * 4))

        current_pps = sum(d["pps"] for d in self.devices)
        current_mbps = round((current_pps * 380 * 8) / 1000000.0, 2)

        return {
            "total_devices": total_devices,
            "normal_count": normal,
            "suspicious_count": suspicious,
            "high_risk_count": high_risk,
            "quarantined_count": quarantined,
            "unresolved_alerts": unresolved_alerts,
            "new_alerts": new_alerts,
            "health_score": health_score,
            "current_pps": round(current_pps, 1),
            "current_mbps": current_mbps,
            "packets_analyzed_total": self.packets_analyzed_total,
            "bytes_analyzed_total": self.bytes_analyzed_total
        }

    def get_analytics_summary(self, timeframe: str = "24h") -> Dict[str, Any]:
        valid_timeframes = ["1h", "6h", "24h", "7d"]
        if timeframe not in valid_timeframes:
            timeframe = "24h"

        kpis = self.get_summary_kpis()

        multipliers = {
            "1h": 0.04,
            "6h": 0.25,
            "24h": 1.0,
            "7d": 7.0
        }
        mult = multipliers[timeframe]

        recent_count = len(self.recent_flows)
        base_flows = int(94200 * mult) + recent_count

        # Dynamic protocol calculations from flows
        proto_counts = {"TCP": 0, "UDP": 0, "MQTT": 0, "RTSP": 0, "CoAP": 0}
        for f in self.recent_flows:
            p = f.get("protocol", "TCP").upper()
            if "COAP" in p:
                proto_counts["CoAP"] += 1
            elif p in proto_counts:
                proto_counts[p] += 1
            else:
                proto_counts["TCP"] += 1

        tcp_flows = int(base_flows * 0.518) + proto_counts["TCP"]
        udp_flows = int(base_flows * 0.284) + proto_counts["UDP"]
        mqtt_flows = int(base_flows * 0.103) + proto_counts["MQTT"]
        rtsp_flows = int(base_flows * 0.069) + proto_counts["RTSP"]
        coap_flows = int(base_flows * 0.026) + proto_counts["CoAP"]
        total_proto_flows = tcp_flows + udp_flows + mqtt_flows + rtsp_flows + coap_flows

        protocol_breakdown = [
            {
                "protocol": "TCP",
                "flows": tcp_flows,
                "percentage": round((tcp_flows / total_proto_flows) * 100, 1),
                "bytes_gb": round(tcp_flows * 0.000305, 2),
                "description": "Standard Streams & Telnet Scans",
                "color": "#22C55E"
            },
            {
                "protocol": "UDP",
                "flows": udp_flows,
                "percentage": round((udp_flows / total_proto_flows) * 100, 1),
                "bytes_gb": round(udp_flows * 0.000302, 2),
                "description": "DNS / Amplification / SSDP Floods",
                "color": "#F59E0B"
            },
            {
                "protocol": "MQTT",
                "flows": mqtt_flows,
                "percentage": round((mqtt_flows / total_proto_flows) * 100, 1),
                "bytes_gb": round(mqtt_flows * 0.000145, 2),
                "description": "Smart Home IoT Telemetry",
                "color": "#38BDF8"
            },
            {
                "protocol": "RTSP",
                "flows": rtsp_flows,
                "percentage": round((rtsp_flows / total_proto_flows) * 100, 1),
                "bytes_gb": round(rtsp_flows * 0.00148, 2),
                "description": "Surveillance Camera Feeds",
                "color": "#A78BFA"
            },
            {
                "protocol": "CoAP / Others",
                "flows": coap_flows,
                "percentage": round((coap_flows / total_proto_flows) * 100, 1),
                "bytes_gb": round(coap_flows * 0.000160, 2),
                "description": "Custom Embedded M2M & Sensors",
                "color": "#64748B"
            }
        ]

        # Port attack incursion counts: baseline scaled + flow hits
        port_hits = {23: 0, 2323: 0, 80: 0, 53: 0, 37215: 0, 5555: 0, 1883: 0, 554: 0}
        for f in self.recent_flows:
            port = f.get("dest_port")
            if port in port_hits:
                port_hits[port] += 1

        top_attacked_ports = [
            {
                "port": 23,
                "service": "Telnet",
                "exploit_vector": "Mirai & Bashlite credential stuffing & scanner",
                "cve": "CVE-2021-36260",
                "incursions": int(14820 * mult) + port_hits[23],
                "risk_level": "High-Risk",
                "badge": "Critical"
            },
            {
                "port": 2323,
                "service": "Telnet Alt",
                "exploit_vector": "Mirai secondary scanner fallback",
                "cve": "Mirai-Scan",
                "incursions": int(9940 * mult) + port_hits[2323],
                "risk_level": "High-Risk",
                "badge": "Critical"
            },
            {
                "port": 80,
                "service": "HTTP Web GUI",
                "exploit_vector": "Web GUI buffer overflow & HTTP DoS",
                "cve": "CVE-2020-25506",
                "incursions": int(7510 * mult) + port_hits[80],
                "risk_level": "Suspicious",
                "badge": "Elevated"
            },
            {
                "port": 53,
                "service": "DNS Resolver",
                "exploit_vector": "Amplified UDP reflection flooding",
                "cve": "DNS-Amp-DDoS",
                "incursions": int(4320 * mult) + port_hits[53],
                "risk_level": "High-Risk",
                "badge": "Critical"
            },
            {
                "port": 37215,
                "service": "Huawei UPnP",
                "exploit_vector": "UPnP Remote Code Execution",
                "cve": "CVE-2017-17215",
                "incursions": int(3190 * mult) + port_hits[37215],
                "risk_level": "High-Risk",
                "badge": "Critical"
            },
            {
                "port": 5555,
                "service": "Android ADB",
                "exploit_vector": "ADB.Miner cryptojacking infection",
                "cve": "ADB-RCE-Worm",
                "incursions": int(2580 * mult) + port_hits[5555],
                "risk_level": "Suspicious",
                "badge": "Warning"
            },
            {
                "port": 1883,
                "service": "MQTT Broker",
                "exploit_vector": "Unauthorized broker publish / injection",
                "cve": "CWE-306",
                "incursions": int(1420 * mult) + port_hits[1883],
                "risk_level": "Suspicious",
                "badge": "Warning"
            },
            {
                "port": 554,
                "service": "RTSP Stream",
                "exploit_vector": "RTSP stream hijacking & packet flood",
                "cve": "CVE-2018-9995",
                "incursions": int(890 * mult) + port_hits[554],
                "risk_level": "Suspicious",
                "badge": "Warning"
            }
        ]

        # Botnet Strains
        mirai_hits = sum(1 for a in self.alerts if "mirai" in a.get("title", "").lower() or "telnet" in a.get("title", "").lower())
        bashlite_hits = sum(1 for a in self.alerts if "bashlite" in a.get("title", "").lower() or "flood" in a.get("title", "").lower())
        torii_hits = sum(1 for a in self.alerts if "torii" in a.get("title", "").lower() or "rat" in a.get("title", "").lower())

        botnet_strains = [
            {
                "family": "Mirai Variant (Telnet Brute & Port Scan)",
                "type": "Credential Brute-Force & Port Scanner",
                "target_hardware": "Hikvision & Dahua Cameras, DVRs",
                "hits": int(68 * mult) + mirai_hits,
                "risk": "High-Risk",
                "badge": "Critical",
                "status": "Active Incursions Logged"
            },
            {
                "family": "Bashlite / Gafgyt (Volumetric DoS Engine)",
                "type": "SYN/UDP Volumetric DoS Engine",
                "target_hardware": "Modbus Gateways, Routers",
                "hits": int(42 * mult) + bashlite_hits,
                "risk": "High-Risk",
                "badge": "Critical",
                "status": "Active Incursions Logged"
            },
            {
                "family": "Hajime / IoT P2P Worm",
                "type": "Decentralized P2P Botnet Worm",
                "target_hardware": "Embedded Linux CPEs, Micro-controllers",
                "hits": int(17 * mult),
                "risk": "Suspicious",
                "badge": "Elevated",
                "status": "Probing Detected"
            },
            {
                "family": "Torii / Modular IoT RAT",
                "type": "Multi-Stage Stealth Exfiltration RAT",
                "target_hardware": "Smart Lighting Gateways, Hubs",
                "hits": int(11 * mult) + torii_hits,
                "risk": "High-Risk",
                "badge": "Critical",
                "status": "Active Incursions Logged"
            },
            {
                "family": "ADB.Miner / Cryptojacker",
                "type": "Monero Cryptojacking Worm",
                "target_hardware": "Android TVs, Media Hubs",
                "hits": int(9 * mult),
                "risk": "Suspicious",
                "badge": "Warning",
                "status": "Probing Detected"
            },
            {
                "family": "Dark_Nexus / Embedded Weaponizer",
                "type": "Reverse-Engineering Payloads",
                "target_hardware": "Network Attached Storage (NAS), Thermostats",
                "hits": int(6 * mult),
                "risk": "High-Risk",
                "badge": "Critical",
                "status": "Blocked by Quarantine"
            }
        ]

        # Multi-timeframe trend timeline
        timeline = []
        if timeframe == "1h":
            times = ["10:00", "10:05", "10:10", "10:15", "10:20", "10:25", "10:30", "10:35", "10:40", "10:45", "10:50", "10:55"]
            normals = [310, 325, 298, 340, 360, 315, 330, 355, 380, 365, 345, 370]
            suspicious_vals = [14, 18, 12, 22, 28, 19, 24, 31, 35, 29, 22, 26]
            high_risks = [4, 6, 3, 11, 19, 8, 14, 21, 25, 17, 12, 16]
            for i in range(12):
                timeline.append({
                    "time": times[i],
                    "normal": normals[i],
                    "suspicious": suspicious_vals[i],
                    "high_risk": high_risks[i]
                })
        elif timeframe == "6h":
            times = ["05:30", "06:00", "06:30", "07:00", "07:30", "08:00", "08:30", "09:00", "09:30", "10:00", "10:30", "11:00"]
            normals = [1850, 1920, 2100, 2350, 2480, 2650, 2540, 2720, 2890, 2780, 2690, 2820]
            suspicious_vals = [85, 95, 110, 145, 180, 210, 195, 230, 260, 225, 210, 240]
            high_risks = [25, 32, 45, 78, 115, 160, 140, 195, 220, 175, 160, 185]
            for i in range(12):
                timeline.append({
                    "time": times[i],
                    "normal": normals[i],
                    "suspicious": suspicious_vals[i],
                    "high_risk": high_risks[i]
                })
        elif timeframe == "24h":
            times = ["00:00", "02:00", "04:00", "06:00", "08:00", "10:00", "12:00", "14:00", "16:00", "18:00", "20:00", "22:00"]
            normals = [4200, 4150, 4300, 5800, 7200, 8900, 9400, 10200, 9800, 8700, 7600, 6100]
            suspicious_vals = [140, 155, 170, 320, 490, 840, 1120, 980, 860, 710, 520, 380]
            high_risks = [20, 18, 25, 45, 110, 320, 480, 410, 350, 280, 190, 110]
            for i in range(12):
                timeline.append({
                    "time": times[i],
                    "normal": normals[i],
                    "suspicious": suspicious_vals[i],
                    "high_risk": high_risks[i]
                })
        else: # 7d
            times = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            normals = [48500, 52400, 61200, 78900, 89400, 94500, 88200]
            suspicious_vals = [2100, 2450, 3200, 4850, 6120, 5900, 5300]
            high_risks = [780, 920, 1450, 2350, 3100, 2850, 2400]
            for i in range(7):
                timeline.append({
                    "time": times[i],
                    "normal": normals[i],
                    "suspicious": suspicious_vals[i],
                    "high_risk": high_risks[i]
                })

        # Geographic Threat Intelligence & ASN Matrix
        geographic_threats = [
            {
                "country": "Russian Federation",
                "code": "RU",
                "flag": "🇷🇺",
                "asn": "AS14061 (DigitalOcean LLC)",
                "probes": int(18450 * mult),
                "share_pct": 34.2,
                "threat_score": 96,
                "risk_level": "High-Risk",
                "badge": "Critical"
            },
            {
                "country": "China",
                "code": "CN",
                "flag": "🇨🇳",
                "asn": "AS4134 (Chinanet Backbone)",
                "probes": int(12380 * mult),
                "share_pct": 22.9,
                "threat_score": 91,
                "risk_level": "High-Risk",
                "badge": "Critical"
            },
            {
                "country": "United States",
                "code": "US",
                "flag": "🇺🇸",
                "asn": "AS8075 (Microsoft Cloud Scanners)",
                "probes": int(8120 * mult),
                "share_pct": 15.0,
                "threat_score": 68,
                "risk_level": "Suspicious",
                "badge": "Elevated"
            },
            {
                "country": "Brazil",
                "code": "BR",
                "flag": "🇧🇷",
                "asn": "AS28573 (Claro Telecom)",
                "probes": int(5640 * mult),
                "share_pct": 10.4,
                "threat_score": 84,
                "risk_level": "High-Risk",
                "badge": "Critical"
            },
            {
                "country": "Netherlands",
                "code": "NL",
                "flag": "🇳🇱",
                "asn": "AS49981 (WorldStream B.V.)",
                "probes": int(4920 * mult),
                "share_pct": 9.1,
                "threat_score": 79,
                "risk_level": "Suspicious",
                "badge": "Elevated"
            },
            {
                "country": "Vietnam",
                "code": "VN",
                "flag": "🇻🇳",
                "asn": "AS7552 (Viettel Group)",
                "probes": int(4510 * mult),
                "share_pct": 8.4,
                "threat_score": 82,
                "risk_level": "High-Risk",
                "badge": "Critical"
            }
        ]

        total_probes_geo = sum(g["probes"] for g in geographic_threats)
        if total_probes_geo > 0:
            for g in geographic_threats:
                g["share_pct"] = round((g["probes"] / total_probes_geo) * 100, 1)

        total_suspicious = sum(t["suspicious"] for t in timeline)
        total_high = sum(t["high_risk"] for t in timeline)
        malicious_pct = round(((total_suspicious + total_high) / max(1, base_flows)) * 100, 1)
        peak_incursion_mbps = round(max(35.0, kpis.get("current_mbps", 18.5) * 8.2), 1)

        return {
            "timeframe": timeframe,
            "kpis": {
                "total_flows": total_proto_flows,
                "malicious_ratio_pct": malicious_pct,
                "active_strains_count": len([s for s in botnet_strains if s["hits"] > 0]),
                "peak_incursion_mbps": peak_incursion_mbps,
                "health_score": kpis.get("health_score", 78)
            },
            "protocol_breakdown": protocol_breakdown,
            "top_attacked_ports": top_attacked_ports,
            "botnet_family_distribution": botnet_strains,
            "hourly_timeline": timeline,
            "geographic_threats": geographic_threats
        }

