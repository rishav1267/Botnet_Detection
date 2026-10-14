#!/usr/bin/env python3
"""
IoT Botnet Detection System — HTTP Backend & REST API Server
Runs on Python standard library http.server with threaded request handling.
"""

import os
import sys
import json
import time
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import urllib.parse

from detection_engine import DualDetectionCoordinator
from iot_network_simulator import IoTNetworkManager

# Initialize Detection Coordinator and Network Manager
coordinator = DualDetectionCoordinator()
network_manager = IoTNetworkManager(coordinator)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True


class IoTSystemRequestHandler(BaseHTTPRequestHandler):
    """Handles REST API requests and serves static web assets."""

    def end_headers(self):
        # Enable CORS for local testing
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def _send_json(self, data, status_code=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            raw_body = self.rfile.read(content_length).decode("utf-8")
            try:
                return json.loads(raw_body)
            except Exception:
                return {}
        return {}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # API Routes
        if path == "/api/health":
            return self._send_json({
                "status": "healthy",
                "uptime_seconds": int(time.time()),
                "detection_engine": "operational",
                "ml_engine": "active" if coordinator.ml_engine.is_trained else "fallback",
                "rule_engine": "active",
                "latency_us": 142,
                "packet_drop_rate": 0.0012,
                "memory_buffer_mb": 42.8,
                "cpu_usage_pct": 3.8
            })

        elif path == "/api/kpi":
            return self._send_json(network_manager.get_summary_kpis())

        elif path == "/api/devices":
            return self._send_json({
                "devices": network_manager.devices,
                "summary": network_manager.get_summary_kpis()
            })

        elif path == "/api/traffic":
            limit = int(query.get("limit", [50])[0])
            status_filter = query.get("status", [None])[0]
            flows = network_manager.recent_flows[:limit]
            if status_filter:
                flows = [f for f in flows if f["status"].lower() == status_filter.lower()]
            return self._send_json({
                "flows": flows,
                "total_recorded": len(network_manager.recent_flows),
                "timestamp": time.strftime("%H:%M:%S")
            })

        elif path == "/api/traffic/tick":
            # Stream one tick
            scenario = query.get("scenario", [None])[0]
            flow = network_manager.tick_stream(scenario)
            return self._send_json({
                "new_flow": flow,
                "new_alert": flow.get("new_alert"),
                "kpis": network_manager.get_summary_kpis()
            })

        elif path == "/api/threats/rules":
            return self._send_json({
                "rules": list(coordinator.rule_engine.rules.values())
            })

        elif path == "/api/ml/model":
            ml = coordinator.ml_engine
            return self._send_json({
                "model_name": "Random Forest IoT Classifier (Scikit-Learn)",
                "n_estimators": getattr(ml, "n_estimators", 45),
                "max_depth": getattr(ml, "max_depth", 9),
                "sample_size": getattr(ml, "sample_size", 2400),
                "test_split_pct": getattr(ml, "test_split_pct", 25),
                "accuracy": ml.accuracy,
                "precision": ml.precision,
                "recall": ml.recall,
                "f1_score": ml.f1_score,
                "roc_auc": getattr(ml, "roc_auc", 0.996),
                "feature_importance": ml.feature_importance,
                "confusion_matrix": ml.confusion_matrix,
                "feature_names": ml.FEATURE_NAMES,
                "feature_metadata": getattr(ml, "FEATURE_METADATA", {}),
                "classes": ml.CLASSES,
                "roc_curve": getattr(ml, "roc_curve_data", []),
                "pr_curve": getattr(ml, "pr_curve_data", [])
            })

        elif path == "/api/alerts":
            return self._send_json({
                "alerts": network_manager.alerts,
                "total": len(network_manager.alerts),
                "unresolved": sum(1 for a in network_manager.alerts if not a.get("resolved", False)),
                "new_count": sum(1 for a in network_manager.alerts if a.get("status") == "New")
            })

        elif path == "/api/export/alerts/csv":
            csv_lines = [
                "Alert ID,Timestamp,Severity,Device ID,Device Name,Source IP,Threat Classification,Title,Detection Source,Reason,Status,MITRE Technique,Suggested Action,Action Taken"
            ]
            for a in network_manager.alerts:
                title = a.get("title", "").replace('"', '""')
                dev_name = a.get("device_name", "").replace('"', '""')
                cat = a.get("classification", a.get("category", "")).replace('"', '""')
                reason = a.get("reason", a.get("details", "")).replace('"', '""')
                mitre = a.get("mitre_technique", "").replace('"', '""')
                action = a.get("suggested_action", "").replace('"', '""')
                taken = a.get("action_taken", "").replace('"', '""')
                csv_lines.append(
                    f'"{a.get("id")}","{a.get("timestamp")}","{a.get("severity")}","{a.get("device_id")}","{dev_name}","{a.get("source_ip")}","{cat}","{title}","{a.get("detection_source")}","{reason}","{a.get("status")}","{mitre}","{action}","{taken}"'
                )
            body = "\n".join(csv_lines).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=iot_security_incidents.csv")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        elif path == "/api/export/alerts/json":
            body = json.dumps(network_manager.alerts, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=iot_security_incidents.json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        elif path == "/api/analytics":
            timeframe = query.get("timeframe", ["24h"])[0]
            return self._send_json(network_manager.get_analytics_summary(timeframe))

        elif path == "/api/export/analytics/csv":
            timeframe = query.get("timeframe", ["24h"])[0]
            analytics_data = network_manager.get_analytics_summary(timeframe)
            csv_lines = [
                f"# NETGUARD IoT Threat Telemetry & Botnet Analytics Report ({timeframe.upper()})",
                f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                "",
                "# SECTION: Executive KPIs",
                "Total Flows,Malicious Ratio (%),Active Botnet Strains,Peak Incursion Throughput (Mbps),Security Health Score",
                f"{analytics_data['kpis']['total_flows']},{analytics_data['kpis']['malicious_ratio_pct']}%,{analytics_data['kpis']['active_strains_count']},{analytics_data['kpis']['peak_incursion_mbps']} Mbps,{analytics_data['kpis']['health_score']}/100",
                "",
                "# SECTION: Protocol Composition Breakdown",
                "Protocol,Flow Volume,Share (%),Throughput (GB),Description",
            ]
            for p in analytics_data["protocol_breakdown"]:
                csv_lines.append(f'"{p["protocol"]}",{p["flows"]},{p["percentage"]}%,{p.get("bytes_gb", 0)},"{p["description"]}"')

            csv_lines.extend([
                "",
                "# SECTION: Top Targeted IoT Ports & Exploit Vectors",
                "Port,Standard Service,Exploit Vector,CVE Reference,Incursions Logged,Risk Classification"
            ])
            for pt in analytics_data["top_attacked_ports"]:
                csv_lines.append(f'{pt["port"]},"{pt["service"]}","{pt["exploit_vector"]}","{pt.get("cve","")}","{pt["incursions"]}","{pt["risk_level"]}"')

            csv_lines.extend([
                "",
                "# SECTION: Identified Botnet Malware Signatures",
                "Malware Family,Vector Type,Target Hardware,Hits Logged,Risk Severity,Status"
            ])
            for st in analytics_data["botnet_family_distribution"]:
                csv_lines.append(f'"{st["family"]}","{st.get("type","")}","{st.get("target_hardware","")}",{st["hits"]},"{st["risk"]}","{st.get("status","")}"')

            csv_lines.extend([
                "",
                "# SECTION: Geographic Threat Origins & ASN Matrix",
                "Country,Country Code,Top Autonomous System (ASN),Probes Logged,Global Share (%),Threat Score,Status"
            ])
            for g in analytics_data["geographic_threats"]:
                csv_lines.append(f'"{g["country"]}","{g["code"]}","{g["asn"]}",{g["probes"]},{g["share_pct"]}%,{g["threat_score"]}/100,"{g["risk_level"]}"')

            body = "\n".join(csv_lines).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=iot_analytics_threat_report.csv")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        elif path == "/api/export/analytics/json":
            timeframe = query.get("timeframe", ["24h"])[0]
            analytics_data = network_manager.get_analytics_summary(timeframe)
            body = json.dumps(analytics_data, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=iot_analytics_threat_report.json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        elif path == "/api/export/report":
            kpis = network_manager.get_summary_kpis()
            analytics_data = network_manager.get_analytics_summary("24h")
            report_text = f"""# NETGUARD IoT Cybersecurity & Botnet Detection Security Audit Report
**Classification:** TLP:AMBER | CONFIDENTIAL EXECUTIVE AUDIT  
**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Overall Security Posture Score:** {kpis['health_score']}/100 ({'OPTIMAL' if kpis['health_score'] > 85 else ('DEGRADED' if kpis['health_score'] > 60 else 'CRITICAL')})

---

## 1. Executive Fleet Summary
- **Monitored IoT Hardware Nodes:** {kpis['total_devices']}
- **Clean / Benign Baseline Assets:** {kpis['normal_count']}
- **Suspicious Probing Entities:** {kpis['suspicious_count']}
- **Active High-Risk / Compromised Botnet Nodes:** {kpis['high_risk_count']}
- **Quarantined & Isolated Devices:** {kpis['quarantined_count']}
- **Total Packet Telemetry Inspected:** {kpis['packets_analyzed_total']:,}
- **Current Network Bandwidth:** {kpis['current_mbps']} Mbps ({kpis['current_pps']} pps)
- **Unresolved Incident Tickets:** {kpis['unresolved_alerts']}

---

## 2. Machine-Learning Dual-Detection Benchmarks
- **Supervised Classifier:** Random Forest Ensemble (Scikit-Learn)
- **Feature Vector Dimension:** 11 Real-Time Network & Behavioral Features
- **Validation Accuracy:** {coordinator.ml_engine.accuracy * 100:.1f}%
- **Precision:** {coordinator.ml_engine.precision * 100:.1f}%
- **Recall Rate:** {coordinator.ml_engine.recall * 100:.1f}%
- **F1-Score:** {coordinator.ml_engine.f1_score * 100:.1f}%
- **Heuristic Rule Engine:** 10 Active Real-Time Snort/Suricata-style Inspection Rules

---

## 3. High-Risk Assets & Detected Botnet Signatures
"""
            high_risk_nodes = [d for d in network_manager.devices if d["status"] == "High-Risk"]
            if high_risk_nodes:
                for d in high_risk_nodes:
                    vulns = ', '.join(d.get('vulnerabilities', ['Unpatched firmware']))
                    report_text += f"- **{d['name']}** (`{d['ip']}` / `{d['mac']}`)\n  - Risk Score: {d.get('risk_score', 0)}/100 | Status: {'ISOLATED / QUARANTINED' if d.get('quarantined') else 'ACTIVE IN FLEET'}\n  - Known Vulnerabilities: {vulns}\n  - Recommended Action: {d.get('recommended_action', 'Isolate and patch.')}\n\n"
            else:
                report_text += "No active high-risk compromise detected in the fleet.\n\n"

            report_text += f"""---

## 4. Top Targeted IoT Ports
"""
            for pt in analytics_data["top_attacked_ports"][:5]:
                report_text += f"- **Port {pt['port']} ({pt['service']})**: {pt['incursions']:,} probes | Exploit: {pt['exploit_vector']} ({pt.get('cve','')})\n"

            report_text += f"""
---

## 5. Strategic Remediation Roadmap
1. **Automated Quarantine Enforcement**: Maintain zero-trust microsegmentation on VLAN switches to isolate devices exhibiting abnormal packet bursts (>200 pps) or port 23/2323 credential sweeps.
2. **Firmware Upgrade & Patch Baseline**: Immediately remediate unpatched Hikvision CVE-2021-36260 and Huawei UPnP CVE-2017-17215 vulnerabilities.
3. **Credential Hardening**: Disable factory-default Telnet and enforce key-based SSH management across all edge IoT nodes.
4. **Boundary Egress Filtering**: Restrict outbound DNS reflection (port 53) and isolate external ADB (port 5555) access.
"""
            body = report_text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=iot_security_audit_report.md")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        elif path == "/api/risk/config":
            return self._send_json(network_manager.risk_config)

        elif path == "/api/export/devices/csv":
            csv_lines = [
                "Device ID,Device Name,Device Type,IP Address,MAC Address,Protocol,First Seen,Last Activity,Packet Rate (pps),Bytes Transferred,Connection Frequency (conn/10s),Risk Score,Security Classification,Quarantined"
            ]
            for d in network_manager.devices:
                name = d.get("name", "").replace('"', '""')
                cat = d.get("category", "").replace('"', '""')
                proto = d.get("protocol", "").replace('"', '""')
                csv_lines.append(
                    f'"{d.get("id")}","{name}","{cat}","{d.get("ip")}","{d.get("mac")}","{proto}","{d.get("first_seen")}","{d.get("last_activity")}",{d.get("pps", 0):.1f},"{d.get("bytes_transferred")}",{d.get("conn_freq", 0):.1f},{d.get("risk_score", 0)},"{d.get("security_classification")}","{d.get("quarantined")}"'
                )
            body = "\n".join(csv_lines).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=iot_device_inventory.csv")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Serve Static Files
        return self._serve_static(path)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        if path == "/api/devices/quarantine":
            dev_id = body.get("device_id")
            quarantine = body.get("quarantined", True)
            success = network_manager.set_device_quarantine(dev_id, quarantine)
            return self._send_json({
                "success": success,
                "device_id": dev_id,
                "quarantined": quarantine,
                "devices": network_manager.devices,
                "kpis": network_manager.get_summary_kpis()
            })

        elif path == "/api/devices/scan":
            dev_id = body.get("device_id")
            # Simulate vulnerability scan result
            target = next((d for d in network_manager.devices if d["id"] == dev_id), None)
            if not target:
                return self._send_json({"error": "Device not found"}, 404)
            return self._send_json({
                "device_id": dev_id,
                "name": target["name"],
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "open_ports": [23, 80, 554] if target["status"] == "High-Risk" else [80, 443],
                "vulnerabilities": target["vulnerabilities"],
                "risk_rating": target["status"],
                "remediation": "Update firmware and isolate IoT VLAN."
            })

        elif path == "/api/threats/rules/update":
            rule_id = body.get("rule_id")
            field = body.get("field")
            val = body.get("value")
            success = coordinator.rule_engine.update_threshold(rule_id, field, val)
            return self._send_json({"success": success, "rule_id": rule_id, "field": field, "value": val})

        elif path == "/api/ml/predict":
            # Real-time prediction endpoint
            prediction = coordinator.ml_engine.predict(body)
            return self._send_json(prediction)

        elif path == "/api/ml/retrain":
            n_est = int(body.get("n_estimators", 45))
            depth = int(body.get("max_depth", 9))
            size = int(body.get("sample_size", 2400))
            split = int(body.get("test_split_pct", 25))
            res = coordinator.ml_engine.retrain(n_estimators=n_est, max_depth=depth, sample_size=size, test_split_pct=split)
            return self._send_json(res)

        elif path == "/api/alerts/status":
            alert_id = body.get("alert_id")
            new_status = body.get("status", "Acknowledged")
            comment = body.get("comment", "")
            alert = network_manager.update_alert_status(alert_id, new_status, comment)
            if not alert:
                return self._send_json({"error": "Alert not found"}, 404)
            return self._send_json({
                "success": True,
                "alert": alert,
                "kpis": network_manager.get_summary_kpis()
            })

        elif path == "/api/alerts/note":
            alert_id = body.get("alert_id")
            author = body.get("author", "SecOps Analyst")
            note_text = body.get("note", "")
            alert = network_manager.add_alert_note(alert_id, author, note_text)
            if not alert:
                return self._send_json({"error": "Alert not found"}, 404)
            return self._send_json({"success": True, "alert": alert})

        elif path == "/api/alerts/bulk":
            alert_ids = body.get("alert_ids", [])
            action = body.get("action", "acknowledge")
            res = network_manager.bulk_update_alerts(alert_ids, action)
            return self._send_json({
                "success": True,
                "result": res,
                "alerts": network_manager.alerts,
                "kpis": network_manager.get_summary_kpis()
            })

        elif path == "/api/alerts/resolve":
            alert_id = body.get("alert_id")
            alert = network_manager.update_alert_status(alert_id, "Resolved", "Resolved by SecOps Analyst")
            return self._send_json({"success": alert is not None, "alert_id": alert_id})

        elif path == "/api/simulation/attack":
            scenario = body.get("scenario")
            network_manager.attack_mode = scenario if scenario != "reset" else None
            # Generate 3 rapid burst flows for immediate visualization
            burst = [network_manager.tick_stream(network_manager.attack_mode) for _ in range(3)]
            return self._send_json({
                "scenario": network_manager.attack_mode,
                "generated_burst": burst,
                "kpis": network_manager.get_summary_kpis()
            })

        elif path == "/api/risk/config":
            thresholds = body.get("thresholds")
            weights = body.get("weights")
            if thresholds and isinstance(thresholds, dict):
                network_manager.risk_config["thresholds"].update(thresholds)
            if weights and isinstance(weights, dict):
                network_manager.risk_config["weights"].update(weights)
            updated_devices = network_manager.recalculate_all_risks()
            return self._send_json({
                "success": True,
                "risk_config": network_manager.risk_config,
                "devices": updated_devices,
                "kpis": network_manager.get_summary_kpis()
            })

        elif path == "/api/traffic/ingest":
            analyzed = network_manager.ingest_external_flow(body)
            return self._send_json({
                "success": True,
                "analyzed_flow": analyzed,
                "kpis": network_manager.get_summary_kpis()
            })

        else:
            return self._send_json({"error": "Not Found"}, 404)

    def _serve_static(self, path):
        if path in ["/", ""]:
            path = "/index.html"

        # Sanitize path to prevent directory traversal
        clean_path = os.path.normpath(path).lstrip("/")
        full_path = os.path.join(STATIC_DIR, clean_path)

        if not os.path.isfile(full_path):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            return

        mime_type, _ = mimetypes.guess_type(full_path)
        if not mime_type:
            if full_path.endswith(".js"):
                mime_type = "application/javascript"
            elif full_path.endswith(".css"):
                mime_type = "text/css"
            elif full_path.endswith(".html"):
                mime_type = "text/html"
            elif full_path.endswith(".json"):
                mime_type = "application/json"
            else:
                mime_type = "application/octet-stream"

        try:
            with open(full_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", f"{mime_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode("utf-8"))


def run_server(port=8080):
    from backend.app import run_server as backend_run
    backend_run(port)


if __name__ == "__main__":
    port = 8080
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run_server(port)
