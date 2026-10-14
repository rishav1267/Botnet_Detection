"""
Export Controller — Generates Downloadable CSV, JSON, and Markdown Forensic Reports
"""

import json
import time
from typing import Dict, Any, Tuple
from backend.services import analytics_service, device_service, alert_service


class ExportController:
    """Handles downloadable attachments and file serialization."""

    @staticmethod
    def export_report_markdown() -> Tuple[int, bytes, Dict[str, str]]:
        report_text = analytics_service.generate_audit_report_markdown()
        body = report_text.encode("utf-8")
        headers = {
            "Content-Type": "text/markdown; charset=utf-8",
            "Content-Disposition": "attachment; filename=iot_security_audit_report.md",
            "Content-Length": str(len(body))
        }
        return 200, body, headers

    @staticmethod
    def export_devices_csv() -> Tuple[int, bytes, Dict[str, str]]:
        devices = device_service.get_devices()
        csv_lines = [
            "Device ID,Device Name,Device Type,IP Address,MAC Address,Protocol,First Seen,Last Activity,Packet Rate (pps),Bytes Transferred,Connection Frequency (conn/10s),Risk Score,Security Classification,Quarantined"
        ]
        for d in devices:
            name = d.get("name", "").replace('"', '""')
            cat = d.get("category", "").replace('"', '""')
            proto = d.get("protocol", "").replace('"', '""')
            csv_lines.append(
                f'"{d.get("id")}","{name}","{cat}","{d.get("ip")}","{d.get("mac")}","{proto}","{d.get("first_seen")}","{d.get("last_activity")}",{d.get("pps", 0):.1f},"{d.get("bytes_transferred")}",{d.get("conn_freq", 0):.1f},{d.get("risk_score", 0)},"{d.get("security_classification")}","{d.get("quarantined")}"'
            )
        body = "\n".join(csv_lines).encode("utf-8")
        headers = {
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition": "attachment; filename=iot_device_inventory.csv",
            "Content-Length": str(len(body))
        }
        return 200, body, headers

    @staticmethod
    def export_alerts_csv() -> Tuple[int, bytes, Dict[str, str]]:
        alerts = alert_service.get_alerts()
        csv_lines = [
            "Alert ID,Timestamp,Device ID,Device Name,Source IP,Severity,Status,Resolved,Classification,Title,Reason,Details,MITRE Technique,Action Taken"
        ]
        for a in alerts:
            title = a.get("title", "").replace('"', '""')
            reason = a.get("reason", "").replace('"', '""')
            details = a.get("details", "").replace('"', '""')
            action = a.get("action_taken", "").replace('"', '""')
            csv_lines.append(
                f'"{a.get("id")}","{a.get("timestamp")}","{a.get("device_id")}","{a.get("device_name")}","{a.get("source_ip")}","{a.get("severity")}","{a.get("status")}","{a.get("resolved")}","{a.get("classification")}","{title}","{reason}","{details}","{a.get("mitre_technique")}","{action}"'
            )
        body = "\n".join(csv_lines).encode("utf-8")
        headers = {
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition": "attachment; filename=iot_security_incidents.csv",
            "Content-Length": str(len(body))
        }
        return 200, body, headers

    @staticmethod
    def export_alerts_json() -> Tuple[int, bytes, Dict[str, str]]:
        alerts = alert_service.get_alerts()
        body = json.dumps({"alerts": alerts, "count": len(alerts), "exported_at": time.strftime("%Y-%m-%d %H:%M:%S UTC")}, indent=2).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Content-Disposition": "attachment; filename=iot_security_incidents.json",
            "Content-Length": str(len(body))
        }
        return 200, body, headers

    @staticmethod
    def export_analytics_csv(query_params: Dict[str, Any]) -> Tuple[int, bytes, Dict[str, str]]:
        timeframe = query_params.get("timeframe", ["24h"])[0] if isinstance(query_params.get("timeframe"), list) else query_params.get("timeframe", "24h")
        analytics_data = analytics_service.get_analytics_summary(timeframe)
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
        headers = {
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition": "attachment; filename=iot_analytics_threat_report.csv",
            "Content-Length": str(len(body))
        }
        return 200, body, headers

    @staticmethod
    def export_analytics_json(query_params: Dict[str, Any]) -> Tuple[int, bytes, Dict[str, str]]:
        timeframe = query_params.get("timeframe", ["24h"])[0] if isinstance(query_params.get("timeframe"), list) else query_params.get("timeframe", "24h")
        analytics_data = analytics_service.get_analytics_summary(timeframe)
        body = json.dumps(analytics_data, indent=2).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Content-Disposition": "attachment; filename=iot_analytics_threat_report.json",
            "Content-Length": str(len(body))
        }
        return 200, body, headers
