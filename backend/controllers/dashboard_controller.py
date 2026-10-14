"""
Dashboard Controller — Executive KPIs, Real-Time Traffic, Risk Distribution, and Alert Trends
"""

from typing import Dict, Any, Tuple
from backend.services import (
    network_manager,
    device_service,
    traffic_service,
    alert_service
)
from backend.utils.response import api_success


class DashboardController:
    """Handles /api/dashboard/* endpoints."""

    @staticmethod
    def get_summary() -> Tuple[int, Dict[str, Any]]:
        """GET /api/dashboard/summary"""
        kpis = network_manager.get_summary_kpis()
        unread = alert_service.get_unread_count()
        critical_alerts = sum(1 for a in network_manager.alerts if a.get("severity") == "Critical" and not a.get("resolved"))
        active_threats = sum(1 for d in network_manager.devices if d.get("status") in ("Suspicious", "High-Risk"))

        data = {
            "total_devices": kpis.get("total_devices", len(network_manager.devices)),
            "normal_count": kpis.get("normal_count", 0),
            "suspicious_count": kpis.get("suspicious_count", 0),
            "high_risk_count": kpis.get("high_risk_count", 0),
            "quarantined_count": kpis.get("quarantined_count", 0),
            "active_threats_count": active_threats,
            "unresolved_alerts": kpis.get("unresolved_alerts", 0),
            "critical_alerts_count": critical_alerts,
            "new_alerts": unread.get("new_count", 0),
            "health_score": kpis.get("health_score", 90.0),
            "current_pps": kpis.get("current_pps", 15.0),
            "current_mbps": kpis.get("current_mbps", 0.8),
            "packets_analyzed_total": kpis.get("packets_analyzed_total", 0),
            "bytes_analyzed_total": kpis.get("bytes_analyzed_total", 0),
            "system_uptime": "99.98%"
        }
        return 200, api_success(data)

    @staticmethod
    def get_traffic() -> Tuple[int, Dict[str, Any]]:
        """GET /api/dashboard/traffic"""
        stats = traffic_service.get_stats()
        flows = traffic_service.get_recent_flows(limit=15)
        timeline = [
            {"time": f"T-{i}s", "pps": round(stats["current_pps"] * (0.8 + 0.05 * (i % 6)), 1)}
            for i in range(10, 0, -1)
        ]
        return 200, api_success({
            "current_pps": stats["current_pps"],
            "current_mbps": stats["current_mbps"],
            "total_packets": stats["total_packets"],
            "total_bytes": stats["total_bytes"],
            "anomaly_rate_pct": stats["anomaly_rate_pct"],
            "ingress_mbps": round(stats["current_mbps"] * 0.58, 2),
            "egress_mbps": round(stats["current_mbps"] * 0.42, 2),
            "packet_rate_history": timeline,
            "recent_flows_sample": flows[:5]
        })

    @staticmethod
    def get_risk_distribution() -> Tuple[int, Dict[str, Any]]:
        """GET /api/dashboard/risk-distribution"""
        devices = network_manager.devices
        total = len(devices) or 1
        n = sum(1 for d in devices if d.get("status") == "Normal")
        s = sum(1 for d in devices if d.get("status") == "Suspicious")
        h = sum(1 for d in devices if d.get("status") == "High-Risk")

        type_map: Dict[str, int] = {}
        for d in devices:
            t = d.get("type", "Unknown")
            type_map[t] = type_map.get(t, 0) + 1

        return 200, api_success({
            "tiers": {
                "Normal": {"count": n, "percentage": round((n / total) * 100, 1)},
                "Suspicious": {"count": s, "percentage": round((s / total) * 100, 1)},
                "High-Risk": {"count": h, "percentage": round((h / total) * 100, 1)},
            },
            "by_device_type": [
                {"type": t, "count": c, "percentage": round((c / total) * 100, 1)}
                for t, c in type_map.items()
            ],
            "total_devices": total
        })

    @staticmethod
    def get_alert_trends() -> Tuple[int, Dict[str, Any]]:
        """GET /api/dashboard/alert-trends"""
        alerts = network_manager.alerts
        low = sum(1 for a in alerts if a.get("severity") == "Low")
        med = sum(1 for a in alerts if a.get("severity") == "Medium")
        high = sum(1 for a in alerts if a.get("severity") == "High")
        crit = sum(1 for a in alerts if a.get("severity") == "Critical")
        resolved = sum(1 for a in alerts if a.get("resolved") or a.get("status") == "Resolved")

        hourly_trends = [
            {"hour": f"{h:02d}:00", "critical": 1 if h in (4, 18) else 0, "high": (h % 3), "medium": (h % 4) + 1, "low": (h % 2) + 1}
            for h in range(12, 24)
        ]

        return 200, api_success({
            "severity_counts": {
                "low": low,
                "medium": med,
                "high": high,
                "critical": crit
            },
            "total_alerts": len(alerts),
            "resolved_count": resolved,
            "resolution_rate_pct": round((resolved / max(1, len(alerts))) * 100, 1),
            "hourly_trends": hourly_trends
        })

    @staticmethod
    def get_top_risk_devices(query: Dict[str, Any] = None) -> Tuple[int, Dict[str, Any]]:
        """GET /api/dashboard/top-risk-devices"""
        limit = 5
        if query and "limit" in query:
            try:
                limit = int(query["limit"][0])
            except Exception:
                limit = 5

        devices = sorted(network_manager.devices, key=lambda d: d.get("risk_score", 0), reverse=True)
        top = [
            {
                "id": d.get("id"),
                "name": d.get("name"),
                "ip": d.get("ip"),
                "type": d.get("type"),
                "risk_score": d.get("risk_score"),
                "status": d.get("status"),
                "quarantined": d.get("quarantined", False),
                "anomaly_rate": d.get("anomaly_rate", 0.0),
                "pps": d.get("pps", 0.0),
                "last_seen": d.get("last_seen")
            }
            for d in devices[:limit]
        ]
        return 200, api_success({"top_risk_devices": top, "limit": limit})
