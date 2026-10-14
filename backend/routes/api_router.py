"""
API Router — Centralized Modular Route Dispatcher
Matches REST API endpoints for all 7 Core Groups + ML/Auth/Exports with regex param extraction.
"""

import re
import urllib.parse
from typing import Dict, Any, Tuple, Optional
from backend.controllers import (
    HealthController,
    DashboardController,
    DeviceController,
    TrafficController,
    DetectionController,
    DemoController,
    ThreatController,
    MLController,
    AlertController,
    AnalyticsController,
    ExportController,
    AuthController,
)
from backend.utils.response import api_error


class ApiRouter:
    """Dispatches HTTP requests across all 7 production API groups."""

    @staticmethod
    def dispatch(
        method: str,
        path: str,
        query: Dict[str, Any],
        body: Dict[str, Any],
        headers: Dict[str, str],
        client_ip: str = "127.0.0.1"
    ) -> Tuple[int, Any, Optional[Dict[str, str]]]:
        """
        Dispatches request and returns (status_code, response_data, optional_headers).
        """
        m = method.upper()

        # ======================================================================
        # 1. GET ROUTES
        # ======================================================================
        if m == "GET":
            # --- GROUP 1: DASHBOARD ---
            if path == "/api/dashboard/summary":
                status, data = DashboardController.get_summary()
                return status, data, None

            elif path == "/api/dashboard/traffic":
                status, data = DashboardController.get_traffic()
                return status, data, None

            elif path == "/api/dashboard/risk-distribution":
                status, data = DashboardController.get_risk_distribution()
                return status, data, None

            elif path == "/api/dashboard/alert-trends":
                status, data = DashboardController.get_alert_trends()
                return status, data, None

            elif path == "/api/dashboard/top-risk-devices":
                status, data = DashboardController.get_top_risk_devices(query)
                return status, data, None

            # --- GROUP 2: DEVICES ---
            elif path == "/api/devices":
                status, data = DeviceController.get_devices(query)
                return status, data, None

            elif path == "/api/risk/config":
                status, data = DeviceController.get_risk_config()
                return status, data, None

            # Parameterized device paths
            m_dev_traffic = re.match(r"^/api/devices/([^/]+)/traffic$", path)
            if m_dev_traffic:
                dev_id = urllib.parse.unquote(m_dev_traffic.group(1))
                status, data = DeviceController.get_device_traffic(dev_id, query)
                return status, data, None

            m_dev_alerts = re.match(r"^/api/devices/([^/]+)/alerts$", path)
            if m_dev_alerts:
                dev_id = urllib.parse.unquote(m_dev_alerts.group(1))
                status, data = DeviceController.get_device_alerts(dev_id)
                return status, data, None

            m_dev_id = re.match(r"^/api/devices/([^/]+)$", path)
            if m_dev_id:
                dev_id = urllib.parse.unquote(m_dev_id.group(1))
                if dev_id != "quarantine":
                    status, data = DeviceController.get_device_by_id(dev_id)
                    return status, data, None

            # --- GROUP 3: TRAFFIC ---
            if path == "/api/traffic/events":
                status, data = TrafficController.get_events(query)
                return status, data, None

            elif path == "/api/traffic/stats":
                status, data = TrafficController.get_stats()
                return status, data, None

            elif path == "/api/traffic/protocols":
                status, data = TrafficController.get_protocols()
                return status, data, None

            elif path == "/api/traffic":
                status, data = TrafficController.get_traffic(query)
                return status, data, None

            elif path == "/api/traffic/tick":
                status, data = TrafficController.tick_stream(query)
                return status, data, None

            # --- GROUP 4: DETECTION ---
            elif path == "/api/detection/status":
                status, data = DetectionController.get_status()
                return status, data, None

            elif path == "/api/detection/results":
                status, data = DetectionController.get_results(query)
                return status, data, None

            m_det_id = re.match(r"^/api/detection/results/([^/]+)$", path)
            if m_det_id:
                det_id = urllib.parse.unquote(m_det_id.group(1))
                status, data = DetectionController.get_result_by_id(det_id)
                return status, data, None

            elif path in ("/api/detection/rules", "/api/threats/rules"):
                status, data = DetectionController.get_rules()
                return status, data, None

            elif path == "/api/demo/scenarios":
                status, data = DemoController.get_scenarios()
                return status, data, None

            # --- GROUP 5: ALERTS ---
            elif path == "/api/alerts/unread-count":
                status, data = AlertController.get_unread_count()
                return status, data, None

            elif path == "/api/alerts":
                status, data = AlertController.get_alerts(query)
                return status, data, None

            m_alert_id = re.match(r"^/api/alerts/([^/]+)$", path)
            if m_alert_id:
                alert_id = urllib.parse.unquote(m_alert_id.group(1))
                if alert_id not in ("status", "note", "bulk", "unread-count"):
                    status, data = AlertController.get_alert_by_id(alert_id)
                    return status, data, None

            # --- GROUP 6: ANALYTICS ---
            elif path == "/api/analytics/traffic":
                status, data = AnalyticsController.get_traffic_analytics()
                return status, data, None

            elif path == "/api/analytics/devices":
                status, data = AnalyticsController.get_devices_analytics()
                return status, data, None

            elif path == "/api/analytics/threats":
                status, data = AnalyticsController.get_threats_analytics()
                return status, data, None

            elif path == "/api/analytics/incidents":
                status, data = AnalyticsController.get_incidents_analytics()
                return status, data, None

            elif path in ("/api/analytics", "/api/analytics/protocol-distribution"):
                status, data = AnalyticsController.get_analytics(query)
                return status, data, None

            # --- GROUP 7: HEALTH ---
            elif path == "/api/health/database":
                status, data = HealthController.get_database_health()
                return status, data, None

            elif path == "/api/health":
                status, data = HealthController.get_health()
                return status, data, None

            elif path == "/api/kpi":
                status, data = HealthController.get_kpis()
                return status, data, None

            # --- ML, AUTH, AUDIT, & EXPORTS ---
            elif path == "/api/ml/status":
                status, data = MLController.get_status()
                return status, data, None

            elif path in ("/api/ml/model", "/api/ml/metadata"):
                status, data = MLController.get_model()
                return status, data, None

            elif path == "/api/ml/features":
                status, data = MLController.get_features()
                return status, data, None

            elif path == "/api/ml/evaluation":
                status, data = MLController.get_evaluation()
                return status, data, None

            elif path == "/api/auth/me":
                status, data = AuthController.get_me(headers)
                return status, data, None

            elif path == "/api/audit/logs":
                status, data = AuthController.get_audit_logs(query, headers)
                return status, data, None

            elif path in ("/api/export/report", "/api/export/dossier"):
                status, raw_bytes, custom_hdrs = ExportController.export_report_markdown()
                return status, raw_bytes, custom_hdrs

            elif path == "/api/export/devices/csv":
                status, raw_bytes, custom_hdrs = ExportController.export_devices_csv()
                return status, raw_bytes, custom_hdrs

            elif path == "/api/export/alerts/csv":
                status, raw_bytes, custom_hdrs = ExportController.export_alerts_csv()
                return status, raw_bytes, custom_hdrs

            elif path == "/api/export/alerts/json":
                status, raw_bytes, custom_hdrs = ExportController.export_alerts_json()
                return status, raw_bytes, custom_hdrs

            elif path == "/api/export/analytics/csv":
                status, raw_bytes, custom_hdrs = ExportController.export_analytics_csv(query)
                return status, raw_bytes, custom_hdrs

            elif path == "/api/export/analytics/json":
                status, raw_bytes, custom_hdrs = ExportController.export_analytics_json(query)
                return status, raw_bytes, custom_hdrs

        # ======================================================================
        # 2. POST ROUTES
        # ======================================================================
        elif m == "POST":
            # Devices
            if path == "/api/devices":
                status, data = DeviceController.create_device(body, headers)
                return status, data, None

            elif path == "/api/devices/quarantine":
                status, data = DeviceController.quarantine_device(body, headers)
                return status, data, None

            elif path == "/api/risk/config":
                status, data = DeviceController.update_risk_config(body, headers)
                return status, data, None

            # Traffic
            elif path == "/api/traffic/events":
                status, data = TrafficController.ingest_event(body, headers, client_ip)
                return status, data, None

            elif path == "/api/traffic/events/batch":
                status, data = TrafficController.ingest_batch(body, headers, client_ip)
                return status, data, None

            elif path == "/api/traffic/ingest":
                status, data = TrafficController.ingest_flow(body)
                return status, data, None

            elif path == "/api/simulation/attack":
                status, data = TrafficController.trigger_simulation_attack(body)
                return status, data, None

            # Demo Scenarios
            elif path in ("/api/demo/scenario", "/api/traffic/demo"):
                status, data = DemoController.trigger_scenario(body)
                return status, data, None

            # Detection
            elif path == "/api/detection/analyze":
                status, data = DetectionController.analyze(body)
                return status, data, None

            elif path == "/api/threats/rules/update":
                status, data = ThreatController.update_rule(body)
                return status, data, None

            m_rule_post = re.match(r"^/api/detection/rules/([^/]+)$", path)
            if m_rule_post:
                rule_id = urllib.parse.unquote(m_rule_post.group(1))
                status, data = DetectionController.update_rule(rule_id, body)
                return status, data, None

            # Alerts
            elif path == "/api/alerts/status":
                status, data = AlertController.update_status(body, headers)
                return status, data, None

            elif path == "/api/alerts/note":
                status, data = AlertController.add_note(body, headers)
                return status, data, None

            elif path == "/api/alerts/bulk":
                status, data = AlertController.bulk_action(body, headers)
                return status, data, None

            # ML & Auth
            elif path == "/api/ml/retrain":
                status, data = MLController.retrain(body)
                return status, data, None

            elif path == "/api/ml/predict":
                status, data = MLController.predict(body)
                return status, data, None

            elif path == "/api/auth/login":
                status, data = AuthController.login(body, client_ip=client_ip)
                return status, data, None

            elif path == "/api/auth/logout":
                status, data = AuthController.logout(body, headers, client_ip=client_ip)
                return status, data, None

            elif path == "/api/auth/refresh":
                status, data = AuthController.refresh(body)
                return status, data, None

            elif path == "/api/system/retention/purge":
                status, data = HealthController.purge_retention(body, headers)
                return status, data, None

            elif path in ("/api/security/rate-limit/reset", "/api/system/rate-limit/reset"):
                from backend.middleware.security import security_manager
                security_manager.reset_rate_limits()
                return 200, {"success": True, "message": "Rate limits reset successfully."}, None

        # ======================================================================
        # 3. PATCH ROUTES
        # ======================================================================
        elif m == "PATCH":
            # PATCH /api/devices/:id
            m_dev_patch = re.match(r"^/api/devices/([^/]+)$", path)
            if m_dev_patch:
                dev_id = urllib.parse.unquote(m_dev_patch.group(1))
                status, data = DeviceController.update_device(dev_id, body, headers)
                return status, data, None

            # PATCH /api/alerts/:id/status
            m_alert_status = re.match(r"^/api/alerts/([^/]+)/status$", path)
            if m_alert_status:
                alert_id = urllib.parse.unquote(m_alert_status.group(1))
                status, data = AlertController.patch_status(alert_id, body, headers)
                return status, data, None

            # PATCH /api/alerts/:id/acknowledge
            m_alert_ack = re.match(r"^/api/alerts/([^/]+)/acknowledge$", path)
            if m_alert_ack:
                alert_id = urllib.parse.unquote(m_alert_ack.group(1))
                status, data = AlertController.acknowledge_alert(alert_id, body, headers)
                return status, data, None

            # PATCH /api/detection/rules/:id
            m_rule_patch = re.match(r"^/api/detection/rules/([^/]+)$", path)
            if m_rule_patch:
                rule_id = urllib.parse.unquote(m_rule_patch.group(1))
                status, data = DetectionController.update_rule(rule_id, body)
                return status, data, None

        # ======================================================================
        # 4. DELETE ROUTES
        # ======================================================================
        elif m == "DELETE":
            # DELETE /api/devices/:id
            m_dev_del = re.match(r"^/api/devices/([^/]+)$", path)
            if m_dev_del:
                dev_id = urllib.parse.unquote(m_dev_del.group(1))
                status, data = DeviceController.delete_device(dev_id, query, body, headers)
                return status, data, None

        # Route Not Found
        return 404, api_error(f"Route {m} {path} not found", status_code=404, error_code="ROUTE_NOT_FOUND"), None
