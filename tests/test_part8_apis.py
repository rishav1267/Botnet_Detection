"""
Unit and Integration Tests for Part 8 Functional REST APIs
Exercises every API group with valid and invalid inputs, verifying status codes,
validation schemas, state transitions, security controls, and response structures.
"""

import os
import sys
import unittest

# Ensure parent directory is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.routes.api_router import ApiRouter
from backend.config.settings import settings


class TestPart8APIs(unittest.TestCase):
    """Exercises all 7 API groups for Part 8."""

    def dispatch(self, method: str, path: str, query=None, body=None, headers=None, client_ip="127.0.0.1"):
        query = query or {}
        body = body or {}
        headers = headers or {}
        status, data, _ = ApiRouter.dispatch(method, path, query, body, headers, client_ip)
        return status, data

    # ==========================================================================
    # GROUP 1: DASHBOARD
    # ==========================================================================
    def test_01_dashboard_summary(self):
        st, data = self.dispatch("GET", "/api/dashboard/summary")
        self.assertEqual(st, 200)
        self.assertTrue(data["success"])
        res = data["data"]
        for key in ["total_devices", "normal_count", "suspicious_count", "high_risk_count", "quarantined_count", "health_score", "current_pps", "current_mbps"]:
            self.assertIn(key, res)

    def test_02_dashboard_traffic(self):
        st, data = self.dispatch("GET", "/api/dashboard/traffic")
        self.assertEqual(st, 200)
        self.assertTrue(data["success"])
        res = data["data"]
        self.assertIn("current_pps", res)
        self.assertIn("current_mbps", res)
        self.assertIn("packet_rate_history", res)

    def test_03_dashboard_risk_distribution(self):
        st, data = self.dispatch("GET", "/api/dashboard/risk-distribution")
        self.assertEqual(st, 200)
        res = data["data"]
        self.assertIn("tiers", res)
        self.assertIn("by_device_type", res)
        self.assertIn("Normal", res["tiers"])
        self.assertIn("High-Risk", res["tiers"])

    def test_04_dashboard_alert_trends(self):
        st, data = self.dispatch("GET", "/api/dashboard/alert-trends")
        self.assertEqual(st, 200)
        res = data["data"]
        self.assertIn("severity_counts", res)
        self.assertIn("hourly_trends", res)

    def test_05_dashboard_top_risk_devices(self):
        st, data = self.dispatch("GET", "/api/dashboard/top-risk-devices", query={"limit": ["3"]})
        self.assertEqual(st, 200)
        res = data["data"]
        self.assertIn("top_risk_devices", res)
        self.assertLessEqual(len(res["top_risk_devices"]), 3)

    # ==========================================================================
    # GROUP 2: DEVICES CRUD & SAFEGUARDS
    # ==========================================================================
    def test_06_devices_list_and_filters(self):
        # Unfiltered list
        st, data = self.dispatch("GET", "/api/devices")
        self.assertEqual(st, 200)
        self.assertIn("devices", data)

        # Filtered with pagination
        st, data = self.dispatch("GET", "/api/devices", query={"page": ["1"], "limit": ["5"], "risk_level": ["Normal"]})
        self.assertEqual(st, 200)
        self.assertIn("pagination", data)
        self.assertEqual(data["pagination"]["page"], 1)
        self.assertLessEqual(len(data["devices"]), 5)

    def test_07_device_by_id(self):
        st, data = self.dispatch("GET", "/api/devices/DEV-101")
        self.assertEqual(st, 200)
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["device"]["id"], "DEV-101")

        # 404 on non-existent
        st_404, data_404 = self.dispatch("GET", "/api/devices/DEV-DOES-NOT-EXIST")
        self.assertEqual(st_404, 404)
        self.assertFalse(data_404["success"])

    def test_08_device_traffic_and_alerts(self):
        st, data = self.dispatch("GET", "/api/devices/DEV-101/traffic")
        self.assertEqual(st, 200)
        self.assertIn("flows", data["data"])

        st, data = self.dispatch("GET", "/api/devices/DEV-101/alerts")
        self.assertEqual(st, 200)
        self.assertIn("alerts", data["data"])

    def test_09_device_create_and_validation(self):
        # Invalid IP
        st, data = self.dispatch("POST", "/api/devices", body={
            "name": "Invalid Node",
            "type": "Camera",
            "ip_address": "999.999.999.999",
            "mac_address": "AA:BB:CC:DD:EE:FF"
        })
        self.assertEqual(st, 400)

        # Invalid MAC
        st, data = self.dispatch("POST", "/api/devices", body={
            "name": "Invalid Node",
            "type": "Camera",
            "ip_address": "192.168.1.50",
            "mac_address": "NOT-A-MAC"
        })
        self.assertEqual(st, 400)

        # Valid create
        valid_payload = {
            "id": "DEV-TEST-PART8",
            "name": "Smart Water Sensor",
            "type": "Industrial Flow Sensor",
            "ip_address": "192.168.1.199",
            "mac_address": "00:1A:2B:3C:4D:99",
            "location": "Water Treatment Plant",
            "firmware_version": "2.1.0"
        }
        st, data = self.dispatch("POST", "/api/devices", body=valid_payload)
        self.assertEqual(st, 201)
        self.assertEqual(data["data"]["device"]["id"], "DEV-TEST-PART8")

        # Duplicate ID conflict (409)
        st_dup, data_dup = self.dispatch("POST", "/api/devices", body=valid_payload)
        self.assertEqual(st_dup, 409)

    def test_10_device_patch(self):
        # Update valid fields
        st, data = self.dispatch("PATCH", "/api/devices/DEV-TEST-PART8", body={
            "name": "Smart Water Sensor (Updated)",
            "location": "Filtration Zone 2"
        })
        self.assertEqual(st, 200)
        self.assertEqual(data["data"]["device"]["name"], "Smart Water Sensor (Updated)")

        # Invalid status
        st, data = self.dispatch("PATCH", "/api/devices/DEV-TEST-PART8", body={"status": "SuperDangerous"})
        self.assertEqual(st, 400)

    def test_11_device_delete_safeguard(self):
        from backend.middleware.auth import generate_token
        admin_hdrs = {"Authorization": f"Bearer {generate_token('admin-test', 'admin', role='admin')}"}
        # First quarantine the device
        self.dispatch("POST", "/api/devices/quarantine", body={"device_id": "DEV-TEST-PART8", "quarantined": True}, headers=admin_hdrs)

        # Attempt delete without force -> blocked by safeguard (400)
        st_blocked, data_blocked = self.dispatch("DELETE", "/api/devices/DEV-TEST-PART8", headers=admin_hdrs)
        self.assertEqual(st_blocked, 400)
        self.assertIn("safeguard", str(data_blocked).lower())

        # Delete with explicit force -> 200 OK
        st_ok, data_ok = self.dispatch("DELETE", "/api/devices/DEV-TEST-PART8", query={"force": ["true"]}, headers=admin_hdrs)
        self.assertEqual(st_ok, 200)
        self.assertEqual(data_ok["data"]["deleted_id"], "DEV-TEST-PART8")

    # ==========================================================================
    # GROUP 3: TRAFFIC INGESTION & STATS
    # ==========================================================================
    def test_12_traffic_ingestion_auth_and_schema(self):
        flow_payload = {
            "source_ip": "192.168.1.45",
            "destination_ip": "10.0.0.1",
            "source_port": 502,
            "destination_port": 502,
            "protocol": "TCP",
            "packet_count": 150,
            "byte_count": 9600,
            "duration_sec": 1.2
        }

        # 1. Unauthenticated request -> 401 Unauthorized
        st_no_auth, data_no_auth = self.dispatch("POST", "/api/traffic/events", body=flow_payload)
        self.assertEqual(st_no_auth, 401)
        self.assertEqual(data_no_auth["error_code"], "UNAUTHORIZED")

        # 2. Authenticated but invalid port
        bad_port_payload = dict(flow_payload, destination_port=999999)
        st_bad, data_bad = self.dispatch(
            "POST", "/api/traffic/events",
            body=bad_port_payload,
            headers={"X-API-Key": settings.INGESTION_API_KEY}
        )
        self.assertEqual(st_bad, 400)

        # 3. Authenticated valid request -> 201 Created
        st_ok, data_ok = self.dispatch(
            "POST", "/api/traffic/events",
            body=flow_payload,
            headers={"X-API-Key": settings.INGESTION_API_KEY}
        )
        self.assertEqual(st_ok, 201)
        self.assertTrue(data_ok["success"])
        self.assertIn("event_id", data_ok["data"])
        self.assertIn("verdict", data_ok["data"])

    def test_13_traffic_stats_and_protocols(self):
        st, data = self.dispatch("GET", "/api/traffic/stats")
        self.assertEqual(st, 200)
        self.assertIn("current_pps", data["data"])
        self.assertIn("total_packets", data["data"])

        st, data = self.dispatch("GET", "/api/traffic/protocols")
        self.assertEqual(st, 200)
        self.assertIn("protocols", data["data"])

    # ==========================================================================
    # GROUP 4: DETECTION
    # ==========================================================================
    def test_14_detection_analyze_and_status(self):
        # Ad-hoc analysis with raw flow
        st, data = self.dispatch("POST", "/api/detection/analyze", body={
            "flow": {
                "packet_count": 500,
                "byte_count": 32000,
                "packets_per_sec": 250.0,
                "syn_ratio": 0.95,
                "dest_port": 23,
                "protocol": "TCP"
            }
        })
        self.assertEqual(st, 200)
        res = data["data"]
        self.assertIn("detection_id", res)
        self.assertIn("verdict", res)
        self.assertIn("ml_analysis", res)

        # Detection engine status
        st_st, data_st = self.dispatch("GET", "/api/detection/status")
        self.assertEqual(st_st, 200)
        self.assertIn("rule_engine", data_st["data"])
        self.assertIn("ml_engine", data_st["data"])

        # Fetch detection results paginated
        st_res, data_res = self.dispatch("GET", "/api/detection/results")
        self.assertEqual(st_res, 200)
        self.assertIn("results", data_res["data"])

    # ==========================================================================
    # GROUP 5: ALERTS & STATE TRANSITIONS
    # ==========================================================================
    def test_15_alerts_triage_and_state_transitions(self):
        # Fetch alert ID
        st, data = self.dispatch("GET", "/api/alerts")
        self.assertEqual(st, 200)
        alerts = data["alerts"]
        self.assertTrue(len(alerts) > 0)
        alert_id = alerts[0]["id"]

        # 1. Acknowledge alert
        st_ack, data_ack = self.dispatch("PATCH", f"/api/alerts/{alert_id}/acknowledge", body={"analyst": "Lead Analyst"})
        self.assertEqual(st_ack, 200)

        # 2. Transition to Resolved
        st_res, data_res = self.dispatch("PATCH", f"/api/alerts/{alert_id}/status", body={"status": "Resolved", "reason": "Patched device firewall"})
        self.assertEqual(st_res, 200)

        # 3. Transition from Resolved back to Investigating WITHOUT reason -> Blocked (400)
        st_inv_bad, data_inv_bad = self.dispatch("PATCH", f"/api/alerts/{alert_id}/status", body={"status": "Investigating"})
        self.assertEqual(st_inv_bad, 400)
        self.assertIn("reason", str(data_inv_bad).lower())

        # 4. Transition from Resolved with reason -> 200 OK
        st_inv_ok, data_inv_ok = self.dispatch("PATCH", f"/api/alerts/{alert_id}/status", body={"status": "Investigating", "reason": "Further telemetry required"})
        self.assertEqual(st_inv_ok, 200)

        # 5. Check unread count endpoint
        st_cnt, data_cnt = self.dispatch("GET", "/api/alerts/unread-count")
        self.assertEqual(st_cnt, 200)
        self.assertIn("unread_count", data_cnt["data"])

    # ==========================================================================
    # GROUP 6: ANALYTICS
    # ==========================================================================
    def test_16_analytics_endpoints(self):
        for ep in ["traffic", "devices", "threats", "incidents"]:
            st, data = self.dispatch("GET", f"/api/analytics/{ep}")
            self.assertEqual(st, 200)
            self.assertTrue(data["success"])

    # ==========================================================================
    # GROUP 7: HEALTH (NO SECRETS)
    # ==========================================================================
    def test_17_health_no_secrets(self):
        st, data = self.dispatch("GET", "/api/health")
        self.assertEqual(st, 200)
        text = str(data).lower()
        self.assertNotIn("password", text)
        self.assertNotIn("secret", text)

        st, data_db = self.dispatch("GET", "/api/health/database")
        self.assertEqual(st, 200)
        text_db = str(data_db).lower()
        self.assertNotIn("password", text_db)
        self.assertNotIn("mongodb://", text_db)
        self.assertIn("storage_mode", data_db["data"])
        self.assertIn("record_counts", data_db["data"])


if __name__ == "__main__":
    unittest.main()
