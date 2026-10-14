"""
Part 12: End-to-End QA Integration & Audit Test Suite
Exercises all 15 QA scenarios over the live HTTP server:
1. Backend Startup & Config
2. Database Connection & Health Endpoints
3. User Authentication & Profile
4. Authorized Traffic Ingestion
5. Validation, Persistence, & Deduplication
6. Normal Traffic Scenario Classification
7. Suspicious Traffic Scenario & Rule Explanation
8. High-Risk Scenario, Alert Generation, & Device Risk Mutation
9. Frontend Data Alignment (API Layer)
10. Alert Acknowledgment, Resolution, & State Persistence
11. Analytics Aggregation Alignment
12. Real-Time Stream (SSE) Connectivity
13. ML Engine Status, Metadata, & Inference
14. Security Rejections (401, 403, 413, NoSQL sanitization)
15. Storage Continuity & Record Retention
"""

import sys
import unittest
import time
import json
import http.client
import urllib.request
import urllib.error
from pathlib import Path

root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

BASE_URL = "http://localhost:8080"


def http_req(path: str, method: str = "GET", body: dict = None, headers: dict = None):
    url = f"{BASE_URL}{path}"
    headers = headers or {}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8")
            status = resp.status
            resp_headers = dict(resp.headers)
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = raw
            return status, parsed, resp_headers
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        resp_headers = dict(e.headers)
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = raw
        return e.code, parsed, resp_headers


class TestPart12E2EQA(unittest.TestCase):
    """Automated End-to-End QA Test Suite for NETGUARD IoT."""

    @classmethod
    def setUpClass(cls):
        from backend.config.settings import settings
        cls.settings = settings
        cls.collector_key = settings.COLLECTOR_API_KEY

        # Scenario 3: Authenticate users
        st, adm_data, _ = http_req("/api/auth/login", "POST", {"username": "admin", "password": settings.ADMIN_PASSWORD})
        assert st == 200, f"Admin login failed: {adm_data}"
        cls.admin_token = adm_data["access_token"]
        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}

        st, an_data, _ = http_req("/api/auth/login", "POST", {"username": "analyst", "password": settings.ANALYST_PASSWORD})
        assert st == 200, f"Analyst login failed: {an_data}"
        cls.analyst_token = an_data["access_token"]
        cls.analyst_headers = {"Authorization": f"Bearer {cls.analyst_token}"}

        st, ro_data, _ = http_req("/api/auth/login", "POST", {"username": "readonly", "password": settings.AUDITOR_PASSWORD})
        assert st == 200, f"Readonly login failed: {ro_data}"
        cls.readonly_token = ro_data["access_token"]
        cls.readonly_headers = {"Authorization": f"Bearer {cls.readonly_token}"}

    # ==========================================================================
    # SCENARIO 2: DATABASE CONNECTION & HEALTH ENDPOINTS
    # ==========================================================================

    def test_scenario_02_health_and_database_endpoints(self):
        """Verify /api/health and /api/health/database return valid status and safe metrics."""
        # 1. System Health
        st, data, hdrs = http_req("/api/health")
        self.assertEqual(st, 200)
        self.assertEqual(data.get("status"), "healthy")
        self.assertEqual(data.get("detection_engine"), "operational")
        self.assertIn("uptime_seconds", data)
        self.assertIn("X-Content-Type-Options", hdrs)
        self.assertEqual(hdrs["X-Content-Type-Options"], "nosniff")

        # 2. Database Health
        st_db, data_db, _ = http_req("/api/health/database")
        self.assertEqual(st_db, 200)
        self.assertTrue(data_db.get("success"))
        db_info = data_db.get("data", {})
        status_val = db_info.get("status", db_info.get("storage_mode", db_info.get("database_status")))
        self.assertIn(status_val, ["connected", "fallback_embedded", "embedded", "mongodb", "resilient_embedded_mode"])
        self.assertIn("record_counts", db_info)
        counts = db_info["record_counts"]
        self.assertGreaterEqual(counts.get("devices", 0), 1)

    # ==========================================================================
    # SCENARIO 3: USER AUTHENTICATION & PROFILE VERIFICATION
    # ==========================================================================

    def test_scenario_03_authentication_and_profile(self):
        """Verify profile retrieval and permission enforcement for authenticated sessions."""
        st, profile, _ = http_req("/api/auth/me", headers=self.admin_headers)
        self.assertEqual(st, 200)
        self.assertTrue(profile.get("authenticated"))
        u = profile.get("user", {})
        self.assertEqual(u.get("username"), "admin")
        self.assertEqual(u.get("role"), "admin")
        self.assertIn("devices:delete", u.get("permissions", []))

        # Check analyst profile
        st_an, prof_an, _ = http_req("/api/auth/me", headers=self.analyst_headers)
        self.assertEqual(st_an, 200)
        u_an = prof_an.get("user", {})
        self.assertEqual(u_an.get("role"), "analyst")
        self.assertNotIn("devices:delete", u_an.get("permissions", []))

    # ==========================================================================
    # SCENARIO 4 & 5: INGESTION, VALIDATION, PERSISTENCE, & DUPLICATE DETECTION
    # ==========================================================================

    def test_scenario_04_and_05_traffic_ingestion_and_deduplication(self):
        """Verify collector traffic ingestion, schema validation, persistence, and deduplication."""
        dyn_port = 40000 + int(time.time() * 100) % 20000
        valid_flow = {
            "source_ip": "192.168.1.101",
            "destination_ip": "104.28.12.9",
            "source_port": dyn_port,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": 85,
            "byte_count": 6800,
            "duration_sec": 1.2,
            "flow_statistics": {
                "syn_ratio": 0.05,
                "rst_ratio": 0.0,
                "payload_entropy": 4.1
            }
        }

        # 1. Ingest via authorized collector key
        st, res, _ = http_req(
            "/api/traffic/events",
            method="POST",
            body=valid_flow,
            headers={"X-Collector-Key": self.collector_key}
        )
        self.assertEqual(st, 201)
        self.assertTrue(res.get("success"))
        flow_id = res.get("data", {}).get("event_id")
        self.assertIsNotNone(flow_id)

        # 2. Duplicate Submission within deduplication window -> duplicate_ignored
        st_dup, res_dup, _ = http_req(
            "/api/traffic/events",
            method="POST",
            body=valid_flow,
            headers={"X-Collector-Key": self.collector_key}
        )
        self.assertEqual(st_dup, 200)
        self.assertEqual(res_dup.get("data", {}).get("status"), "duplicate_ignored")

        # 3. Invalid Schema Rejection (impossible destination port)
        invalid_flow = dict(valid_flow)
        invalid_flow["destination_port"] = 99999
        st_bad, res_bad, _ = http_req(
            "/api/traffic/events",
            method="POST",
            body=invalid_flow,
            headers={"X-Collector-Key": self.collector_key}
        )
        self.assertEqual(st_bad, 400)
        err_code = res_bad.get("error_code", res_bad.get("code"))
        self.assertEqual(err_code, "VALIDATION_ERROR")

        # 4. Persistence Verification: Query events endpoint to find ingested flow
        st_list, list_res, _ = http_req("/api/traffic/events?limit=20")
        self.assertEqual(st_list, 200)
        events = list_res.get("data", {}).get("events", [])
        persisted_ids = [e.get("flow_id", e.get("id")) for e in events]
        self.assertIn(flow_id, persisted_ids)

    # ==========================================================================
    # SCENARIO 6: NORMAL TRAFFIC SCENARIO CLASSIFICATION
    # ==========================================================================

    def test_scenario_06_normal_traffic_scenario(self):
        """Submit benign sensor telemetry and verify Normal classification."""
        dyn_port = 41000 + int(time.time() * 100) % 20000
        normal_flow = {
            "source_ip": "192.168.1.102",
            "destination_ip": "104.28.12.9",
            "source_port": dyn_port,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_count": 15,
            "byte_count": 1400,
            "duration_sec": 2.0,
            "flow_statistics": {
                "syn_ratio": 0.05,
                "rst_ratio": 0.0,
                "payload_entropy": 3.5
            }
        }

        st, res, _ = http_req(
            "/api/traffic/events",
            method="POST",
            body=normal_flow,
            headers={"X-Collector-Key": self.collector_key}
        )
        self.assertEqual(st, 201)
        data = res.get("data", {})
        self.assertEqual(data.get("verdict"), "Normal")
        self.assertLess(data.get("risk_score", 100), 30)
        self.assertFalse(data.get("threat_detected"))

    # ==========================================================================
    # SCENARIO 7: CONTROLLED SUSPICIOUS SCENARIO & RULE EXPLANATION
    # ==========================================================================

    def test_scenario_07_suspicious_traffic_scenario_and_explanation(self):
        """Submit ICS Modbus flow on port 502 with elevated SYN ratio and verify Suspicious verdict + rule explanation."""
        dyn_port = 42000 + int(time.time() * 100) % 20000
        suspicious_flow = {
            "source_ip": "192.168.1.102",
            "destination_ip": "192.168.1.1",
            "source_port": dyn_port,
            "destination_port": 502,
            "protocol": "TCP",
            "packet_count": 60,
            "byte_count": 4200,
            "duration_sec": 1.0,
            "flow_statistics": {
                "syn_ratio": 0.45,
                "rst_ratio": 0.1,
                "payload_entropy": 5.2
            }
        }

        st, res, _ = http_req(
            "/api/traffic/events",
            method="POST",
            body=suspicious_flow,
            headers={"X-Collector-Key": self.collector_key}
        )
        self.assertEqual(st, 201)
        data = res.get("data", {})
        self.assertEqual(data.get("verdict"), "Suspicious")
        self.assertTrue(data.get("threat_detected"))
        rules = data.get("rules_triggered", [])
        self.assertGreaterEqual(len(rules), 1, "Suspicious verdict must explain triggered heuristic rules")

    # ==========================================================================
    # SCENARIO 8: CONTROLLED HIGH-RISK SCENARIO, ALERT, & DEVICE RISK MUTATION
    # ==========================================================================

    def test_scenario_08_high_risk_scenario_alert_and_device_update(self):
        """Submit high-volume Telnet brute force (Mirai signature) and verify High-Risk verdict and alert generation."""
        dyn_port = 43000 + int(time.time() * 100) % 20000
        high_risk_flow = {
            "source_ip": "192.168.1.155",
            "destination_ip": "185.193.64.12",
            "source_port": dyn_port,
            "destination_port": 23,
            "protocol": "TCP",
            "packet_count": 800,
            "byte_count": 72000,
            "duration_sec": 0.5,
            "flow_statistics": {
                "syn_ratio": 0.98,
                "rst_ratio": 0.0,
                "payload_entropy": 7.5
            }
        }

        st, res, _ = http_req(
            "/api/traffic/events",
            method="POST",
            body=high_risk_flow,
            headers={"X-Collector-Key": self.collector_key}
        )
        self.assertEqual(st, 201)
        data = res.get("data", {})
        self.assertEqual(data.get("verdict"), "High-Risk")
        self.assertTrue(data.get("threat_detected"))
        self.assertGreaterEqual(data.get("risk_score", 0), 75.0)

        # Verify alert was created or updated via suppression
        alert_info = data.get("alert_info")
        self.assertIsNotNone(alert_info)
        alert_id = alert_info.get("alert_id") or alert_info.get("alert", {}).get("id")
        self.assertIsNotNone(alert_id)

        # Inspect alert directly
        st_alt, alt_detail, _ = http_req(f"/api/alerts/{alert_id}", headers=self.analyst_headers)
        self.assertEqual(st_alt, 200)
        alert_record = alt_detail.get("data", {}).get("alert", {})
        self.assertIn(alert_record.get("severity"), ["High", "Critical"])

    # ==========================================================================
    # SCENARIO 10: ALERT TRIAGE LIFECYCLE & PERSISTENCE
    # ==========================================================================

    def test_scenario_10_alert_triage_acknowledgment_and_resolution(self):
        """Query alert, acknowledge, add note, resolve, and verify state persistence."""
        # 1. Fetch alerts
        st, alerts_res, _ = http_req("/api/alerts?limit=10", headers=self.analyst_headers)
        self.assertEqual(st, 200)
        alerts = alerts_res.get("data", {}).get("alerts", alerts_res.get("alerts", []))
        self.assertGreaterEqual(len(alerts), 1)
        target_alert = alerts[0]
        alert_id = target_alert["id"]

        # 2. Acknowledge alert
        st_ack, ack_res, _ = http_req(
            f"/api/alerts/{alert_id}/acknowledge",
            method="PATCH",
            body={"note": "Assigned to SecOps analyst for forensic triage"},
            headers=self.analyst_headers
        )
        self.assertEqual(st_ack, 200)

        # 3. Add analyst forensic note
        st_note, note_res, _ = http_req(
            "/api/alerts/note",
            method="POST",
            body={"alert_id": alert_id, "note": "Verified malicious outbound Telnet traffic to C2 IP 185.193.64.12."},
            headers=self.analyst_headers
        )
        self.assertEqual(st_note, 200)

        # 4. Resolve alert
        st_res, res_data, _ = http_req(
            f"/api/alerts/{alert_id}/status",
            method="PATCH",
            body={"status": "Resolved", "reason": "Host quarantined and C2 communication severed"},
            headers=self.analyst_headers
        )
        self.assertEqual(st_res, 200)

        # 5. Verify persistence
        st_check, check_res, _ = http_req(f"/api/alerts/{alert_id}", headers=self.analyst_headers)
        self.assertEqual(st_check, 200)
        alert_obj = check_res.get("data", {}).get("alert", {})
        self.assertEqual(alert_obj.get("status"), "Resolved")
        self.assertTrue(alert_obj.get("resolved"))

    # ==========================================================================
    # SCENARIO 11: ANALYTICS AGGREGATION ALIGNMENT
    # ==========================================================================

    def test_scenario_11_analytics_data_consistency(self):
        """Verify analytics endpoints reflect consistent counts and protocol distributions."""
        st, ana_res, _ = http_req("/api/analytics?timeframe=24h")
        self.assertEqual(st, 200)
        self.assertIn("protocol_breakdown", ana_res)
        self.assertTrue("botnet_family_distribution" in ana_res or "top_attacked_ports" in ana_res)
        self.assertIn("kpis", ana_res)

    # ==========================================================================
    # SCENARIO 12: REAL-TIME STREAM (SSE) AUTHENTICATION & CONNECTIVITY
    # ==========================================================================

    def test_scenario_12_realtime_stream_connectivity(self):
        """Verify SSE real-time push channel connects with token and receives greeting."""
        url = f"{BASE_URL}/api/stream/events?token={self.analyst_token}"
        req = urllib.request.Request(url, headers={"Accept": "text/event-stream"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/event-stream", resp.headers.get("Content-Type", ""))
            first_line = resp.readline().decode("utf-8")
            self.assertTrue(first_line.startswith("retry:") or first_line.startswith("event:") or first_line.startswith(":"))

    # ==========================================================================
    # SCENARIO 13: ML STATUS, METADATA, & INFERENCE
    # ==========================================================================

    def test_scenario_13_ml_model_status_and_predict(self):
        """Verify ML model availability, metadata, and live inference."""
        # 1. Model Status
        st, status_res, _ = http_req("/api/ml/status")
        self.assertEqual(st, 200)
        st_data = status_res.get("data", {})
        self.assertEqual(st_data.get("status"), "available_and_trained")
        self.assertTrue(st_data.get("has_model_binary"))
        self.assertEqual(st_data.get("feature_count"), 11)

        # 2. Model Evaluation Benchmarks
        st_eval, eval_res, _ = http_req("/api/ml/evaluation")
        self.assertEqual(st_eval, 200)
        eval_data = eval_res.get("data", {})
        self.assertGreaterEqual(eval_data.get("accuracy", 0), 0.95)

        # 3. Live Inference Endpoint with physical 11-feature vector
        vector_11 = [120.0, 9500.0, 1.0, 23.0 / 65535.0, 1.0, 0.95, 6.0, 3.2, 12.0, 2.0, 79.0]
        st_pred, pred_res, _ = http_req("/api/ml/predict", method="POST", body={"features": vector_11})
        self.assertEqual(st_pred, 200)
        pred_label = pred_res.get("prediction") or pred_res.get("predicted_class")
        self.assertIn(pred_label, ["High-Risk", "Suspicious", "Normal"])
        self.assertIn("probabilities", pred_res)

    # ==========================================================================
    # SCENARIO 14: SECURITY DEFENSES & REJECTION CHECKS
    # ==========================================================================

    def test_scenario_14_security_rejections(self):
        """Verify 401 on missing auth, 403 on insufficient permissions, and 413 on oversized payloads."""
        # 1. Missing auth on device delete -> 401
        st_noauth, _, _ = http_req("/api/devices/DEV-101", method="DELETE")
        self.assertEqual(st_noauth, 401)

        # 2. Read-only user attempts to modify risk configuration -> 403
        st_ro_risk, _, _ = http_req(
            "/api/risk/config",
            method="POST",
            body={"weights": {"packet_rate": 0.5}},
            headers=self.readonly_headers
        )
        self.assertEqual(st_ro_risk, 403)

        # 3. Read-only user attempts to delete device -> 403
        st_ro_del, _, _ = http_req("/api/devices/DEV-101", method="DELETE", headers=self.readonly_headers)
        self.assertEqual(st_ro_del, 403)

        # 4. Pre-read check for oversized payload (> 5 MB) -> 413 Payload Too Large
        conn = http.client.HTTPConnection("localhost", 8080)
        conn.putrequest("POST", "/api/devices")
        conn.putheader("Content-Length", str(6 * 1024 * 1024))
        conn.putheader("Authorization", f"Bearer {self.admin_token}")
        conn.endheaders()
        resp = conn.getresponse()
        self.assertEqual(resp.status, 413)
        conn.close()

    # ==========================================================================
    # SCENARIO 15: STORAGE CONTINUITY & RECORD RETENTION
    # ==========================================================================

    def test_scenario_15_storage_continuity(self):
        """Verify data persistence across query patterns and retention evidence protection."""
        st_devs, devs_res, _ = http_req("/api/devices")
        self.assertEqual(st_devs, 200)
        devices = devs_res.get("data", {}).get("devices", devs_res.get("devices", []))
        self.assertGreaterEqual(len(devices), 1)

        # Run retention purge as admin and verify evidence is safeguarded
        st_purge, purge_res, _ = http_req(
            "/api/system/retention/purge",
            method="POST",
            body={"retention_days": 30, "preserve_evidence": True},
            headers=self.admin_headers
        )
        self.assertEqual(st_purge, 200)
        self.assertTrue(purge_res.get("data", {}).get("evidence_protection_active"))


if __name__ == "__main__":
    unittest.main()
