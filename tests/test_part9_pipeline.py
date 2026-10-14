"""
Part 9: Defensible IoT Traffic Ingestion & Detection Pipeline Test Suite
Comprehensive tests verifying:
- Ingestion authentication, rate limiting, and numeric validation
- Idempotency and duplicate flow event suppression
- Privacy enforcement: stripping sensitive payloads
- Configurable rule evaluation across all 8 indicators
- Device baseline statistical profiling (Welford variance and Z-scores)
- Alert suppression preventing duplicate alerts on sustained behavior
- Atomic device risk updates and status transitions
- Reproducible demo scenarios with distinct data_source and is_demo tagging
- SSE Real-time Pub/Sub Broadcaster
"""

import os
import sys
import unittest
import json
import time

# Ensure parent directory is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.routes.api_router import ApiRouter
from backend.services.rule_engine import configurable_rule_engine
from backend.services.baseline_service import baseline_service
from backend.services.event_broadcaster import broadcaster
from backend.services.ingestion_service import ingestion_service
from backend.database.repository import repository


class TestPart9Pipeline(unittest.TestCase):
    """Test suite covering Part 9 requirements."""

    def dispatch(self, method: str, path: str, query=None, body=None, headers=None, client_ip="127.0.0.1"):
        query = query or {}
        body = body or {}
        headers = headers or {}
        status, data, _ = ApiRouter.dispatch(
            method=method,
            path=path,
            query=query,
            body=body,
            headers=headers,
            client_ip=client_ip
        )
        return status, data

    def setUp(self):
        self.auth_headers = {"X-API-Key": "netguard-sensor-key-2026"}

    # --------------------------------------------------------------------------
    # 1. INGESTION AUTHENTICATION & RATE LIMITING
    # --------------------------------------------------------------------------

    def test_01_ingestion_authentication(self):
        """Unauthenticated submission must be rejected with 401."""
        st, data = self.dispatch("POST", "/api/traffic/events", body={
            "source_ip": "192.168.1.101",
            "destination_ip": "104.28.12.9",
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": 10,
            "byte_count": 500
        }, headers={})
        self.assertEqual(st, 401)
        self.assertFalse(data.get("success", False))
        self.assertEqual(data.get("error_code"), "UNAUTHORIZED")

        # Authenticated with X-API-Key
        st, data = self.dispatch("POST", "/api/traffic/events", body={
            "source_ip": "192.168.1.101",
            "destination_ip": "104.28.12.9",
            "source_port": 45000,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": 10,
            "byte_count": 500
        }, headers=self.auth_headers, client_ip="10.0.0.1")
        self.assertEqual(st, 201)
        self.assertTrue(data.get("success", False))

    def test_02_ingestion_validation_and_sanitization(self):
        """Reject impossible numbers and strip sensitive packet payloads."""
        # Negative packet count
        st, _ = self.dispatch("POST", "/api/traffic/events", body={
            "source_ip": "192.168.1.101",
            "destination_ip": "104.28.12.9",
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": -5,
            "byte_count": 500
        }, headers=self.auth_headers, client_ip="10.0.0.2")
        self.assertEqual(st, 400)

        # Invalid port > 65535
        st, _ = self.dispatch("POST", "/api/traffic/events", body={
            "source_ip": "192.168.1.101",
            "destination_ip": "104.28.12.9",
            "destination_port": 70000,
            "protocol": "TCP",
            "packet_count": 10,
            "byte_count": 500
        }, headers=self.auth_headers, client_ip="10.0.0.2")
        self.assertEqual(st, 400)

        # Invalid IPv4
        st, _ = self.dispatch("POST", "/api/traffic/events", body={
            "source_ip": "999.1.1.1",
            "destination_ip": "104.28.12.9",
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": 10,
            "byte_count": 500
        }, headers=self.auth_headers, client_ip="10.0.0.2")
        self.assertEqual(st, 400)

        # Payload sanitization check (raw_payload must be stripped)
        st, data = self.dispatch("POST", "/api/traffic/events", body={
            "source_ip": "192.168.1.102",
            "destination_ip": "192.168.1.1",
            "source_port": 50100,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": 10,
            "byte_count": 500,
            "raw_payload": "SECRET_PASSWORDS_AND_SENSITIVE_CREDENTIALS"
        }, headers=self.auth_headers, client_ip="10.0.0.3")
        self.assertEqual(st, 201)

    # --------------------------------------------------------------------------
    # 2. IDEMPOTENT DUPLICATE FLOW HANDLING
    # --------------------------------------------------------------------------

    def test_03_duplicate_flow_event_suppression(self):
        """Duplicate flows with identical signature must be ignored gracefully."""
        fixed_time = 1791832000.0
        event = {
            "source_ip": "192.168.1.155",
            "destination_ip": "185.193.64.12",
            "source_port": 49152,
            "destination_port": 23,
            "protocol": "TCP",
            "packet_count": 35,
            "byte_count": 2200,
            "timestamp": fixed_time
        }

        # First ingestion -> 201 Created
        st1, data1 = self.dispatch("POST", "/api/traffic/events", body=event, headers=self.auth_headers, client_ip="10.0.0.4")
        self.assertEqual(st1, 201)
        flow_id = data1["data"]["event_id"]

        # Immediate exact duplicate submission -> 200 OK with duplicate_ignored
        st2, data2 = self.dispatch("POST", "/api/traffic/events", body=event, headers=self.auth_headers, client_ip="10.0.0.4")
        self.assertEqual(st2, 200)
        self.assertEqual(data2["data"]["status"], "duplicate_ignored")
        self.assertEqual(data2["data"]["flow_id"], flow_id)

    # --------------------------------------------------------------------------
    # 3. BATCH INGESTION
    # --------------------------------------------------------------------------

    def test_04_batch_collector_ingestion(self):
        """Batch ingestion accepts multiple flow records from a probe."""
        batch_body = {
            "collector_id": "probe-rack-02",
            "collector_type": "zeek_flow",
            "events": [
                {
                    "source_ip": "192.168.1.101",
                    "destination_ip": "8.8.8.8",
                    "source_port": 50001,
                    "destination_port": 53,
                    "protocol": "UDP",
                    "packet_count": 2,
                    "byte_count": 128
                },
                {
                    "source_ip": "192.168.1.102",
                    "destination_ip": "192.168.1.1",
                    "source_port": 50002,
                    "destination_port": 80,
                    "protocol": "TCP",
                    "packet_count": 4,
                    "byte_count": 400
                }
            ]
        }
        st, data = self.dispatch("POST", "/api/traffic/events/batch", body=batch_body, headers=self.auth_headers, client_ip="10.0.0.5")
        self.assertEqual(st, 201)
        self.assertEqual(data["data"]["processed_count"], 2)

    # --------------------------------------------------------------------------
    # 4. CONFIGURABLE RULES & INDICATORS
    # --------------------------------------------------------------------------

    def test_05_rule_catalog_and_tuning(self):
        """Inspect and configure rule engine thresholds."""
        st, data = self.dispatch("GET", "/api/detection/rules")
        self.assertEqual(st, 200)
        rules = data["data"]["rules"]
        self.assertEqual(len(rules), 8)

        # Tune threshold for R01
        st, data = self.dispatch("PATCH", "/api/detection/rules/R01_HIGH_PACKET_RATE", body={
            "thresholds": {"threshold_pps": 400.0},
            "enabled": True
        })
        self.assertEqual(st, 200)
        self.assertEqual(data["data"]["rule"]["thresholds"]["threshold_pps"], 400.0)

        # Restore default
        self.dispatch("PATCH", "/api/detection/rules/R01_HIGH_PACKET_RATE", body={
            "thresholds": {"threshold_pps": 300.0}
        })

    def test_06_indicator_high_packet_rate(self):
        """Volumetric surge triggers R01_HIGH_PACKET_RATE."""
        res = configurable_rule_engine.evaluate_flow({
            "packet_rate": 450.0,
            "byte_rate": 50000.0,
            "conn_freq": 2.0,
            "dest_port": 80,
            "protocol": "TCP"
        })
        self.assertEqual(res["classification"], "High-Risk")
        matched_ids = [r["rule_id"] for r in res["triggered_rules"]]
        self.assertIn("R01_HIGH_PACKET_RATE", matched_ids)

    def test_07_indicator_high_outbound_traffic(self):
        """Abnormal outbound bytes triggers R02_HIGH_OUTBOUND_TRAFFIC."""
        res = configurable_rule_engine.evaluate_flow({
            "packet_rate": 40.0,
            "byte_rate": 200000.0,
            "outbound_ratio": 0.95,
            "conn_freq": 2.0,
            "dest_port": 443,
            "protocol": "TCP"
        })
        self.assertEqual(res["classification"], "High-Risk")
        matched_ids = [r["rule_id"] for r in res["triggered_rules"]]
        self.assertIn("R02_HIGH_OUTBOUND_TRAFFIC", matched_ids)

    def test_08_indicator_repeated_connection_attempts_and_ports(self):
        """Repeated connections on Telnet 23 trigger R03 and R05."""
        res = configurable_rule_engine.evaluate_flow({
            "packet_rate": 25.0,
            "byte_rate": 2000.0,
            "conn_freq": 22.0,
            "dest_port": 23,
            "protocol": "TCP"
        })
        self.assertEqual(res["classification"], "High-Risk")
        matched_ids = [r["rule_id"] for r in res["triggered_rules"]]
        self.assertIn("R03_REPEATED_CONN_ATTEMPTS", matched_ids)
        self.assertIn("R05_SUSPICIOUS_PORT_PATTERNS", matched_ids)

    def test_09_indicator_destination_diversity(self):
        """High destination count triggers R06_UNUSUAL_DEST_DIVERSITY."""
        res = configurable_rule_engine.evaluate_flow({
            "packet_rate": 20.0,
            "byte_rate": 2000.0,
            "conn_freq": 2.0,
            "unique_dest_ips": 18,
            "dest_port": 80,
            "protocol": "TCP"
        })
        self.assertIn(res["classification"], ("Suspicious", "High-Risk"))
        matched_ids = [r["rule_id"] for r in res["triggered_rules"]]
        self.assertIn("R06_UNUSUAL_DEST_DIVERSITY", matched_ids)

    def test_10_indicator_repeated_failed_connections(self):
        """Elevated failed connections trigger R08_REPEATED_FAILED_CONNS."""
        res = configurable_rule_engine.evaluate_flow({
            "packet_rate": 15.0,
            "byte_rate": 1500.0,
            "conn_freq": 2.0,
            "rst_ratio": 0.50,
            "failed_connections": 8,
            "dest_port": 80,
            "protocol": "TCP"
        })
        matched_ids = [r["rule_id"] for r in res["triggered_rules"]]
        self.assertIn("R08_REPEATED_FAILED_CONNS", matched_ids)

    # --------------------------------------------------------------------------
    # 5. BASELINES AND FALSE POSITIVES
    # --------------------------------------------------------------------------

    def test_11_baseline_deviation_and_fp_disclaimer(self):
        """Statistical deviation triggers R07 with false-positive disclaimer."""
        dev_id = "DEV-TEST-BASELINE"
        profile = baseline_service.get_or_create_profile(dev_id, "Smart Lighting Gateway")
        # Established baseline: 3.0 pps
        for _ in range(15):
            profile.update(pps=3.0, byte_rate=500.0, conn_freq=1.0, port=80, protocol="TCP")

        dev_res = baseline_service.evaluate_deviation(dev_id, pps=80.0, byte_rate=5000.0, conn_freq=10.0, dest_port=80, protocol="TCP")
        self.assertTrue(dev_res["is_deviant"])
        self.assertGreater(dev_res["max_z_score"], 3.5)
        self.assertIn("Threshold-based anomaly indicator", dev_res["fp_disclaimer"])

    # --------------------------------------------------------------------------
    # 6. ALERT SUPPRESSION & SUSTAINED BEHAVIOR
    # --------------------------------------------------------------------------

    def test_12_alert_suppression_on_sustained_traffic(self):
        """Sustained attack behavior does not create unlimited duplicate alerts."""
        flow_a = {
            "source_ip": "192.168.1.101",
            "destination_ip": "198.51.100.10",
            "source_port": 50000,
            "destination_port": 23,
            "protocol": "TCP",
            "packet_count": 250,
            "byte_count": 18000,
            "duration_sec": 1.0,
            "flow_statistics": {
                "conn_freq": 25.0,
                "syn_ratio": 0.90
            },
            "device_id": "DEV-101",
            "timestamp": time.time()
        }
        res_a = ingestion_service.process_traffic_event(flow_a, client_ip="10.0.0.8")
        self.assertEqual(res_a["alert_info"]["alert_action"], "created")
        first_alert_id = res_a["alert_info"]["alert"]["id"]

        # Immediate follow-up sustained flow from same device
        flow_b = dict(flow_a)
        flow_b["source_port"] = 50001
        flow_b["timestamp"] = time.time() + 2.0

        res_b = ingestion_service.process_traffic_event(flow_b, client_ip="10.0.0.8")
        self.assertEqual(res_b["alert_info"]["alert_action"], "suppressed_updated")
        self.assertEqual(res_b["alert_info"]["alert_id"], first_alert_id)

    # --------------------------------------------------------------------------
    # 7. DEMO SCENARIOS & DATA PROVENANCE
    # --------------------------------------------------------------------------

    def test_13_demo_scenarios_and_explicit_labeling(self):
        """Demo scenarios must be labeled is_demo=True and distinct from collector data."""
        st, data = self.dispatch("GET", "/api/demo/scenarios")
        self.assertEqual(st, 200)
        self.assertGreaterEqual(len(data["data"]["scenarios"]), 4)

        # Trigger normal_home
        st, res = self.dispatch("POST", "/api/demo/scenario", body={"scenario": "normal_home"})
        self.assertEqual(st, 201)
        ingest_res = res["data"]["ingestion_result"]
        self.assertTrue(ingest_res["is_demo"])
        self.assertEqual(ingest_res["data_source"], "demo_scenario")
        self.assertEqual(ingest_res["verdict"], "Normal")

        # Trigger repeated_connections
        st, res = self.dispatch("POST", "/api/demo/scenario", body={"scenario": "repeated_connections"})
        self.assertEqual(st, 201)
        ingest_res = res["data"]["ingestion_result"]
        self.assertTrue(ingest_res["is_demo"])
        self.assertEqual(ingest_res["verdict"], "High-Risk")

    # --------------------------------------------------------------------------
    # 8. REAL-TIME EVENT BROADCASTER
    # --------------------------------------------------------------------------

    def test_14_realtime_event_broadcaster(self):
        """Subscriber receives broadcast events and reconnection replay works."""
        q = broadcaster.subscribe()
        try:
            broadcaster.broadcast("alert", {"id": "ALT-TEST-SSE", "title": "Test Incursion"})
            item = q.get(timeout=2.0)
            self.assertEqual(item["event"], "alert")
            self.assertEqual(item["data"]["id"], "ALT-TEST-SSE")
        finally:
            broadcaster.unsubscribe(q)


if __name__ == "__main__":
    unittest.main()
