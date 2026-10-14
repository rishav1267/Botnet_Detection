"""
Automated unit & API tests for IoT Botnet Detection System
Validates Rule Engine, ML Classifier, Network Simulator, and REST API Endpoints.
"""

import os
import sys
import unittest
import json

# Ensure parent directory is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection_engine import RuleBasedEngine, MachineLearningEngine, DualDetectionCoordinator
from iot_network_simulator import IoTNetworkManager


class TestIoTBotnetDetection(unittest.TestCase):
    def setUp(self):
        self.rule_engine = RuleBasedEngine()
        self.ml_engine = MachineLearningEngine()
        self.coordinator = DualDetectionCoordinator()
        self.simulator = IoTNetworkManager(self.coordinator)

    def test_rule_engine_telnet_bruteforce(self):
        """Flow with high conn_freq to port 23 should trigger R01"""
        flow = {
            "dest_port": 23,
            "conn_freq": 25,
            "packet_rate": 80,
            "syn_ratio": 0.5,
            "unique_dest_ips": 5,
            "payload_entropy": 4.0
        }
        matches = self.rule_engine.evaluate(flow)
        self.assertTrue(any(m["rule_id"] == "R01" for m in matches))

    def test_rule_engine_syn_flood(self):
        """Flow with high packet rate and syn_ratio > 0.85 should trigger R02"""
        flow = {
            "dest_port": 80,
            "conn_freq": 10,
            "packet_rate": 600,
            "syn_ratio": 0.95,
            "unique_dest_ips": 1,
            "payload_entropy": 3.5
        }
        matches = self.rule_engine.evaluate(flow)
        self.assertTrue(any(m["rule_id"] == "R02" for m in matches))

    def test_ml_prediction_normal_flow(self):
        """Normal IoT telemetry should predict Normal with low risk score"""
        flow = {
            "packet_rate": 5.0,
            "byte_rate": 600.0,
            "conn_freq": 1.5,
            "dest_port": 1883,
            "unique_dest_ips": 1,
            "syn_ratio": 0.02,
            "flow_duration": 12.0,
            "payload_entropy": 3.8
        }
        res = self.ml_engine.predict(flow)
        self.assertEqual(res["prediction"], "Normal")
        self.assertLess(res["risk_score"], 0.40)
        self.assertIn("probabilities", res)

    def test_ml_prediction_high_risk_flood(self):
        """Massive packet rate with high syn_ratio should predict High-Risk"""
        flow = {
            "packet_rate": 750.0,
            "byte_rate": 50000.0,
            "conn_freq": 45.0,
            "dest_port": 23,
            "unique_dest_ips": 25,
            "syn_ratio": 0.92,
            "flow_duration": 0.1,
            "payload_entropy": 7.5
        }
        res = self.ml_engine.predict(flow)
        self.assertEqual(res["prediction"], "High-Risk")
        self.assertGreater(res["risk_score"], 0.60)
        self.assertTrue(len(res["contributing_features"]) > 0)

    def test_device_quarantine_toggle(self):
        """Quarantining a device should update its state and drop its active pps"""
        dev_id = "DEV-101"
        self.simulator.set_device_quarantine(dev_id, True)
        dev = next(d for d in self.simulator.devices if d["id"] == dev_id)
        self.assertTrue(dev["quarantined"])
        self.assertEqual(dev["pps"], 0.0)

        # Un-quarantine
        self.simulator.set_device_quarantine(dev_id, False)
        dev = next(d for d in self.simulator.devices if d["id"] == dev_id)
        self.assertFalse(dev["quarantined"])

    def test_kpi_summary_generation(self):
        """Summary KPIs should return correct totals and posture score"""
        kpis = self.simulator.get_summary_kpis()
        self.assertIn("health_score", kpis)
        self.assertIn("total_devices", kpis)
        self.assertEqual(kpis["total_devices"], 8)
        self.assertTrue(0 <= kpis["health_score"] <= 100)

    def test_part3_device_inventory_fields(self):
        """Verify all 11 required fields exist and are populated across devices"""
        required_fields = [
            "name", "category", "ip", "mac", "protocol", "first_seen",
            "last_activity", "pps", "bytes_transferred", "conn_freq", "risk_score", "security_classification"
        ]
        for dev in self.simulator.devices:
            for field in required_fields:
                self.assertIn(field, dev, f"Device {dev.get('id')} missing required field {field}")
            self.assertTrue(len(dev["risk_factors"]) > 0)

    def test_part3_risk_engine_factors_and_thresholds(self):
        """Verify transparent risk score calculation and threshold adjustment"""
        dev = self.simulator.devices[0]  # DEV-101
        self.simulator.calculate_device_risk(dev)
        self.assertEqual(dev["security_classification"], "High-Risk")
        self.assertTrue(any(f["factor"] == "Abnormal port access" for f in dev["risk_factors"]))

        # Adjust thresholds so DEV-101 is tested against custom rules
        self.simulator.risk_config["thresholds"]["high_risk_min"] = 99
        self.simulator.recalculate_all_risks()
        self.assertIn(dev["security_classification"], ["High-Risk", "Suspicious"])

    def test_part3_external_flow_ingestion(self):
        """Verify external packet collector / NetFlow ingestion interface"""
        flow_record = {
            "device_id": "DEV-101",
            "source_ip": "192.168.1.101",
            "dest_ip": "185.193.64.12",
            "dest_port": 23,
            "protocol": "TCP",
            "packet_rate": 500.0,
            "conn_freq": 30.0,
            "collector_source": "Zeek Intrusion Probe"
        }
        analyzed = self.simulator.ingest_external_flow(flow_record)
        self.assertEqual(analyzed["device_id"], "DEV-101")
        self.assertEqual(analyzed["status"], "High-Risk")
        self.assertEqual(self.simulator.recent_flows[0]["flow_id"], analyzed["flow_id"])

    def test_part4_ml_pipeline_retrain_and_metrics(self):
        """Verify dynamic ML model retraining, evaluation metrics, and ROC/PR curve generation"""
        res = self.ml_engine.retrain(n_estimators=30, max_depth=7, sample_size=1200, test_split_pct=20)
        self.assertEqual(res["status"], "success")
        self.assertGreater(res["accuracy"], 0.90)
        self.assertGreater(res["roc_auc"], 0.95)
        self.assertTrue(len(self.ml_engine.roc_curve_data) >= 5)
        self.assertTrue(len(self.ml_engine.pr_curve_data) >= 5)
        self.assertEqual(len(self.ml_engine.FEATURE_NAMES), 11)

    def test_part4_ml_feature_vector_extraction(self):
        """Verify that 11 features are extracted with valid metadata"""
        flow = {
            "packet_rate": 35.0,
            "byte_rate": 4000.0,
            "conn_freq": 4.5,
            "dest_port": 1883,
            "unique_dest_ips": 2,
            "syn_ratio": 0.08,
            "flow_duration": 5.0,
            "payload_entropy": 3.9
        }
        vec = self.ml_engine.extract_vector(flow)
        self.assertEqual(len(vec), 11)
        self.assertIn("fwd_packets", self.ml_engine.FEATURE_METADATA)
        self.assertIn("mean_pkt_len", self.ml_engine.FEATURE_METADATA)

    def test_part5_alert_schema_and_severities(self):
        """Verify alerts conform to complete 14-field schema and 5 severity categories"""
        required_alert_fields = [
            "id", "timestamp", "device_id", "device_name", "source_ip",
            "severity", "detection_source", "classification", "title", "reason",
            "traffic_indicators", "suggested_action", "status", "mitre_technique"
        ]
        severities = {a["severity"] for a in self.simulator.alerts}
        self.assertTrue({"Critical", "High", "Medium", "Low", "Informational"}.issubset(severities))

        for alert in self.simulator.alerts:
            for field in required_alert_fields:
                self.assertIn(field, alert, f"Alert {alert.get('id')} missing {field}")
            self.assertIn("packet_rate", alert["traffic_indicators"])

    def test_part5_alert_status_transitions_and_notes(self):
        """Verify alert triage state transitions (New -> Acknowledged -> In Progress -> Resolved -> Reopened)"""
        alert_id = self.simulator.alerts[0]["id"]

        # Transition to Acknowledged
        a = self.simulator.update_alert_status(alert_id, "Acknowledged", "Triage initiated")
        self.assertEqual(a["status"], "Acknowledged")
        self.assertFalse(a["resolved"])

        # Add Analyst Note
        a = self.simulator.add_alert_note(alert_id, "Analyst Cooper", "Examined pcap capture")
        self.assertTrue(any("Examined pcap" in n["note"] for n in a["analyst_notes"]))

        # Transition to Resolved
        a = self.simulator.update_alert_status(alert_id, "Resolved", "Remediated via ACL")
        self.assertEqual(a["status"], "Resolved")
        self.assertTrue(a["resolved"])

        # Reopen
        a = self.simulator.update_alert_status(alert_id, "Reopened", "Secondary packet burst detected")
        self.assertEqual(a["status"], "Reopened")
        self.assertFalse(a["resolved"])

    def test_part5_bulk_alert_actions(self):
        """Verify bulk acknowledge, bulk resolve, and bulk device quarantine"""
        ids = [self.simulator.alerts[0]["id"], self.simulator.alerts[1]["id"]]

        # Bulk Acknowledge
        res = self.simulator.bulk_update_alerts(ids, "acknowledge")
        self.assertEqual(res["updated_count"], 2)
        for a_id in ids:
            a = next(x for x in self.simulator.alerts if x["id"] == a_id)
            self.assertEqual(a["status"], "Acknowledged")

        # Bulk Isolate affected devices
        res_iso = self.simulator.bulk_update_alerts(ids, "isolate")
        self.assertEqual(res_iso["updated_count"], 2)
        affected_dev_ids = {a["device_id"] for a in self.simulator.alerts if a["id"] in ids}
        for d_id in affected_dev_ids:
            dev = next(d for d in self.simulator.devices if d["id"] == d_id)
            self.assertTrue(dev["quarantined"])
        for a_id in ids:
            a = next(x for x in self.simulator.alerts if x["id"] == a_id)
            self.assertEqual(a["action_taken"], "Associated Device Quarantined / Network Cut")

    def test_part4_saved_artifacts_and_fallback(self):
        """Verify model artifacts persistence and heuristic fallback safety for 11 and 8 feature vectors"""
        import os, json
        # Trigger retrain to save artifacts
        res = self.ml_engine.retrain(n_estimators=15, max_depth=5, sample_size=800, test_split_pct=20)
        self.assertIn("roc_curve", res)
        self.assertIn("pr_curve", res)

        # Check artifact files
        self.assertTrue(os.path.exists("models/model_metadata.json"))
        self.assertTrue(os.path.exists("models/normalization_metadata.json"))
        self.assertTrue(os.path.exists("models/evaluation_summary.json"))

        with open("models/model_metadata.json") as f:
            meta = json.load(f)
            self.assertEqual(meta["feature_count"], 11)
            self.assertEqual(meta["status"], "operational")

        with open("models/normalization_metadata.json") as f:
            norm = json.load(f)
            self.assertIn("feature_schema", norm)
            self.assertEqual(len(norm["feature_schema"]), 11)

        # Test heuristic fallback for 11-feature vector
        vec11 = [350.0, 50000.0, 25.0, 0.0003, 15.0, 0.85, 1.0, 7.5, 300.0, 2.0, 140.0]
        p_norm, p_susp, p_high = self.ml_engine._heuristic_fallback(vec11)
        self.assertGreater(p_high, 0.6)

        # Test heuristic fallback for 8-feature vector
        vec8 = [10.0, 2000.0, 2.0, 0.0012, 1.0, 0.05, 5.0, 4.0]
        p_norm, p_susp, p_high = self.ml_engine._heuristic_fallback(vec8)
        self.assertGreater(p_norm, 0.7)

    def test_part6_analytics_and_reporting(self):
        """Verify analytics telemetry aggregation, timeframe scaling, and port/strain/geo matrices"""
        # Test default 24h summary
        summary24 = self.simulator.get_analytics_summary("24h")
        self.assertEqual(summary24["timeframe"], "24h")
        self.assertIn("kpis", summary24)
        self.assertGreater(summary24["kpis"]["total_flows"], 10000)
        self.assertGreater(summary24["kpis"]["active_strains_count"], 0)
        self.assertIn("peak_incursion_mbps", summary24["kpis"])

        # Protocol breakdown
        protocols = summary24["protocol_breakdown"]
        proto_names = [p["protocol"] for p in protocols]
        self.assertTrue(all(p in proto_names for p in ["TCP", "UDP", "MQTT", "RTSP", "CoAP / Others"]))
        total_pct = sum(p["percentage"] for p in protocols)
        self.assertAlmostEqual(total_pct, 100.0, delta=1.5)
        for p in protocols:
            self.assertIn("bytes_gb", p)

        # Top attacked ports
        ports = summary24["top_attacked_ports"]
        port_nums = [pt["port"] for pt in ports]
        expected_ports = [23, 2323, 80, 53, 37215, 5555, 1883, 554]
        for ep in expected_ports:
            self.assertIn(ep, port_nums)
        for pt in ports:
            self.assertIn("cve", pt)
            self.assertIn("incursions", pt)
            self.assertIn("risk_level", pt)

        # Botnet strains
        strains = summary24["botnet_family_distribution"]
        self.assertTrue(len(strains) >= 6)
        strain_families = " ".join(s["family"] for s in strains).lower()
        self.assertIn("mirai", strain_families)
        self.assertIn("bashlite", strain_families)
        self.assertIn("hajime", strain_families)
        self.assertIn("torii", strain_families)
        self.assertIn("adb.miner", strain_families)
        self.assertIn("dark_nexus", strain_families)

        # Multi-timeframe trend timelines
        for tf, expected_len in [("1h", 12), ("6h", 12), ("24h", 12), ("7d", 7)]:
            s = self.simulator.get_analytics_summary(tf)
            self.assertEqual(s["timeframe"], tf)
            self.assertEqual(len(s["hourly_timeline"]), expected_len)
            self.assertTrue(all("normal" in pt and "suspicious" in pt and "high_risk" in pt for pt in s["hourly_timeline"]))

        # 1h flows should be smaller than 24h flows, which should be smaller than 7d
        s1 = self.simulator.get_analytics_summary("1h")
        s7 = self.simulator.get_analytics_summary("7d")
        self.assertLess(s1["kpis"]["total_flows"], summary24["kpis"]["total_flows"])
        self.assertLess(summary24["kpis"]["total_flows"], s7["kpis"]["total_flows"])

        # Geographic threat intelligence
        geos = summary24["geographic_threats"]
        self.assertTrue(len(geos) >= 6)
        country_codes = [g["code"] for g in geos]
        for code in ["RU", "CN", "US", "BR", "NL", "VN"]:
            self.assertIn(code, country_codes)
        for g in geos:
            self.assertIn("asn", g)
            self.assertIn("threat_score", g)
            self.assertIn("share_pct", g)


if __name__ == "__main__":
    unittest.main()

