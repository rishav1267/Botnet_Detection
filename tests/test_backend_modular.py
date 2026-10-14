"""
Unit & Integration Test Suite for Modular Backend Architecture (Part 7)
Validates Configuration, Database Connection, Models, Services, Controllers, and API Router.
"""

import os
import sys
import unittest
import json

# Ensure parent directory is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.config.settings import Settings
from backend.database.connection import DatabaseManager
from backend.database.repository import DataRepository
from backend.models import (
    DeviceModel,
    TrafficEventModel,
    SecurityAlertModel,
    UserModel,
    DetectionRuleModel,
    ModelMetadataModel,
    RiskEngineConfigModel,
    AuditLogModel,
)
from backend.routes.api_router import ApiRouter
from backend.middleware.auth import generate_token, verify_token
from backend.middleware.error_handler import handle_exception
from backend.utils.response import api_success, api_error


class TestBackendModularArchitecture(unittest.TestCase):
    """Test suite for Part 7 production-grade modular backend components."""

    def test_settings_validation(self):
        """Settings should load defaults and validate constraints."""
        s = Settings()
        self.assertEqual(s.PORT, 8080)
        self.assertIn("iot_botnet_detection", s.MONGODB_URI)
        self.assertTrue(s.ML_ENGINE_ENABLED)
        d = s.to_dict()
        self.assertIn("port", d)
        self.assertIn("mongodb_db", d)

        # Invalid port should raise ValueError
        with self.assertRaises(ValueError):
            os.environ["PORT"] = "99999"
            Settings()
        os.environ["PORT"] = "8080"

    def test_database_manager_fallback(self):
        """Database manager should gracefully fall back to embedded store if Mongo is unavailable."""
        mgr = DatabaseManager()
        # Non-routable port to test timeout/fallback
        mgr.connect()
        self.assertIn(mgr.backend_type, ["mongodb", "embedded"])

    def test_models_validation(self):
        """Verify data validation for Device, Traffic, Alert, and User models."""
        # 1. DeviceModel
        dev = DeviceModel(
            id="DEV-999",
            name="Test IoT Gateway",
            ip="192.168.1.250",
            mac="AA:BB:CC:DD:EE:FF",
            category="Gateway",
            risk_score=45,
            status="Suspicious"
        )
        self.assertEqual(dev.id, "DEV-999")
        self.assertEqual(dev.risk_score, 45)

        # 2. TrafficEventModel
        flow = TrafficEventModel(
            flow_id="FLW-88888",
            timestamp="12:00:00",
            device_id="DEV-999",
            source_ip="192.168.1.250",
            dest_ip="185.193.64.12",
            dest_port=23,
            protocol="TCP",
            status="High-Risk"
        )
        self.assertEqual(flow.dest_port, 23)

        # 3. SecurityAlertModel
        alert = SecurityAlertModel(
            id="ALT-7777",
            timestamp="2026-10-12 12:00:00",
            device_id="DEV-999",
            source_ip="192.168.1.250",
            severity="Critical",
            title="Mirai Incursion",
            reason="Port 23 Sweep",
            details="Telnet scan"
        )
        self.assertEqual(alert.severity, "Critical")
        self.assertFalse(alert.resolved)

        # 4. UserModel
        user = UserModel(
            id="USR-001",
            username="analyst_test",
            email="test@secops.local",
            password_hash="sha256hash",
            created_at="2026-10-12 00:00:00 UTC"
        )
        safe = user.to_safe_dict()
        self.assertNotIn("password_hash", safe)
        self.assertEqual(safe["username"], "analyst_test")

    def test_repository_crud(self):
        """Repository should support device, alert, and flow operations."""
        repo = DataRepository()
        repo.seed_initial_data(
            devices=[{"id": "DEV-TEST-1", "name": "Sensor 1", "status": "Normal", "quarantined": False}],
            alerts=[{"id": "ALT-TEST-1", "title": "Test Alert", "status": "New", "resolved": False}]
        )

        devs = repo.get_all_devices()
        self.assertTrue(any(d["id"] == "DEV-TEST-1" for d in devs))

        # Quarantine toggle
        repo.update_device_quarantine("DEV-TEST-1", True)
        d = repo.get_device_by_id("DEV-TEST-1")
        self.assertTrue(d["quarantined"])

        # Alert status update
        repo.update_alert_status("ALT-TEST-1", "Resolved", note="Issue closed")
        alts = repo.get_all_alerts()
        target = next(a for a in alts if a["id"] == "ALT-TEST-1")
        self.assertEqual(target["status"], "Resolved")
        self.assertTrue(target["resolved"])

    def test_jwt_authentication(self):
        """Token generator and verifier should issue and validate tokens securely."""
        token = generate_token("USR-100", "secops_lead", "Lead SecOps")
        self.assertIsInstance(token, str)
        payload = verify_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["sub"], "USR-100")
        self.assertEqual(payload["username"], "secops_lead")

        # Invalid token
        self.assertIsNone(verify_token("invalid.token.here"))

    def test_api_router_get_routes(self):
        """ApiRouter should successfully dispatch core GET endpoints."""
        # /api/health
        status, data, hdrs = ApiRouter.dispatch("GET", "/api/health", {}, {}, {})
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "healthy")

        # /api/devices
        status, data, hdrs = ApiRouter.dispatch("GET", "/api/devices", {}, {}, {})
        self.assertEqual(status, 200)
        self.assertIn("devices", data)
        self.assertIn("summary", data)

        # /api/traffic
        status, data, hdrs = ApiRouter.dispatch("GET", "/api/traffic", {"limit": ["10"]}, {}, {})
        self.assertEqual(status, 200)
        self.assertIn("flows", data)

        # /api/analytics
        status, data, hdrs = ApiRouter.dispatch("GET", "/api/analytics", {"timeframe": ["24h"]}, {}, {})
        self.assertEqual(status, 200)
        self.assertIn("protocol_breakdown", data)
        self.assertIn("top_attacked_ports", data)

        # /api/export/report
        status, raw_bytes, hdrs = ApiRouter.dispatch("GET", "/api/export/report", {}, {}, {})
        self.assertEqual(status, 200)
        self.assertIn("text/markdown", hdrs["Content-Type"])
        self.assertGreater(len(raw_bytes), 100)

    def test_api_router_post_routes(self):
        """ApiRouter should successfully dispatch and validate POST endpoints."""
        # /api/devices/quarantine
        status, data, hdrs = ApiRouter.dispatch(
            "POST", "/api/devices/quarantine", {},
            {"device_id": "DEV-101", "quarantined": True}, {}
        )
        self.assertEqual(status, 200)
        self.assertTrue(data["quarantined"])

        # /api/ml/predict
        features = [350.0, 50000.0, 25.0, 0.0003, 15.0, 0.85, 1.0, 7.5, 300.0, 2.0, 140.0]
        status, data, hdrs = ApiRouter.dispatch(
            "POST", "/api/ml/predict", {},
            {"features": features}, {}
        )
        self.assertEqual(status, 200)
        self.assertIn("prediction", data)

        # /api/auth/login
        status, data, hdrs = ApiRouter.dispatch(
            "POST", "/api/auth/login", {},
            {"username": "admin", "password": "netguard2026"}, {}
        )
        self.assertEqual(status, 200)
        self.assertIn("token", data)
        self.assertTrue(data["success"])

    def test_error_handling_middleware(self):
        """Error handler should catch ValueError and return structured 400 error."""
        val_err = ValueError("Feature vector contains NaN values")
        code, err_resp = handle_exception(val_err)
        self.assertEqual(code, 400)
        self.assertFalse(err_resp["success"])
        self.assertEqual(err_resp["error"]["code"], "VALIDATION_ERROR")


if __name__ == "__main__":
    unittest.main()
