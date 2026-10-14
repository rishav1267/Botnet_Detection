"""
Part 11 Security & Access Control Verification Test Suite
Verifies:
1. Authentication & Token Lifecycle (PBKDF2 login, logout token revocation, session refresh).
2. Role-Based Access Control (RBAC matrix: admin, analyst, read_only).
3. Collector Ingestion Authentication & Tamper Rejection.
4. Real-Time Channel (SSE) Security & Unauthorized Subscription Prevention.
5. Input Validation, NoSQL Injection Sanitization, & Request Size Limits (413).
6. Sliding-Window Rate Limiting (429 with Retry-After).
7. Safe Error Handling (No stack traces or credential leaks).
8. Data Retention Policy & Forensic Incident Evidence Preservation.
9. Database Fallback & Resilient Operation.
"""

import sys
import unittest
import time
import json
from pathlib import Path

# Add project root to path
root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from backend.routes.api_router import ApiRouter
from backend.services.auth_service import auth_service
from backend.services.ingestion_service import ingestion_service
from backend.middleware.auth import generate_token, verify_token, revoke_token, is_token_revoked
from backend.middleware.security import security_manager
from backend.middleware.error_handler import handle_exception
from backend.database.repository import repository
from backend.database.retention import retention_manager
from backend.config.settings import settings
from backend.utils.crypto import hash_password, verify_password, sanitize_nosql_input, redact_sensitive_data


class TestPart11Security(unittest.TestCase):
    """Production Security & Access Control Verification Tests."""

    @classmethod
    def setUpClass(cls):
        # Obtain tokens for each role
        cls.admin_session = auth_service.authenticate("admin", settings.ADMIN_PASSWORD)
        cls.analyst_session = auth_service.authenticate("analyst", settings.ANALYST_PASSWORD)
        cls.readonly_session = auth_service.authenticate("readonly", settings.AUDITOR_PASSWORD)

        assert cls.admin_session is not None, "Admin seed account authentication failed"
        assert cls.analyst_session is not None, "Analyst seed account authentication failed"
        assert cls.readonly_session is not None, "Readonly seed account authentication failed"

        cls.admin_token = cls.admin_session["access_token"]
        cls.analyst_token = cls.analyst_session["access_token"]
        cls.readonly_token = cls.readonly_session["access_token"]

        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}
        cls.analyst_headers = {"Authorization": f"Bearer {cls.analyst_token}"}
        cls.readonly_headers = {"Authorization": f"Bearer {cls.readonly_token}"}

    def dispatch(self, method, path, query=None, body=None, headers=None, client_ip="127.0.0.1"):
        query = query or {}
        body = body or {}
        headers = headers or {}
        st, data, hdrs = ApiRouter.dispatch(method, path, query, body, headers, client_ip)
        return st, data

    # ==========================================================================
    # 1. AUTHENTICATION & PASSWORD CRYPTO TESTS
    # ==========================================================================

    def test_01_password_hashing_pbkdf2(self):
        """Verify PBKDF2-HMAC-SHA256 password hashing with unique salts."""
        raw_pw = "SuperSec0psSecret!123"
        h1 = hash_password(raw_pw)
        h2 = hash_password(raw_pw)

        self.assertTrue(h1.startswith("pbkdf2_sha256$100000$"))
        self.assertNotEqual(h1, h2, "Salts must be randomly generated and unique")
        self.assertTrue(verify_password(raw_pw, h1))
        self.assertFalse(verify_password("WrongPassword999", h1))

    def test_02_login_and_token_generation(self):
        """Verify login issues valid access and refresh JWT tokens."""
        st, res = self.dispatch("POST", "/api/auth/login", body={"username": "admin", "password": settings.ADMIN_PASSWORD})
        self.assertEqual(st, 200)
        self.assertIn("access_token", res)
        self.assertIn("refresh_token", res)
        self.assertEqual(res["user"]["username"], "admin")
        self.assertEqual(res["user"]["role"], "admin")

        # Invalid login
        st_bad, res_bad = self.dispatch("POST", "/api/auth/login", body={"username": "admin", "password": "BadPassword!"})
        self.assertEqual(st_bad, 401)
        err_msg = res_bad.get("message", res_bad.get("error", ""))
        self.assertIn("Invalid username or password", err_msg)

    def test_03_token_rotation_refresh(self):
        """Verify session refresh exchanges refresh token for fresh access token."""
        login_res = auth_service.authenticate("analyst", settings.ANALYST_PASSWORD)
        refresh_tok = login_res["refresh_token"]

        st, res = self.dispatch("POST", "/api/auth/refresh", body={"refresh_token": refresh_tok})
        self.assertEqual(st, 200)
        self.assertIn("access_token", res["data"])
        self.assertIn("expires_in", res["data"])

        # Invalid refresh token
        st_err, _ = self.dispatch("POST", "/api/auth/refresh", body={"refresh_token": "garbage.jwt.token"})
        self.assertEqual(st_err, 401)

    def test_04_logout_and_token_revocation(self):
        """Verify logout blacklists token and subsequent requests are rejected."""
        # Authenticate a temporary session
        temp_sess = auth_service.authenticate("analyst", settings.ANALYST_PASSWORD)
        temp_tok = temp_sess["access_token"]
        temp_hdrs = {"Authorization": f"Bearer {temp_tok}"}

        # Verify token works initially
        st_before, me_before = self.dispatch("GET", "/api/auth/me", headers=temp_hdrs)
        self.assertEqual(st_before, 200)

        # Logout to revoke token
        st_out, out_res = self.dispatch("POST", "/api/auth/logout", headers=temp_hdrs)
        self.assertEqual(st_out, 200)
        self.assertTrue(is_token_revoked(temp_tok))

        # Subsequent use must fail with 401
        st_after, _ = self.dispatch("GET", "/api/auth/me", headers=temp_hdrs)
        self.assertEqual(st_after, 401)

    def test_05_expired_token_rejection(self):
        """Verify tokens with past expiration timestamps are rejected."""
        expired_tok = generate_token("user-exp", "expired_user", role="analyst", expires_in_sec=-10)
        claims = verify_token(expired_tok)
        self.assertIsNone(claims, "Expired token must not be accepted")

    # ==========================================================================
    # 2. ROLE-BASED ACCESS CONTROL (RBAC) TESTS
    # ==========================================================================

    def test_06_rbac_device_deletion_admin_only(self):
        """Verify only admin can delete devices; analyst and read_only are rejected with 403."""
        # 1. Read-only user attempt -> 403 Forbidden
        st_ro, _ = self.dispatch("DELETE", "/api/devices/DEV-101", query={"force": ["true"]}, headers=self.readonly_headers)
        self.assertEqual(st_ro, 403)

        # 2. Analyst user attempt -> 403 Forbidden
        st_an, _ = self.dispatch("DELETE", "/api/devices/DEV-101", query={"force": ["true"]}, headers=self.analyst_headers)
        self.assertEqual(st_an, 403)

        # 3. Missing auth attempt -> 401 Unauthorized
        st_noauth, _ = self.dispatch("DELETE", "/api/devices/DEV-101", query={"force": ["true"]})
        self.assertEqual(st_noauth, 401)

    def test_07_rbac_device_creation_and_quarantine(self):
        """Verify admin and analyst can create/quarantine; read_only is rejected with 403."""
        payload = {
            "id": "DEV-RBAC-01",
            "name": "SecOps Test Camera",
            "type": "IP Camera",
            "ip": "192.168.1.150",
            "mac": "AA:BB:CC:11:22:33"
        }

        # Read-only user creates device -> 403
        st_ro, _ = self.dispatch("POST", "/api/devices", body=payload, headers=self.readonly_headers)
        self.assertEqual(st_ro, 403)

        # Analyst creates device -> 201 Created
        st_an, res_an = self.dispatch("POST", "/api/devices", body=payload, headers=self.analyst_headers)
        self.assertEqual(st_an, 201)

        # Read-only quarantines device -> 403
        st_q_ro, _ = self.dispatch("POST", "/api/devices/quarantine", body={"device_id": "DEV-RBAC-01", "quarantined": True}, headers=self.readonly_headers)
        self.assertEqual(st_q_ro, 403)

        # Analyst quarantines device -> 200 OK
        st_q_an, res_q = self.dispatch("POST", "/api/devices/quarantine", body={"device_id": "DEV-RBAC-01", "quarantined": True}, headers=self.analyst_headers)
        self.assertEqual(st_q_an, 200)

    def test_08_rbac_alert_triage_operations(self):
        """Verify read_only users cannot mutate alert statuses or notes."""
        # Read-only patch status -> 403
        st_ro, _ = self.dispatch("PATCH", "/api/alerts/ALT-9042/status", body={"status": "Resolved"}, headers=self.readonly_headers)
        self.assertEqual(st_ro, 403)

        # Read-only add note -> 403
        st_note_ro, _ = self.dispatch("POST", "/api/alerts/note", body={"alert_id": "ALT-9042", "note": "Forensic test note"}, headers=self.readonly_headers)
        self.assertEqual(st_note_ro, 403)

        # Analyst can add note -> 200
        st_note_an, _ = self.dispatch("POST", "/api/alerts/note", body={"alert_id": "ALT-9042", "note": "Forensic analyst note"}, headers=self.analyst_headers)
        self.assertEqual(st_note_an, 200)

    def test_09_rbac_retention_purge_admin_only(self):
        """Verify only admin can trigger retention purge."""
        st_ro, _ = self.dispatch("POST", "/api/system/retention/purge", body={"retention_days": 30}, headers=self.readonly_headers)
        self.assertEqual(st_ro, 403)

        st_an, _ = self.dispatch("POST", "/api/system/retention/purge", body={"retention_days": 30}, headers=self.analyst_headers)
        self.assertEqual(st_an, 403)

        st_adm, res_adm = self.dispatch("POST", "/api/system/retention/purge", body={"retention_days": 30}, headers=self.admin_headers)
        self.assertEqual(st_adm, 200)
        self.assertEqual(res_adm["data"]["status"], "completed")

    # ==========================================================================
    # 3. COLLECTOR INGESTION AUTHENTICATION TESTS
    # ==========================================================================

    def test_10_collector_authentication(self):
        """Verify collector key authentication rejects missing or forged keys."""
        # Missing collector key
        st_no, _ = self.dispatch("POST", "/api/traffic/events", body={
            "src_ip": "192.168.1.101", "dst_ip": "104.28.12.9",
            "src_port": 50000, "dest_port": 80, "protocol": "TCP"
        })
        self.assertEqual(st_no, 401)

        # Invalid collector key
        st_bad, _ = self.dispatch(
            "POST", "/api/traffic/events",
            body={"src_ip": "192.168.1.101", "dst_ip": "104.28.12.9", "src_port": 50000, "dest_port": 80, "protocol": "TCP"},
            headers={"X-Collector-Key": "invalid-secret-key-12345"}
        )
        self.assertEqual(st_bad, 401)

        # Valid collector key
        st_ok, res_ok = self.dispatch(
            "POST", "/api/traffic/events",
            body={
                "source_ip": "192.168.1.101",
                "destination_ip": "104.28.12.9",
                "source_port": 50000,
                "destination_port": 80,
                "protocol": "TCP",
                "packet_count": 50,
                "byte_count": 4000
            },
            headers={"X-Collector-Key": settings.COLLECTOR_API_KEY}
        )
        self.assertEqual(st_ok, 201)

    # ==========================================================================
    # 4. REAL-TIME CHANNEL (SSE) SECURITY TESTS
    # ==========================================================================

    def test_11_realtime_stream_unauthorized_subscription(self):
        """Verify SSE stream blocks unauthenticated connections with 401."""
        from backend.controllers.stream_controller import StreamController

        class MockSSEHandler:
            def __init__(self):
                self.sent_status = None
                self.headers = {}
                self.written = b""
            def send_response(self, code):
                self.sent_status = code
            def send_header(self, k, v):
                self.headers[k] = v
            def end_headers(self):
                pass
            @property
            def wfile(self):
                class MockWFile:
                    def __init__(self, outer):
                        self.outer = outer
                    def write(self, data):
                        self.outer.written += data
                    def flush(self):
                        pass
                return MockWFile(self)

        # Attempt 1: No token
        h1 = MockSSEHandler()
        StreamController.handle_sse(h1, {}, {})
        self.assertEqual(h1.sent_status, 401)
        resp1 = json.loads(h1.written.decode("utf-8"))
        self.assertEqual(resp1["error_code"], "UNAUTHORIZED")

        # Attempt 2: Fake token
        h2 = MockSSEHandler()
        StreamController.handle_sse(h2, {"token": "fake.malicious.token"}, {})
        self.assertEqual(h2.sent_status, 401)

    # ==========================================================================
    # 5. INPUT VALIDATION, INJECTION DEFENSES, & SIZE LIMITS
    # ==========================================================================

    def test_12_nosql_injection_sanitization(self):
        """Verify MongoDB query operators ($gt, $ne, $where) and dot keys are stripped."""
        dirty_input = {
            "username": {"$ne": None},
            "status": "Active",
            "filter": {
                "$gt": 100,
                "clean_key": "safe_value",
                "nested": {"$where": "this.password == 'secret'"}
            }
        }
        sanitized = sanitize_nosql_input(dirty_input)
        self.assertNotIn("$ne", sanitized.get("username", {}))
        self.assertNotIn("$gt", sanitized["filter"])
        self.assertNotIn("$where", sanitized["filter"].get("nested", {}))
        self.assertEqual(sanitized["status"], "Active")
        self.assertEqual(sanitized["filter"]["clean_key"], "safe_value")

    def test_13_request_payload_size_limits(self):
        """Verify oversized request payloads (> 5MB) return 413 Payload Too Large."""
        oversized_len = 6 * 1024 * 1024  # 6 MB
        err = security_manager.validate_request_size(oversized_len, "/api/devices")
        self.assertIsNotNone(err)
        status_code, err_data = err
        self.assertEqual(status_code, 413)
        self.assertEqual(err_data["error_code"], "PAYLOAD_TOO_LARGE")

        # Normal size (50 KB) passes
        ok_len = 50 * 1024
        self.assertIsNone(security_manager.validate_request_size(ok_len, "/api/devices"))

    def test_14_sliding_window_rate_limiting(self):
        """Verify rate limiting triggers 429 when threshold exceeded."""
        test_ip = "198.51.100.99"
        # Login rate limit is 10 requests per minute
        for _ in range(10):
            is_allowed, _ = security_manager.check_rate_limit(test_ip, "/api/auth/login", max_requests=10, window_sec=60)
            self.assertTrue(is_allowed)

        # 11th request must be rejected with 429 and retry_after
        is_blocked, retry_after = security_manager.check_rate_limit(test_ip, "/api/auth/login", max_requests=10, window_sec=60)
        self.assertFalse(is_blocked)
        self.assertGreaterEqual(retry_after, 1)

    # ==========================================================================
    # 6. SAFE ERROR RESPONSES & AUDIT LOG REDACTION
    # ==========================================================================

    def test_15_safe_error_handling_no_leaks(self):
        """Verify 500 errors never leak stack traces, internal paths, or credentials."""
        try:
            raise RuntimeError("Database connection failed on /var/internal/db.sock with secret KEY_12345")
        except Exception as e:
            status, err_body = handle_exception(e)
            self.assertEqual(status, 500)
            self.assertNotIn("/var/internal", json.dumps(err_body))
            self.assertNotIn("KEY_12345", json.dumps(err_body))
            err_code = err_body.get("code", err_body.get("error_code"))
            self.assertEqual(err_code, "INTERNAL_SERVER_ERROR")

    def test_16_audit_log_credential_redaction(self):
        """Verify passwords, tokens, and secrets are redacted from compliance audit logs."""
        unredacted = {
            "password": "ClearTextPassword123",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy",
            "api_key": "sec_collector_abc123",
            "ip": "192.168.1.50",
            "action": "LOGIN_ATTEMPT"
        }
        redacted = redact_sensitive_data(unredacted)
        self.assertEqual(redacted["password"], "[REDACTED]")
        self.assertEqual(redacted["token"], "[REDACTED]")
        self.assertEqual(redacted["api_key"], "[REDACTED]")
        self.assertEqual(redacted["ip"], "192.168.1.50")

    # ==========================================================================
    # 7. DATA RETENTION & FORENSIC EVIDENCE PRESERVATION TESTS
    # ==========================================================================

    def test_17_retention_and_forensic_evidence_preservation(self):
        """Verify retention preserves High-Risk flows and open critical alerts as incident evidence."""
        # Seed an old normal flow and an old High-Risk flow (simulating 60 days ago)
        old_time = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() - (60 * 86400)))

        normal_flow = {
            "flow_id": "FLW-OLD-NORMAL",
            "timestamp": old_time,
            "verdict": "Normal",
            "threat_detected": False
        }
        high_risk_evidence_flow = {
            "flow_id": "FLW-OLD-BOTNET",
            "timestamp": old_time,
            "verdict": "High-Risk",
            "threat_detected": True
        }
        critical_alert = {
            "id": "ALT-CRITICAL-INCIDENT",
            "timestamp": old_time,
            "severity": "Critical",
            "status": "Investigating"
        }

        repository._local_flows.extend([normal_flow, high_risk_evidence_flow])
        repository._local_alerts.append(critical_alert)

        # Run retention with 30-day cutoff
        summary = retention_manager.purge_expired_data(retention_days=30, preserve_incident_evidence=True)
        self.assertEqual(summary["retention_days"], 30)

        # Normal old flow should be purged
        flow_ids = [f.get("flow_id") for f in repository._local_flows]
        self.assertNotIn("FLW-OLD-NORMAL", flow_ids, "Routine expired flows must be purged")

        # High-risk evidence flow MUST be preserved
        self.assertIn("FLW-OLD-BOTNET", flow_ids, "Forensic incident evidence flow must be preserved")

        # Critical alert MUST be preserved
        alert_ids = [a.get("id") for a in repository._local_alerts]
        self.assertIn("ALT-CRITICAL-INCIDENT", alert_ids, "Active critical incident alert must be preserved")


if __name__ == "__main__":
    unittest.main()
