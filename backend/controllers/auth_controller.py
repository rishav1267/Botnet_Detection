"""
Authentication & Audit Log Controller
Handles secure SecOps login, session refresh, logout revocation, and audit logs.
"""

from typing import Dict, Any, Tuple, Optional
from backend.services import auth_service
from backend.database.repository import repository
from backend.validation.schemas import LoginPayload, RefreshPayload, LogoutPayload
from backend.middleware.auth import verify_token, check_permission
from backend.utils.crypto import redact_sensitive_data
from backend.utils.response import api_error, api_success
from backend.config.settings import settings


class AuthController:
    """Handles SecOps analyst login, session verification, token rotation, and audit logs."""

    @staticmethod
    def login(payload: Dict[str, Any], client_ip: str = "127.0.0.1") -> Tuple[int, Dict[str, Any]]:
        """
        POST /api/auth/login
        Authenticates user with username & password, returns JWT access and refresh tokens.
        """
        try:
            validated = LoginPayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="INVALID_CREDENTIALS")

        session = auth_service.authenticate(validated.username, validated.password)
        if not session:
            # Audit failed login attempt without revealing password
            repository.record_audit(
                action="LOGIN_FAILED",
                user_id=validated.username.strip(),
                details={"ip": client_ip, "reason": "Invalid credentials"}
            )
            return 401, api_error("Invalid username or password", status_code=401, error_code="UNAUTHORIZED")

        # Audit successful login
        repository.record_audit(
            action="USER_LOGIN",
            user_id=session["user"]["username"],
            details={
                "ip": client_ip,
                "role": session["user"]["role"],
                "role_display": session["user"]["role_display"]
            }
        )

        return 200, {
            "success": True,
            **session
        }

    @staticmethod
    def logout(payload: Dict[str, Any] = None, headers: Dict[str, str] = None, client_ip: str = "127.0.0.1") -> Tuple[int, Dict[str, Any]]:
        """
        POST /api/auth/logout
        Revokes active session token to prevent token reuse.
        """
        payload = payload or {}
        headers = headers or {}
        auth_hdr = headers.get("Authorization", headers.get("authorization", ""))

        token = None
        if auth_hdr.lower().startswith("bearer "):
            token = auth_hdr[7:].strip()
        elif payload.get("token"):
            token = payload.get("token")

        if token:
            claims = verify_token(token)
            username = claims.get("username", "anonymous") if claims else "unknown"
            auth_service.logout(token)
            repository.record_audit(
                action="USER_LOGOUT",
                user_id=username,
                details={"ip": client_ip, "token_revoked": True}
            )

        return 200, api_success({
            "message": "Successfully logged out. Session token has been revoked.",
            "revoked": True
        })

    @staticmethod
    def refresh(payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """
        POST /api/auth/refresh
        Exchanges a valid refresh token for a newly issued short-lived access token.
        """
        try:
            validated = RefreshPayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="INVALID_REFRESH_TOKEN")

        result = auth_service.refresh_session(validated.refresh_token)
        if not result:
            return 401, api_error("Invalid or expired refresh token", status_code=401, error_code="TOKEN_EXPIRED")

        return 200, api_success(result)

    @staticmethod
    def get_me(headers: Dict[str, str]) -> Tuple[int, Dict[str, Any]]:
        """
        GET /api/auth/me
        Returns active authenticated user identity, role, and authorized permissions.
        """
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        if not auth_header.lower().startswith("bearer "):
            return 401, api_error("Missing or malformed Authorization header", status_code=401, error_code="UNAUTHORIZED")

        token = auth_header.split(" ", 1)[1].strip()
        payload = verify_token(token)
        if not payload:
            return 401, api_error("Invalid or expired session token", status_code=401, error_code="TOKEN_EXPIRED")

        profile = auth_service.get_user_profile(payload)
        return 200, {
            "authenticated": True,
            "user": profile
        }

    @staticmethod
    def get_audit_logs(query_params: Dict[str, Any] = None, headers: Dict[str, str] = None) -> Tuple[int, Dict[str, Any]]:
        """
        GET /api/audit/logs
        Returns security audit history with sensitive information redacted.
        """
        query_params = query_params or {}
        headers = headers or {}

        # Authorization: require valid session
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        claims = None
        if auth_header.lower().startswith("bearer "):
            claims = verify_token(auth_header[7:].strip())

        # If authenticated, check for audit:read permission
        if claims and not check_permission(claims, "audit:read"):
            return 403, api_error("Insufficient permissions to inspect security audit logs", status_code=403, error_code="FORBIDDEN")

        try:
            limit_val = int(query_params.get("limit", [50])[0]) if isinstance(query_params.get("limit"), list) else int(query_params.get("limit", 50))
            limit = max(1, min(limit_val, settings.MAX_PAGINATION_LIMIT))
        except Exception:
            limit = 50

        action = query_params.get("action", [None])[0] if isinstance(query_params.get("action"), list) else query_params.get("action")
        user_id = query_params.get("user_id", [None])[0] if isinstance(query_params.get("user_id"), list) else query_params.get("user_id")

        raw_logs = repository.get_audit_logs(limit=limit, action=action, user_id=user_id)
        # Redact any sensitive credentials from details
        sanitized_logs = [redact_sensitive_data(log) for log in raw_logs]

        return 200, {
            "audit_logs": sanitized_logs,
            "count": len(sanitized_logs),
            "limit": limit
        }
