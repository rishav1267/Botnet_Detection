"""
Authentication Service — User Login, Credential Verification, Token Issuance, and Lifecycle
Implements PBKDF2-HMAC-SHA256 verification, refresh tokens, and role definitions.
"""

import time
from typing import Optional, Dict, Any
from backend.config.settings import settings
from backend.middleware.auth import (
    generate_token,
    revoke_token,
    verify_token,
    canonical_role,
    ROLE_PERMISSIONS
)
from backend.utils.crypto import hash_password, verify_password
from backend.utils.logger import logger


class AuthService:
    """Manages SecOps analyst accounts, credentials, and session tokens."""

    def __init__(self):
        # Initialize default accounts with secure salted PBKDF2-HMAC-SHA256 hashes
        admin_pass = settings.ADMIN_PASSWORD
        analyst_pass = settings.ANALYST_PASSWORD
        auditor_pass = settings.AUDITOR_PASSWORD

        self.users: Dict[str, Dict[str, Any]] = {
            "admin": {
                "id": "USR-001",
                "username": "admin",
                "email": "secops-admin@netguard.iot",
                "role": "admin",
                "role_display": "Lead SecOps Engineer",
                "password_hash": hash_password(admin_pass),
                "created_at": "2026-10-01 00:00:00 UTC",
                "is_active": True
            },
            "analyst": {
                "id": "USR-002",
                "username": "analyst",
                "email": "alex.vance@netguard.iot",
                "role": "analyst",
                "role_display": "SecOps Analyst",
                "password_hash": hash_password(analyst_pass),
                "created_at": "2026-10-01 00:00:00 UTC",
                "is_active": True
            },
            "auditor": {
                "id": "USR-003",
                "username": "auditor",
                "email": "auditor@netguard.iot",
                "role": "read_only",
                "role_display": "Security Auditor",
                "password_hash": hash_password(auditor_pass),
                "created_at": "2026-10-01 00:00:00 UTC",
                "is_active": True
            },
            "readonly": {
                "id": "USR-004",
                "username": "readonly",
                "email": "readonly@netguard.iot",
                "role": "read_only",
                "role_display": "Read-Only Viewer",
                "password_hash": hash_password(auditor_pass),
                "created_at": "2026-10-01 00:00:00 UTC",
                "is_active": True
            }
        }

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Verify credentials using timing-safe PBKDF2 verification.
        Returns access token, refresh token, and user metadata.
        """
        clean_user = (username or "").strip().lower()
        user = self.users.get(clean_user)
        if not user or not user.get("is_active"):
            return None

        # Verify password hash securely
        if not verify_password(password, user["password_hash"]):
            return None

        # Generate short-lived access token and longer-lived refresh token
        access_token = generate_token(
            user_id=user["id"],
            username=user["username"],
            role=user["role"],
            token_type="access"
        )
        refresh_token = generate_token(
            user_id=user["id"],
            username=user["username"],
            role=user["role"],
            token_type="refresh"
        )

        permissions = sorted(list(ROLE_PERMISSIONS.get(user["role"], [])))

        return {
            "token": access_token,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": settings.JWT_ACCESS_EXPIRATION_MINUTES * 60,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "role_display": user["role_display"],
                "permissions": permissions
            }
        }

    def refresh_session(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Exchange a valid unexpired refresh token for a new access token.
        """
        claims = verify_token(refresh_token)
        if not claims or claims.get("type") != "refresh":
            return None

        username = claims.get("username", "").lower()
        user = self.users.get(username)
        if not user or not user.get("is_active"):
            return None

        new_access_token = generate_token(
            user_id=user["id"],
            username=user["username"],
            role=user["role"],
            token_type="access"
        )

        return {
            "access_token": new_access_token,
            "token": new_access_token,
            "token_type": "Bearer",
            "expires_in": settings.JWT_ACCESS_EXPIRATION_MINUTES * 60
        }

    def logout(self, token: str) -> bool:
        """Revoke active access and/or refresh token."""
        return revoke_token(token)

    def get_user_profile(self, claims: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Retrieve sanitized user profile for /api/auth/me."""
        username = claims.get("username", "").lower()
        user = self.users.get(username)
        role = canonical_role(claims.get("role", "read_only"))
        perms = sorted(list(ROLE_PERMISSIONS.get(role, [])))

        return {
            "id": claims.get("sub", user["id"] if user else "UNKNOWN"),
            "username": claims.get("username", user["username"] if user else "unknown"),
            "email": user["email"] if user else f"{claims.get('username')}@netguard.iot",
            "role": role,
            "role_display": user.get("role_display", role) if user else role,
            "permissions": perms
        }


# Singleton service instance
auth_service = AuthService()
