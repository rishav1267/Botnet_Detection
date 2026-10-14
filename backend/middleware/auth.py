"""
Authentication & Authorization Middleware
Provides token validation, session extraction, token revocation blacklist,
and Role-Based Access Control (RBAC) verification.
"""

import os
import hmac
import hashlib
import json
import base64
import time
import threading
from typing import Optional, Dict, Any, List, Set
from backend.config.settings import settings
from backend.utils.logger import logger

# Thread-safe in-memory token revocation blacklist (for explicit logouts)
_revocation_lock = threading.Lock()
_revoked_tokens: Set[str] = set()

# Role hierarchy definitions
ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "admin": {
        "devices:read", "devices:create", "devices:update", "devices:delete", "devices:quarantine",
        "alerts:read", "alerts:update", "alerts:acknowledge", "alerts:bulk", "alerts:note",
        "traffic:read", "traffic:ingest", "detection:run", "detection:rules",
        "risk:update", "ml:read", "ml:retrain", "audit:read", "system:manage"
    },
    "analyst": {
        "devices:read", "devices:create", "devices:update", "devices:quarantine",
        "alerts:read", "alerts:update", "alerts:acknowledge", "alerts:bulk", "alerts:note",
        "traffic:read", "traffic:ingest", "detection:run", "detection:rules",
        "ml:read", "ml:retrain", "audit:read"
    },
    "read_only": {
        "devices:read", "alerts:read", "traffic:read", "detection:read", "ml:read", "audit:read"
    }
}


def canonical_role(role_name: str) -> str:
    """Normalize human-readable role strings to canonical identifiers."""
    r = (role_name or "").lower().strip()
    if r in ("admin", "lead secops engineer", "administrator", "root"):
        return "admin"
    if r in ("analyst", "secops analyst", "soc analyst", "operator"):
        return "analyst"
    if r in ("read_only", "readonly", "auditor", "security auditor", "viewer", "guest"):
        return "read_only"
    return "read_only"


def generate_token(
    user_id: str,
    username: str,
    role: str = "SecOps Analyst",
    token_type: str = "access",
    expires_in_sec: Optional[int] = None
) -> str:
    """Generate a signed HMAC-SHA256 authenticated JWT with unique jti claim."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    canon_role = canonical_role(role)

    if expires_in_sec is not None:
        exp = now + expires_in_sec
    elif token_type == "refresh":
        exp = now + (settings.JWT_REFRESH_EXPIRATION_DAYS * 86400)
    else:
        # Default access token: 60 minutes (or settings.JWT_EXPIRATION_HOURS)
        exp = now + (settings.JWT_ACCESS_EXPIRATION_MINUTES * 60)

    payload = {
        "jti": os.urandom(16).hex(),
        "sub": user_id,
        "username": username,
        "role": canon_role,
        "role_display": role,
        "type": token_type,
        "iat": now,
        "exp": exp
    }

    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{h_b64}.{p_b64}".encode()

    signature = hmac.new(settings.JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    return f"{h_b64}.{p_b64}.{sig_b64}"


def revoke_token(token: str) -> bool:
    """Add a token to the revoked blacklist upon user logout."""
    if not token:
        return False
    # Clean token prefix if Bearer was included
    clean_token = token.strip()
    if clean_token.lower().startswith("bearer "):
        clean_token = clean_token[7:].strip()

    with _revocation_lock:
        _revoked_tokens.add(clean_token)
        # Periodic cleanup of expired tokens from blacklist to prevent memory bloat
        if len(_revoked_tokens) > 5000:
            _cleanup_expired_revocations()
    return True


def is_token_revoked(token: str) -> bool:
    """Check if token is in the revocation blacklist."""
    clean_token = token.strip()
    if clean_token.lower().startswith("bearer "):
        clean_token = clean_token[7:].strip()
    with _revocation_lock:
        return clean_token in _revoked_tokens


def _cleanup_expired_revocations():
    """Remove expired tokens from the blacklist set."""
    now = time.time()
    to_remove = set()
    for tok in _revoked_tokens:
        try:
            parts = tok.split(".")
            if len(parts) == 3:
                p_bytes = base64.urlsafe_b64decode(parts[1] + "=="[:len(parts[1]) % 4])
                payload = json.loads(p_bytes.decode())
                if payload.get("exp", 0) < now:
                    to_remove.add(tok)
        except Exception:
            to_remove.add(tok)
    for tok in to_remove:
        _revoked_tokens.discard(tok)


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify HMAC-SHA256 signature, expiry, and revocation state."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        # Check blacklist
        if is_token_revoked(token):
            logger.debug("[Auth] Rejected revoked token.")
            return None

        h_b64, p_b64, sig_b64 = parts
        signing_input = f"{h_b64}.{p_b64}".encode()
        expected_sig = hmac.new(settings.JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        actual_sig = base64.urlsafe_b64decode(sig_b64 + "=="[:len(sig_b64) % 4])

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload_bytes = base64.urlsafe_b64decode(p_b64 + "=="[:len(p_b64) % 4])
        payload = json.loads(payload_bytes.decode())

        if payload.get("exp", 0) < time.time():
            return None

        return payload
    except Exception as e:
        logger.debug(f"[Auth] Token verification exception: {e}")
        return None


def verify_jwt_token(auth_header: str) -> Optional[Dict[str, Any]]:
    """Helper to verify Bearer Authorization header or raw JWT token string."""
    if not auth_header:
        return None
    token = auth_header.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return verify_token(token)


def check_permission(claims: Optional[Dict[str, Any]], required_permission: str) -> bool:
    """Verify if the token claims hold the specified RBAC permission."""
    if not claims:
        return False
    role = canonical_role(claims.get("role", ""))
    perms = ROLE_PERMISSIONS.get(role, set())
    return required_permission in perms


def check_role(claims: Optional[Dict[str, Any]], allowed_roles: List[str]) -> bool:
    """Verify if token role matches at least one of the allowed roles."""
    if not claims:
        return False
    user_role = canonical_role(claims.get("role", ""))
    allowed_canon = [canonical_role(r) for r in allowed_roles]
    return user_role in allowed_canon
