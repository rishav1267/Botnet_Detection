"""
Cryptographic and Security Utilities
Provides PBKDF2-HMAC-SHA256 password hashing, timing-safe comparison,
NoSQL query sanitization, and sensitive data redaction for audit logs.
"""

import os
import re
import hmac
import hashlib
from typing import Any, Dict, List, Union


# Standard iteration count for PBKDF2 (NIST SP 800-63B recommends >= 100,000 for SHA-256)
DEFAULT_PBKDF2_ITERATIONS = 100_000
SALT_SIZE_BYTES = 16

# Sensitive field patterns for audit logging and error redaction
SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|token|secret|jwt|api_key|collector_key|authorization|cookie|session_id|private_key)",
    re.IGNORECASE
)


def hash_password(password: str, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> str:
    """
    Hash a plaintext password using PBKDF2-HMAC-SHA256 with a unique cryptographic salt.
    Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")

    salt = os.urandom(SALT_SIZE_BYTES)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations
    )
    return f"pbkdf2_sha256${iterations}${salt.hex()}${key.hex()}"


def verify_password(password: str, encoded_hash: str) -> bool:
    """
    Verify a plaintext password against an encoded PBKDF2 or legacy hash using timing-safe comparison.
    """
    if not password or not encoded_hash:
        return False

    try:
        if encoded_hash.startswith("pbkdf2_sha256$"):
            parts = encoded_hash.split("$")
            if len(parts) != 4:
                return False
            _, iter_str, salt_hex, expected_hex = parts
            iterations = int(iter_str)
            salt = bytes.fromhex(salt_hex)
            expected_key = bytes.fromhex(expected_hex)

            candidate_key = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                iterations
            )
            return hmac.compare_digest(candidate_key, expected_key)

        # Backward compatibility for existing SHA-256 seed hashes
        elif len(encoded_hash) == 64 and all(c in "0123456789abcdefABCDEF" for c in encoded_hash):
            candidate_hex = hashlib.sha256(password.encode("utf-8")).hexdigest()
            return hmac.compare_digest(candidate_hex.lower(), encoded_hash.lower())

        return False
    except Exception:
        return False


def redact_sensitive_data(obj: Any) -> Any:
    """
    Recursively sanitize dictionaries, lists, and primitives to mask credentials
    and tokens before logging or persisting in audit records.
    """
    if isinstance(obj, dict):
        sanitized = {}
        for k, v in obj.items():
            if SENSITIVE_KEY_PATTERN.search(str(k)):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = redact_sensitive_data(v)
        return sanitized
    elif isinstance(obj, (list, tuple)):
        return [redact_sensitive_data(item) for item in obj]
    elif isinstance(obj, str):
        # Mask Bearer tokens in headers or strings
        if obj.lower().startswith("bearer "):
            return "Bearer [REDACTED]"
        return obj
    return obj


def sanitize_nosql_input(val: Any) -> Any:
    """
    Sanitize incoming request values to prevent NoSQL operator injection.
    Recursively strips keys beginning with '$' or dots in dictionary keys.
    """
    if isinstance(val, dict):
        clean_dict = {}
        for k, v in val.items():
            str_key = str(k).strip()
            # Reject NoSQL query operators ($gt, $ne, $where, $regex, etc.)
            if str_key.startswith("$") or "." in str_key:
                continue
            clean_dict[str_key] = sanitize_nosql_input(v)
        return clean_dict
    elif isinstance(val, (list, tuple)):
        return [sanitize_nosql_input(x) for x in val]
    elif isinstance(val, str):
        # Strip null bytes and control chars
        return val.replace("\x00", "").strip()
    return val


def sanitize_text(text: str, max_length: int = 2000) -> str:
    """
    Sanitize arbitrary user-supplied string: strip null bytes,
    remove dangerous HTML script tags, and enforce length bound.
    """
    if not isinstance(text, str):
        return ""
    clean = text.replace("\x00", "").strip()
    # Strip basic script tags
    clean = re.sub(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", "", clean, flags=re.IGNORECASE | re.DOTALL)
    if len(clean) > max_length:
        clean = clean[:max_length]
    return clean
