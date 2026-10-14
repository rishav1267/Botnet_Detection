"""
Standardized API Response Builder & Error Formatters
"""

import json
from typing import Any, Dict, Optional


def api_success(data: Any, message: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build a standardized success response."""
    payload = {
        "success": True,
        "data": data,
    }
    if message:
        payload["message"] = message
    if meta:
        payload["meta"] = meta
    return payload


def api_error(message: str, status_code: int = 400, error_code: str = "BAD_REQUEST", details: Optional[Any] = None) -> Dict[str, Any]:
    """Build a standardized error response."""
    payload = {
        "success": False,
        "error_code": error_code,
        "message": message,
        "error": {
            "code": error_code,
            "message": message,
            "status": status_code
        }
    }
    if details:
        payload["error"]["details"] = details
        payload["details"] = details
    return payload
