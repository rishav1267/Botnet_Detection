"""
CORS Middleware for NETGUARD IoT Backend
"""

from typing import Dict
from backend.config.settings import settings


def apply_cors_headers(headers: Dict[str, str], origin: str = None) -> Dict[str, str]:
    """Inject standard CORS response headers."""
    allowed = settings.CORS_ORIGIN
    headers["Access-Control-Allow-Origin"] = allowed if allowed != "*" else (origin or "*")
    headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With, Cache-Control, X-API-Key"
    headers["Access-Control-Max-Age"] = "86400"
    return headers
