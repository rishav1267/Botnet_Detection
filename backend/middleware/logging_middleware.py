"""
Request Logging Middleware for HTTP Traffic Telemetry
"""

import time
from backend.utils.logger import logger


def log_request(method: str, path: str, status_code: int, duration_ms: float, client_ip: str = "127.0.0.1"):
    """Log formatted HTTP request with status and execution time."""
    level = "INFO"
    if status_code >= 500:
        level = "ERROR"
    elif status_code >= 400:
        level = "WARNING"

    log_fn = getattr(logger, level.lower(), logger.info)
    log_fn(f"[HTTP] {method:<6} {path} -> {status_code} ({duration_ms:.2f}ms) [{client_ip}]")
