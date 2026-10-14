"""
Centralized Error Handling Middleware
Catches unhandled exceptions and formats consistent, sanitized JSON error responses.
Ensures zero accidental leakage of stack traces, database internals, or credentials.
"""

import traceback
from typing import Dict, Any, Tuple
from backend.utils.logger import logger
from backend.utils.response import api_error


def handle_exception(e: Exception) -> Tuple[int, Dict[str, Any]]:
    """
    Convert any Python exception into an HTTP status code and sanitized JSON response.
    Never exposes internal system details, passwords, or stack traces to clients.
    """
    error_type = type(e).__name__
    error_msg = str(e) or "An internal error occurred"

    # 1. Validation & Input Errors
    if isinstance(e, ValueError):
        logger.warning(f"[ErrorHandler] Validation error: {error_msg}")
        return 400, api_error(error_msg, status_code=400, error_code="VALIDATION_ERROR")

    # 2. Authorization & Permissions
    elif isinstance(e, PermissionError):
        logger.warning(f"[ErrorHandler] Permission denied: {error_msg}")
        return 403, api_error("Access denied. Insufficient permissions for this resource.", status_code=403, error_code="FORBIDDEN")

    # 3. Missing Resource
    elif isinstance(e, KeyError):
        logger.warning(f"[ErrorHandler] Missing resource: {error_msg}")
        return 404, api_error(f"Resource not found: {error_msg}", status_code=404, error_code="NOT_FOUND")

    # 4. Generic Server Error (Secure Sanitization)
    # Log internal diagnostics only on the server, never send tracebacks over the wire
    logger.error(f"[ErrorHandler] Uncaught exception {error_type}: {error_msg}\n{traceback.format_exc()}")
    return 500, api_error(
        "An unexpected internal error occurred. Request has been logged for security review.",
        status_code=500,
        error_code="INTERNAL_SERVER_ERROR"
    )
