"""
Security Alert & Incident Triage Controller
Handles incident lifecycle, state transitions, acknowledgments, forensics, and pagination.
"""

from typing import Dict, Any, Tuple, Optional
from backend.services import alert_service
from backend.validation.schemas import (
    AlertStatusPayload,
    AlertTransitionPayload,
    AlertAcknowledgePayload,
    AlertNotePayload,
    AlertBulkPayload
)
from backend.utils.response import api_error, api_success


class AlertController:
    """Handles incident ticketing, forensic notes thread, and SecOps triage."""

    @staticmethod
    def get_alerts(query_params: Dict[str, Any] = None) -> Tuple[int, Dict[str, Any]]:
        """GET /api/alerts with pagination, search, and severity/status filters."""
        query_params = query_params or {}
        severity = query_params.get("severity", [None])[0] if isinstance(query_params.get("severity"), list) else query_params.get("severity")
        status = query_params.get("status", [None])[0] if isinstance(query_params.get("status"), list) else query_params.get("status")
        device_id = query_params.get("device_id", [None])[0] if isinstance(query_params.get("device_id"), list) else query_params.get("device_id")
        search = query_params.get("search", query_params.get("q", [None]))[0] if isinstance(query_params.get("search", query_params.get("q")), list) else query_params.get("search")

        try:
            page = int(query_params.get("page", ["1"])[0]) if isinstance(query_params.get("page"), list) else int(query_params.get("page", 1))
        except Exception:
            page = 1
        try:
            limit = int(query_params.get("limit", ["20"])[0]) if isinstance(query_params.get("limit"), list) else int(query_params.get("limit", 20))
        except Exception:
            limit = 20
        from backend.config.settings import settings
        limit = max(1, min(limit, settings.MAX_PAGINATION_LIMIT))

        # Query paginated alerts
        page_items, pagination, unread_count = alert_service.get_alerts_paginated(
            severity=severity,
            status=status,
            device_id=device_id,
            search=search,
            page=page,
            limit=limit
        )

        # For simple queries without page/limit, return full list to preserve frontend compatibility
        if not search and not device_id and "page" not in query_params and "limit" not in query_params:
            all_alerts = alert_service.get_alerts(severity=severity, status=status)
            return 200, {
                "success": True,
                "alerts": all_alerts,
                "total": len(all_alerts),
                "unread_count": unread_count
            }

        return 200, {
            "success": True,
            "alerts": page_items,
            "pagination": pagination,
            "total": pagination["total"],
            "unread_count": unread_count
        }

    @staticmethod
    def get_alert_by_id(alert_id: str) -> Tuple[int, Dict[str, Any]]:
        """GET /api/alerts/:id"""
        alert = alert_service.get_alert_by_id(alert_id)
        if not alert:
            return 404, api_error(
                f"Security alert '{alert_id}' not found",
                status_code=404,
                error_code="ALERT_NOT_FOUND"
            )
        return 200, api_success({"alert": alert})

    @staticmethod
    def patch_status(alert_id: str, payload: Dict[str, Any], headers: Dict[str, str] = None) -> Tuple[int, Dict[str, Any]]:
        """PATCH /api/alerts/:id/status with state transition verification."""
        headers = headers or {}
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        author = "SecOps Analyst"

        if auth_header:
            from backend.middleware.auth import verify_jwt_token
            token_claims = verify_jwt_token(auth_header)
            if not token_claims:
                return 401, api_error("Invalid or expired session token", status_code=401, error_code="UNAUTHORIZED")
            if token_claims.get("role") == "read_only":
                return 403, api_error("Read-only users cannot modify incident triage status", status_code=403, error_code="FORBIDDEN")
            author = token_claims.get("username", token_claims.get("sub", author))

        try:
            validated = AlertTransitionPayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="INVALID_STATUS")

        success, updated, err_msg, status_code = alert_service.update_alert_status(
            alert_id=alert_id,
            new_status=validated.status,
            reason=validated.reason,
            author=validated.author or author
        )
        if not success:
            return status_code, api_error(
                err_msg or "Failed to update alert status",
                status_code=status_code,
                error_code="INVALID_TRANSITION" if status_code == 400 else "ALERT_NOT_FOUND"
            )

        return 200, api_success({
            "alert": updated,
            "message": f"Alert {alert_id} transition completed to {validated.status}"
        })

    @staticmethod
    def acknowledge_alert(alert_id: str, payload: Dict[str, Any] = None, headers: Dict[str, str] = None) -> Tuple[int, Dict[str, Any]]:
        """PATCH /api/alerts/:id/acknowledge"""
        payload = payload or {}
        headers = headers or {}
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        analyst_name = "SecOps Analyst"

        if auth_header:
            from backend.middleware.auth import verify_jwt_token
            token_claims = verify_jwt_token(auth_header)
            if not token_claims:
                return 401, api_error("Invalid or expired session token", status_code=401, error_code="UNAUTHORIZED")
            if token_claims.get("role") == "read_only":
                return 403, api_error("Read-only users cannot acknowledge alerts", status_code=403, error_code="FORBIDDEN")
            analyst_name = token_claims.get("username", token_claims.get("sub", analyst_name))

        try:
            validated = AlertAcknowledgePayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="INVALID_PAYLOAD")

        success, updated, err_msg, status_code = alert_service.acknowledge_alert(
            alert_id=alert_id,
            analyst=validated.analyst or analyst_name,
            note=validated.note
        )
        if not success:
            return status_code, api_error(
                err_msg or "Failed to acknowledge alert",
                status_code=status_code,
                error_code="ALERT_NOT_FOUND"
            )

        return 200, api_success({
            "alert": updated,
            "message": f"Alert {alert_id} acknowledged by {validated.analyst or analyst_name}"
        })

    @staticmethod
    def get_unread_count() -> Tuple[int, Dict[str, Any]]:
        """GET /api/alerts/unread-count"""
        counts = alert_service.get_unread_count()
        return 200, api_success(counts)

    @staticmethod
    def update_status(payload: Dict[str, Any], headers: Dict[str, str] = None) -> Tuple[int, Dict[str, Any]]:
        """POST /api/alerts/status (legacy compatibility)"""
        headers = headers or {}
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        if auth_header:
            from backend.middleware.auth import verify_jwt_token
            token_claims = verify_jwt_token(auth_header)
            if not token_claims:
                return 401, api_error("Invalid or expired session token", status_code=401, error_code="UNAUTHORIZED")
            if token_claims.get("role") == "read_only":
                return 403, api_error("Read-only users cannot modify alert status", status_code=403, error_code="FORBIDDEN")

        try:
            validated = AlertStatusPayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="INVALID_STATUS")

        success, updated, err_msg, status_code = alert_service.update_alert_status(
            alert_id=validated.alert_id,
            new_status=validated.status,
            reason=validated.note
        )
        if not success:
            return status_code, api_error(
                err_msg or f"Alert {validated.alert_id} not found",
                status_code=status_code,
                error_code="ALERT_NOT_FOUND"
            )

        return 200, {
            "success": True,
            "alert": updated,
            "message": f"Alert {validated.alert_id} status updated to {validated.status}"
        }

    @staticmethod
    def add_note(payload: Dict[str, Any], headers: Dict[str, str] = None) -> Tuple[int, Dict[str, Any]]:
        """POST /api/alerts/note"""
        headers = headers or {}
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        author_name = "SecOps Analyst"

        if auth_header:
            from backend.middleware.auth import verify_jwt_token
            token_claims = verify_jwt_token(auth_header)
            if not token_claims:
                return 401, api_error("Invalid or expired session token", status_code=401, error_code="UNAUTHORIZED")
            if token_claims.get("role") == "read_only":
                return 403, api_error("Read-only users cannot add notes to incidents", status_code=403, error_code="FORBIDDEN")
            author_name = token_claims.get("username", token_claims.get("sub", author_name))

        try:
            validated = AlertNotePayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="INVALID_NOTE")

        updated = alert_service.add_analyst_note(
            alert_id=validated.alert_id,
            note=validated.note,
            author=validated.author or author_name
        )
        if not updated:
            return 404, api_error(f"Alert {validated.alert_id} not found", status_code=404, error_code="ALERT_NOT_FOUND")

        return 200, {
            "success": True,
            "alert": updated,
            "message": "Forensic analyst note added to incident trail."
        }

    @staticmethod
    def bulk_action(payload: Dict[str, Any], headers: Dict[str, str] = None) -> Tuple[int, Dict[str, Any]]:
        """POST /api/alerts/bulk"""
        headers = headers or {}
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        if auth_header:
            from backend.middleware.auth import verify_jwt_token
            token_claims = verify_jwt_token(auth_header)
            if not token_claims:
                return 401, api_error("Invalid or expired session token", status_code=401, error_code="UNAUTHORIZED")
            if token_claims.get("role") == "read_only":
                return 403, api_error("Read-only users cannot perform bulk triage actions", status_code=403, error_code="FORBIDDEN")

        try:
            validated = AlertBulkPayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="INVALID_BULK_ACTION")

        result = alert_service.bulk_update(
            alert_ids=validated.alert_ids,
            action=validated.action
        )
        return 200, {
            "success": True,
            **result
        }

