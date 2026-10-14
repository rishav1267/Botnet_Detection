"""
Device & Asset Inventory Controller
Complete CRUD, search, pagination, filters, and safety safeguards for IoT assets.
"""

from typing import Dict, Any, Tuple, Optional
from backend.services import device_service, traffic_service
from backend.validation.schemas import (
    QuarantinePayload,
    RiskConfigPayload,
    DeviceCreatePayload,
    DeviceUpdatePayload
)
from backend.middleware.auth import verify_jwt_token
from backend.utils.response import api_error, api_success


class DeviceController:
    """Handles device inventory, quarantine operations, risk configuration, and lifecycle."""

    @staticmethod
    def get_devices(query: Dict[str, Any] = None) -> Tuple[int, Dict[str, Any]]:
        """GET /api/devices with pagination, search, sorting, and filters."""
        query = query or {}
        search = query.get("search", query.get("q", [None]))[0]
        risk_level = query.get("risk_level", query.get("risk_category", [None]))[0]
        protocol = query.get("protocol", [None])[0]
        device_type = query.get("device_type", query.get("type", [None]))[0]
        sort_by = query.get("sort_by", ["risk_score"])[0]
        sort_order = query.get("sort_order", ["desc"])[0]

        try:
            page = int(query.get("page", ["1"])[0])
        except Exception:
            page = 1
        try:
            limit = int(query.get("limit", query.get("page_size", ["20"]))[0])
        except Exception:
            limit = 20
        from backend.config.settings import settings
        limit = max(1, min(limit, settings.MAX_PAGINATION_LIMIT))

        # Query paginated devices from service
        devices_page, pagination, summary = device_service.get_devices_paginated(
            search=search,
            risk_level=risk_level,
            protocol=protocol,
            device_type=device_type,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            limit=limit
        )

        # Merge summary with live KPIs
        kpis = traffic_service.get_summary_kpis()
        summary.update(kpis)

        # If no query filter/pagination params were requested, return full list to preserve frontend compatibility
        if not search and not risk_level and not protocol and not device_type and "page" not in query and "limit" not in query:
            return 200, {
                "success": True,
                "devices": device_service.get_devices(),
                "summary": summary
            }

        return 200, {
            "success": True,
            "devices": devices_page,
            "pagination": pagination,
            "summary": summary
        }

    @staticmethod
    def get_device_by_id(device_id: str) -> Tuple[int, Dict[str, Any]]:
        """GET /api/devices/:id"""
        dev = device_service.get_device(device_id)
        if not dev:
            return 404, api_error(f"Device '{device_id}' not found", status_code=404, error_code="DEVICE_NOT_FOUND")
        return 200, api_success({"device": dev})

    @staticmethod
    def get_device_traffic(device_id: str, query: Dict[str, Any] = None) -> Tuple[int, Dict[str, Any]]:
        """GET /api/devices/:id/traffic"""
        dev = device_service.get_device(device_id)
        if not dev:
            return 404, api_error(f"Device '{device_id}' not found", status_code=404, error_code="DEVICE_NOT_FOUND")

        query = query or {}
        try:
            limit = int(query.get("limit", ["50"])[0])
        except Exception:
            limit = 50
        try:
            page = int(query.get("page", ["1"])[0])
        except Exception:
            page = 1

        flows = device_service.get_device_traffic(device_id, limit=limit, page=page)
        return 200, api_success({
            "device_id": device_id,
            "flows": flows,
            "count": len(flows),
            "page": page,
            "limit": limit
        })

    @staticmethod
    def get_device_alerts(device_id: str) -> Tuple[int, Dict[str, Any]]:
        """GET /api/devices/:id/alerts"""
        dev = device_service.get_device(device_id)
        if not dev:
            return 404, api_error(f"Device '{device_id}' not found", status_code=404, error_code="DEVICE_NOT_FOUND")

        alerts = device_service.get_device_alerts(device_id)
        return 200, api_success({
            "device_id": device_id,
            "alerts": alerts,
            "count": len(alerts)
        })

    @staticmethod
    def create_device(payload: Dict[str, Any], headers: Dict[str, str] = None) -> Tuple[int, Dict[str, Any]]:
        """POST /api/devices"""
        headers = headers or {}
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        actor = "SecOps Analyst"

        if auth_header:
            token_claims = verify_jwt_token(auth_header)
            if not token_claims:
                return 401, api_error("Invalid or expired session token", status_code=401, error_code="UNAUTHORIZED")
            if token_claims.get("role") == "read_only":
                return 403, api_error("Read-only users cannot register new IoT devices", status_code=403, error_code="FORBIDDEN")
            actor = token_claims.get("username", token_claims.get("sub", actor))

        try:
            validated = DeviceCreatePayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="VALIDATION_ERROR")

        success, dev, err = device_service.create_device(validated.model_dump(), actor=actor)
        if not success:
            return 409, api_error(err or "Device conflict", status_code=409, error_code="DEVICE_CONFLICT")

        return 201, api_success({"device": dev, "message": f"Device {dev.get('id')} registered successfully."})

    @staticmethod
    def update_device(device_id: str, payload: Dict[str, Any], headers: Dict[str, str] = None) -> Tuple[int, Dict[str, Any]]:
        """PATCH /api/devices/:id"""
        headers = headers or {}
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        actor = "SecOps Analyst"

        if auth_header:
            token_claims = verify_jwt_token(auth_header)
            if not token_claims:
                return 401, api_error("Invalid or expired session token", status_code=401, error_code="UNAUTHORIZED")
            if token_claims.get("role") == "read_only":
                return 403, api_error("Read-only users cannot modify device configurations", status_code=403, error_code="FORBIDDEN")
            actor = token_claims.get("username", token_claims.get("sub", actor))

        try:
            validated = DeviceUpdatePayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="VALIDATION_ERROR")

        updates = validated.model_dump(exclude_unset=True)
        success, updated, err = device_service.update_device(device_id, updates, actor=actor)
        if not success:
            return 404, api_error(err or f"Device '{device_id}' not found", status_code=404, error_code="DEVICE_NOT_FOUND")

        return 200, api_success({"device": updated, "message": f"Device {device_id} updated successfully."})

    @staticmethod
    def delete_device(
        device_id: str,
        query: Dict[str, Any] = None,
        payload: Dict[str, Any] = None,
        headers: Dict[str, str] = None
    ) -> Tuple[int, Dict[str, Any]]:
        """DELETE /api/devices/:id with safeguards against deleting quarantined assets."""
        query = query or {}
        payload = payload or {}
        headers = headers or {}
        actor = "SecOps Analyst"

        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        if not auth_header:
            return 401, api_error("Authentication required to delete IoT devices.", status_code=401, error_code="UNAUTHORIZED")

        token_claims = verify_jwt_token(auth_header)
        if not token_claims:
            return 401, api_error("Invalid or expired session token", status_code=401, error_code="UNAUTHORIZED")

        # Deletion strictly requires admin privileges
        if token_claims.get("role") != "admin":
            return 403, api_error(
                f"Deleting IoT devices requires administrator privileges. Current role: '{token_claims.get('role')}'.",
                status_code=403,
                error_code="FORBIDDEN"
            )
        actor = token_claims.get("username", token_claims.get("sub", actor))

        force = (
            query.get("force", ["false"])[0].lower() in ("true", "1") or
            payload.get("confirm_override", False) is True
        )

        success, msg, status_code = device_service.delete_device(device_id, force=force, actor=actor)
        if not success:
            return status_code, api_error(msg or "Deletion failed", status_code=status_code, error_code="SAFEGUARD_BLOCKED" if status_code == 400 else "DEVICE_NOT_FOUND")

        return 200, api_success({"deleted_id": device_id, "message": msg})

    @staticmethod
    def quarantine_device(payload: Dict[str, Any], headers: Dict[str, str] = None) -> Tuple[int, Dict[str, Any]]:
        """POST /api/devices/quarantine"""
        headers = headers or {}
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        if auth_header:
            token_claims = verify_jwt_token(auth_header)
            if not token_claims:
                return 401, api_error("Invalid or expired session token", status_code=401, error_code="UNAUTHORIZED")
            if token_claims.get("role") == "read_only":
                return 403, api_error("Read-only users cannot modify quarantine status", status_code=403, error_code="FORBIDDEN")

        try:
            validated = QuarantinePayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="INVALID_PAYLOAD")

        success = device_service.set_quarantine(validated.device_id, validated.quarantined)
        if not success:
            return 404, api_error(f"Device {validated.device_id} not found", status_code=404, error_code="DEVICE_NOT_FOUND")

        return 200, {
            "success": True,
            "device_id": validated.device_id,
            "quarantined": validated.quarantined,
            "message": f"Device {validated.device_id} quarantine updated to {validated.quarantined}"
        }

    @staticmethod
    def get_risk_config() -> Tuple[int, Dict[str, Any]]:
        """GET /api/risk/config"""
        return 200, device_service.get_risk_config()

    @staticmethod
    def update_risk_config(payload: Dict[str, Any], headers: Dict[str, str] = None) -> Tuple[int, Dict[str, Any]]:
        """POST /api/risk/config"""
        headers = headers or {}
        auth_header = headers.get("Authorization", headers.get("authorization", ""))
        if auth_header:
            token_claims = verify_jwt_token(auth_header)
            if not token_claims:
                return 401, api_error("Invalid or expired session token", status_code=401, error_code="UNAUTHORIZED")
            if token_claims.get("role") != "admin":
                return 403, api_error("Modifying risk engine configuration requires administrator role", status_code=403, error_code="FORBIDDEN")

        try:
            validated = RiskConfigPayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="INVALID_PAYLOAD")

        updated = device_service.update_risk_config(validated.model_dump(exclude_unset=True))
        return 200, {
            "success": True,
            "risk_config": updated,
            "message": "Risk engine weights and thresholds updated successfully."
        }

