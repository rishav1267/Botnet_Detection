"""
Detection Controller — Rule-Based and Machine Learning Hybrid Analysis Endpoints
"""

from typing import Dict, Any, Tuple
from backend.services.detection_service import detection_service
from backend.validation.schemas import DetectionAnalyzePayload
from backend.utils.response import api_error, api_success


class DetectionController:
    """Handles /api/detection/* endpoints."""

    @staticmethod
    def analyze(payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """
        POST /api/detection/analyze
        Executes real rule-based and ML inference.
        Returns explicit model-unavailable status if ML is unconfigured.
        Supports both {"flow": {...}} wrapper, {"features": [...]}, and flat flow dictionaries.
        """
        payload = payload or {}
        if "flow" in payload or "features" in payload:
            try:
                validated = DetectionAnalyzePayload(**payload)
                flow_data = validated.flow
                features = validated.features
                device_id = validated.device_id
            except Exception as e:
                return 400, api_error(str(e), status_code=400, error_code="VALIDATION_ERROR")
        else:
            flow_data = {k: v for k, v in payload.items() if k not in ("device_id", "features")}
            features = None
            device_id = payload.get("device_id")

        result = detection_service.analyze(
            flow_data=flow_data,
            features=features,
            device_id=device_id
        )

        return 200, api_success(result)

    @staticmethod
    def get_results(query: Dict[str, Any] = None) -> Tuple[int, Dict[str, Any]]:
        """GET /api/detection/results with pagination."""
        query = query or {}
        verdict = query.get("verdict", [None])[0]
        device_id = query.get("device_id", [None])[0]

        try:
            page = int(query.get("page", ["1"])[0])
        except Exception:
            page = 1
        try:
            limit = int(query.get("limit", ["20"])[0])
        except Exception:
            limit = 20

        results, pagination = detection_service.get_results_paginated(
            verdict=verdict,
            device_id=device_id,
            page=page,
            limit=limit
        )

        return 200, api_success({
            "results": results,
            "pagination": pagination
        })

    @staticmethod
    def get_result_by_id(detection_id: str) -> Tuple[int, Dict[str, Any]]:
        """GET /api/detection/results/:id"""
        result = detection_service.get_result_by_id(detection_id)
        if not result:
            return 404, api_error(
                f"Detection record '{detection_id}' not found",
                status_code=404,
                error_code="DETECTION_NOT_FOUND"
            )
        return 200, api_success({"result": result})

    @staticmethod
    def get_status() -> Tuple[int, Dict[str, Any]]:
        """GET /api/detection/status"""
        return 200, api_success(detection_service.get_status())

    @staticmethod
    def get_rules() -> Tuple[int, Dict[str, Any]]:
        """GET /api/detection/rules — List all configurable detection rules."""
        from backend.services.rule_engine import configurable_rule_engine
        rules = configurable_rule_engine.get_rules()
        return 200, api_success({
            "rules": rules,
            "total_rules": len(rules),
            "enabled_count": sum(1 for r in rules if r.get("enabled", True))
        })

    @staticmethod
    def update_rule(rule_id: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """PATCH /api/detection/rules/:id — Configure thresholds, severity, and enabled state."""
        from backend.services.rule_engine import configurable_rule_engine
        from backend.validation.schemas import RuleConfigUpdatePayload

        payload["rule_id"] = rule_id
        try:
            validated = RuleConfigUpdatePayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="VALIDATION_ERROR")

        updated = configurable_rule_engine.update_rule(rule_id, validated.model_dump(exclude_unset=True))
        if not updated:
            return 404, api_error(f"Rule '{rule_id}' not found", status_code=404, error_code="RULE_NOT_FOUND")

        return 200, api_success({
            "message": f"Rule '{rule_id}' updated successfully",
            "rule": updated
        })
