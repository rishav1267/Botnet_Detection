"""
Threat Detection Rules Controller
"""

from typing import Dict, Any, Tuple
from backend.services import detection_service
from backend.validation.schemas import RuleUpdatePayload
from backend.utils.response import api_error


class ThreatController:
    """Handles Snort/Suricata heuristic rule management."""

    @staticmethod
    def get_rules() -> Tuple[int, Dict[str, Any]]:
        return 200, {
            "rules": list(detection_service.rule_engine.rules.values())
        }

    @staticmethod
    def update_rule(payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        try:
            validated = RuleUpdatePayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="INVALID_PAYLOAD")

        rule_id = validated.rule_id
        if rule_id not in detection_service.rule_engine.rules:
            return 404, api_error(f"Rule {rule_id} not found", status_code=404, error_code="RULE_NOT_FOUND")

        rule = detection_service.rule_engine.rules[rule_id]
        if validated.enabled is not None:
            rule["enabled"] = validated.enabled
        if validated.threshold is not None:
            rule["threshold"] = validated.threshold

        return 200, {
            "success": True,
            "rule": rule,
            "message": f"Rule {rule_id} updated successfully"
        }
