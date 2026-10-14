"""
Demo Controller — Manages Reproducible IoT Botnet Demonstration Scenarios
"""

from typing import Dict, Any, Tuple
from backend.services.demo_service import demo_service
from backend.validation.schemas import DemoScenarioPayload
from backend.utils.response import api_error, api_success


class DemoController:
    """Handles demo scenarios with strict labeling isolating demo data from real collector data."""

    @staticmethod
    def get_scenarios() -> Tuple[int, Dict[str, Any]]:
        """GET /api/demo/scenarios"""
        scenarios = demo_service.list_scenarios()
        return 200, api_success({
            "scenarios": scenarios,
            "disclaimer": "Demonstration mode: events generated here are tagged is_demo=True and distinct from real collector telemetry."
        })

    @staticmethod
    def trigger_scenario(payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """POST /api/demo/scenario"""
        try:
            validated = DemoScenarioPayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="VALIDATION_ERROR")

        try:
            result = demo_service.run_scenario(
                scenario_name=validated.scenario,
                device_id=validated.device_id
            )
            return 201, api_success(result)
        except ValueError as ve:
            return 400, api_error(str(ve), status_code=400, error_code="INVALID_SCENARIO")
        except Exception as e:
            return 500, api_error(f"Failed to execute demo scenario: {str(e)}", status_code=500, error_code="DEMO_EXECUTION_ERROR")
