"""
Analytics & Threat Intelligence Controller
Handles calculated telemetry, fleet distributions, threat trends, and incident benchmarks.
"""

from typing import Dict, Any, Tuple
from backend.services import analytics_service
from backend.utils.response import api_success


class AnalyticsController:
    """Handles aggregated telemetry analytics and timeframe metrics."""

    @staticmethod
    def get_traffic_analytics() -> Tuple[int, Dict[str, Any]]:
        """GET /api/analytics/traffic"""
        return 200, api_success(analytics_service.get_traffic_analytics())

    @staticmethod
    def get_devices_analytics() -> Tuple[int, Dict[str, Any]]:
        """GET /api/analytics/devices"""
        return 200, api_success(analytics_service.get_devices_analytics())

    @staticmethod
    def get_threats_analytics() -> Tuple[int, Dict[str, Any]]:
        """GET /api/analytics/threats"""
        return 200, api_success(analytics_service.get_threats_analytics())

    @staticmethod
    def get_incidents_analytics() -> Tuple[int, Dict[str, Any]]:
        """GET /api/analytics/incidents"""
        return 200, api_success(analytics_service.get_incidents_analytics())

    @staticmethod
    def get_analytics(query_params: Dict[str, Any] = None) -> Tuple[int, Dict[str, Any]]:
        """GET /api/analytics (full summary)"""
        query_params = query_params or {}
        timeframe = query_params.get("timeframe", ["24h"])[0] if isinstance(query_params.get("timeframe"), list) else query_params.get("timeframe", "24h")
        summary = analytics_service.get_analytics_summary(timeframe=timeframe)
        return 200, summary
