"""
Traffic Telemetry & Ingestion Controller
Production network flow ingestion with authentication, rate limiting, and analytics.
"""

import time
from typing import Dict, Any, Tuple
from backend.services import traffic_service
from backend.config.settings import settings
from backend.validation.schemas import TrafficEventPayload, SimulationAttackPayload
from backend.middleware.auth import verify_jwt_token
from backend.utils.response import api_error, api_success


class TrafficController:
    """Handles network flow queries, stream generation, secure ingestion, and metrics."""

    @staticmethod
    def ingest_event(payload: Dict[str, Any], headers: Dict[str, str] = None, client_ip: str = "127.0.0.1") -> Tuple[int, Dict[str, Any]]:
        """
        POST /api/traffic/events
        Secure ingestion endpoint for IoT telemetry agents and network taps.
        Enforces authentication and rate limiting to prevent arbitrary unauthenticated event flooding.
        """
        headers = headers or {}
        headers_lower = {str(k).lower(): str(v).strip() for k, v in headers.items()}

        # 1. Authentication Check (X-API-Key or Bearer JWT)
        from backend.services.ingestion_service import ingestion_service
        is_authenticated, _ = ingestion_service.authenticate_collector(headers)

        if not is_authenticated:
            return 401, api_error(
                "Authentication required to ingest traffic events. Please provide a valid X-API-Key header or Bearer JWT token.",
                status_code=401,
                error_code="UNAUTHORIZED"
            )

        # 2. Rate Limiting Check
        if not ingestion_service.check_rate_limit(client_ip, max_requests=240, window_sec=60):
            return 429, api_error(
                "Ingestion rate limit exceeded (max 240 events/min per client IP). Slow down submission rate.",
                status_code=429,
                error_code="RATE_LIMIT_EXCEEDED"
            )

        # 3. Schema Validation & Sanitization
        try:
            validated = TrafficEventPayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="VALIDATION_ERROR")

        # 4. Ingest and execute detection through defensible pipeline
        event_dict = validated.model_dump()
        result = ingestion_service.process_traffic_event(event_dict, client_ip=client_ip)

        if result.get("status") == "duplicate_ignored":
            return 200, api_success({
                "status": "duplicate_ignored",
                "flow_id": result.get("flow_id"),
                "flow_hash": result.get("flow_hash"),
                "message": result.get("message")
            })

        return 201, api_success({
            "event_id": result.get("flow_id", f"EVT-{int(time.time()*1000)}"),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "verdict": result.get("verdict", "Normal"),
            "risk_score": result.get("risk_score", 10.0),
            "data_source": result.get("data_source", "collector"),
            "is_demo": result.get("is_demo", False),
            "threat_detected": result.get("verdict") in ("Suspicious", "High-Risk"),
            "rules_triggered": result.get("rules_triggered", []),
            "alert_info": result.get("alert_info"),
            "device_update": result.get("device_update")
        })

    @staticmethod
    def ingest_batch(payload: Dict[str, Any], headers: Dict[str, str] = None, client_ip: str = "127.0.0.1") -> Tuple[int, Dict[str, Any]]:
        """
        POST /api/traffic/events/batch
        Batch flow ingestion for NetFlow / IPFIX collector probes.
        """
        headers = headers or {}
        from backend.services.ingestion_service import ingestion_service
        from backend.validation.schemas import CollectorBatchPayload

        is_authenticated, _ = ingestion_service.authenticate_collector(headers)
        if not is_authenticated:
            return 401, api_error("Authentication required for batch collector ingestion.", status_code=401, error_code="UNAUTHORIZED")

        if not ingestion_service.check_rate_limit(client_ip, max_requests=60, window_sec=60):
            return 429, api_error("Batch ingestion rate limit exceeded.", status_code=429, error_code="RATE_LIMIT_EXCEEDED")

        try:
            validated = CollectorBatchPayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="VALIDATION_ERROR")

        results = []
        for ev in validated.events:
            ev_dict = ev.model_dump()
            ev_dict["collector_id"] = validated.collector_id
            ev_dict["collector_type"] = validated.collector_type
            res = ingestion_service.process_traffic_event(ev_dict, client_ip=client_ip, collector_override=validated.collector_id)
            results.append(res)

        return 201, api_success({
            "collector_id": validated.collector_id,
            "processed_count": len(results),
            "events": results
        })

    @staticmethod
    def get_events(query: Dict[str, Any] = None) -> Tuple[int, Dict[str, Any]]:
        """GET /api/traffic/events with pagination and filters."""
        query = query or {}
        device_id = query.get("device_id", [None])[0]
        protocol = query.get("protocol", [None])[0]
        verdict = query.get("verdict", query.get("status", [None]))[0]
        attack_category = query.get("attack_category", [None])[0]

        try:
            page = int(query.get("page", ["1"])[0])
        except Exception:
            page = 1
        try:
            limit = int(query.get("limit", ["50"])[0])
        except Exception:
            limit = 50
        from backend.config.settings import settings
        limit = max(1, min(limit, settings.MAX_PAGINATION_LIMIT))

        events, pagination = traffic_service.get_traffic_events(
            device_id=device_id,
            protocol=protocol,
            verdict=verdict,
            attack_category=attack_category,
            page=page,
            limit=limit
        )

        # Support is_demo / data_source filtering
        is_demo_param = query.get("is_demo", [None])[0]
        data_source_param = query.get("data_source", [None])[0]

        if is_demo_param is not None:
            want_demo = is_demo_param.lower() in ("true", "1")
            events = [e for e in events if bool(e.get("is_demo", False)) == want_demo]
        if data_source_param:
            events = [e for e in events if e.get("data_source", "").lower() == data_source_param.lower()]

        return 200, api_success({
            "events": events,
            "pagination": pagination
        })

    @staticmethod
    def get_stats() -> Tuple[int, Dict[str, Any]]:
        """GET /api/traffic/stats"""
        return 200, api_success(traffic_service.get_stats())

    @staticmethod
    def get_protocols() -> Tuple[int, Dict[str, Any]]:
        """GET /api/traffic/protocols"""
        return 200, api_success(traffic_service.get_protocols())

    @staticmethod
    def get_traffic(query_params: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """GET /api/traffic (backward compatibility)"""
        limit = int(query_params.get("limit", [50])[0]) if isinstance(query_params.get("limit"), list) else int(query_params.get("limit", 50))
        status_filter = query_params.get("status", [None])[0] if isinstance(query_params.get("status"), list) else query_params.get("status")

        flows = traffic_service.get_recent_flows(limit=limit, status_filter=status_filter)
        return 200, {
            "flows": flows,
            "total_recorded": len(flows),
            "timestamp": time.strftime("%H:%M:%S")
        }

    @staticmethod
    def tick_stream(query_params: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """GET /api/traffic/tick"""
        scenario = query_params.get("scenario", [None])[0] if isinstance(query_params.get("scenario"), list) else query_params.get("scenario")
        result = traffic_service.tick_stream(scenario=scenario)
        return 200, result

    @staticmethod
    def ingest_flow(payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """POST /api/traffic/ingest (internal dashboard simulation ingestion)"""
        if not payload or not isinstance(payload, dict):
            return 400, api_error("Payload must be a JSON object", status_code=400, error_code="INVALID_PAYLOAD")
        analyzed = traffic_service.ingest_custom_flow(payload)
        return 200, {
            "success": True,
            "analyzed_flow": analyzed
        }

    @staticmethod
    def trigger_simulation_attack(payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """POST /api/simulation/attack"""
        try:
            validated = SimulationAttackPayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="INVALID_PAYLOAD")

        result = traffic_service.trigger_attack_scenario(validated.scenario or "mirai_telnet")
        return 200, result
