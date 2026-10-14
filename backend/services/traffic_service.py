"""
Traffic Service — Manages Live Flow Ingestion, Streaming Ticks, and Network Telemetry
"""

import time
from typing import List, Dict, Any, Optional, Tuple
from backend.database.repository import repository
from backend.utils.logger import logger


class TrafficService:
    """Business logic for network traffic monitoring and telemetry ingestion."""

    def __init__(self, network_manager):
        self.network_manager = network_manager
        # Ingestion rate limiter: {ip: [timestamps]}
        self._rate_limits: Dict[str, List[float]] = {}

    def check_rate_limit(self, client_ip: str, max_requests: int = 120, window_sec: int = 60) -> bool:
        """Rate limiter for traffic ingestion (e.g. 120 requests/minute per client)."""
        now = time.time()
        timestamps = self._rate_limits.setdefault(client_ip, [])
        # Expire old timestamps
        self._rate_limits[client_ip] = [t for t in timestamps if now - t < window_sec]
        if len(self._rate_limits[client_ip]) >= max_requests:
            return False
        self._rate_limits[client_ip].append(now)
        return True

    def get_recent_flows(self, limit: int = 50, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return recently recorded traffic flows with optional status filter."""
        flows = self.network_manager.recent_flows[:limit]
        if status_filter:
            flows = [f for f in flows if f.get("status", "").lower() == status_filter.lower()]
        return flows

    def get_traffic_events(
        self,
        device_id: Optional[str] = None,
        protocol: Optional[str] = None,
        verdict: Optional[str] = None,
        attack_category: Optional[str] = None,
        page: int = 1,
        limit: int = 50
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Query traffic events with filters and pagination."""
        return repository.get_traffic_events_paginated(
            device_id=device_id,
            protocol=protocol,
            verdict=verdict,
            attack_category=attack_category,
            page=page,
            limit=limit
        )

    def tick_stream(self, scenario: Optional[str] = None) -> Dict[str, Any]:
        """Simulate a telemetry tick and ingest a new flow."""
        flow = self.network_manager.tick_stream(scenario)
        repository.record_flow(flow)
        return {
            "new_flow": flow,
            "new_alert": flow.get("new_alert"),
            "kpis": self.network_manager.get_summary_kpis()
        }

    def ingest_custom_flow(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest an external network flow event and run detection."""
        analyzed = self.network_manager.ingest_external_flow(flow_data)
        repository.record_flow(analyzed)
        return analyzed

    def ingest_traffic_event(self, event_data: Dict[str, Any], client_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """Validate and ingest an incoming event from sensor, run detection, and persist."""
        # Convert schema payload to internal flow format
        formatted = {
            "source_ip": event_data["source_ip"],
            "dest_ip": event_data["destination_ip"],
            "source_port": event_data["source_port"],
            "dest_port": event_data["destination_port"],
            "protocol": event_data["protocol"],
            "packet_count": event_data["packet_count"],
            "byte_count": event_data["byte_count"],
            "duration": event_data.get("duration_sec", 1.0),
            "device_id": event_data.get("device_id"),
        }
        if "flow_statistics" in event_data and event_data["flow_statistics"]:
            formatted.update(event_data["flow_statistics"])

        analyzed = self.network_manager.ingest_external_flow(formatted)
        repository.record_flow(analyzed)
        logger.info(f"[TrafficService] Ingested flow from {client_ip} -> Verdict: {analyzed.get('verdict', analyzed.get('status'))}")
        return analyzed

    def get_stats(self) -> Dict[str, Any]:
        """Return current network throughput, PPS, and flow statistics."""
        return repository.get_traffic_stats()

    def get_protocols(self) -> Dict[str, Any]:
        """Return protocol breakdown with byte and packet distributions."""
        return repository.get_traffic_protocols()

    def trigger_attack_scenario(self, scenario: str) -> Dict[str, Any]:
        """Trigger a simulated botnet attack scenario."""
        flow = self.network_manager.trigger_attack_simulation(scenario)
        repository.record_audit(
            action="SIMULATION_ATTACK_TRIGGER",
            user_id="secops_analyst",
            details={"scenario": scenario, "flow_id": flow.get("flow_id")}
        )
        return {
            "scenario": scenario,
            "flow": flow,
            "message": f"Injected active scenario: {scenario}"
        }

    def get_summary_kpis(self) -> Dict[str, Any]:
        """Return executive summary KPIs."""
        return self.network_manager.get_summary_kpis()
