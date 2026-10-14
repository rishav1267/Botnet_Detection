"""
Request Payload Validation & Sanitization Schemas
Production validation for IoT Botnet Detection REST API endpoints.
"""

import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


# ==============================================================================
# DEVICE SCHEMAS
# ==============================================================================

class DeviceCreatePayload(BaseModel):
    """Schema for registering a new IoT device."""
    id: Optional[str] = None
    name: str = Field(..., min_length=2, max_length=120)
    type: str = Field(..., min_length=2, max_length=80)
    ip_address: str = Field(...)
    mac_address: str = Field(...)
    location: Optional[str] = "Default Subnet"
    firmware_version: Optional[str] = "1.0.0"
    device_group: Optional[str] = "Perimeter"

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        d = dict(data)
        if "ip" in d and "ip_address" not in d:
            d["ip_address"] = d["ip"]
        if "mac" in d and "mac_address" not in d:
            d["mac_address"] = d["mac"]
        return d

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        parts = v.strip().split(".")
        if len(parts) != 4:
            raise ValueError(f"Invalid IPv4 address format: {v}")
        for p in parts:
            if not p.isdigit() or not (0 <= int(p) <= 255):
                raise ValueError(f"Invalid IPv4 octet: {p} in {v}")
        return v.strip()

    @field_validator("mac_address")
    @classmethod
    def validate_mac(cls, v: str) -> str:
        mac_pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        if not re.match(mac_pattern, v.strip()):
            raise ValueError(f"Invalid MAC address format: {v}. Expected XX:XX:XX:XX:XX:XX")
        return v.strip().upper()


class DeviceUpdatePayload(BaseModel):
    """Schema for updating IoT device properties."""
    name: Optional[str] = Field(None, min_length=1, max_length=120)
    type: Optional[str] = Field(None, min_length=1, max_length=80)
    location: Optional[str] = Field(None, max_length=120)
    firmware_version: Optional[str] = Field(None, max_length=50)
    status: Optional[str] = None
    quarantined: Optional[bool] = None
    tags: Optional[List[str]] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        valid = ["Normal", "Suspicious", "High-Risk"]
        match = [s for s in valid if s.lower() == v.lower()]
        if not match:
            raise ValueError(f"Invalid device status '{v}'. Allowed: {', '.join(valid)}")
        return match[0]


class QuarantinePayload(BaseModel):
    device_id: str = Field(..., min_length=1)
    quarantined: bool = Field(...)


# ==============================================================================
# ==============================================================================
# TRAFFIC EVENT SCHEMAS
# ==============================================================================

class FlowStatisticsPayload(BaseModel):
    """Flow statistical metrics extracted by the collector."""
    syn_ratio: Optional[float] = Field(default=0.0, ge=0.0, le=1.0)
    rst_ratio: Optional[float] = Field(default=0.0, ge=0.0, le=1.0)
    payload_entropy: Optional[float] = Field(default=4.0, ge=0.0, le=8.0)
    failed_connections: Optional[int] = Field(default=0, ge=0)
    unique_dest_ips: Optional[int] = Field(default=1, ge=1)
    packet_rate: Optional[float] = Field(default=None, ge=0.0)
    byte_rate: Optional[float] = Field(default=None, ge=0.0)
    conn_freq: Optional[float] = Field(default=None, ge=0.0)
    fwd_packets: Optional[int] = Field(default=0, ge=0)
    bwd_packets: Optional[int] = Field(default=0, ge=0)
    avg_packet_size: Optional[float] = Field(default=128.0, ge=0.0)


class TrafficEventPayload(BaseModel):
    """Documented schema for incoming IoT network traffic flow events from authorized collectors."""
    source_ip: str = Field(...)
    destination_ip: str = Field(...)
    source_port: Optional[int] = Field(default=1024, ge=1, le=65535)
    destination_port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(...)
    packet_count: int = Field(..., ge=1, description="Flow packet count must be >= 1")
    byte_count: int = Field(..., ge=1, description="Flow byte count must be >= 1")
    duration_sec: Optional[float] = Field(default=1.0, ge=0.0, description="Flow window duration in seconds")
    direction: Optional[str] = Field(default="outbound")
    connection_frequency: Optional[float] = Field(default=None, ge=0.0)
    flow_statistics: Optional[FlowStatisticsPayload] = None
    device_id: Optional[str] = None
    timestamp: Optional[Any] = None
    data_source: Optional[str] = Field(default="collector", description="collector, demo_scenario, synthetic_tick")
    is_demo: Optional[bool] = Field(default=False)
    collector_id: Optional[str] = Field(default="sensor-gw-01")
    collector_type: Optional[str] = Field(default="netflow_ipfix")
    raw_payload: Optional[str] = Field(default=None, description="Sensitive raw packet payload")

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        d = dict(data)
        # Normalize destination IP / port aliases
        if "dest_ip" in d and "destination_ip" not in d:
            d["destination_ip"] = d["dest_ip"]
        if "dest_port" in d and "destination_port" not in d:
            d["destination_port"] = d["dest_port"]

        # Duration default
        duration = float(d.get("duration_sec") or d.get("flow_duration") or 1.0)
        d["duration_sec"] = duration

        # Packet count from packet rate if missing
        if "packet_count" not in d and "packet_rate" in d:
            d["packet_count"] = max(1, int(float(d["packet_rate"]) * duration))
        if "byte_count" not in d and "byte_rate" in d:
            d["byte_count"] = max(1, int(float(d["byte_rate"]) * duration))

        # Flattened flow statistics extraction
        flow_stats = dict(d.get("flow_statistics") or {})
        stat_keys = [
            "syn_ratio", "rst_ratio", "payload_entropy", "failed_connections",
            "unique_dest_ips", "packet_rate", "byte_rate", "conn_freq",
            "fwd_packets", "bwd_packets", "avg_packet_size"
        ]
        for k in stat_keys:
            if k in d and k not in flow_stats:
                flow_stats[k] = d[k]
        if flow_stats:
            d["flow_statistics"] = flow_stats

        return d

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        valid_protocols = ["TCP", "UDP", "ICMP", "MQTT", "COAP", "HTTP", "HTTPS", "DNS", "TLS", "TELNET", "SSH", "RTSP", "NTP"]
        if v.upper() not in valid_protocols:
            raise ValueError(f"Unsupported protocol: {v}. Allowed: {', '.join(valid_protocols)}")
        return v.upper()

    @field_validator("direction")
    @classmethod
    def validate_direction(cls, v: Optional[str]) -> str:
        if not v:
            return "outbound"
        allowed = ["inbound", "outbound", "internal", "lateral"]
        if v.lower() not in allowed:
            raise ValueError(f"Invalid flow direction '{v}'. Allowed: {', '.join(allowed)}")
        return v.lower()

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        v_clean = v.strip()
        if v_clean.lower() in ("unknown", "any", "0.0.0.0"):
            return v_clean
        parts = v_clean.split(".")
        if len(parts) != 4:
            raise ValueError(f"Invalid IPv4 address format: {v_clean}")
        for p in parts:
            if not p.isdigit() or not (0 <= int(p) <= 255):
                raise ValueError(f"Invalid IPv4 octet: {p} in {v_clean}")
        return v_clean

    @field_validator("raw_payload")
    @classmethod
    def sanitize_payload(cls, v: Optional[str]) -> Optional[str]:
        # Do not store raw sensitive packet payload - enforce privacy and metadata preference
        if v:
            return "[PAYLOAD_STRIPPED_PRIVACY_ENFORCED]"
        return None


class CollectorBatchPayload(BaseModel):
    """Batch ingestion schema from network probes."""
    collector_id: str = Field(..., min_length=2, max_length=64)
    collector_type: Optional[str] = "netflow_ipfix"
    events: List[TrafficEventPayload] = Field(..., min_length=1, max_length=500)


# ==============================================================================
# DETECTION & CONFIGURABLE RULE SCHEMAS
# ==============================================================================

class RuleConfigUpdatePayload(BaseModel):
    """Schema for updating configurable detection rule thresholds and settings."""
    rule_id: str = Field(..., min_length=1)
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    severity: Optional[str] = None
    thresholds: Optional[Dict[str, float]] = None
    suggested_investigation: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        valid = ["High-Risk", "Suspicious", "Low", "Informational"]
        match = [s for s in valid if s.lower() == v.lower()]
        if not match:
            raise ValueError(f"Invalid rule severity '{v}'. Allowed: {', '.join(valid)}")
        return match[0]


class DemoScenarioPayload(BaseModel):
    """Schema for triggering reproducible demo traffic scenarios."""
    scenario: str = Field(..., min_length=2)
    device_id: Optional[str] = None
    intensity: Optional[str] = Field(default="moderate")

    @field_validator("scenario")
    @classmethod
    def validate_scenario(cls, v: str) -> str:
        valid_scenarios = [
            "normal_home",
            "repeated_connections",
            "unusually_high_traffic",
            "suspicious_destinations",
            "mirai_telnet",
            "syn_flood",
            "c2_beacon",
            "udp_blast",
            "reset"
        ]
        if v.lower() not in valid_scenarios:
            raise ValueError(f"Unknown demo scenario '{v}'. Allowed: {', '.join(valid_scenarios)}")
        return v.lower()

class DetectionAnalyzePayload(BaseModel):
    """Schema for running ad-hoc detection analysis on a flow or feature vector."""
    flow: Optional[Dict[str, Any]] = None
    features: Optional[List[float]] = None
    device_id: Optional[str] = None


class RuleUpdatePayload(BaseModel):
    rule_id: str = Field(..., min_length=1)
    enabled: Optional[bool] = None
    threshold: Optional[float] = None


# ==============================================================================
# ALERT SCHEMAS & TRANSITION VALIDATION
# ==============================================================================

class AlertStatusPayload(BaseModel):
    alert_id: str = Field(..., min_length=1)
    status: str = Field(..., min_length=1)
    note: Optional[str] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        valid = ["New", "Investigating", "Resolved", "False Positive"]
        matching = [s for s in valid if s.lower() == v.lower()]
        if not matching:
            raise ValueError(f"Invalid alert status '{v}'. Allowed: {', '.join(valid)}")
        return matching[0]


class AlertTransitionPayload(BaseModel):
    """Schema for alert status transitions with mandatory reason when reopening."""
    status: str = Field(..., min_length=1)
    reason: Optional[str] = None
    author: Optional[str] = "SecOps Analyst"

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        valid = ["New", "Investigating", "Resolved", "False Positive"]
        matching = [s for s in valid if s.lower() == v.lower()]
        if not matching:
            raise ValueError(f"Invalid alert status '{v}'. Allowed: {', '.join(valid)}")
        return matching[0]


class AlertAcknowledgePayload(BaseModel):
    """Schema for acknowledging an alert."""
    analyst: Optional[str] = "SecOps Analyst"
    note: Optional[str] = "Incident acknowledged and assigned for investigation."


class AlertNotePayload(BaseModel):
    alert_id: str = Field(..., min_length=1)
    note: str = Field(..., min_length=1, max_length=2000)
    author: Optional[str] = Field(default="SecOps Analyst")


class AlertBulkPayload(BaseModel):
    alert_ids: List[str] = Field(..., min_length=1)
    action: str = Field(...)

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        valid = ["acknowledge", "resolve", "reopen", "investigate", "isolate"]
        if v.lower() not in valid:
            raise ValueError(f"Invalid bulk action '{v}'. Allowed: {', '.join(valid)}")
        return v.lower()


# ==============================================================================
# MACHINE LEARNING & RISK ENGINE
# ==============================================================================

class MLRetrainPayload(BaseModel):
    n_estimators: Optional[int] = Field(default=45, ge=5, le=300)
    max_depth: Optional[int] = Field(default=9, ge=2, le=30)
    sample_size: Optional[int] = Field(default=2400, ge=200, le=20000)
    test_split_pct: Optional[int] = Field(default=25, ge=10, le=50)


class MLPredictPayload(BaseModel):
    features: List[float] = Field(..., min_length=8, max_length=15)


class RiskConfigPayload(BaseModel):
    weights: Optional[Dict[str, float]] = None
    thresholds: Optional[Dict[str, float]] = None
    strict_mode: Optional[bool] = None


class SimulationAttackPayload(BaseModel):
    scenario: Optional[str] = Field(default="mirai_telnet")


class LoginPayload(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)


class RefreshPayload(BaseModel):
    refresh_token: str = Field(..., min_length=10)


class LogoutPayload(BaseModel):
    token: Optional[str] = None
