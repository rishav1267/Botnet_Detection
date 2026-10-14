"""
Device Model & Schema for IoT Hardware Assets
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class RiskFactor(BaseModel):
    factor: str
    weight: str
    detail: str


class DeviceModel(BaseModel):
    id: str = Field(..., description="Unique hardware identifier e.g. DEV-101")
    name: str = Field(..., description="Device descriptive name e.g. Hikvision DS-2CD IP Camera")
    ip: str = Field(..., description="IPv4 Address on IoT VLAN")
    mac: str = Field(..., description="Hardware MAC address")
    category: str = Field(..., description="Hardware category e.g. Surveillance Camera")
    firmware: str = Field(default="v1.0.0", description="Installed firmware build version")
    vendor: str = Field(default="Generic Vendor", description="Original Equipment Manufacturer")
    protocol: str = Field(default="TCP", description="Primary transport or application protocol")
    status: str = Field(default="Normal", description="Security state: Normal, Suspicious, High-Risk")
    security_classification: str = Field(default="Normal", description="Canonical security classification")
    risk_score: int = Field(default=0, ge=0, le=100, description="Calculated risk score between 0 and 100")
    first_seen: str = Field(default="Just now", description="Asset onboarding timestamp")
    last_seen: str = Field(default="Just now", description="Latest heartbeat timestamp")
    last_activity: str = Field(default="Just now", description="Latest traffic flow timestamp")
    pps: float = Field(default=0.0, ge=0.0, description="Current telemetry packet rate in pps")
    packet_rate: float = Field(default=0.0, ge=0.0, description="Packet rate alias")
    bytes_transferred: str = Field(default="0 MB", description="Cumulative bytes transferred")
    conn_freq: float = Field(default=1.0, ge=0.0, description="Connection bursts per 10 seconds")
    quarantined: bool = Field(default=False, description="Whether device is network-isolated")
    vulnerabilities: List[str] = Field(default_factory=list, description="Known CVE vulnerabilities")
    risk_factors: List[RiskFactor] = Field(default_factory=list, description="Risk contributors")
    recommended_action: str = Field(default="Maintain routine baseline monitoring.", description="Remediation steps")
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Normalized anomaly index")

    def to_mongo_dict(self) -> Dict[str, Any]:
        return self.model_dump()
