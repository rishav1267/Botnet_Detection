"""
Security Alert & Incident History Models
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class AnalystNote(BaseModel):
    author: str = Field(default="SecOps Analyst", description="Name/Role of author")
    timestamp: str = Field(..., description="Timestamp of note")
    note: str = Field(..., description="Investigation remark")


class SecurityAlertModel(BaseModel):
    id: str = Field(..., description="Unique alert ID e.g. ALT-9021")
    timestamp: str = Field(..., description="Alert trigger timestamp")
    device_id: str = Field(..., description="Associated IoT device ID")
    device_name: str = Field(default="IoT Device", description="Associated device name")
    source_ip: str = Field(..., description="Source IP address")
    flow_id: str = Field(default="FLW-00000", description="Originating flow ID")
    severity: str = Field(default="Medium", description="Critical, High, Medium, Low, Informational")
    detection_source: str = Field(default="Dual-Fused Heuristics", description="Rule Engine, ML, Dual-Fused")
    classification: str = Field(default="Anomaly", description="Threat type e.g. Botnet Incursion")
    title: str = Field(..., description="Short descriptive threat headline")
    reason: str = Field(..., description="Immediate trigger condition")
    details: str = Field(..., description="Detailed forensic breakdown")
    traffic_indicators: Dict[str, Any] = Field(default_factory=dict, description="pps, byte_rate, port, entropy")
    suggested_action: str = Field(default="Audit asset and isolate if anomalous.", description="Remediation steps")
    status: str = Field(default="New", description="New, Acknowledged, In Progress, Resolved, Reopened")
    resolved: bool = Field(default=False, description="Whether incident is closed/resolved")
    mitre_technique: str = Field(default="T1110", description="MITRE ATT&CK technique reference")
    analyst_notes: List[AnalystNote] = Field(default_factory=list, description="Historical analyst thread")
    action_taken: str = Field(default="Alert Dispatched", description="Remediation action taken")

    def to_mongo_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class IncidentHistoryModel(BaseModel):
    id: str = Field(..., description="Incident history log ID")
    alert_id: str = Field(..., description="Associated alert ID")
    timestamp: str = Field(..., description="Action timestamp")
    user_id: str = Field(default="system", description="Analyst or system identity")
    previous_status: str
    new_status: str
    action: str
    notes: Optional[str] = None
