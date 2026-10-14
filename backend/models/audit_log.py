"""
Audit Log Schema for SecOps Compliance & Action Tracking
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class AuditLogModel(BaseModel):
    id: str = Field(..., description="Unique audit event identifier")
    timestamp: str = Field(..., description="UTC ISO-8601 timestamp")
    user_id: str = Field(default="system", description="Originating actor/analyst")
    action: str = Field(..., description="Action name e.g. DEVICE_QUARANTINE, ALERT_RESOLVED")
    resource_type: str = Field(..., description="device, alert, rule, model, simulation")
    resource_id: str = Field(..., description="Target entity identifier")
    ip_address: Optional[str] = Field(default="127.0.0.1", description="Client IP address")
    status: str = Field(default="SUCCESS", description="SUCCESS, FAILURE, WARNING")
    details: Dict[str, Any] = Field(default_factory=dict, description="Metadata payload")
