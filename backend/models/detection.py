"""
Detection Results & Heuristic Rule Models
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class DetectionRuleModel(BaseModel):
    rule_id: str = Field(..., description="Rule ID e.g. R01")
    name: str = Field(..., description="Descriptive rule name")
    category: str = Field(default="Botnet Reconnaissance")
    severity: str = Field(default="High-Risk")
    condition: str = Field(..., description="Human-readable rule condition")
    enabled: bool = Field(default=True)
    mitre_attack: str = Field(default="T1110")
    description: str = Field(default="")
    threshold: Optional[float] = None
    trigger_count: int = Field(default=0)


class DetectionResultModel(BaseModel):
    id: str = Field(..., description="Unique detection run ID")
    flow_id: str = Field(..., description="Analyzed flow ID")
    timestamp: str = Field(...)
    device_id: str
    status: str = Field(default="Normal")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    rule_matches: List[Dict[str, Any]] = Field(default_factory=list)
    ml_probabilities: Dict[str, float] = Field(default_factory=dict)
    contributing_features: List[Dict[str, Any]] = Field(default_factory=list)
