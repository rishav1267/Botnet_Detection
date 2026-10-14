"""
User Preference & System Risk Configuration Models
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class RiskEngineConfigModel(BaseModel):
    version: str = Field(default="1.1")
    updated_at: str = Field(...)
    weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "pps": 0.25,
            "port": 0.30,
            "beacon": 0.25,
            "cve": 0.20
        }
    )
    thresholds: Dict[str, float] = Field(
        default_factory=lambda: {
            "normal_max": 25.0,
            "suspicious_max": 65.0
        }
    )
    strict_mode: bool = Field(default=False)


class UserPreferenceModel(BaseModel):
    user_id: str
    theme: str = Field(default="cyber-dark-green")
    stream_cadence_ms: int = Field(default=1000)
    sound_alerts_enabled: bool = Field(default=True)
    table_page_size: int = Field(default=10)
