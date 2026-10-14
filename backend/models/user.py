"""
User Account & Identity Model
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, EmailStr


class UserModel(BaseModel):
    id: str = Field(..., description="Unique user identity e.g. USR-001")
    username: str = Field(..., min_length=3, max_length=50, description="Login username")
    email: str = Field(..., description="Contact email address")
    role: str = Field(default="SecOps Analyst", description="Role: Admin, SecOps Analyst, Auditor")
    password_hash: str = Field(..., description="Hashed credential string")
    full_name: str = Field(default="SecOps Analyst", description="Display full name")
    is_active: bool = Field(default=True)
    created_at: str = Field(..., description="Account creation timestamp")
    last_login: Optional[str] = None

    def to_safe_dict(self) -> Dict[str, Any]:
        """Export user profile without password hash."""
        d = self.model_dump()
        d.pop("password_hash", None)
        return d
