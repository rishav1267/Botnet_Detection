"""
Machine Learning Model Metadata Schema
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ModelMetadataModel(BaseModel):
    model_name: str = Field(default="Random Forest IoT Classifier (Scikit-Learn)")
    version: str = Field(default="1.0.0")
    algorithm: str = Field(default="RandomForestClassifier")
    feature_count: int = Field(default=11)
    feature_schema: List[str] = Field(default_factory=list)
    n_estimators: int = Field(default=45)
    max_depth: int = Field(default=9)
    sample_size: int = Field(default=2400)
    test_split_pct: int = Field(default=25)
    accuracy: float = Field(default=0.992)
    precision: float = Field(default=0.988)
    recall: float = Field(default=0.994)
    f1_score: float = Field(default=0.991)
    roc_auc: float = Field(default=0.996)
    feature_importance: Dict[str, float] = Field(default_factory=dict)
    confusion_matrix: List[List[int]] = Field(default_factory=list)
    status: str = Field(default="operational")
    created_at: str = Field(...)
    updated_at: str = Field(...)
