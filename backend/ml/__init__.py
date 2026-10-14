"""
IoT Botnet Detection System — Machine Learning Subsystem
"""

from backend.ml.dataset import DATASET_PROVENANCE, generate_benchmark_dataset, save_dataset_provenance
from backend.ml.feature_pipeline import FeaturePipeline, FEATURE_NAMES, FEATURE_METADATA
from backend.ml.inference_service import MLInferenceService, ml_inference_service
from backend.ml.trainer import train_and_evaluate_model
from backend.ml.fusion import EvidenceFusionCoordinator

__all__ = [
    "DATASET_PROVENANCE",
    "generate_benchmark_dataset",
    "save_dataset_provenance",
    "FeaturePipeline",
    "FEATURE_NAMES",
    "FEATURE_METADATA",
    "MLInferenceService",
    "ml_inference_service",
    "train_and_evaluate_model",
    "EvidenceFusionCoordinator",
]
