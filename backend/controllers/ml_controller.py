"""
Machine Learning Pipeline Controller
Exposes production model status, evaluation benchmarks, feature schemas, retraining, and inference.
"""

from typing import Dict, Any, Tuple
from backend.services import ml_service
from backend.validation.schemas import MLRetrainPayload, MLPredictPayload
from backend.utils.response import api_error, api_success


class MLController:
    """Handles Random Forest model evaluation, retraining, and real-time inference."""

    @staticmethod
    def get_status() -> Tuple[int, Dict[str, Any]]:
        """GET /api/ml/status — Operational state of ML subsystem."""
        return 200, api_success(ml_service.get_status())

    @staticmethod
    def get_model() -> Tuple[int, Dict[str, Any]]:
        """GET /api/ml/model or /api/ml/metadata — Model configuration and metrics."""
        return 200, ml_service.get_model_info()

    @staticmethod
    def get_features() -> Tuple[int, Dict[str, Any]]:
        """GET /api/ml/features — Feature schema definitions and bounds."""
        return 200, api_success(ml_service.get_features())

    @staticmethod
    def get_evaluation() -> Tuple[int, Dict[str, Any]]:
        """GET /api/ml/evaluation — Authentic evaluation benchmarks and confusion matrix."""
        return 200, api_success(ml_service.get_evaluation())

    @staticmethod
    def retrain(payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """POST /api/ml/retrain — Reproducible retraining trigger with validation."""
        payload = payload or {}
        try:
            validated = MLRetrainPayload(**payload)
        except Exception as e:
            return 400, api_error(str(e), status_code=400, error_code="INVALID_HYPERPARAMETERS")

        try:
            result = ml_service.retrain(
                n_estimators=validated.n_estimators or 45,
                max_depth=validated.max_depth or 9,
                sample_size=validated.sample_size or 3000,
                test_split_pct=validated.test_split_pct or 25
            )
            return 200, result
        except Exception as e:
            return 500, api_error(f"Retraining failed: {str(e)}", status_code=500, error_code="TRAINING_FAILURE")

    @staticmethod
    def predict(payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """POST /api/ml/predict — Execute model inference on feature vector or flow object."""
        if not payload or not isinstance(payload, dict):
            return 400, api_error("Payload must be a JSON object", status_code=400, error_code="INVALID_PAYLOAD")

        # Branch A: Explicit numerical vector provided
        if "features" in payload:
            raw_features = payload.get("features")
            if not isinstance(raw_features, (list, tuple)):
                return 400, api_error("Field 'features' must be an array of numeric values", status_code=400, error_code="INVALID_FEATURE_VECTOR")

            pred = ml_service.predict_features(raw_features)
            if pred.get("status") == "validation_error":
                return 400, api_error(pred.get("error", "Invalid feature vector"), status_code=400, error_code="VALIDATION_ERROR")
            return 200, pred

        # Branch B: Flow dictionary provided
        flow_data = payload.get("flow") or payload
        pred = ml_service.predict_flow(flow_data)
        if pred.get("status") in ("validation_error", "extraction_error"):
            return 400, api_error(pred.get("error", "Invalid flow parameters"), status_code=400, error_code="VALIDATION_ERROR")
        return 200, pred
