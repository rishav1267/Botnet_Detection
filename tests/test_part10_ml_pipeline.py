"""
Unit & Integration Test Suite for Part 10: Machine-Learning Pipeline
Tests Preprocessing, Model Inference, Feature Attributions, Boundary Checks,
Evidence Fusion, REST Endpoints, and Failure Handling.
"""

import os
import sys
import unittest
import math
import numpy as np

# Ensure parent directory is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.ml.dataset import generate_benchmark_dataset, DATASET_PROVENANCE
from backend.ml.feature_pipeline import FeaturePipeline, FEATURE_NAMES, FEATURE_METADATA
from backend.ml.inference_service import MLInferenceService
from backend.ml.trainer import train_and_evaluate_model
from backend.ml.fusion import EvidenceFusionCoordinator
from backend.services.ml_service import MLService
from backend.controllers.ml_controller import MLController
from backend.services.detection_service import DetectionService


class TestPart10MLPipeline(unittest.TestCase):
    """Part 10 Machine Learning Pipeline Verification Suite."""

    @classmethod
    def setUpClass(cls):
        # Ensure a trained model and preprocessor exist for tests
        cls.models_dir = "models"
        train_res = train_and_evaluate_model(
            sample_size=600,
            n_estimators=15,
            max_depth=5,
            test_split_pct=25,
            random_seed=42,
            models_dir=cls.models_dir
        )
        cls.train_res = train_res

    # =========================================================================
    # ROUND 1: PREPROCESSING, MODEL LOADING & INFERENCE
    # =========================================================================

    def test_01_feature_pipeline_valid_vector(self):
        """Test valid 11-feature vector passes validation untouched."""
        valid_vec = [15.0, 1920.0, 2.5, 80/65535, 1.0, 0.05, 2.0, 4.1, 15.0, 15.0, 128.0]
        sanitized = FeaturePipeline.validate_raw_vector(valid_vec)
        self.assertEqual(len(sanitized), 11)
        self.assertEqual(sanitized[0], 15.0)
        self.assertEqual(sanitized[4], 1.0)

    def test_02_feature_extraction_from_flow(self):
        """Test extraction of 11 features from standard network flow dictionary."""
        flow = {
            "source_ip": "192.168.1.101",
            "dest_ip": "104.28.12.9",
            "dest_port": 443,
            "packet_rate": 22.0,
            "byte_rate": 2816.0,
            "conn_freq": 1.5,
            "flow_duration": 3.0,
            "flow_statistics": {
                "syn_ratio": 0.02,
                "payload_entropy": 3.9,
                "unique_dest_ips": 1,
                "fwd_packets": 35,
                "bwd_packets": 31,
                "avg_packet_size": 128.0
            }
        }
        vec = FeaturePipeline.extract_from_flow(flow)
        self.assertEqual(len(vec), 11)
        self.assertAlmostEqual(vec[0], 22.0)
        self.assertAlmostEqual(vec[3], 443 / 65535.0, places=4)
        self.assertAlmostEqual(vec[5], 0.02)
        self.assertAlmostEqual(vec[7], 3.9)

    def test_03_inference_service_loaded_state(self):
        """Test MLInferenceService loads trained model and sets available_and_trained."""
        service = MLInferenceService(
            model_path=os.path.join(self.models_dir, "iot_botnet_model.joblib"),
            preprocessor_path=os.path.join(self.models_dir, "feature_preprocessor.joblib")
        )
        status = service.get_status()
        self.assertEqual(status["status"], "available_and_trained")
        self.assertTrue(status["has_model_binary"])
        self.assertTrue(status["has_preprocessor"])
        self.assertEqual(len(status["feature_names"]), 11)

    def test_04_inference_prediction_and_confidence(self):
        """Test inference returns class, calibrated confidence, and anomaly score."""
        service = MLInferenceService(
            model_path=os.path.join(self.models_dir, "iot_botnet_model.joblib"),
            preprocessor_path=os.path.join(self.models_dir, "feature_preprocessor.joblib")
        )
        # High-Risk vector (Mirai SYN flood profile)
        attack_vec = [650.0, 52000.0, 35.0, 23/65535, 12.0, 0.95, 0.5, 7.5, 300.0, 1.0, 60.0]
        res = service.predict_vector(attack_vec)

        self.assertEqual(res["status"], "available_and_trained")
        self.assertEqual(res["prediction"], "High-Risk")
        self.assertGreater(res["confidence"], 0.5)
        self.assertGreater(res["anomaly_score"], 0.5)
        self.assertIn("High-Risk", res["probabilities"])
        self.assertIn("confidence_interpretation", res)
        self.assertIsInstance(res["contributing_features"], list)
        self.assertGreater(len(res["contributing_features"]), 0)

    # =========================================================================
    # ROUND 2: VALIDATION, EDGE CASES, MISSING MODELS & EVALUATION
    # =========================================================================

    def test_05_dimension_mismatch_rejection(self):
        """Test rejection of feature vectors with incorrect dimensions."""
        short_vec = [10.0, 20.0, 30.0]
        with self.assertRaises(ValueError) as ctx:
            FeaturePipeline.validate_raw_vector(short_vec)
        self.assertIn("dimension mismatch", str(ctx.exception).lower())

    def test_06_nan_and_inf_rejection(self):
        """Test rejection of NaN and Infinite values in feature vectors."""
        nan_vec = [float("nan")] * 11
        with self.assertRaises(ValueError) as ctx:
            FeaturePipeline.validate_raw_vector(nan_vec)
        self.assertIn("nan", str(ctx.exception).lower())

        inf_vec = [float("inf")] + [10.0, 2.0, 0.1, 1.0, 0.05, 1.0, 4.0, 10.0, 10.0, 100.0]
        with self.assertRaises(ValueError) as ctx:
            FeaturePipeline.validate_raw_vector(inf_vec)
        self.assertIn("infinite", str(ctx.exception).lower())

    def test_07_physical_bounds_rejection(self):
        """Test rejection of physically impossible numeric values."""
        # Negative packet rate
        neg_rate_vec = [-5.0] + [10.0] * 10
        with self.assertRaises(ValueError) as ctx:
            FeaturePipeline.validate_raw_vector(neg_rate_vec)
        self.assertIn("negative", str(ctx.exception).lower())

        # Entropy > 8.0 bits
        high_entropy_vec = [10.0, 500.0, 2.0, 0.1, 1.0, 0.05, 1.0, 9.5, 10.0, 10.0, 50.0]
        with self.assertRaises(ValueError) as ctx:
            FeaturePipeline.validate_raw_vector(high_entropy_vec)
        self.assertIn("entropy", str(ctx.exception).lower())

    def test_08_missing_model_file_handling(self):
        """Test missing model file enters available_not_trained state without crashing."""
        service = MLInferenceService(
            model_path="models/non_existent_model.joblib",
            preprocessor_path="models/non_existent_preprocessor.joblib"
        )
        status = service.get_status()
        self.assertEqual(status["status"], "available_not_trained")
        self.assertFalse(status["has_model_binary"])

        # Predict should use heuristic fallback and declare fallback
        benign_vec = [5.0, 500.0, 1.0, 80/65535, 1.0, 0.05, 5.0, 4.0, 10.0, 10.0, 50.0]
        res = service.predict_vector(benign_vec)
        self.assertTrue(res["is_fallback"])
        self.assertEqual(res["prediction"], "Normal")

    def test_09_evaluation_metrics_authenticity(self):
        """Test that genuine evaluation metrics contain authentic confusion matrix and ROC."""
        eval_data = self.train_res["evaluation"]
        self.assertIn("accuracy", eval_data)
        self.assertIn("precision", eval_data)
        self.assertIn("recall", eval_data)
        self.assertIn("f1_score", eval_data)
        self.assertIn("confusion_matrix", eval_data)
        self.assertIn("roc_curve", eval_data)
        self.assertIn("class_imbalance_report", eval_data)

        # Verify confusion matrix is 3x3
        cm = eval_data["confusion_matrix"]
        self.assertEqual(len(cm), 3)
        self.assertEqual(len(cm[0]), 3)

        # Verify class imbalance was tracked
        imb = eval_data["class_imbalance_report"]
        self.assertGreater(imb["Normal (0)"], 0)
        self.assertGreater(imb["Suspicious (1)"], 0)
        self.assertGreater(imb["High-Risk (2)"], 0)

    # =========================================================================
    # ROUND 3: BACKEND INTEGRATION, EVIDENCE FUSION & ENDPOINTS
    # =========================================================================

    def test_10_evidence_fusion_consensus_attack(self):
        """Test consensus attack when both rules and ML trigger High-Risk."""
        rule_eval = {
            "classification": "High-Risk",
            "risk_score": 90.0,
            "triggered_rules": [{"id": "R01", "name": "Packet Rate Surge"}]
        }
        ml_eval = {
            "status": "available_and_trained",
            "prediction": "High-Risk",
            "confidence": 0.98,
            "anomaly_score": 0.95
        }
        fused = EvidenceFusionCoordinator.fuse_evidence(rule_eval, ml_eval)
        self.assertEqual(fused["verdict"], "High-Risk")
        self.assertIn("Consensus", fused["agreement_state"])
        self.assertGreaterEqual(fused["risk_score"], 95.0)

    def test_11_evidence_fusion_heuristic_override(self):
        """Test heuristic override when known exploit rule fires but ML prediction is Normal."""
        rule_eval = {
            "classification": "High-Risk",
            "risk_score": 88.0,
            "triggered_rules": [{"id": "R05", "name": "Telnet Exploit Port"}]
        }
        ml_eval = {
            "status": "available_and_trained",
            "prediction": "Normal",
            "confidence": 0.90,
            "anomaly_score": 0.05
        }
        fused = EvidenceFusionCoordinator.fuse_evidence(rule_eval, ml_eval)
        self.assertEqual(fused["verdict"], "High-Risk")
        self.assertIn("Heuristic Override", fused["agreement_state"])
        self.assertIn("Exploit signatures override", fused["verdict_rationale"])

    def test_12_evidence_fusion_ml_anomaly(self):
        """Test zero-day anomaly detection when rules pass but ML flags High-Risk."""
        rule_eval = {
            "classification": "Normal",
            "risk_score": 5.0,
            "triggered_rules": []
        }
        ml_eval = {
            "status": "available_and_trained",
            "prediction": "High-Risk",
            "confidence": 0.94,
            "anomaly_score": 0.90
        }
        fused = EvidenceFusionCoordinator.fuse_evidence(rule_eval, ml_eval)
        self.assertEqual(fused["verdict"], "High-Risk")
        self.assertIn("ML Anomaly Detected", fused["agreement_state"])

    def test_13_detection_service_dual_evidence(self):
        """Test DetectionService provides separately identifiable rule and ML evidence."""
        det_service = DetectionService()
        test_flow = {
            "source_ip": "192.168.1.101",
            "dest_ip": "185.193.64.12",
            "dest_port": 23,
            "protocol": "TCP",
            "packet_rate": 500.0,
            "byte_rate": 60000.0,
            "conn_freq": 25.0,
            "syn_ratio": 0.95,
            "flow_duration": 0.8
        }
        result = det_service.analyze(flow_data=test_flow)
        self.assertIn("verdict", result)
        self.assertIn("rule_evidence", result)
        self.assertIn("ml_evidence", result)
        self.assertIn("agreement_state", result)
        self.assertIn("verdict_rationale", result)

    def test_14_ml_controller_endpoints(self):
        """Test all REST ML Controller endpoints respond with expected structure."""
        # 1. GET /api/ml/status
        st_code, st_res = MLController.get_status()
        self.assertEqual(st_code, 200)
        self.assertIn("status", st_res["data"])

        # 2. GET /api/ml/model
        m_code, m_res = MLController.get_model()
        self.assertEqual(m_code, 200)
        self.assertIn("model_name", m_res)
        self.assertIn("accuracy", m_res)

        # 3. GET /api/ml/features
        f_code, f_res = MLController.get_features()
        self.assertEqual(f_code, 200)
        self.assertEqual(f_res["data"]["feature_count"], 11)

        # 4. POST /api/ml/predict with valid vector
        valid_vec = [10.0, 1000.0, 2.0, 80/65535, 1.0, 0.05, 2.0, 4.0, 10.0, 10.0, 100.0]
        p_code, p_res = MLController.predict({"features": valid_vec})
        self.assertEqual(p_code, 200)
        self.assertEqual(p_res["prediction"], "Normal")

        # 5. POST /api/ml/predict with malformed payload (NaN) -> 400
        bad_code, bad_res = MLController.predict({"features": [float("nan")] * 11})
        self.assertEqual(bad_code, 400)
        self.assertIn("error", bad_res)


if __name__ == "__main__":
    unittest.main()
