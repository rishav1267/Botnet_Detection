"""
Detection Service — Integrates Rule-Based Engine and Machine Learning Classifier
Combines heuristic signature rules with Scikit-Learn inference via EvidenceFusionCoordinator.
"""

import time
import uuid
from typing import Dict, Any, List, Optional, Tuple

from detection_engine import DualDetectionCoordinator, RuleBasedEngine, MachineLearningEngine
from backend.services.rule_engine import configurable_rule_engine
from backend.ml.inference_service import ml_inference_service
from backend.ml.fusion import EvidenceFusionCoordinator
from backend.ml.feature_pipeline import FeaturePipeline
from backend.database.repository import repository
from backend.utils.logger import logger


class DetectionService:
    """Orchestrates heuristic and ML dual-detection pipelines."""

    def __init__(self):
        self.coordinator = DualDetectionCoordinator()
        self.ml_inference = ml_inference_service
        logger.info("[DetectionService] Initialized DualDetectionCoordinator with Scikit-Learn ML and Rule Engine.")

    @property
    def ml_engine(self) -> MachineLearningEngine:
        return self.coordinator.ml_engine

    @property
    def rule_engine(self) -> RuleBasedEngine:
        return self.coordinator.rule_engine

    def analyze_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a network flow through the dual-engine pipeline.
        Maintains independent rule and ML predictions with explainable evidence fusion.
        """
        # 1. Rule-Based Evaluation
        rule_eval = configurable_rule_engine.evaluate_flow(flow)
        rule_matches = rule_eval.get("triggered_rules", [])

        # 2. ML Prediction (Safe Inference)
        ml_result = self.ml_inference.predict_flow(flow)

        # 3. Evidence Fusion
        fused = EvidenceFusionCoordinator.fuse_evidence(rule_eval, ml_result)

        return {
            "flow_id": flow.get("id") or flow.get("flow_id", f"FLW-{int(time.time()*1000)%1000000}"),
            "timestamp": flow.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
            "device_id": flow.get("device_id", "IOT-001"),
            "device_name": flow.get("device_name", "Unknown IoT Device"),
            "source_ip": flow.get("source_ip", "192.168.1.100"),
            "dest_ip": flow.get("dest_ip") or flow.get("destination_ip", "104.28.12.9"),
            "protocol": flow.get("protocol", "TCP"),
            "dest_port": flow.get("dest_port") or flow.get("destination_port", 80),
            "status": fused["verdict"],
            "verdict": fused["verdict"],
            "risk_score": fused["risk_score"],
            "agreement_state": fused["agreement_state"],
            "verdict_rationale": fused["verdict_rationale"],
            "rule_matches": rule_matches,
            "rule_evidence": fused["rule_evidence"],
            "ml_prediction": ml_result,
            "ml_evidence": fused["ml_evidence"],
            "raw_features": flow.get("raw_features", {
                "packet_rate": flow.get("packet_rate", 0),
                "byte_rate": flow.get("byte_rate", 0),
                "conn_freq": flow.get("conn_freq", 0),
                "dest_port_norm": min(1.0, float(flow.get("dest_port", 80)) / 65535.0),
                "unique_dest_ips": flow.get("unique_dest_ips", 1),
                "syn_ratio": flow.get("syn_ratio", 0.0),
                "payload_entropy": flow.get("payload_entropy", 4.0),
                "flow_duration": flow.get("flow_duration", 1.0),
                "fwd_packets": flow.get("fwd_packets", 0),
                "bwd_packets": flow.get("bwd_packets", 0),
                "mean_pkt_len": flow.get("mean_pkt_len", flow.get("mean_packet_len", 64.0))
            })
        }

    def analyze(
        self,
        flow_data: Optional[Dict[str, Any]] = None,
        features: Optional[List[float]] = None,
        device_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute real detection analysis.
        If ML inference is not configured or model unavailable, returns explicit model_unavailable status
        while preserving rule-based ingestion.
        """
        detection_id = f"DET-{str(uuid.uuid4())[:8].upper()}"
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # 1. Prepare flow representation
        flow = flow_data or {}
        if features and not flow:
            pps = float(features[0]) if len(features) > 0 else 10.0
            bps = float(features[1]) if len(features) > 1 else 500.0
            conn = float(features[2]) if len(features) > 2 else 2.0
            port_norm = float(features[3]) if len(features) > 3 else 80.0 / 65535.0
            ips = int(features[4]) if len(features) > 4 else 1
            syn = float(features[5]) if len(features) > 5 else 0.05
            dur = float(features[6]) if len(features) > 6 else 1.0
            ent = float(features[7]) if len(features) > 7 else 4.2
            fwd = int(features[8]) if len(features) > 8 else 10
            bwd = int(features[9]) if len(features) > 9 else 5
            mpl = float(features[10]) if len(features) > 10 else 100.0

            flow = {
                "packet_rate": pps,
                "byte_rate": bps,
                "conn_freq": conn,
                "dest_port": int(port_norm * 65535),
                "dest_port_norm": port_norm,
                "unique_dest_ips": ips,
                "syn_ratio": syn,
                "flow_duration": dur,
                "payload_entropy": ent,
                "fwd_packets": fwd,
                "bwd_packets": bwd,
                "mean_pkt_len": mpl,
                "protocol": "TCP"
            }

        # 2. Rule-Based Evaluation
        rule_eval = configurable_rule_engine.evaluate_flow(flow)

        # 3. Machine Learning Evaluation
        if features:
            ml_result = self.ml_inference.predict_vector(features)
        else:
            ml_result = self.ml_inference.predict_flow(flow)

        # 4. Evidence Fusion
        fused = EvidenceFusionCoordinator.fuse_evidence(rule_eval, ml_result)

        result = {
            "detection_id": detection_id,
            "device_id": device_id or flow.get("device_id", "UNKNOWN"),
            "timestamp": timestamp,
            "verdict": fused["verdict"],
            "risk_score": fused["risk_score"],
            "agreement_state": fused["agreement_state"],
            "verdict_rationale": fused["verdict_rationale"],
            "rules_evaluated": rule_eval.get("rule_count_evaluated", 8),
            "rules_triggered": rule_eval.get("triggered_rules", []),
            "rule_evidence": fused["rule_evidence"],
            "ml_analysis": ml_result,
            "ml_evidence": fused["ml_evidence"],
            "dual_evidence": {
                "fusion": fused,
                "rule_evidence": fused["rule_evidence"],
                "ml_evidence": fused["ml_evidence"]
            },
            "analyzed_flow": flow
        }

        # Persist to database
        repository.save_detection_result(result)
        return result

    def get_results_paginated(
        self,
        page: int = 1,
        limit: int = 20,
        device_id: Optional[str] = None,
        verdict: Optional[str] = None
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Return paginated detection history records."""
        return repository.get_detection_results_paginated(
            page=page,
            limit=limit,
            device_id=device_id,
            verdict=verdict
        )

    def get_result_by_id(self, detection_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve single detection record by unique ID."""
        return repository.get_detection_result(detection_id)

    def get_status(self) -> Dict[str, Any]:
        """Return operational status of detection coordinator."""
        return {
            "status": "operational",
            "rule_engine": "active",
            "ml_engine": self.ml_inference.status,
            "rules_count": len(self.coordinator.rule_engine.rules),
            "ml_model": self.ml_inference.MODEL_NAME,
            "ml_status": self.ml_inference.status
        }


# Global singleton instance
detection_service = DetectionService()
