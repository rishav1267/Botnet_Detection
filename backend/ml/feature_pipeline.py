"""
IoT Botnet Detection System — Standardized Feature Extraction & Preprocessing Pipeline
Enforces consistent feature ordering, scaling, validation, and types across training and inference.
"""

import math
import os
from typing import Dict, Any, List, Optional, Tuple, Union
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler


FEATURE_NAMES = [
    "packet_rate",
    "byte_rate",
    "conn_freq",
    "dest_port_norm",
    "unique_dest_ips",
    "syn_ratio",
    "flow_duration",
    "payload_entropy",
    "fwd_packets",
    "bwd_packets",
    "mean_pkt_len"
]

FEATURE_METADATA: Dict[str, Dict[str, str]] = {
    "packet_rate": {
        "label": "Packet Rate",
        "unit": "pps",
        "category": "Volumetric",
        "formula": "packet_count / flow_duration",
        "range": "0.1 - 1000.0 pps",
        "description": "Rate of packets transmitted per second."
    },
    "byte_rate": {
        "label": "Byte Rate",
        "unit": "B/s",
        "category": "Volumetric",
        "formula": "byte_count / flow_duration",
        "range": "64 - 1000000 B/s",
        "description": "Throughput transmitted per second."
    },
    "conn_freq": {
        "label": "Connection Frequency",
        "unit": "conn/10s",
        "category": "Timing",
        "formula": "Handshakes initiated per 10s window",
        "range": "0.1 - 60.0 conn",
        "description": "Connection initiation frequency over sliding time window."
    },
    "dest_port_norm": {
        "label": "Destination Port (Normalized)",
        "unit": "norm [0, 1]",
        "category": "Transport",
        "formula": "destination_port / 65535.0",
        "range": "0.0 - 1.0",
        "description": "Normalized target service port number."
    },
    "unique_dest_ips": {
        "label": "Target IP Dispersion",
        "unit": "count",
        "category": "Reconnaissance",
        "formula": "Distinct destination IPv4s contacted",
        "range": "1 - 100 endpoints",
        "description": "Number of unique target endpoints in current sampling window."
    },
    "syn_ratio": {
        "label": "TCP SYN Ratio",
        "unit": "ratio [0, 1]",
        "category": "Protocol Flag",
        "formula": "syn_flags_count / packet_count",
        "range": "0.0 - 1.0",
        "description": "Proportion of TCP packets with SYN flag set without ACK."
    },
    "flow_duration": {
        "label": "Flow Window Duration",
        "unit": "seconds",
        "category": "Timing",
        "formula": "end_time - start_time",
        "range": "0.01 - 60.0 sec",
        "description": "Duration of network flow session window."
    },
    "payload_entropy": {
        "label": "Shannon Payload Entropy",
        "unit": "bits/byte",
        "category": "Payload Analysis",
        "formula": "-sum(p(x) * log2(p(x)))",
        "range": "0.0 - 8.0 bits",
        "description": "Information entropy of extracted byte distribution."
    },
    "fwd_packets": {
        "label": "Forward Packet Count",
        "unit": "packets",
        "category": "Directional",
        "formula": "Count of Client -> Destination packets",
        "range": "1 - 5000 pkts",
        "description": "Outbound/client packet count."
    },
    "bwd_packets": {
        "label": "Backward Packet Count",
        "unit": "packets",
        "category": "Directional",
        "formula": "Count of Destination -> Client packets",
        "range": "0 - 2500 pkts",
        "description": "Inbound response packet count."
    },
    "mean_pkt_len": {
        "label": "Mean Packet Length",
        "unit": "bytes",
        "category": "Payload Analysis",
        "formula": "byte_count / packet_count",
        "range": "40 - 1500 bytes",
        "description": "Average packet payload size in flow."
    }
}


class FeaturePipeline:
    """
    Standardized feature extraction and scaling pipeline.
    Guarantees that training and inference use identical feature representations and scaling.
    """

    def __init__(self, scaler: Optional[StandardScaler] = None):
        self.scaler = scaler or StandardScaler()
        self.is_fitted = hasattr(self.scaler, "mean_") and self.scaler.mean_ is not None

    @staticmethod
    def validate_raw_vector(vector: Union[List[float], np.ndarray]) -> List[float]:
        """
        Validate incoming numerical feature vector against physical bounds and NaN/Inf checks.
        Raises ValueError with clear explanation if vector is malformed.
        """
        if vector is None:
            raise ValueError("Feature vector cannot be None.")

        if isinstance(vector, np.ndarray):
            vec_list = vector.tolist()
        elif isinstance(vector, (list, tuple)):
            vec_list = list(vector)
        else:
            raise ValueError(f"Feature vector must be a list or array, got {type(vector).__name__}")

        if len(vec_list) != len(FEATURE_NAMES):
            raise ValueError(
                f"Feature vector dimension mismatch: expected {len(FEATURE_NAMES)} features, got {len(vec_list)}."
            )

        sanitized = []
        for i, val in enumerate(vec_list):
            name = FEATURE_NAMES[i]
            try:
                f_val = float(val)
            except (TypeError, ValueError):
                raise ValueError(f"Invalid numeric value for feature '{name}' at index {i}: {val}")

            if math.isnan(f_val):
                raise ValueError(f"Feature vector contains NaN value for '{name}' at index {i}.")
            if math.isinf(f_val):
                raise ValueError(f"Feature vector contains infinite value for '{name}' at index {i}.")

            # Sanity constraints
            if name in ("packet_rate", "byte_rate", "conn_freq", "flow_duration", "fwd_packets", "bwd_packets", "mean_pkt_len") and f_val < 0.0:
                raise ValueError(f"Negative value impossible for physical metric '{name}': {f_val}")

            if name in ("dest_port_norm", "syn_ratio") and not (0.0 <= f_val <= 1.0):
                raise ValueError(f"Normalized feature '{name}' must be within [0.0, 1.0], got {f_val}")

            if name == "payload_entropy" and not (0.0 <= f_val <= 8.0):
                raise ValueError(f"Shannon entropy '{name}' must be within [0.0, 8.0], got {f_val}")

            sanitized.append(f_val)

        return sanitized

    @staticmethod
    def extract_from_flow(flow: Dict[str, Any]) -> List[float]:
        """
        Convert network flow dictionary or telemetry record into normalized 11-feature vector.
        Supports both direct flow parameters and nested flow_statistics payloads.
        """
        duration = float(flow.get("flow_duration") or flow.get("duration_sec") or 1.0)
        duration = max(0.01, duration)

        # Check nested flow_statistics if present
        stats = flow.get("flow_statistics") or {}
        if not isinstance(stats, dict):
            stats = {}

        # 1. Packet Rate
        if "packet_rate" in flow:
            pps = float(flow["packet_rate"])
        elif "packet_count" in flow:
            pps = float(flow["packet_count"]) / duration
        else:
            pps = 10.0

        # 2. Byte Rate
        if "byte_rate" in flow:
            bps = float(flow["byte_rate"])
        elif "byte_count" in flow:
            bps = float(flow["byte_count"]) / duration
        else:
            bps = pps * 128.0

        # 3. Connection Frequency
        conn_freq = float(flow.get("conn_freq") or flow.get("conn_frequency") or flow.get("connection_frequency") or stats.get("conn_frequency") or 2.0)

        # 4. Destination Port (Normalized to [0.0, 1.0])
        if "dest_port_norm" in flow:
            port_norm = float(flow["dest_port_norm"])
        else:
            port = float(flow.get("dest_port") or flow.get("destination_port") or flow.get("port") or 80)
            port_norm = max(0.0, min(1.0, port / 65535.0))

        # 5. Unique Destination IPs
        unique_ips = float(flow.get("unique_dest_ips") or stats.get("unique_dest_ips") or 1.0)
        unique_ips = max(1.0, unique_ips)

        # 6. TCP SYN Ratio
        syn_ratio = float(flow.get("syn_ratio") or stats.get("syn_ratio") or 0.05)
        syn_ratio = max(0.0, min(1.0, syn_ratio))

        # 7. Payload Entropy
        entropy = float(flow.get("payload_entropy") or stats.get("payload_entropy") or 4.2)
        entropy = max(0.0, min(8.0, entropy))

        # 8. Forward / Backward Packets
        total_packets = max(1.0, pps * duration)
        if "fwd_packets" in flow or "fwd_packets" in stats:
            fwd_pkts = float(flow.get("fwd_packets") or stats.get("fwd_packets"))
        else:
            fwd_pkts = max(1.0, total_packets * (0.85 if syn_ratio > 0.5 else 0.6))

        if "bwd_packets" in flow or "bwd_packets" in stats:
            bwd_pkts = float(flow.get("bwd_packets") or stats.get("bwd_packets"))
        else:
            bwd_pkts = max(0.0, total_packets - fwd_pkts)

        # 9. Mean Packet Length
        if "mean_pkt_len" in flow or "avg_packet_size" in flow:
            mean_pkt_len = float(flow.get("mean_pkt_len") or flow.get("avg_packet_size"))
        elif "avg_packet_size" in stats:
            mean_pkt_len = float(stats["avg_packet_size"])
        else:
            mean_pkt_len = max(40.0, min(1500.0, bps / max(1.0, pps)))

        raw_vector = [
            pps, bps, conn_freq, port_norm, unique_ips,
            syn_ratio, duration, entropy, fwd_pkts, bwd_pkts, mean_pkt_len
        ]
        return FeaturePipeline.validate_raw_vector(raw_vector)

    def fit(self, X_train: np.ndarray) -> "FeaturePipeline":
        """Fit feature scaler exclusively on training dataset partition to prevent data leakage."""
        self.scaler.fit(X_train)
        self.is_fitted = True
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Apply fitted standardization transform to feature matrix."""
        if not self.is_fitted:
            raise RuntimeError("FeaturePipeline scaler has not been fitted.")
        return self.scaler.transform(X)

    def transform_vector(self, vector: List[float]) -> np.ndarray:
        """Transform a single 1D feature vector for inference."""
        validated = self.validate_raw_vector(vector)
        if not self.is_fitted:
            # Fallback to unscaled if preprocessor not fitted
            return np.array([validated], dtype=np.float64)
        return self.scaler.transform([validated])

    def save(self, filepath: str = "models/feature_preprocessor.joblib"):
        """Persist fitted scaler to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self.scaler, filepath)

    @classmethod
    def load(cls, filepath: str = "models/feature_preprocessor.joblib") -> "FeaturePipeline":
        """Load fitted scaler from disk."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Feature preprocessor not found at {filepath}")
        scaler = joblib.load(filepath)
        return cls(scaler=scaler)
