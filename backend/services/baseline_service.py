"""
Device Baseline Service — Historical Behavioral Profiling & Statistical Anomaly Scoring
Mitigates false positives by comparing active flow features against device-specific baselines
or device class profiles (Welford's online variance algorithm).
"""

import math
import time
import threading
from typing import Dict, Any, List, Optional, Tuple
from backend.utils.logger import logger


class DeviceBaselineProfile:
    """Statistical profile representing normal baseline behavior for an IoT endpoint."""

    def __init__(self, device_id: str, device_category: str = "Generic IoT"):
        self.device_id = device_id
        self.device_category = device_category
        self.sample_count = 0
        self.last_updated = time.time()

        # Initial baseline expectations based on IoT category
        defaults = self._category_defaults(device_category)
        self.pps_mean = defaults["pps_mean"]
        self.pps_m2 = defaults["pps_std"] ** 2
        self.pps_std = defaults["pps_std"]

        self.byte_rate_mean = defaults["byte_rate_mean"]
        self.byte_rate_m2 = defaults["byte_rate_std"] ** 2
        self.byte_rate_std = defaults["byte_rate_std"]

        self.conn_freq_mean = defaults["conn_freq_mean"]
        self.conn_freq_m2 = defaults["conn_freq_std"] ** 2
        self.conn_freq_std = defaults["conn_freq_std"]

        self.known_ports = set(defaults["known_ports"])
        self.known_protocols = set(defaults["known_protocols"])

    def _category_defaults(self, category: str) -> Dict[str, Any]:
        cat_lower = category.lower()
        if "camera" in cat_lower or "surveillance" in cat_lower:
            return {
                "pps_mean": 25.0, "pps_std": 10.0,
                "byte_rate_mean": 32000.0, "byte_rate_std": 8000.0,
                "conn_freq_mean": 2.0, "conn_freq_std": 1.0,
                "known_ports": [80, 443, 554, 8000, 8080],
                "known_protocols": ["TCP", "RTSP", "HTTP", "HTTPS"]
            }
        elif "lighting" in cat_lower or "hue" in cat_lower or "bridge" in cat_lower:
            return {
                "pps_mean": 3.0, "pps_std": 1.5,
                "byte_rate_mean": 500.0, "byte_rate_std": 250.0,
                "conn_freq_mean": 1.0, "conn_freq_std": 0.5,
                "known_ports": [80, 443, 8080],
                "known_protocols": ["TCP", "HTTP", "HTTPS"]
            }
        elif "thermostat" in cat_lower or "sensor" in cat_lower:
            return {
                "pps_mean": 1.5, "pps_std": 0.8,
                "byte_rate_mean": 250.0, "byte_rate_std": 100.0,
                "conn_freq_mean": 0.5, "conn_freq_std": 0.2,
                "known_ports": [443, 8883, 1883],
                "known_protocols": ["TCP", "MQTT", "TLS"]
            }
        elif "speaker" in cat_lower or "audio" in cat_lower:
            return {
                "pps_mean": 40.0, "pps_std": 15.0,
                "byte_rate_mean": 48000.0, "byte_rate_std": 12000.0,
                "conn_freq_mean": 3.0, "conn_freq_std": 1.5,
                "known_ports": [80, 443, 1900, 5353],
                "known_protocols": ["TCP", "UDP", "HTTP", "HTTPS"]
            }
        else:
            return {
                "pps_mean": 5.0, "pps_std": 3.0,
                "byte_rate_mean": 1500.0, "byte_rate_std": 600.0,
                "conn_freq_mean": 1.5, "conn_freq_std": 0.8,
                "known_ports": [80, 443, 123, 53],
                "known_protocols": ["TCP", "UDP", "DNS", "NTP"]
            }

    def update(self, pps: float, byte_rate: float, conn_freq: float, port: int, protocol: str):
        """Update running statistical baseline using Welford's algorithm."""
        self.sample_count += 1
        n = self.sample_count
        self.last_updated = time.time()

        # Update PPS online variance
        delta_pps = pps - self.pps_mean
        self.pps_mean += delta_pps / n
        delta2_pps = pps - self.pps_mean
        self.pps_m2 += delta_pps * delta2_pps
        self.pps_std = math.sqrt(self.pps_m2 / n) if n > 1 else max(1.0, self.pps_mean * 0.3)

        # Update Byte Rate online variance
        delta_b = byte_rate - self.byte_rate_mean
        self.byte_rate_mean += delta_b / n
        delta2_b = byte_rate - self.byte_rate_mean
        self.byte_rate_m2 += delta_b * delta2_b
        self.byte_rate_std = math.sqrt(self.byte_rate_m2 / n) if n > 1 else max(50.0, self.byte_rate_mean * 0.3)

        # Update Connection Frequency
        delta_c = conn_freq - self.conn_freq_mean
        self.conn_freq_mean += delta_c / n
        delta2_c = conn_freq - self.conn_freq_mean
        self.conn_freq_m2 += delta_c * delta2_c
        self.conn_freq_std = math.sqrt(self.conn_freq_m2 / n) if n > 1 else max(0.5, self.conn_freq_mean * 0.3)

        # Track observed ports and protocols
        if port > 0:
            self.known_ports.add(port)
        if protocol:
            self.known_protocols.add(protocol.upper())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "category": self.device_category,
            "sample_count": self.sample_count,
            "pps_baseline": {"mean": round(self.pps_mean, 2), "std": round(self.pps_std, 2)},
            "byte_rate_baseline": {"mean": round(self.byte_rate_mean, 2), "std": round(self.byte_rate_std, 2)},
            "conn_freq_baseline": {"mean": round(self.conn_freq_mean, 2), "std": round(self.conn_freq_std, 2)},
            "known_ports": sorted(list(self.known_ports))[:15],
            "known_protocols": sorted(list(self.known_protocols))
        }


class BaselineService:
    """Manages baseline models across the IoT fleet with false-positive mitigation controls."""

    def __init__(self):
        self._lock = threading.Lock()
        self._profiles: Dict[str, DeviceBaselineProfile] = {}
        # Sensitivity settings: 'strict' (Z=2.5), 'standard' (Z=3.5), 'lenient' (Z=5.0)
        self.sensitivity_mode = "standard"
        self.z_threshold = 3.5

    def set_sensitivity(self, mode: str):
        """Configure baseline deviation sensitivity threshold."""
        mode_clean = mode.lower()
        if mode_clean == "strict":
            self.sensitivity_mode = "strict"
            self.z_threshold = 2.5
        elif mode_clean == "lenient":
            self.sensitivity_mode = "lenient"
            self.z_threshold = 5.0
        else:
            self.sensitivity_mode = "standard"
            self.z_threshold = 3.5
        logger.info(f"[BaselineService] Sensitivity configured to {self.sensitivity_mode} (Z-score threshold: {self.z_threshold})")

    def get_or_create_profile(self, device_id: str, device_category: str = "Generic IoT") -> DeviceBaselineProfile:
        with self._lock:
            if device_id not in self._profiles:
                self._profiles[device_id] = DeviceBaselineProfile(device_id, device_category)
            return self._profiles[device_id]

    def record_flow_telemetry(self, device_id: str, pps: float, byte_rate: float, conn_freq: float, port: int, protocol: str, is_normal: bool = True):
        """Incorporate telemetry into baseline if benign or baseline-learning eligible."""
        if not device_id or device_id == "UNKNOWN":
            return
        # Avoid corrupting baseline with confirmed high-risk attack traffic
        if is_normal:
            profile = self.get_or_create_profile(device_id)
            with self._lock:
                profile.update(pps, byte_rate, conn_freq, port, protocol)

    def evaluate_deviation(
        self,
        device_id: str,
        pps: float,
        byte_rate: float,
        conn_freq: float,
        dest_port: int,
        protocol: str,
        device_category: str = "Generic IoT"
    ) -> Dict[str, Any]:
        """
        Evaluate current flow against device's historical baseline profile.
        Returns statistical deviation scores and explainable false-positive warnings.
        """
        profile = self.get_or_create_profile(device_id, device_category)

        # Calculate Z-scores with non-zero divisors
        z_pps = (pps - profile.pps_mean) / max(profile.pps_std, 1.0)
        z_byte = (byte_rate - profile.byte_rate_mean) / max(profile.byte_rate_std, 100.0)
        z_conn = (conn_freq - profile.conn_freq_mean) / max(profile.conn_freq_std, 0.5)

        deviations = []
        is_deviant = False

        if z_pps > self.z_threshold:
            is_deviant = True
            deviations.append({
                "metric": "packet_rate",
                "observed": round(pps, 1),
                "baseline_mean": round(profile.pps_mean, 1),
                "z_score": round(z_pps, 2),
                "description": f"Packet rate ({pps:.1f} pps) exceeds baseline mean ({profile.pps_mean:.1f} ± {profile.pps_std:.1f} pps, Z={z_pps:.1f})"
            })

        if z_byte > self.z_threshold:
            is_deviant = True
            deviations.append({
                "metric": "byte_rate",
                "observed": round(byte_rate, 1),
                "baseline_mean": round(profile.byte_rate_mean, 1),
                "z_score": round(z_byte, 2),
                "description": f"Bandwidth throughput ({byte_rate:.0f} B/s) exceeds baseline (Z={z_byte:.1f})"
            })

        if z_conn > self.z_threshold:
            is_deviant = True
            deviations.append({
                "metric": "conn_freq",
                "observed": round(conn_freq, 1),
                "baseline_mean": round(profile.conn_freq_mean, 1),
                "z_score": round(z_conn, 2),
                "description": f"Connection frequency ({conn_freq:.1f} conn/10s) exceeds baseline cadence (Z={z_conn:.1f})"
            })

        # Check port anomaly
        novel_port = dest_port not in profile.known_ports if profile.sample_count > 10 else False
        if novel_port and dest_port not in (80, 443, 53, 123):
            deviations.append({
                "metric": "unusual_port",
                "observed": dest_port,
                "description": f"Destination port {dest_port} has not been observed in {profile.sample_count} historical baseline flows"
            })

        max_z = max(0.0, z_pps, z_byte, z_conn)
        return {
            "device_id": device_id,
            "sample_count": profile.sample_count,
            "is_deviant": is_deviant,
            "sensitivity": self.sensitivity_mode,
            "max_z_score": round(max_z, 2),
            "deviations": deviations,
            "fp_disclaimer": "Threshold-based anomaly indicator. Legitimate bursts (e.g. cloud backups or firmware sync) can elevate metrics. Verify forensic indicators prior to confirming botnet compromise."
        }

    def get_profile_summary(self, device_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            if device_id in self._profiles:
                return self._profiles[device_id].to_dict()
        return None


# Global singleton baseline service
baseline_service = BaselineService()
