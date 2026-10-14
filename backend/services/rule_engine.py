"""
Configurable Rule-Based Detection Engine for IoT Network Traffic
Evaluates telemetry against 8 indicators, computes transparent risk scores,
and implements alert suppression to prevent flood of duplicate alerts during sustained attacks.
"""

import time
import threading
from typing import Dict, Any, List, Optional, Tuple
from backend.services.baseline_service import baseline_service
from backend.utils.logger import logger


class ConfigurableRule:
    """Configurable detection rule representation."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        required_features: List[str],
        thresholds: Dict[str, Any],
        severity: str,
        suggested_investigation: str,
        enabled: bool = True
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.required_features = required_features
        self.thresholds = thresholds
        self.severity = severity  # 'High-Risk', 'Suspicious', 'Low'
        self.suggested_investigation = suggested_investigation
        self.enabled = enabled
        self.hit_count = 0
        self.last_triggered = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "required_features": self.required_features,
            "thresholds": self.thresholds,
            "severity": self.severity,
            "suggested_investigation": self.suggested_investigation,
            "enabled": self.enabled,
            "hit_count": self.hit_count,
            "last_triggered": self.last_triggered
        }


class ConfigurableRuleEngine:
    """
    Evaluates 8 IoT Botnet Indicators:
    1. Unusually high packet rates (volumetric flood)
    2. Abnormally high outbound traffic (exfiltration / outbound blast)
    3. Repeated connection attempts (brute force sweeps)
    4. Unusual connection frequency (cadence beaconing)
    5. Suspicious port patterns (Telnet 23/2323, SSH 22, CWMP 7547, ADB 5555, etc.)
    6. Unusual destination diversity (horizontal scanning)
    7. Deviations from device established baseline
    8. Repeated failed connections / high TCP RST ratio
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.rules: Dict[str, ConfigurableRule] = self._init_default_rules()

        # Scoring thresholds (documented & configurable)
        self.scoring_config = {
            "threshold_normal_max": 29,
            "threshold_suspicious_max": 69,
            "threshold_high_risk_min": 70,
            "weight_high_risk_rule": 35,
            "weight_suspicious_rule": 18,
            "weight_baseline_deviation": 20
        }

        # Alert suppression cache: {(device_id, rule_id): {"alert_id": ..., "first_seen": ..., "last_seen": ..., "count": ...}}
        self._suppression_cache: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.suppression_window_sec = 300  # 5 minutes suppression window

    def _init_default_rules(self) -> Dict[str, ConfigurableRule]:
        return {
            "R01_HIGH_PACKET_RATE": ConfigurableRule(
                rule_id="R01_HIGH_PACKET_RATE",
                name="Volumetric Packet Rate Surge",
                description="Unusually high packet rate exceeding volumetric flood baseline.",
                required_features=["packet_rate"],
                thresholds={"threshold_pps": 300.0},
                severity="High-Risk",
                suggested_investigation="Inspect egress traffic, check if device is weaponized in a DDoS attack, isolate VLAN port if anomalous."
            ),
            "R02_HIGH_OUTBOUND_TRAFFIC": ConfigurableRule(
                rule_id="R02_HIGH_OUTBOUND_TRAFFIC",
                name="Abnormal Outbound Data Transfer",
                description="High outbound byte rate and elevated outbound ratio indicating exfiltration or outbound attack.",
                required_features=["byte_rate", "outbound_ratio"],
                thresholds={"threshold_bps": 120000.0, "threshold_outbound_ratio": 0.80},
                severity="High-Risk",
                suggested_investigation="Verify destination IP reputation, inspect for unauthorized file staging or reflection attack participation."
            ),
            "R03_REPEATED_CONN_ATTEMPTS": ConfigurableRule(
                rule_id="R03_REPEATED_CONN_ATTEMPTS",
                name="Repeated Connection Attempts",
                description="Rapid burst of connection attempts indicative of automated credential brute force.",
                required_features=["conn_freq"],
                thresholds={"threshold_conn_freq": 16.0},
                severity="High-Risk",
                suggested_investigation="Review authentication logs, disable exposed default Telnet/SSH management ports."
            ),
            "R04_UNUSUAL_CONN_FREQUENCY": ConfigurableRule(
                rule_id="R04_UNUSUAL_CONN_FREQUENCY",
                name="Unusual Connection Cadence",
                description="High connection frequency or fixed cadence beaconing to external systems.",
                required_features=["conn_freq", "payload_entropy"],
                thresholds={"threshold_conn_freq": 8.0, "threshold_entropy": 6.8},
                severity="Suspicious",
                suggested_investigation="Check if external IP is an authorized vendor cloud endpoint; monitor for persistent C2 beaconing."
            ),
            "R05_SUSPICIOUS_PORT_PATTERNS": ConfigurableRule(
                rule_id="R05_SUSPICIOUS_PORT_PATTERNS",
                name="Suspicious IoT Target Port Patterns",
                description="Traffic communicating with high-risk vulnerable IoT administration or backdoor ports.",
                required_features=["dest_port"],
                thresholds={"target_ports": [23, 2323, 22, 7547, 5555, 6379, 1900, 37215]},
                severity="High-Risk",
                suggested_investigation="Check for active Telnet/ADB access; verify if device vendor credentials were changed from factory defaults."
            ),
            "R06_UNUSUAL_DEST_DIVERSITY": ConfigurableRule(
                rule_id="R06_UNUSUAL_DEST_DIVERSITY",
                name="Unusual Destination IP Diversity",
                description="Device communicating with an abnormal number of distinct destination IPs (horizontal scan).",
                required_features=["unique_dest_ips"],
                thresholds={"threshold_unique_ips": 10.0},
                severity="Suspicious",
                suggested_investigation="Inspect whether host is conducting network discovery or worm-like lateral spread across LAN."
            ),
            "R07_BASELINE_DEVIATION": ConfigurableRule(
                rule_id="R07_BASELINE_DEVIATION",
                name="Device Baseline Deviation",
                description="Statistically significant divergence from historical baseline profile (Z > 3.5).",
                required_features=["packet_rate", "device_id"],
                thresholds={"threshold_z_score": 3.5},
                severity="Suspicious",
                suggested_investigation="Audit firmware update status and compare with peer devices of identical make and model."
            ),
            "R08_REPEATED_FAILED_CONNS": ConfigurableRule(
                rule_id="R08_REPEATED_FAILED_CONNS",
                name="Elevated Failed Connections & TCP RST",
                description="Abnormal ratio of failed connections or TCP RST packets suggesting blocked port probes.",
                required_features=["rst_ratio", "failed_connections"],
                thresholds={"threshold_rst_ratio": 0.35, "threshold_failed_conns": 5.0},
                severity="Suspicious",
                suggested_investigation="Determine target subnet; verify if device is blindly attempting connections to decommissioned IPs."
            )
        }

    def get_rules(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in self.rules.values()]

    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with self._lock:
            if rule_id not in self.rules:
                return None
            rule = self.rules[rule_id]
            if "name" in updates and updates["name"]:
                rule.name = updates["name"]
            if "description" in updates and updates["description"]:
                rule.description = updates["description"]
            if "enabled" in updates and updates["enabled"] is not None:
                rule.enabled = bool(updates["enabled"])
            if "severity" in updates and updates["severity"]:
                rule.severity = updates["severity"]
            if "suggested_investigation" in updates and updates["suggested_investigation"]:
                rule.suggested_investigation = updates["suggested_investigation"]
            if "thresholds" in updates and isinstance(updates["thresholds"], dict):
                rule.thresholds.update(updates["thresholds"])
            return rule.to_dict()

    def evaluate_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate enabled rules against the normalized flow event.
        Returns triggered rules, baseline evaluation, score, and verdict.
        """
        pps = float(flow.get("packet_rate", 0.0))
        bps = float(flow.get("byte_rate", 0.0))
        conn_freq = float(flow.get("conn_freq", 0.0))
        port = int(flow.get("dest_port", 80))
        protocol = str(flow.get("protocol", "TCP")).upper()
        unique_ips = int(flow.get("unique_dest_ips", 1))
        syn_ratio = float(flow.get("syn_ratio", 0.0))
        rst_ratio = float(flow.get("rst_ratio", 0.0))
        entropy = float(flow.get("payload_entropy", 4.0))
        failed_conns = int(flow.get("failed_connections", 0))
        outbound_ratio = float(flow.get("outbound_ratio", 0.5))
        dev_id = flow.get("device_id", "DEV-UNKNOWN")
        dev_category = flow.get("device_category", "Generic IoT")

        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        triggered_rules = []

        with self._lock:
            # 1. R01: High Packet Rate
            r1 = self.rules["R01_HIGH_PACKET_RATE"]
            if r1.enabled and pps >= r1.thresholds.get("threshold_pps", 300.0):
                r1.hit_count += 1
                r1.last_triggered = now_str
                triggered_rules.append({
                    "rule_id": r1.rule_id,
                    "name": r1.name,
                    "severity": r1.severity,
                    "reason": f"Volumetric packet rate ({pps:.1f} pps) exceeded threshold ({r1.thresholds.get('threshold_pps', 300.0)} pps)",
                    "suggested_investigation": r1.suggested_investigation
                })

            # 2. R02: High Outbound Traffic
            r2 = self.rules["R02_HIGH_OUTBOUND_TRAFFIC"]
            if r2.enabled and (bps >= r2.thresholds.get("threshold_bps", 120000.0) or outbound_ratio >= r2.thresholds.get("threshold_outbound_ratio", 0.80) and bps > 30000.0):
                r2.hit_count += 1
                r2.last_triggered = now_str
                triggered_rules.append({
                    "rule_id": r2.rule_id,
                    "name": r2.name,
                    "severity": r2.severity,
                    "reason": f"Outbound bandwidth ({bps:.0f} B/s, outbound ratio {outbound_ratio:.2f}) indicates high data exfiltration or reflection volume",
                    "suggested_investigation": r2.suggested_investigation
                })

            # 3. R03: Repeated Connection Attempts
            r3 = self.rules["R03_REPEATED_CONN_ATTEMPTS"]
            if r3.enabled and conn_freq >= r3.thresholds.get("threshold_conn_freq", 16.0):
                r3.hit_count += 1
                r3.last_triggered = now_str
                triggered_rules.append({
                    "rule_id": r3.rule_id,
                    "name": r3.name,
                    "severity": r3.severity,
                    "reason": f"Connection burst rate ({conn_freq:.1f} conn/10s) exceeded limit ({r3.thresholds.get('threshold_conn_freq', 16.0)})",
                    "suggested_investigation": r3.suggested_investigation
                })

            # 4. R04: Unusual Connection Frequency / Cadence
            r4 = self.rules["R04_UNUSUAL_CONN_FREQUENCY"]
            if r4.enabled and conn_freq >= r4.thresholds.get("threshold_conn_freq", 8.0) and entropy >= r4.thresholds.get("threshold_entropy", 6.8):
                r4.hit_count += 1
                r4.last_triggered = now_str
                triggered_rules.append({
                    "rule_id": r4.rule_id,
                    "name": r4.name,
                    "severity": r4.severity,
                    "reason": f"High cadence beaconing ({conn_freq:.1f} conn/10s) with high entropy ({entropy:.2f})",
                    "suggested_investigation": r4.suggested_investigation
                })

            # 5. R05: Suspicious Port Patterns
            r5 = self.rules["R05_SUSPICIOUS_PORT_PATTERNS"]
            target_ports = r5.thresholds.get("target_ports", [23, 2323, 22])
            if r5.enabled and port in target_ports:
                r5.hit_count += 1
                r5.last_triggered = now_str
                triggered_rules.append({
                    "rule_id": r5.rule_id,
                    "name": r5.name,
                    "severity": r5.severity,
                    "reason": f"Traffic targeted high-risk IoT administrative port {port} commonly swept by Mirai/Gafgyt botnets",
                    "suggested_investigation": r5.suggested_investigation
                })

            # 6. R06: Unusual Destination Diversity
            r6 = self.rules["R06_UNUSUAL_DEST_DIVERSITY"]
            if r6.enabled and unique_ips >= r6.thresholds.get("threshold_unique_ips", 10.0):
                r6.hit_count += 1
                r6.last_triggered = now_str
                triggered_rules.append({
                    "rule_id": r6.rule_id,
                    "name": r6.name,
                    "severity": r6.severity,
                    "reason": f"Device contacted {unique_ips} distinct destination IPs within sampling interval (horizontal sweep)",
                    "suggested_investigation": r6.suggested_investigation
                })

            # 7. R07: Baseline Deviation
            r7 = self.rules["R07_BASELINE_DEVIATION"]
            baseline_result = baseline_service.evaluate_deviation(dev_id, pps, bps, conn_freq, port, protocol, dev_category)
            if r7.enabled and baseline_result.get("is_deviant", False):
                r7.hit_count += 1
                r7.last_triggered = now_str
                reasons = "; ".join([d["description"] for d in baseline_result.get("deviations", [])])
                triggered_rules.append({
                    "rule_id": r7.rule_id,
                    "name": r7.name,
                    "severity": r7.severity,
                    "reason": f"Historical baseline anomaly: {reasons}",
                    "suggested_investigation": r7.suggested_investigation
                })

            # 8. R08: Repeated Failed Connections & TCP RST
            r8 = self.rules["R08_REPEATED_FAILED_CONNS"]
            if r8.enabled and (rst_ratio >= r8.thresholds.get("threshold_rst_ratio", 0.35) or failed_conns >= r8.thresholds.get("threshold_failed_conns", 5.0)):
                r8.hit_count += 1
                r8.last_triggered = now_str
                triggered_rules.append({
                    "rule_id": r8.rule_id,
                    "name": r8.name,
                    "severity": r8.severity,
                    "reason": f"Elevated failed connections ({failed_conns}) or TCP RST proportion ({rst_ratio:.2f}) indicates blocked port sweep",
                    "suggested_investigation": r8.suggested_investigation
                })

        # Calculate explainable risk score
        score = 0.0
        has_high_rule = False
        has_susp_rule = False

        for r in triggered_rules:
            if r["severity"] == "High-Risk":
                score += self.scoring_config["weight_high_risk_rule"]
                has_high_rule = True
            elif r["severity"] == "Suspicious":
                score += self.scoring_config["weight_suspicious_rule"]
                has_susp_rule = True

        if baseline_result.get("is_deviant", False):
            score += min(25.0, baseline_result.get("max_z_score", 0.0) * 4.0)

        # Baseline learning: if flow is benign, record to update baseline
        if not has_high_rule and not has_susp_rule:
            baseline_service.record_flow_telemetry(dev_id, pps, bps, conn_freq, port, protocol, is_normal=True)

        final_score = int(min(100.0, max(0.0, score)))

        if final_score >= self.scoring_config["threshold_high_risk_min"] or has_high_rule:
            classification = "High-Risk"
            if final_score < 70:
                final_score = 75
        elif final_score >= self.scoring_config["threshold_normal_max"] + 1 or has_susp_rule:
            classification = "Suspicious"
            if final_score < 35:
                final_score = 45
        else:
            classification = "Normal"
            final_score = max(5, final_score)

        return {
            "classification": classification,
            "risk_score": final_score,
            "triggered_rules": triggered_rules,
            "rule_count_evaluated": len(self.rules),
            "baseline_analysis": baseline_result
        }

    def check_alert_suppression(self, device_id: str, rule_id: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an alert for (device_id, rule_id) is currently suppressed.
        Returns: (is_suppressed, existing_alert_id)
        """
        key = (device_id, rule_id)
        now = time.time()
        with self._lock:
            # Purge expired suppression entries
            expired = [k for k, v in self._suppression_cache.items() if now - v["last_seen"] > self.suppression_window_sec]
            for k in expired:
                del self._suppression_cache[k]

            if key in self._suppression_cache:
                entry = self._suppression_cache[key]
                entry["last_seen"] = now
                entry["hit_count"] += 1
                return True, entry["alert_id"]
        return False, None

    def register_alert_in_suppression(self, device_id: str, rule_id: str, alert_id: str):
        """Register newly created alert in the suppression window cache."""
        key = (device_id, rule_id)
        now = time.time()
        with self._lock:
            self._suppression_cache[key] = {
                "alert_id": alert_id,
                "first_seen": now,
                "last_seen": now,
                "hit_count": 1
            }


# Global singleton rule engine instance
configurable_rule_engine = ConfigurableRuleEngine()
