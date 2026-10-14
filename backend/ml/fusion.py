"""
IoT Botnet Detection System — Evidence Fusion Coordinator
Combines Rule-Based Heuristic Detections and Machine Learning Predictions
with explicit evidence attribution, disagreement documentation, and zero double-counting.
"""

from typing import Dict, Any, List


class EvidenceFusionCoordinator:
    """
    Synthesizes dual-tier evidence from:
    1. Deterministic Rule-Based Engine (Known signatures, CVE ports, protocol floods)
    2. Statistical ML Classifier (Multi-dimensional feature vector distributions)

    Evidence Combination Matrix:
    - Rule: High-Risk + ML: High-Risk   --> Consensus (High-Risk), Score: 95-100
    - Rule: High-Risk + ML: Normal      --> Heuristic Override (Exploit Signature), Score: 85-90
    - Rule: Normal    + ML: High-Risk   --> ML Anomaly Detected (Zero-Day / Out-of-Spec), Score: 75-85
    - Rule: Suspicious + ML: Suspicious --> Consensus (Suspicious), Score: 55-65
    - Rule: Suspicious + ML: Normal     --> Cautious Flag (Review Recommended), Score: 40-50
    - Rule: Normal    + ML: Suspicious  --> Low-Confidence Anomaly, Score: 35-45
    - Rule: Normal    + ML: Normal      --> Consensus (Normal), Score: 5-15
    """

    @staticmethod
    def fuse_evidence(
        rule_eval: Dict[str, Any],
        ml_eval: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Produce a fused verdict while preserving independent rule and ML records.
        """
        rule_verdict = rule_eval.get("classification") or rule_eval.get("verdict") or "Normal"
        rules_triggered = rule_eval.get("triggered_rules") or rule_eval.get("rules_triggered") or []
        rule_score = float(rule_eval.get("risk_score") or 10.0)

        ml_status = ml_eval.get("status", "unavailable")
        ml_verdict = ml_eval.get("prediction", "Unknown")
        ml_conf = float(ml_eval.get("confidence", 0.0))
        ml_anomaly = float(ml_eval.get("anomaly_score", 0.0))

        # Check if ML is operating normally
        ml_active = ml_status in ("available_and_trained", "demonstration_mode") and ml_verdict != "Unknown"

        # ---------------------------------------------------------------------
        # Case A: Both engines operational
        # ---------------------------------------------------------------------
        if ml_active:
            if rule_verdict == "High-Risk" and ml_verdict == "High-Risk":
                final_verdict = "High-Risk"
                agreement = "Consensus (Attack Confirmed)"
                risk_score = max(95.0, min(100.0, rule_score * 0.5 + ml_anomaly * 50.0))
                rationale = (
                    f"Strong consensus: Rule Engine triggered {len(rules_triggered)} high-risk rule(s) "
                    f"and Machine Learning verified high-risk pattern with {ml_conf*100:.1f}% confidence."
                )

            elif rule_verdict == "High-Risk" and ml_verdict != "High-Risk":
                final_verdict = "High-Risk"
                agreement = "Heuristic Override (Known Attack Signature)"
                risk_score = 88.0
                top_rule = rules_triggered[0].get("name") if rules_triggered else "Exploit Rule"
                rationale = (
                    f"Heuristic Override: Deterministic rule triggered ({top_rule}). "
                    f"ML classified as '{ml_verdict}'. Exploit signatures override statistical baseline."
                )

            elif rule_verdict != "High-Risk" and ml_verdict == "High-Risk":
                final_verdict = "High-Risk"
                agreement = "ML Anomaly Detected (Zero-Day Pattern)"
                risk_score = round(75.0 + ml_conf * 15.0, 1)
                rationale = (
                    f"Statistical Anomaly: ML model flagged severe out-of-distribution flow with {ml_conf*100:.1f}% confidence "
                    f"even though no static rule pattern matched. Potential novel zero-day or obfuscated botnet activity."
                )

            elif rule_verdict == "Suspicious" and ml_verdict == "Suspicious":
                final_verdict = "Suspicious"
                agreement = "Consensus (Suspicious Anomaly)"
                risk_score = 60.0
                rationale = (
                    f"Dual-engine agreement: Suspicious traffic parameters detected by both heuristics and ML ({ml_conf*100:.1f}% confidence)."
                )

            elif rule_verdict == "Suspicious" and ml_verdict == "Normal":
                final_verdict = "Suspicious"
                agreement = "Disagreement (Heuristic Warning)"
                risk_score = 45.0
                rationale = (
                    f"Minor divergence: Rule engine flagged reconnaissance/cadence threshold, but ML considers features benign. "
                    f"Classified as Suspicious for analyst review."
                )

            elif rule_verdict == "Normal" and ml_verdict == "Suspicious":
                final_verdict = "Suspicious"
                agreement = "Disagreement (ML Anomaly Warning)"
                risk_score = 42.0
                rationale = (
                    f"Minor divergence: ML detected slight statistical deviation ({ml_conf*100:.1f}% confidence), "
                    f"while static rules passed. Flagged for passive monitoring."
                )

            else:  # Normal + Normal
                final_verdict = "Normal"
                agreement = "Consensus (Benign Routine Telemetry)"
                risk_score = 5.0
                rationale = (
                    f"Full consensus: All heuristic checks satisfied and ML verified benign profile ({ml_conf*100:.1f}% confidence)."
                )

        # ---------------------------------------------------------------------
        # Case B: ML is unavailable or in error state (Fail-Safe Preservation)
        # ---------------------------------------------------------------------
        else:
            final_verdict = rule_verdict
            risk_score = rule_score
            agreement = "Rule-Only Fallback (ML Subsystem Offline)"
            rationale = (
                f"ML service in '{ml_status}' state. Verdict derived solely from rule-based heuristic checks. "
                f"Ingestion and deterministic threat detection preserved without interruption."
            )

        return {
            "verdict": final_verdict,
            "risk_score": round(risk_score, 1),
            "agreement_state": agreement,
            "verdict_rationale": rationale,
            "rule_evidence": {
                "verdict": rule_verdict,
                "risk_score": rule_score,
                "rules_triggered": rules_triggered,
                "rules_evaluated_count": rule_eval.get("rule_count_evaluated", 8)
            },
            "ml_evidence": {
                "status": ml_status,
                "model_version": ml_eval.get("model_version", "N/A"),
                "prediction": ml_verdict,
                "confidence": ml_conf,
                "anomaly_score": ml_anomaly,
                "probabilities": ml_eval.get("probabilities", {}),
                "is_fallback": ml_eval.get("is_fallback", True),
                "contributing_features": ml_eval.get("contributing_features", [])
            }
        }
