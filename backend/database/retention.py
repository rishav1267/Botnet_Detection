"""
Data Retention & Forensic Evidence Preservation Manager
Implements automated and configurable lifecycle management for network telemetry,
security alerts, and compliance audit logs with strict safeguards against deleting
unresolved incident evidence.
"""

import time
from typing import Dict, Any, List, Optional
from backend.config.settings import settings
from backend.database.connection import db_manager
from backend.database.repository import repository
from backend.utils.logger import logger


class RetentionManager:
    """Manages telemetry record retention, audit log rotation, and forensic evidence preservation."""

    @staticmethod
    def calculate_cutoff_timestamp(days: int) -> float:
        """Returns epoch seconds for the cutoff point N days in the past."""
        return time.time() - (days * 86400)

    @staticmethod
    def purge_expired_data(
        retention_days: Optional[int] = None,
        preserve_incident_evidence: bool = True
    ) -> Dict[str, Any]:
        """
        Purges telemetry and logs older than retention threshold while strictly
        preserving evidence required for active or high-severity incident investigations.
        """
        days = retention_days if retention_days is not None else settings.DATA_RETENTION_DAYS
        cutoff_epoch = RetentionManager.calculate_cutoff_timestamp(days)
        cutoff_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(cutoff_epoch))

        logger.info(f"[Retention] Starting data retention pass. Retaining records newer than {days} days ({cutoff_str}).")

        # 1. PURGE TRAFFIC FLOWS
        # Forensic Preservation Rule: Flows classified as High-Risk or associated with active incidents are preserved.
        col_flows = db_manager.get_collection("traffic_events")
        flows_purged = 0
        flows_preserved = 0

        # Purge local in-memory store
        new_local_flows = []
        for flow in repository._local_flows:
            flow_ts = flow.get("timestamp", "")
            is_high_risk = flow.get("verdict") in ("High-Risk", "Suspicious") or flow.get("threat_detected", False)
            
            # Simple timestamp check (string format: YYYY-MM-DD HH:MM:SS)
            if flow_ts < cutoff_str:
                if preserve_incident_evidence and is_high_risk:
                    flows_preserved += 1
                    new_local_flows.append(flow)
                else:
                    flows_purged += 1
            else:
                new_local_flows.append(flow)
        repository._local_flows = new_local_flows

        # Purge MongoDB if connected
        if col_flows is not None:
            try:
                if preserve_incident_evidence:
                    # Only delete normal / benign flows older than cutoff
                    del_res = col_flows.delete_many({
                        "timestamp": {"$lt": cutoff_str},
                        "verdict": {"$nin": ["High-Risk", "Suspicious"]},
                        "threat_detected": {"$ne": True}
                    })
                    flows_purged += del_res.deleted_count
                    # Count preserved historical records
                    flows_preserved += col_flows.count_documents({
                        "timestamp": {"$lt": cutoff_str},
                        "$or": [
                            {"verdict": {"$in": ["High-Risk", "Suspicious"]}},
                            {"threat_detected": True}
                        ]
                    })
                else:
                    del_res = col_flows.delete_many({"timestamp": {"$lt": cutoff_str}})
                    flows_purged += del_res.deleted_count
            except Exception as e:
                logger.warning(f"[Retention] MongoDB flow purge warning: {e}")

        # 2. PURGE SECURITY ALERTS
        # Evidence Safeguard: Alerts with severity High/Critical or unresolved status (New, Investigating) MUST NOT be deleted.
        col_alerts = db_manager.get_collection("security_alerts")
        alerts_purged = 0
        alerts_preserved = 0

        new_local_alerts = []
        for alert in repository._local_alerts:
            alert_ts = alert.get("timestamp", "")
            severity = str(alert.get("severity", "")).lower()
            status = str(alert.get("status", "")).lower()

            is_critical_evidence = severity in ("high", "critical") or status in ("new", "investigating", "open")

            if alert_ts < cutoff_str:
                if preserve_incident_evidence and is_critical_evidence:
                    alerts_preserved += 1
                    new_local_alerts.append(alert)
                else:
                    alerts_purged += 1
            else:
                new_local_alerts.append(alert)
        repository._local_alerts = new_local_alerts

        if col_alerts is not None:
            try:
                if preserve_incident_evidence:
                    # Delete only resolved low/medium severity alerts older than cutoff
                    del_alt_res = col_alerts.delete_many({
                        "timestamp": {"$lt": cutoff_str},
                        "severity": {"$nin": ["High", "Critical", "high", "critical"]},
                        "status": {"$in": ["Resolved", "resolved", "False Positive", "false positive"]}
                    })
                    alerts_purged += del_alt_res.deleted_count
                    alerts_preserved += col_alerts.count_documents({
                        "timestamp": {"$lt": cutoff_str},
                        "$or": [
                            {"severity": {"$in": ["High", "Critical", "high", "critical"]}},
                            {"status": {"$nin": ["Resolved", "resolved", "False Positive", "false positive"]}}
                        ]
                    })
                else:
                    del_alt_res = col_alerts.delete_many({"timestamp": {"$lt": cutoff_str}})
                    alerts_purged += del_alt_res.deleted_count
            except Exception as e:
                logger.warning(f"[Retention] MongoDB alert purge warning: {e}")

        # 3. PURGE AUDIT LOGS
        # Routine login/query logs older than cutoff are rotated; critical administrative mutations are kept
        col_audit = db_manager.get_collection("audit_logs")
        audit_purged = 0

        new_local_audits = []
        for a_log in repository._local_audit_logs:
            log_ts = a_log.get("timestamp", "")
            action = a_log.get("action", "")
            if log_ts < cutoff_str and action not in ("DEVICE_DELETE", "ADMIN_ACTION"):
                audit_purged += 1
            else:
                new_local_audits.append(a_log)
        repository._local_audit_logs = new_local_audits

        if col_audit is not None:
            try:
                del_audit_res = col_audit.delete_many({
                    "timestamp": {"$lt": cutoff_str},
                    "action": {"$nin": ["DEVICE_DELETE", "ADMIN_ACTION", "POLICY_CHANGE"]}
                })
                audit_purged += del_audit_res.deleted_count
            except Exception as e:
                logger.warning(f"[Retention] MongoDB audit purge warning: {e}")

        summary = {
            "retention_days": days,
            "cutoff_timestamp": cutoff_str,
            "traffic_flows_purged": flows_purged,
            "traffic_flows_preserved_evidence": flows_preserved,
            "alerts_purged": alerts_purged,
            "alerts_preserved_evidence": alerts_preserved,
            "audit_logs_purged": audit_purged,
            "evidence_protection_active": preserve_incident_evidence,
            "status": "completed"
        }

        logger.info(
            f"[Retention] Complete: {flows_purged} flows purged ({flows_preserved} evidence preserved), "
            f"{alerts_purged} alerts purged ({alerts_preserved} evidence preserved), "
            f"{audit_purged} audit logs purged."
        )

        return summary


# Global singleton instance
retention_manager = RetentionManager()
