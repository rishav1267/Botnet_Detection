"""
Alert Service — Security Incident Management, Triage, Notes Thread, and Bulk Remediation
"""

from typing import List, Dict, Any, Optional, Tuple
from backend.database.repository import repository
from backend.utils.logger import logger


class AlertService:
    """Business logic for security incident alerts and investigation."""

    def __init__(self, network_manager):
        self.network_manager = network_manager

    def get_alerts(self, severity: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return alerts list with optional severity and status filtering."""
        alerts = self.network_manager.alerts
        if severity:
            alerts = [a for a in alerts if a.get("severity", "").lower() == severity.lower()]
        if status:
            alerts = [a for a in alerts if a.get("status", "").lower() == status.lower()]
        return alerts

    def get_alerts_paginated(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        device_id: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        limit: int = 20
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any], int]:
        """Query alerts with filtering, search, and pagination."""
        return repository.get_alerts_paginated(
            severity=severity,
            status=status,
            device_id=device_id,
            search=search,
            page=page,
            limit=limit
        )

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Fetch single alert by alert ID."""
        for a in self.network_manager.alerts:
            if a.get("id") == alert_id:
                return dict(a)
        return repository.get_alert_by_id(alert_id)

    def update_alert_status(
        self,
        alert_id: str,
        new_status: str,
        reason: Optional[str] = None,
        author: str = "SecOps Analyst"
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str], int]:
        """
        Validate state transition and update incident ticket state.
        Returns: (success, updated_alert, error_message, http_status_code)
        """
        target = self.get_alert_by_id(alert_id)
        if not target:
            return False, None, f"Security alert '{alert_id}' not found", 404

        current_status = target.get("status", "New")
        cur_norm = current_status.lower()
        new_norm = new_status.lower()

        # Check valid state transitions
        if cur_norm == new_norm:
            return True, target, None, 200

        # Disallow reopening from Resolved / False Positive without an explicit reason
        if cur_norm in ("resolved", "false positive"):
            if not reason or not reason.strip():
                return False, None, f"Reopening a '{current_status}' alert requires providing an explicit investigation reason.", 400

        # Update in network manager and repository
        updated = self.network_manager.update_alert_status(alert_id, new_status, reason)
        repo_updated = repository.update_alert_status(alert_id, new_status, reason, author)

        final_alert = repo_updated or updated or target
        repository.record_audit(
            action="ALERT_STATUS_UPDATE",
            user_id=author,
            details={"alert_id": alert_id, "from": current_status, "to": new_status, "reason": reason}
        )
        logger.info(f"[AlertService] Alert {alert_id} transition: {current_status} -> {new_status} by {author}")
        return True, final_alert, None, 200

    def acknowledge_alert(
        self,
        alert_id: str,
        analyst: str = "SecOps Analyst",
        note: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str], int]:
        """Acknowledge alert and transition status to Investigating."""
        target = self.get_alert_by_id(alert_id)
        if not target:
            return False, None, f"Security alert '{alert_id}' not found", 404

        # Acknowledge in network manager
        for a in self.network_manager.alerts:
            if a.get("id") == alert_id:
                a["acknowledged"] = True
                a["acknowledged_by"] = analyst
                if a.get("status") == "New":
                    a["status"] = "Investigating"
                break

        updated = repository.acknowledge_alert(alert_id, analyst, note)
        repository.record_audit(
            action="ALERT_ACKNOWLEDGE",
            user_id=analyst,
            details={"alert_id": alert_id}
        )
        return True, updated or target, None, 200

    def get_unread_count(self) -> Dict[str, int]:
        """Return counts of unread or unacknowledged alerts."""
        return repository.get_unread_alert_count()

    def add_analyst_note(self, alert_id: str, note: str, author: str = "SecOps Analyst") -> Optional[Dict[str, Any]]:
        """Append an analyst investigation note to the forensic thread."""
        updated = repository.add_alert_note(alert_id, note, author)
        sim_updated = self.network_manager.add_alert_note(alert_id, author, note)
        res = updated or sim_updated
        if res:
            repository.record_audit(
                action="ALERT_NOTE_ADDED",
                user_id=author,
                details={"alert_id": alert_id, "author": author}
            )
        return res

    def bulk_update(self, alert_ids: List[str], action: str) -> Dict[str, Any]:
        """Perform bulk triage action across multiple incident tickets."""
        result = self.network_manager.bulk_update_alerts(alert_ids, action)
        repository.record_audit(
            action=f"ALERT_BULK_{action.upper()}",
            user_id="secops_analyst",
            details=result
        )
        return result
