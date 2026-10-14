"""
Data Access Repository for NETGUARD IoT System
Decouples business services from database implementations (MongoDB with transparent embedded fallback).
Provides comprehensive query, filter, pagination, aggregation, and mutation capabilities.
"""

import time
import math
from typing import List, Dict, Any, Optional, Tuple
from backend.database.connection import db_manager
from backend.utils.logger import logger


class DataRepository:
    """Production Repository providing CRUD operations with dual-mode storage."""

    def __init__(self):
        # In-memory backing store for fallback and rapid indexing
        self._local_devices: List[Dict[str, Any]] = []
        self._local_flows: List[Dict[str, Any]] = []
        self._local_alerts: List[Dict[str, Any]] = []
        self._local_users: List[Dict[str, Any]] = []
        self._local_audit_logs: List[Dict[str, Any]] = []
        self._local_detection_results: List[Dict[str, Any]] = []
        self._local_metadata: Dict[str, Any] = {}

    def seed_initial_data(self, devices: List[Dict[str, Any]], alerts: List[Dict[str, Any]]):
        """Seed initial dataset if database is empty."""
        self._local_devices = [dict(d) for d in devices]
        self._local_alerts = [dict(a) for a in alerts]

        col_dev = db_manager.get_collection("devices")
        if col_dev is not None:
            try:
                if col_dev.count_documents({}) == 0 and devices:
                    col_dev.insert_many([dict(d) for d in devices])
                    logger.info(f"[Repository] Seeded {len(devices)} devices into MongoDB.")
            except Exception as e:
                logger.warning(f"[Repository] Device seed error: {e}")

        col_alt = db_manager.get_collection("security_alerts")
        if col_alt is not None:
            try:
                if col_alt.count_documents({}) == 0 and alerts:
                    col_alt.insert_many([dict(a) for a in alerts])
                    logger.info(f"[Repository] Seeded {len(alerts)} alerts into MongoDB.")
            except Exception as e:
                logger.warning(f"[Repository] Alerts seed error: {e}")

    # ==========================================================================
    # DEVICES CRUD & ADVANCED QUERY
    # ==========================================================================

    def get_all_devices(self) -> List[Dict[str, Any]]:
        """Fetch all devices."""
        col = db_manager.get_collection("devices")
        if col is not None:
            try:
                docs = list(col.find({}, {"_id": 0}))
                if docs:
                    return docs
            except Exception as e:
                logger.warning(f"[Repository] Failed to read devices from Mongo: {e}")
        return self._local_devices

    def get_devices_paginated(
        self,
        search: Optional[str] = None,
        risk_level: Optional[str] = None,
        protocol: Optional[str] = None,
        device_type: Optional[str] = None,
        sort_by: Optional[str] = "risk_score",
        sort_order: Optional[str] = "desc",
        page: int = 1,
        limit: int = 20
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
        """
        Query devices with search, filtering, sorting, and pagination.
        Returns: (devices_page, pagination_meta, summary_meta)
        """
        all_devs = self.get_all_devices()
        filtered = []

        q = (search or "").strip().lower()
        rf = (risk_level or "").strip().lower()
        pf = (protocol or "").strip().lower()
        tf = (device_type or "").strip().lower()

        for d in all_devs:
            # Search across name, id, ip, mac, type
            if q:
                fields_to_search = [
                    d.get("name", ""),
                    d.get("id", ""),
                    d.get("ip", ""),
                    d.get("mac", ""),
                    d.get("type", ""),
                    d.get("location", "")
                ]
                if not any(q in str(f).lower() for f in fields_to_search):
                    continue

            # Filter by risk level
            if rf:
                d_status = str(d.get("status", "")).lower()
                d_class = str(d.get("security_classification", "")).lower()
                if rf not in (d_status, d_class):
                    continue

            # Filter by protocol
            if pf:
                d_proto = str(d.get("protocol", "")).lower()
                if pf not in d_proto:
                    continue

            # Filter by device type
            if tf:
                d_type = str(d.get("type", "")).lower()
                if tf not in d_type:
                    continue

            filtered.append(d)

        # Sorting
        reverse = (sort_order or "desc").lower() == "desc"
        sort_key = sort_by or "risk_score"

        def get_sort_val(dev):
            val = dev.get(sort_key, 0)
            if isinstance(val, (int, float)):
                return val
            return str(val).lower()

        filtered.sort(key=get_sort_val, reverse=reverse)

        # Pagination
        total = len(filtered)
        limit = max(1, min(limit, 100))
        page = max(1, page)
        total_pages = max(1, math.ceil(total / limit))
        start_idx = (page - 1) * limit
        page_items = filtered[start_idx : start_idx + limit]

        # Calculate high-level summary from whole fleet
        summary = {
            "total": len(all_devs),
            "normal": sum(1 for d in all_devs if d.get("status") == "Normal"),
            "suspicious": sum(1 for d in all_devs if d.get("status") == "Suspicious"),
            "high_risk": sum(1 for d in all_devs if d.get("status") == "High-Risk"),
            "quarantined": sum(1 for d in all_devs if d.get("quarantined", False)),
        }

        pagination = {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        }

        return page_items, pagination, summary

    def get_device_by_id(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Fetch single device by device ID."""
        col = db_manager.get_collection("devices")
        if col is not None:
            try:
                doc = col.find_one({"id": device_id}, {"_id": 0})
                if doc:
                    return doc
            except Exception as e:
                logger.warning(f"[Repository] Mongo find_device error: {e}")
        for d in self._local_devices:
            if d.get("id") == device_id:
                return dict(d)
        return None

    def add_device(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new device into the repository."""
        self._local_devices.append(dict(device))
        col = db_manager.get_collection("devices")
        if col is not None:
            try:
                col.insert_one(dict(device))
            except Exception as e:
                logger.warning(f"[Repository] Mongo add_device error: {e}")
        return dict(device)

    def update_device(self, device_id: str, fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update mutable attributes on a device."""
        target = None
        for d in self._local_devices:
            if d.get("id") == device_id:
                d.update(fields)
                target = dict(d)
                break

        col = db_manager.get_collection("devices")
        if col is not None:
            try:
                col.update_one({"id": device_id}, {"$set": fields})
                if not target:
                    doc = col.find_one({"id": device_id}, {"_id": 0})
                    if doc:
                        target = doc
            except Exception as e:
                logger.warning(f"[Repository] Mongo update_device error: {e}")

        return target

    def delete_device(self, device_id: str) -> bool:
        """Remove a device from storage."""
        before_len = len(self._local_devices)
        self._local_devices = [d for d in self._local_devices if d.get("id") != device_id]
        deleted = len(self._local_devices) < before_len

        col = db_manager.get_collection("devices")
        if col is not None:
            try:
                res = col.delete_one({"id": device_id})
                if res.deleted_count > 0:
                    deleted = True
            except Exception as e:
                logger.warning(f"[Repository] Mongo delete_device error: {e}")

        return deleted

    def update_device_quarantine(self, device_id: str, quarantined: bool) -> bool:
        """Toggle device network quarantine state."""
        found = False
        for d in self._local_devices:
            if d.get("id") == device_id:
                d["quarantined"] = quarantined
                if quarantined:
                    d["pps"] = 0.0
                    d["status"] = "High-Risk"
                    d["security_classification"] = "High-Risk"
                    d["last_seen"] = "Quarantined / Isolated"
                found = True
                break

        col = db_manager.get_collection("devices")
        if col is not None:
            try:
                update_fields = {"quarantined": quarantined}
                if quarantined:
                    update_fields.update({
                        "pps": 0.0,
                        "status": "High-Risk",
                        "security_classification": "High-Risk",
                        "last_seen": "Quarantined / Isolated"
                    })
                res = col.update_one({"id": device_id}, {"$set": update_fields})
                if res.matched_count > 0:
                    found = True
            except Exception as e:
                logger.warning(f"[Repository] Mongo update_quarantine error: {e}")

        return found

    def get_device_traffic(self, device_id: str, limit: int = 50, page: int = 1) -> List[Dict[str, Any]]:
        """Fetch network flows associated with a specific device."""
        device = self.get_device_by_id(device_id)
        device_ip = device.get("ip") if device else None

        all_flows = self.get_recent_flows(limit=500)
        matched = []
        for f in all_flows:
            if f.get("device_id") == device_id:
                matched.append(f)
            elif device_ip and (f.get("source_ip") == device_ip or f.get("dest_ip") == device_ip):
                matched.append(f)

        start = (page - 1) * limit
        return matched[start : start + limit]

    def get_device_alerts(self, device_id: str) -> List[Dict[str, Any]]:
        """Fetch security alerts associated with a specific device."""
        all_alerts = self.get_all_alerts()
        return [a for a in all_alerts if a.get("device_id") == device_id]

    # ==========================================================================
    # TRAFFIC EVENTS CRUD & STATS
    # ==========================================================================

    def record_flow(self, flow: Dict[str, Any]):
        """Append a real or simulated flow event into the event log."""
        self._local_flows.insert(0, dict(flow))
        if len(self._local_flows) > 1000:
            self._local_flows.pop()

        col = db_manager.get_collection("traffic_events")
        if col is not None:
            try:
                col.insert_one(dict(flow))
            except Exception as e:
                logger.warning(f"[Repository] Mongo insert_flow error: {e}")

    def get_recent_flows(self, limit: int = 50, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch recent flows from storage."""
        col = db_manager.get_collection("traffic_events")
        if col is not None:
            try:
                query = {}
                if status_filter:
                    query["status"] = {"$regex": f"^{status_filter}$", "$options": "i"}
                docs = list(col.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit))
                if docs:
                    return docs
            except Exception as e:
                logger.warning(f"[Repository] Mongo get_flows error: {e}")

        flows = self._local_flows
        if status_filter:
            flows = [f for f in flows if f.get("status", "").lower() == status_filter.lower()]
        return flows[:limit]

    def get_traffic_events_paginated(
        self,
        device_id: Optional[str] = None,
        protocol: Optional[str] = None,
        verdict: Optional[str] = None,
        attack_category: Optional[str] = None,
        page: int = 1,
        limit: int = 50
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Query traffic events with filters and pagination."""
        all_flows = self.get_recent_flows(limit=1000)
        filtered = []

        dev_f = (device_id or "").strip()
        proto_f = (protocol or "").strip().lower()
        verd_f = (verdict or "").strip().lower()
        attk_f = (attack_category or "").strip().lower()

        for f in all_flows:
            if dev_f and f.get("device_id") != dev_f:
                continue
            if proto_f and f.get("protocol", "").lower() != proto_f:
                continue
            if verd_f and f.get("verdict", f.get("status", "")).lower() != verd_f:
                continue
            if attk_f and f.get("attack_category", "").lower() != attk_f:
                continue
            filtered.append(f)

        total = len(filtered)
        limit = max(1, min(limit, 200))
        page = max(1, page)
        total_pages = max(1, math.ceil(total / limit))
        start_idx = (page - 1) * limit
        page_items = filtered[start_idx : start_idx + limit]

        pagination = {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        }
        return page_items, pagination

    def get_traffic_stats(self) -> Dict[str, Any]:
        """Aggregate current network throughput, PPS, and flow health."""
        flows = self.get_recent_flows(limit=100)
        total_packets = sum(f.get("packets", f.get("packet_count", 1)) for f in flows)
        total_bytes = sum(f.get("bytes", f.get("byte_count", 64)) for f in flows)
        anomalies = sum(1 for f in flows if f.get("verdict", f.get("status")) in ("Suspicious", "High-Risk"))

        anomaly_rate = round((anomalies / max(1, len(flows))) * 100, 2)
        current_pps = round(sum(f.get("packets_per_sec", 12.5) for f in flows[:10]) / max(1, min(10, len(flows))), 1)
        current_mbps = round(current_pps * 0.0064, 2)

        return {
            "current_pps": current_pps,
            "current_mbps": current_mbps,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "anomaly_rate_pct": anomaly_rate,
            "active_flows_count": len(flows),
            "peak_pps": round(current_pps * 2.8, 1),
            "dropped_packets": 0,
        }

    def get_traffic_protocols(self) -> Dict[str, Any]:
        """Break down network traffic volume and threats by protocol."""
        flows = self.get_recent_flows(limit=250)
        proto_map: Dict[str, Dict[str, Any]] = {}

        for f in flows:
            p = str(f.get("protocol", "TCP")).upper()
            if p not in proto_map:
                proto_map[p] = {"protocol": p, "packets": 0, "bytes": 0, "flows": 0, "threats": 0}
            pkts = f.get("packets", f.get("packet_count", 1))
            bts = f.get("bytes", f.get("byte_count", 64))
            proto_map[p]["packets"] += pkts
            proto_map[p]["bytes"] += bts
            proto_map[p]["flows"] += 1
            if f.get("verdict", f.get("status")) in ("Suspicious", "High-Risk"):
                proto_map[p]["threats"] += 1

        total_bytes = sum(item["bytes"] for item in proto_map.values()) or 1
        result = []
        for p, d in proto_map.items():
            result.append({
                "protocol": p,
                "flows": d["flows"],
                "packets": d["packets"],
                "bytes": d["bytes"],
                "threats": d["threats"],
                "percentage": round((d["bytes"] / total_bytes) * 100, 1)
            })

        result.sort(key=lambda x: x["bytes"], reverse=True)
        return {
            "protocols": result,
            "total_protocols": len(result),
            "total_analyzed_bytes": total_bytes
        }

    # ==========================================================================
    # SECURITY ALERTS CRUD & TRIAGE
    # ==========================================================================

    def get_all_alerts(self, severity: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch all alerts with optional severity/status filter."""
        col = db_manager.get_collection("security_alerts")
        if col is not None:
            try:
                query = {}
                if severity:
                    query["severity"] = {"$regex": f"^{severity}$", "$options": "i"}
                if status:
                    query["status"] = {"$regex": f"^{status}$", "$options": "i"}
                docs = list(col.find(query, {"_id": 0}).sort("timestamp", -1))
                if docs:
                    return docs
            except Exception as e:
                logger.warning(f"[Repository] Mongo get_alerts error: {e}")

        alerts = self._local_alerts
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
        """Query security alerts with filters, search, and pagination."""
        all_alerts = self.get_all_alerts()
        filtered = []

        q = (search or "").strip().lower()
        sev_f = (severity or "").strip().lower()
        stat_f = (status or "").strip().lower()
        dev_f = (device_id or "").strip()

        for a in all_alerts:
            if dev_f and a.get("device_id") != dev_f:
                continue
            if sev_f and a.get("severity", "").lower() != sev_f:
                continue
            if stat_f and a.get("status", "").lower() != stat_f:
                continue
            if q:
                fields = [a.get("id", ""), a.get("device_id", ""), a.get("signature", ""), a.get("attack_type", "")]
                if not any(q in str(f).lower() for f in fields):
                    continue
            filtered.append(a)

        total = len(filtered)
        limit = max(1, min(limit, 100))
        page = max(1, page)
        total_pages = max(1, math.ceil(total / limit))
        start_idx = (page - 1) * limit
        page_items = filtered[start_idx : start_idx + limit]

        unread_count = sum(1 for a in all_alerts if a.get("status", "New").lower() == "new" or not a.get("acknowledged", False))

        pagination = {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        }
        return page_items, pagination, unread_count

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Fetch single alert by alert ID."""
        col = db_manager.get_collection("security_alerts")
        if col is not None:
            try:
                doc = col.find_one({"id": alert_id}, {"_id": 0})
                if doc:
                    return doc
            except Exception as e:
                logger.warning(f"[Repository] Mongo find_alert error: {e}")
        for a in self._local_alerts:
            if a.get("id") == alert_id:
                return dict(a)
        return None

    def add_alert(self, alert: Dict[str, Any]):
        """Persist a new security alert."""
        self._local_alerts.insert(0, dict(alert))
        col = db_manager.get_collection("security_alerts")
        if col is not None:
            try:
                col.insert_one(dict(alert))
            except Exception as e:
                logger.warning(f"[Repository] Mongo insert_alert error: {e}")

    def update_alert_status(
        self,
        alert_id: str,
        new_status: str,
        note: Optional[str] = None,
        author: str = "SecOps Analyst"
    ) -> Optional[Dict[str, Any]]:
        """Update alert status with audit trail."""
        updated = None
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        for a in self._local_alerts:
            if a.get("id") == alert_id:
                a["status"] = new_status
                a["resolved"] = (new_status.lower() == "resolved")
                if "audit_history" not in a:
                    a["audit_history"] = []
                a["audit_history"].append({
                    "action": f"Status updated to {new_status}",
                    "author": author,
                    "timestamp": timestamp,
                    "reason": note or ""
                })
                if note:
                    if "analyst_notes" not in a:
                        a["analyst_notes"] = []
                    a["analyst_notes"].append({
                        "author": author,
                        "timestamp": timestamp,
                        "note": note
                    })
                updated = dict(a)
                break

        col = db_manager.get_collection("security_alerts")
        if col is not None:
            try:
                update_q: Dict[str, Any] = {
                    "$set": {"status": new_status, "resolved": (new_status.lower() == "resolved")},
                    "$push": {"audit_history": {
                        "action": f"Status updated to {new_status}",
                        "author": author,
                        "timestamp": timestamp,
                        "reason": note or ""
                    }}
                }
                if note:
                    update_q["$push"]["analyst_notes"] = {
                        "author": author,
                        "timestamp": timestamp,
                        "note": note
                    }
                col.update_one({"id": alert_id}, update_q)
            except Exception as e:
                logger.warning(f"[Repository] Mongo update_alert error: {e}")

        return updated

    def acknowledge_alert(
        self,
        alert_id: str,
        analyst: str = "SecOps Analyst",
        note: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Acknowledge an alert and advance status to Investigating if New."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        target = None

        for a in self._local_alerts:
            if a.get("id") == alert_id:
                a["acknowledged"] = True
                a["acknowledged_by"] = analyst
                a["acknowledged_at"] = timestamp
                if a.get("status") == "New":
                    a["status"] = "Investigating"
                if "audit_history" not in a:
                    a["audit_history"] = []
                a["audit_history"].append({
                    "action": "Alert Acknowledged",
                    "author": analyst,
                    "timestamp": timestamp,
                    "note": note or "Assigned for triage"
                })
                target = dict(a)
                break

        col = db_manager.get_collection("security_alerts")
        if col is not None:
            try:
                update_doc = {
                    "$set": {
                        "acknowledged": True,
                        "acknowledged_by": analyst,
                        "acknowledged_at": timestamp,
                    },
                    "$push": {
                        "audit_history": {
                            "action": "Alert Acknowledged",
                            "author": analyst,
                            "timestamp": timestamp,
                            "note": note or "Assigned for triage"
                        }
                    }
                }
                col.update_one({"id": alert_id}, update_doc)
            except Exception as e:
                logger.warning(f"[Repository] Mongo ack alert error: {e}")

        return target

    def add_alert_note(
        self,
        alert_id: str,
        note: str,
        author: str = "SecOps Analyst"
    ) -> Optional[Dict[str, Any]]:
        """Append an analyst investigation note to the alert record."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        updated = None

        note_entry = {
            "author": author,
            "timestamp": timestamp,
            "note": note
        }

        for a in self._local_alerts:
            if a.get("id") == alert_id:
                if "analyst_notes" not in a:
                    a["analyst_notes"] = []
                a["analyst_notes"].append(note_entry)
                if "audit_history" not in a:
                    a["audit_history"] = []
                a["audit_history"].append({
                    "action": "Note added",
                    "author": author,
                    "timestamp": timestamp,
                    "reason": note
                })
                updated = dict(a)
                break

        col = db_manager.get_collection("security_alerts")
        if col is not None:
            try:
                res = col.update_one(
                    {"id": alert_id},
                    {
                        "$push": {
                            "analyst_notes": note_entry,
                            "audit_history": {
                                "action": "Note added",
                                "author": author,
                                "timestamp": timestamp,
                                "reason": note
                            }
                        }
                    }
                )
                if not updated and getattr(res, "matched_count", 0) > 0:
                    updated = col.find_one({"id": alert_id}, {"_id": 0})
            except Exception as e:
                logger.warning(f"[Repository] Mongo add_alert_note error: {e}")

        return updated

    def get_unread_alert_count(self) -> Dict[str, int]:
        """Count unread or unacknowledged security alerts."""
        alerts = self.get_all_alerts()
        unread = sum(1 for a in alerts if a.get("status") == "New" or not a.get("acknowledged", False))
        critical_unread = sum(1 for a in alerts if (a.get("status") == "New" or not a.get("acknowledged", False)) and a.get("severity") == "Critical")
        new_count = sum(1 for a in alerts if a.get("status") == "New")
        return {
            "unread_count": unread,
            "critical_unread_count": critical_unread,
            "new_count": new_count
        }

    # ==========================================================================
    # DETECTION RESULTS CRUD
    # ==========================================================================

    def save_detection_result(self, result: Dict[str, Any]):
        """Persist a detection execution result."""
        self._local_detection_results.insert(0, dict(result))
        if len(self._local_detection_results) > 500:
            self._local_detection_results.pop()

        col = db_manager.get_collection("detection_results")
        if col is not None:
            try:
                col.insert_one(dict(result))
            except Exception as e:
                logger.warning(f"[Repository] Mongo insert_detection error: {e}")

    def get_detection_results_paginated(
        self,
        verdict: Optional[str] = None,
        device_id: Optional[str] = None,
        page: int = 1,
        limit: int = 20
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Query persisted detection results."""
        results = self._local_detection_results
        col = db_manager.get_collection("detection_results")
        if col is not None:
            try:
                q: Dict[str, Any] = {}
                if verdict:
                    q["verdict"] = {"$regex": f"^{verdict}$", "$options": "i"}
                if device_id:
                    q["device_id"] = device_id
                docs = list(col.find(q, {"_id": 0}).sort("timestamp", -1).limit(200))
                if docs:
                    results = docs
            except Exception as e:
                logger.warning(f"[Repository] Mongo get_detections error: {e}")

        filtered = []
        for r in results:
            if verdict and r.get("verdict", "").lower() != verdict.lower():
                continue
            if device_id and r.get("device_id") != device_id:
                continue
            filtered.append(r)

        total = len(filtered)
        limit = max(1, min(limit, 100))
        page = max(1, page)
        total_pages = max(1, math.ceil(total / limit))
        start_idx = (page - 1) * limit
        page_items = filtered[start_idx : start_idx + limit]

        pagination = {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
        }
        return page_items, pagination

    def get_detection_result_by_id(self, result_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a specific detection run by ID."""
        col = db_manager.get_collection("detection_results")
        if col is not None:
            try:
                doc = col.find_one({"detection_id": result_id}, {"_id": 0})
                if doc:
                    return doc
            except Exception as e:
                logger.warning(f"[Repository] Mongo find detection error: {e}")
        for r in self._local_detection_results:
            if r.get("detection_id") == result_id or r.get("id") == result_id:
                return dict(r)
        return None

    # ==========================================================================
    # AUDIT LOGS
    # ==========================================================================

    def record_audit(self, action: str, user_id: str, details: Dict[str, Any]):
        """Append an action to the compliance audit log with credential redaction."""
        from backend.utils.crypto import redact_sensitive_data
        sanitized_details = redact_sensitive_data(details) if details else {}
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "action": action,
            "user_id": user_id,
            "details": sanitized_details
        }
        self._local_audit_logs.insert(0, log_entry)
        if len(self._local_audit_logs) > 1000:
            self._local_audit_logs.pop()
        col = db_manager.get_collection("audit_logs")
        if col is not None:
            try:
                col.insert_one(dict(log_entry))
            except Exception as e:
                logger.warning(f"[Repository] Mongo record_audit error: {e}")

    def get_audit_logs(
        self,
        limit: int = 50,
        action: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch audit log records with optional action and user_id filtering."""
        col = db_manager.get_collection("audit_logs")
        query_filter: Dict[str, Any] = {}
        if action:
            query_filter["action"] = action
        if user_id:
            query_filter["user_id"] = user_id

        if col is not None:
            try:
                docs = list(col.find(query_filter, {"_id": 0}).sort("timestamp", -1).limit(limit))
                if docs:
                    return docs
            except Exception as e:
                logger.warning(f"[Repository] Mongo get_audit error: {e}")

        filtered = self._local_audit_logs
        if action:
            filtered = [l for l in filtered if l.get("action") == action]
        if user_id:
            filtered = [l for l in filtered if l.get("user_id") == user_id]
        return filtered[:limit]


# Global repository instance
repository = DataRepository()
