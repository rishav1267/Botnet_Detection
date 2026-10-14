"""
Device Service — Manages IoT Asset Inventory, Risk Calculations, and Quarantine
"""

import time
import uuid
from typing import List, Dict, Any, Optional, Tuple
from backend.database.repository import repository
from backend.utils.logger import logger


class DeviceService:
    """Business logic for IoT devices and asset management."""

    def __init__(self, network_manager):
        self.network_manager = network_manager
        # Sync initial state to repository
        repository.seed_initial_data(self.network_manager.devices, self.network_manager.alerts)

    def get_devices(self) -> List[Dict[str, Any]]:
        """Return all managed IoT devices."""
        return self.network_manager.devices

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
        """Query devices with search, filters, sorting, and pagination."""
        return repository.get_devices_paginated(
            search=search,
            risk_level=risk_level,
            protocol=protocol,
            device_type=device_type,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            limit=limit
        )

    def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Return a single device by ID."""
        for d in self.network_manager.devices:
            if d.get("id") == device_id:
                return dict(d)
        return repository.get_device_by_id(device_id)

    def get_device_traffic(self, device_id: str, limit: int = 50, page: int = 1) -> List[Dict[str, Any]]:
        """Return recent traffic events associated with a device."""
        return repository.get_device_traffic(device_id, limit=limit, page=page)

    def get_device_alerts(self, device_id: str) -> List[Dict[str, Any]]:
        """Return security alerts associated with a device."""
        return repository.get_device_alerts(device_id)

    def create_device(self, data: Dict[str, Any], actor: str = "SecOps Analyst") -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """
        Register a new IoT endpoint.
        Returns: (success, device_dict, error_message)
        """
        device_id = data.get("id") or f"DEV-{str(uuid.uuid4())[:8].upper()}"
        mac = data.get("mac_address", "").upper()
        ip = data.get("ip_address", "")

        # Conflict check
        for existing in self.network_manager.devices:
            if existing.get("id") == device_id:
                return False, {}, f"Device with ID '{device_id}' already exists"
            if existing.get("mac", "").upper() == mac:
                return False, {}, f"Device with MAC '{mac}' already exists"

        new_device = {
            "id": device_id,
            "name": data.get("name", f"IoT Device {device_id}"),
            "type": data.get("type", "Generic Sensor"),
            "ip": ip,
            "mac": mac,
            "firmware": data.get("firmware_version", "1.0.0"),
            "location": data.get("location", "Default Network"),
            "vendor": data.get("vendor", "Generic IoT"),
            "status": "Normal",
            "security_classification": "Normal",
            "risk_score": 5.0,
            "anomaly_rate": 0.0,
            "quarantined": False,
            "pps": 12.0,
            "bytes_transferred": 0,
            "last_seen": "Just now",
            "risk_factors": []
        }

        self.network_manager.devices.append(new_device)
        repository.add_device(new_device)

        repository.record_audit(
            action="DEVICE_REGISTER",
            user_id=actor,
            details={"device_id": device_id, "name": new_device["name"], "ip": ip}
        )
        logger.info(f"[DeviceService] Registered new IoT device {device_id} ({ip})")
        return True, new_device, None

    def update_device(self, device_id: str, updates: Dict[str, Any], actor: str = "SecOps Analyst") -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Update mutable properties of an existing device."""
        target = None
        for d in self.network_manager.devices:
            if d.get("id") == device_id:
                target = d
                break

        if not target:
            return False, None, f"Device '{device_id}' not found"

        # Apply allowed updates
        mutable_fields = ["name", "type", "location", "firmware", "status", "quarantined", "tags"]
        applied = {}
        for k, v in updates.items():
            if k == "firmware_version":
                target["firmware"] = v
                applied["firmware"] = v
            elif k in mutable_fields and v is not None:
                target[k] = v
                applied[k] = v

        if "quarantined" in updates:
            self.set_quarantine(device_id, bool(updates["quarantined"]))

        repository.update_device(device_id, applied)
        repository.record_audit(
            action="DEVICE_UPDATE",
            user_id=actor,
            details={"device_id": device_id, "updates": applied}
        )
        return True, dict(target), None

    def delete_device(
        self,
        device_id: str,
        force: bool = False,
        actor: str = "SecOps Analyst"
    ) -> Tuple[bool, Optional[str], int]:
        """
        Delete a device from inventory with safety safeguards.
        Returns: (success, message, status_code)
        """
        target = self.get_device(device_id)
        if not target:
            return False, f"Device '{device_id}' not found", 404

        # Safeguards check
        if target.get("quarantined", False) and not force:
            return False, f"Device '{device_id}' is currently quarantined as a threat evidence asset. Deletion requires explicit override (?force=true).", 400

        alerts = self.get_device_alerts(device_id)
        unresolved_critical = [a for a in alerts if a.get("severity") == "Critical" and not a.get("resolved", False)]
        if unresolved_critical and not force:
            return False, f"Device '{device_id}' has {len(unresolved_critical)} active unresolved critical security alerts. Deletion requires explicit override (?force=true).", 400

        # Remove from network manager list
        self.network_manager.devices = [d for d in self.network_manager.devices if d.get("id") != device_id]
        repository.delete_device(device_id)

        repository.record_audit(
            action="DEVICE_DELETE",
            user_id=actor,
            details={"device_id": device_id, "force": force}
        )
        logger.info(f"[DeviceService] Device {device_id} deleted by {actor} (force={force})")
        return True, f"Device {device_id} successfully deleted from inventory.", 200

    def set_quarantine(self, device_id: str, quarantined: bool) -> bool:
        """Quarantine or release an IoT device."""
        success = self.network_manager.set_device_quarantine(device_id, quarantined)
        if success:
            repository.update_device_quarantine(device_id, quarantined)
            repository.record_audit(
                action="DEVICE_QUARANTINE" if quarantined else "DEVICE_UNQUARANTINE",
                user_id="secops_analyst",
                details={"device_id": device_id, "quarantined": quarantined}
            )
            logger.info(f"[DeviceService] Device {device_id} quarantine updated to {quarantined}")
        return success

    def get_risk_config(self) -> Dict[str, Any]:
        """Return risk engine weights and thresholds configuration."""
        return self.network_manager.risk_config

    def update_risk_config(self, new_config: Dict[str, Any]) -> Dict[str, Any]:
        """Update risk engine configuration and recalculate fleet risks."""
        if "weights" in new_config and isinstance(new_config["weights"], dict):
            self.network_manager.risk_config["weights"].update(new_config["weights"])
        if "thresholds" in new_config and isinstance(new_config["thresholds"], dict):
            self.network_manager.risk_config["thresholds"].update(new_config["thresholds"])
        if "strict_mode" in new_config:
            self.network_manager.risk_config["strict_mode"] = bool(new_config["strict_mode"])

        self.network_manager.risk_config["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

        for dev in self.network_manager.devices:
            self.network_manager.calculate_device_risk(dev)

        repository.record_audit(
            action="RISK_CONFIG_UPDATE",
            user_id="secops_analyst",
            details=self.network_manager.risk_config
        )
        return self.network_manager.risk_config
