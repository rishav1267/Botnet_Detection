"""
Database Connection Manager for MongoDB with Graceful Fallback
Handles client lifecycle, connection pooling, and collection index creation.
"""

import time
from typing import Optional, Dict, Any
from backend.config.settings import settings
from backend.utils.logger import logger

try:
    import pymongo
    from pymongo import MongoClient, ASCENDING, DESCENDING
    from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False


class DatabaseManager:
    """Manages database connection and collections."""

    def __init__(self):
        self.client: Optional[Any] = None
        self.db: Optional[Any] = None
        self.is_connected: bool = False
        self.backend_type: str = "disconnected"
        self._collections: Dict[str, Any] = {}

    def connect(self) -> bool:
        """Attempt connection to MongoDB with timeout."""
        if not PYMONGO_AVAILABLE:
            logger.warning("[Database] pymongo is not installed. Using local embedded memory/sqlite store.")
            self.backend_type = "embedded"
            return False

        try:
            logger.info(f"[Database] Connecting to MongoDB at {settings.MONGODB_URI}...")
            self.client = MongoClient(
                settings.MONGODB_URI,
                serverSelectionTimeoutMS=settings.MONGODB_TIMEOUT_MS,
                connectTimeoutMS=settings.MONGODB_TIMEOUT_MS,
            )
            # Ping the admin database to verify connectivity
            self.client.admin.command("ping")
            self.db = self.client[settings.MONGODB_DB_NAME]
            self.is_connected = True
            self.backend_type = "mongodb"
            logger.info(f"[Database] Successfully connected to MongoDB database '{settings.MONGODB_DB_NAME}'")

            # Setup indexes
            self._ensure_indexes()
            return True
        except (ConnectionFailure, ServerSelectionTimeoutError, Exception) as e:
            logger.warning(
                f"[Database] MongoDB offline or unreachable ({e}). Operating in resilient embedded storage mode."
            )
            if self.client:
                try:
                    self.client.close()
                except Exception:
                    pass
                self.client = None
            self.is_connected = False
            self.backend_type = "embedded"
            return False

    def _ensure_indexes(self):
        """Create indexes on all collections for high-performance querying."""
        if not self.is_connected or self.db is None:
            return

        try:
            # 1. Devices Collection Indexes
            self.db.devices.create_index([("id", ASCENDING)], unique=True)
            self.db.devices.create_index([("status", ASCENDING)])
            self.db.devices.create_index([("quarantined", ASCENDING)])
            self.db.devices.create_index([("ip", ASCENDING)])

            # 2. Traffic Events Collection Indexes
            self.db.traffic_events.create_index([("flow_id", ASCENDING)], unique=True)
            self.db.traffic_events.create_index([("timestamp", DESCENDING)])
            self.db.traffic_events.create_index([("device_id", ASCENDING)])
            self.db.traffic_events.create_index([("status", ASCENDING)])
            self.db.traffic_events.create_index([("dest_port", ASCENDING)])

            # 3. Security Alerts Collection Indexes
            self.db.security_alerts.create_index([("id", ASCENDING)], unique=True)
            self.db.security_alerts.create_index([("timestamp", DESCENDING)])
            self.db.security_alerts.create_index([("severity", ASCENDING)])
            self.db.security_alerts.create_index([("status", ASCENDING)])
            self.db.security_alerts.create_index([("device_id", ASCENDING)])
            self.db.security_alerts.create_index([("resolved", ASCENDING)])

            # 4. Users Collection Indexes
            self.db.users.create_index([("username", ASCENDING)], unique=True)
            self.db.users.create_index([("email", ASCENDING)], unique=True)

            # 5. Incident History & Audit Logs
            self.db.audit_logs.create_index([("timestamp", DESCENDING)])
            self.db.audit_logs.create_index([("user_id", ASCENDING)])
            self.db.audit_logs.create_index([("action", ASCENDING)])

            # 6. Aggregated Stats
            self.db.traffic_stats.create_index([("timeframe", ASCENDING), ("timestamp", DESCENDING)])

            # 7. Model Metadata
            self.db.model_metadata.create_index([("version", ASCENDING)], unique=True)

            # 8. Detection Results
            self.db.detection_results.create_index([("detection_id", ASCENDING)], unique=True)
            self.db.detection_results.create_index([("timestamp", DESCENDING)])
            self.db.detection_results.create_index([("device_id", ASCENDING)])
            self.db.detection_results.create_index([("verdict", ASCENDING)])

            logger.info("[Database] All production MongoDB indexes verified and established.")
        except Exception as e:
            logger.error(f"[Database] Error creating collection indexes: {e}")

    def get_collection(self, name: str):
        """Get MongoDB collection handle if connected, otherwise None."""
        if self.is_connected and self.db is not None:
            return self.db[name]
        return None

    def get_health_status(self) -> Dict[str, Any]:
        """Return safe database health metrics without exposing secrets or credentials."""
        t0 = time.time()
        ping_latency = 0.0
        if self.is_connected and self.client:
            try:
                self.client.admin.command("ping")
                ping_latency = round((time.time() - t0) * 1000, 2)
            except Exception:
                ping_latency = 0.0
        return {
            "status": "connected" if self.is_connected else "fallback_embedded",
            "storage_mode": self.backend_type,
            "database_name": settings.MONGODB_DB_NAME,
            "ping_latency_ms": ping_latency,
        }

    def close(self):
        """Close connection."""
        if self.client:
            self.client.close()
            self.is_connected = False
            logger.info("[Database] Connection closed.")


db_manager = DatabaseManager()
