"""
Backend Configuration & Environment Settings
Validates required environment variables and provides centralized configuration.
"""

import os
from pathlib import Path
from typing import Dict, Any


def load_dotenv(env_path: str = ".env"):
    """Lightweight .env loader without third-party dependencies."""
    p = Path(env_path)
    if not p.exists():
        return
    try:
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key not in os.environ:
                        os.environ[key] = val
    except Exception as e:
        print(f"[Config] Warning: Failed to parse {env_path}: {e}")


# Load local .env
load_dotenv()


class Settings:
    """Production application settings with validation."""

    def __init__(self):
        # Environment
        self.NODE_ENV: str = os.getenv("NODE_ENV", os.getenv("ENV", "development"))
        self.PORT: int = int(os.getenv("PORT", "8080"))
        self.HOST: str = os.getenv("HOST", "0.0.0.0")
        self.CORS_ORIGIN: str = os.getenv("CORS_ORIGIN", "*")

        # Database (MongoDB)
        self.MONGODB_URI: str = os.getenv(
            "MONGODB_URI", "mongodb://localhost:27017/iot_botnet_detection"
        )
        self.MONGODB_DB_NAME: str = os.getenv("MONGODB_DB_NAME", "iot_botnet_detection")
        self.MONGODB_TIMEOUT_MS: int = int(os.getenv("MONGODB_TIMEOUT_MS", "3000"))

        # Authentication & JWT
        self.JWT_SECRET: str = os.getenv("JWT_SECRET", "netguard_secops_super_secret_jwt_key_2026")
        self.JWT_EXPIRATION_HOURS: int = int(os.getenv("JWT_EXPIRATION_HOURS", "24"))
        self.JWT_ACCESS_EXPIRATION_MINUTES: int = int(os.getenv("JWT_ACCESS_EXPIRATION_MINUTES", "60"))
        self.JWT_REFRESH_EXPIRATION_DAYS: int = int(os.getenv("JWT_REFRESH_EXPIRATION_DAYS", "7"))

        # Seed User Passwords (configurable via environment)
        self.ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "netguard2026")
        self.ANALYST_PASSWORD: str = os.getenv("ANALYST_PASSWORD", "analyst2026")
        self.AUDITOR_PASSWORD: str = os.getenv("AUDITOR_PASSWORD", "auditor2026")

        # Security & DoS Protection
        self.MAX_REQUEST_SIZE_BYTES: int = int(os.getenv("MAX_REQUEST_SIZE_BYTES", str(5 * 1024 * 1024)))  # 5 MB
        self.MAX_BATCH_SIZE_BYTES: int = int(os.getenv("MAX_BATCH_SIZE_BYTES", str(15 * 1024 * 1024)))   # 15 MB
        self.RATE_LIMIT_ENABLED: bool = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
        self.RATE_LIMIT_WINDOW_SEC: int = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))
        self.RATE_LIMIT_MAX_REQUESTS: int = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "120"))
        self.AUTH_RATE_LIMIT_MAX: int = int(os.getenv("AUTH_RATE_LIMIT_MAX", "10"))
        self.COLLECTOR_RATE_LIMIT_MAX: int = int(os.getenv("COLLECTOR_RATE_LIMIT_MAX", "300"))
        self.DATA_RETENTION_DAYS: int = int(os.getenv("DATA_RETENTION_DAYS", "30"))
        self.MAX_PAGINATION_LIMIT: int = int(os.getenv("MAX_PAGINATION_LIMIT", "100"))

        # Machine Learning
        self.ML_ENGINE_ENABLED: bool = os.getenv("ML_ENGINE_ENABLED", "true").lower() == "true"
        self.ML_MODEL_PATH: str = os.getenv("ML_MODEL_PATH", "models/iot_rf_model.pkl")
        self.ML_METADATA_PATH: str = os.getenv("ML_METADATA_PATH", "models/model_metadata.json")
        self.ML_CONFIDENCE_THRESHOLD: float = float(os.getenv("ML_CONFIDENCE_THRESHOLD", "0.60"))

        # Traffic & Ingestion
        self.STREAM_CADENCE_MS: int = int(os.getenv("STREAM_CADENCE_MS", "1000"))
        self.MAX_FLOW_HISTORY: int = int(os.getenv("MAX_FLOW_HISTORY", "1000"))
        self.INGESTION_API_KEY: str = os.getenv("INGESTION_API_KEY", "netguard-sensor-key-2026")
        self.COLLECTOR_API_KEY: str = os.getenv("COLLECTOR_API_KEY", self.INGESTION_API_KEY)
        self.LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

        # Validate configuration
        self._validate()

    def _validate(self):
        """Validate critical configuration constraints."""
        errors = []
        if self.PORT < 1 or self.PORT > 65535:
            errors.append(f"Invalid PORT value: {self.PORT}. Must be between 1 and 65535.")
        if not self.JWT_SECRET:
            errors.append("JWT_SECRET must not be empty.")
        if not self.MONGODB_URI:
            errors.append("MONGODB_URI must not be empty.")

        if errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")

    def to_dict(self) -> Dict[str, Any]:
        """Export sanitized configuration dictionary (hiding secrets)."""
        return {
            "environment": self.NODE_ENV,
            "port": self.PORT,
            "host": self.HOST,
            "cors_origin": self.CORS_ORIGIN,
            "mongodb_uri": self.MONGODB_URI.split("@")[-1] if "@" in self.MONGODB_URI else "configured",
            "mongodb_db": self.MONGODB_DB_NAME,
            "ml_engine_enabled": self.ML_ENGINE_ENABLED,
            "stream_cadence_ms": self.STREAM_CADENCE_MS,
            "log_level": self.LOG_LEVEL,
        }


# Global singleton instance
settings = Settings()
