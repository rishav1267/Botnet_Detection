from iot_network_simulator import IoTNetworkManager
from backend.services.detection_service import detection_service
from backend.services.device_service import DeviceService
from backend.services.traffic_service import TrafficService
from backend.services.alert_service import AlertService
from backend.services.analytics_service import AnalyticsService
from backend.services.ml_service import MLService
from backend.services.auth_service import AuthService
from backend.services.event_broadcaster import broadcaster
from backend.services.baseline_service import baseline_service
from backend.services.rule_engine import configurable_rule_engine
from backend.services.ingestion_service import ingestion_service
from backend.services.demo_service import demo_service

# Initialize network manager bound to detection coordinator
network_manager = IoTNetworkManager(detection_service.coordinator)

# Instantiate singleton services
device_service = DeviceService(network_manager)
traffic_service = TrafficService(network_manager)
alert_service = AlertService(network_manager)
analytics_service = AnalyticsService(network_manager, detection_service.coordinator)
ml_service = MLService(detection_service.ml_engine)
auth_service = AuthService()

__all__ = [
    "network_manager",
    "detection_service",
    "device_service",
    "traffic_service",
    "alert_service",
    "analytics_service",
    "ml_service",
    "auth_service",
    "broadcaster",
    "baseline_service",
    "configurable_rule_engine",
    "ingestion_service",
    "demo_service",
]
