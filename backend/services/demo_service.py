"""
Demo Scenario Service — Reproducible IoT Botnet Demonstrations
Generates explicitly labeled demonstration events for:
1. Normal household IoT activity (benign baseline)
2. Repeated connection attempts (brute force sweep)
3. Unusually high traffic (volumetric flood)
4. Suspicious destination patterns (horizontal reconnaissance)
Ensures demo traffic is explicitly tagged and isolated from real collector telemetry.
"""

import random
import time
from typing import Dict, Any, List
from backend.services.ingestion_service import ingestion_service
from backend.database.repository import repository
from backend.utils.logger import logger


class DemoService:
    """Orchestrates reproducible demo scenarios with clear provenance labeling."""

    SCENARIOS = {
        "normal_home": {
            "name": "Normal Household IoT Activity",
            "description": "Benign local REST/MQTT telemetry from a smart lighting bridge. Low PPS, routine ports, zero alerts.",
            "expected_verdict": "Normal"
        },
        "repeated_connections": {
            "name": "Repeated Connection Attempts",
            "description": "Automated brute force dictionary attack targeting Telnet (port 23/2323) with high burst rate.",
            "expected_verdict": "High-Risk"
        },
        "unusually_high_traffic": {
            "name": "Unusually High Traffic Surge",
            "description": "Volumetric TCP SYN flood exceeding 500 pps, simulating an IoT camera enrolled in a botnet DDoS attack.",
            "expected_verdict": "High-Risk"
        },
        "suspicious_destinations": {
            "name": "Suspicious Destination Diversity",
            "description": "Horizontal network reconnaissance probing 25+ unique external IP endpoints in a short observation window.",
            "expected_verdict": "Suspicious"
        }
    }

    def list_scenarios(self) -> List[Dict[str, Any]]:
        """Return catalog of available reproducible demo scenarios."""
        return [
            {"id": k, **v} for k, v in self.SCENARIOS.items()
        ]

    def run_scenario(self, scenario_name: str, device_id: str = None) -> Dict[str, Any]:
        """
        Execute reproducible scenario through the ingestion pipeline.
        All generated records are tagged with is_demo=True and data_source='demo_scenario'.
        """
        sc_clean = scenario_name.lower().strip()
        all_devs = repository.get_all_devices()

        if sc_clean == "normal_home":
            target_dev = next((d for d in all_devs if d.get("id") == "DEV-102"), all_devs[0] if all_devs else None)
            dev_id = device_id or (target_dev["id"] if target_dev else "DEV-102")
            src_ip = target_dev.get("ip", "192.168.1.102") if target_dev else "192.168.1.102"
            event_payload = {
                "source_ip": src_ip,
                "destination_ip": "192.168.1.1",
                "source_port": random.randint(49152, 65535),
                "destination_port": 80,
                "protocol": "TCP",
                "packet_count": random.randint(2, 4),
                "byte_count": random.randint(180, 480),
                "duration_sec": 1.0,
                "direction": "internal",
                "flow_statistics": {
                    "syn_ratio": 0.05,
                    "rst_ratio": 0.0,
                    "payload_entropy": 3.8,
                    "failed_connections": 0,
                    "unique_dest_ips": 1,
                    "conn_freq": 1.0
                },
                "device_id": dev_id,
                "data_source": "demo_scenario",
                "is_demo": True,
                "collector_id": "demo-scenario-runner",
                "collector_type": "simulated_scenario"
            }

        elif sc_clean == "repeated_connections":
            target_dev = next((d for d in all_devs if d.get("id") == "DEV-101"), all_devs[0] if all_devs else None)
            dev_id = device_id or (target_dev["id"] if target_dev else "DEV-101")
            src_ip = target_dev.get("ip", "192.168.1.101") if target_dev else "192.168.1.101"
            event_payload = {
                "source_ip": src_ip,
                "destination_ip": f"{random.randint(11, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "source_port": random.randint(49152, 65535),
                "destination_port": random.choice([23, 2323, 22]),
                "protocol": "TCP",
                "packet_count": random.randint(180, 320),
                "byte_count": random.randint(12000, 24000),
                "duration_sec": 1.0,
                "direction": "outbound",
                "flow_statistics": {
                    "syn_ratio": 0.88,
                    "rst_ratio": 0.12,
                    "payload_entropy": 6.9,
                    "failed_connections": random.randint(8, 18),
                    "unique_dest_ips": random.randint(4, 9),
                    "conn_freq": 28.5
                },
                "device_id": dev_id,
                "data_source": "demo_scenario",
                "is_demo": True,
                "collector_id": "demo-scenario-runner",
                "collector_type": "simulated_scenario"
            }

        elif sc_clean == "unusually_high_traffic":
            target_dev = next((d for d in all_devs if d.get("id") == "DEV-107"), all_devs[0] if all_devs else None)
            dev_id = device_id or (target_dev["id"] if target_dev else "DEV-107")
            src_ip = target_dev.get("ip", "192.168.1.107") if target_dev else "192.168.1.107"
            event_payload = {
                "source_ip": src_ip,
                "destination_ip": f"{random.randint(11, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "source_port": random.randint(49152, 65535),
                "destination_port": random.choice([80, 443, 8080]),
                "protocol": "TCP",
                "packet_count": random.randint(580, 890),
                "byte_count": random.randint(160000, 280000),
                "duration_sec": 1.0,
                "direction": "outbound",
                "flow_statistics": {
                    "syn_ratio": 0.94,
                    "rst_ratio": 0.05,
                    "payload_entropy": 5.4,
                    "failed_connections": 12,
                    "unique_dest_ips": 3,
                    "conn_freq": 45.0
                },
                "device_id": dev_id,
                "data_source": "demo_scenario",
                "is_demo": True,
                "collector_id": "demo-scenario-runner",
                "collector_type": "simulated_scenario"
            }

        elif sc_clean == "suspicious_destinations":
            target_dev = next((d for d in all_devs if d.get("id") == "DEV-105"), all_devs[0] if all_devs else None)
            dev_id = device_id or (target_dev["id"] if target_dev else "DEV-105")
            src_ip = target_dev.get("ip", "192.168.1.105") if target_dev else "192.168.1.105"
            event_payload = {
                "source_ip": src_ip,
                "destination_ip": "198.51.100.22",
                "source_port": random.randint(49152, 65535),
                "destination_port": 80,
                "protocol": "TCP",
                "packet_count": random.randint(45, 90),
                "byte_count": random.randint(4500, 9500),
                "duration_sec": 1.0,
                "direction": "outbound",
                "flow_statistics": {
                    "syn_ratio": 0.40,
                    "rst_ratio": 0.15,
                    "payload_entropy": 6.2,
                    "failed_connections": 4,
                    "unique_dest_ips": 26,  # triggers R06
                    "conn_freq": 9.5
                },
                "device_id": dev_id,
                "data_source": "demo_scenario",
                "is_demo": True,
                "collector_id": "demo-scenario-runner",
                "collector_type": "simulated_scenario"
            }
        else:
            raise ValueError(f"Unknown scenario '{scenario_name}'. Available: {', '.join(self.SCENARIOS.keys())}")

        # Ingest through the real pipeline
        ingest_res = ingestion_service.process_traffic_event(
            event_payload,
            client_ip="127.0.0.1",
            collector_override="demo-scenario-runner"
        )

        logger.info(f"[DemoService] Executed scenario '{scenario_name}' on device {dev_id} -> Verdict: {ingest_res.get('verdict')}")
        return {
            "scenario": scenario_name,
            "scenario_metadata": self.SCENARIOS[sc_clean],
            "demo_badge": "DEMO SIMULATION DATA — NOT REAL COLLECTOR TRAFFIC",
            "ingestion_result": ingest_res
        }


# Global singleton demo service
demo_service = DemoService()
