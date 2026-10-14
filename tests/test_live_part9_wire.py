"""
Live HTTP Test Script for Part 9 Over The Wire (port 8080)
"""

import urllib.request
import urllib.error
import json
import time

BASE_URL = "http://localhost:8080"
API_KEY = "netguard-sensor-key-2026"


def request(method, path, body=None, headers=None):
    headers = headers or {}
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    if body and "Content-Type" not in headers:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            content = resp.read().decode("utf-8")
            return resp.status, json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        try:
            return e.code, json.loads(content)
        except Exception:
            return e.code, {"raw": content}


def run_checks():
    print("==================================================")
    print(" LIVE WIRE VERIFICATION FOR PART 9 PIPELINE")
    print("==================================================")

    # 1. Health
    st, data = request("GET", "/api/health")
    assert st == 200, f"Health check failed: {st}"
    print(f"[*] Health Check: {st} OK (status={data.get('status')})")

    # 2. Collector Authentication: Unauthenticated vs Authenticated
    st, err = request("POST", "/api/traffic/events", body={"source_ip": "192.168.1.101", "destination_ip": "8.8.8.8", "destination_port": 53, "protocol": "UDP", "packet_count": 2, "byte_count": 128})
    assert st == 401, f"Expected 401 for unauthenticated event, got {st}"
    print(f"[*] Ingestion Auth Guard: {st} OK (UNAUTHORIZED)")

    # 3. Authenticated Ingestion
    import random
    fresh_port = random.randint(40000, 60000)
    fresh_time = time.time()
    st, res = request("POST", "/api/traffic/events", body={
        "source_ip": "192.168.1.101",
        "destination_ip": "198.51.100.77",
        "source_port": fresh_port,
        "destination_port": 23,
        "protocol": "TCP",
        "packet_count": 300,
        "byte_count": 24000,
        "duration_sec": 1.0,
        "direction": "outbound",
        "timestamp": fresh_time,
        "flow_statistics": {
            "syn_ratio": 0.92,
            "conn_freq": 24.0,
            "payload_entropy": 7.1
        },
        "device_id": "DEV-101",
        "collector_id": "sensor-rack-01"
    }, headers={"X-API-Key": API_KEY})
    assert st == 201, f"Expected 201 for valid event, got {st}"
    flow_id = res["data"]["event_id"]
    print(f"[*] Ingestion Authenticated Event: {st} Created (flow_id={flow_id}, verdict={res['data']['verdict']})")

    # 4. Duplicate Flow Event (Exact identical payload with same timestamp)
    st_dup, res_dup = request("POST", "/api/traffic/events", body={
        "source_ip": "192.168.1.101",
        "destination_ip": "198.51.100.77",
        "source_port": fresh_port,
        "destination_port": 23,
        "protocol": "TCP",
        "packet_count": 300,
        "byte_count": 24000,
        "duration_sec": 1.0,
        "direction": "outbound",
        "timestamp": fresh_time,
        "device_id": "DEV-101",
        "collector_id": "sensor-rack-01"
    }, headers={"X-API-Key": API_KEY})
    assert st_dup == 200, f"Expected 200 for duplicate, got {st_dup}"
    assert res_dup["data"]["status"] == "duplicate_ignored"
    print(f"[*] Ingestion Duplicate Idempotency: {st_dup} OK (status={res_dup['data']['status']})")

    # 5. Batch Ingestion
    st_batch, res_batch = request("POST", "/api/traffic/events/batch", body={
        "collector_id": "netflow-probe-01",
        "collector_type": "ipfix",
        "events": [
            {
                "source_ip": "192.168.1.102",
                "destination_ip": "192.168.1.1",
                "source_port": 49152,
                "destination_port": 80,
                "protocol": "TCP",
                "packet_count": 4,
                "byte_count": 350
            },
            {
                "source_ip": "192.168.1.104",
                "destination_ip": "192.168.1.1",
                "source_port": 49153,
                "destination_port": 443,
                "protocol": "TCP",
                "packet_count": 6,
                "byte_count": 820
            }
        ]
    }, headers={"X-API-Key": API_KEY})
    assert st_batch == 201, f"Expected 201 for batch, got {st_batch}"
    print(f"[*] Batch Ingestion: {st_batch} Created (processed={res_batch['data']['processed_count']})")

    # 6. Configurable Rules
    st_rules, res_rules = request("GET", "/api/detection/rules")
    assert st_rules == 200
    assert len(res_rules["data"]["rules"]) == 8
    print(f"[*] Configurable Detection Rules: {st_rules} OK (count={len(res_rules['data']['rules'])})")

    # Tune rule
    st_tune, res_tune = request("PATCH", "/api/detection/rules/R05_SUSPICIOUS_PORT_PATTERNS", body={
        "severity": "High-Risk",
        "suggested_investigation": "SOC Triage: Audit Telnet daemon status and apply firewall filter."
    })
    assert st_tune == 200
    print(f"[*] Detection Rule Tuned: {st_tune} OK (rule={res_tune['data']['rule']['rule_id']})")

    # 7. Demo Scenarios
    st_demo_list, res_demo_list = request("GET", "/api/demo/scenarios")
    assert st_demo_list == 200
    print(f"[*] Demo Scenarios List: {st_demo_list} OK (scenarios={len(res_demo_list['data']['scenarios'])})")

    # Execute normal_home
    st_demo_run1, res_demo_run1 = request("POST", "/api/demo/scenario", body={"scenario": "normal_home"})
    assert st_demo_run1 == 201
    assert res_demo_run1["data"]["ingestion_result"]["is_demo"] is True
    print(f"[*] Demo Scenario 'normal_home': {st_demo_run1} Created (is_demo={res_demo_run1['data']['ingestion_result']['is_demo']}, verdict={res_demo_run1['data']['ingestion_result']['verdict']})")

    # Execute repeated_connections
    st_demo_run2, res_demo_run2 = request("POST", "/api/demo/scenario", body={"scenario": "repeated_connections"})
    assert st_demo_run2 == 201
    assert res_demo_run2["data"]["ingestion_result"]["is_demo"] is True
    print(f"[*] Demo Scenario 'repeated_connections': {st_demo_run2} Created (verdict={res_demo_run2['data']['ingestion_result']['verdict']})")

    # 8. Query Events with Demo Filter
    st_ev_demo, res_ev_demo = request("GET", "/api/traffic/events?is_demo=true")
    assert st_ev_demo == 200
    for ev in res_ev_demo["data"]["events"]:
        assert ev.get("is_demo") is True
    print(f"[*] Traffic Events Filtered by is_demo=true: {st_ev_demo} OK (count={len(res_ev_demo['data']['events'])})")

    # 9. Verify Device Risk Assessment Update
    st_dev, res_dev = request("GET", "/api/devices/DEV-101")
    assert st_dev == 200
    dev = res_dev["data"]["device"]
    print(f"[*] Device DEV-101 Live State: {st_dev} OK (status={dev.get('status')}, risk_score={dev.get('risk_score')})")

    # 10. Verify Alerts Queue
    st_alt, res_alt = request("GET", "/api/alerts?limit=5")
    assert st_alt == 200
    alerts_list = res_alt.get("data", {}).get("alerts", res_alt.get("alerts", []))
    print(f"[*] Security Alerts Queue: {st_alt} OK (count={len(alerts_list)})")

    print("==================================================")
    print(" ALL LIVE OVER-THE-WIRE VERIFICATION CHECKS PASSED!")
    print("==================================================")


if __name__ == "__main__":
    run_checks()
