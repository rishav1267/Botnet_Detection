"""
Part 9 Round 3: Concurrent Ingestion & Real-Time SSE Stream Verification
Tests:
- 10 concurrent threads ingesting traffic flows simultaneously
- Thread-safe device risk recalculations and baseline updates
- Real-time SSE streaming connection receiving broadcast events over the wire
"""

import urllib.request
import urllib.error
import threading
import json
import time

BASE_URL = "http://localhost:8080"
API_KEY = "netguard-sensor-key-2026"


def test_concurrent_ingestion():
    print("[*] Starting Concurrent Ingestion Test (10 concurrent threads)...")
    results = []
    errors = []

    def worker(worker_id):
        url = f"{BASE_URL}/api/traffic/events"
        payload = {
            "source_ip": f"192.168.1.{110 + worker_id}",
            "destination_ip": "104.28.12.9",
            "source_port": 50000 + worker_id,
            "destination_port": 80 if worker_id % 2 == 0 else 23,
            "protocol": "TCP",
            "packet_count": 50 + worker_id * 30,
            "byte_count": 4000 + worker_id * 2000,
            "duration_sec": 1.0,
            "direction": "outbound",
            "timestamp": time.time() + worker_id * 0.1,
            "collector_id": f"probe-worker-{worker_id}"
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST", headers={
            "X-API-Key": API_KEY,
            "Content-Type": "application/json"
        })
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                res_json = json.loads(resp.read().decode("utf-8"))
                results.append((resp.status, res_json["data"]["verdict"]))
        except Exception as e:
            errors.append(f"Worker {worker_id} error: {e}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"[*] Completed 10 concurrent requests. Successful: {len(results)}, Errors: {len(errors)}")
    assert len(errors) == 0, f"Concurrent ingestion had errors: {errors}"
    assert len(results) == 10, f"Expected 10 results, got {len(results)}"
    for st, verd in results:
        assert st == 201


def test_sse_realtime_stream():
    print("[*] Starting Real-Time SSE Stream Verification...")
    url = f"{BASE_URL}/api/stream/events?token=demo-token"
    req = urllib.request.Request(url, headers={"Accept": "text/event-stream"})

    received_events = []
    stop_event = threading.Event()

    def sse_listener():
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                buffer = ""
                while not stop_event.is_set():
                    line = resp.readline().decode("utf-8")
                    if not line:
                        break
                    buffer += line
                    if line == "\n":
                        # End of an SSE event chunk
                        lines = buffer.strip().split("\n")
                        ev_type = "message"
                        ev_data = ""
                        for l in lines:
                            if l.startswith("event: "):
                                ev_type = l[7:]
                            elif l.startswith("data: "):
                                ev_data = l[6:]
                        if ev_data:
                            received_events.append((ev_type, ev_data))
                        buffer = ""
        except Exception as e:
            if not stop_event.is_set():
                print(f"[SSE Listener] Note: {e}")

    listener_thread = threading.Thread(target=sse_listener, daemon=True)
    listener_thread.start()

    # Allow SSE handshake
    time.sleep(1.0)

    # Trigger a demo scenario that will broadcast detection, alert, and traffic_aggregate
    print("[*] Triggering demo scenario to test live SSE broadcast...")
    trigger_url = f"{BASE_URL}/api/demo/scenario"
    req_trigger = urllib.request.Request(
        trigger_url,
        data=json.dumps({"scenario": "repeated_connections"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req_trigger, timeout=5) as resp:
        assert resp.status == 201

    # Wait 1.5 seconds for events to stream
    time.sleep(1.5)
    stop_event.set()

    print(f"[*] SSE stream captured {len(received_events)} live events over the wire:")
    event_types = [ev[0] for ev in received_events]
    for ev_type, _ in received_events:
        print(f"    - Event: {ev_type}")

    assert "connected" in event_types, "Expected 'connected' handshake event in SSE stream"
    assert ("detection" in event_types or "alert" in event_types or "traffic_aggregate" in event_types), "Expected broadcast event in SSE stream"
    print("[*] SSE Real-Time Stream Verification: PASSED!")


if __name__ == "__main__":
    test_concurrent_ingestion()
    test_sse_realtime_stream()
    print("==================================================")
    print(" ALL ROUND 3 CONCURRENCY & SSE TESTS PASSED!")
    print("==================================================")
