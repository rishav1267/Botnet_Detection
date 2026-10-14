"""
Real-Time Event Broadcaster for NETGUARD Dashboard Clients
Provides Server-Sent Events (SSE) and Pub/Sub Event Dispatching.
Broadcasts:
- new traffic aggregates
- new detections
- risk classification changes
- new alerts
- incident status changes
"""

import time
import json
import queue
import threading
from typing import Dict, Any, List, Optional
from backend.utils.logger import logger


class EventBroadcaster:
    """Thread-safe Pub/Sub Hub for Server-Sent Events (SSE) streaming."""

    def __init__(self):
        self._lock = threading.Lock()
        self._subscribers: List[queue.Queue] = []
        self._event_sequence: int = 0
        self._recent_events_cache: List[Dict[str, Any]] = []
        self._max_cache: int = 50

    def subscribe(self, last_event_id: Optional[int] = None) -> queue.Queue:
        """Register a new client listener queue."""
        q = queue.Queue(maxsize=128)
        with self._lock:
            self._subscribers.append(q)
            logger.info(f"[SSE Broadcaster] Client connected. Active streams: {len(self._subscribers)}")

            # Replay recent events if Last-Event-ID provided for reconnection
            if last_event_id is not None:
                for ev in self._recent_events_cache:
                    if ev.get("id", 0) > last_event_id:
                        try:
                            q.put_nowait(ev)
                        except queue.Full:
                            break
        return q

    def unsubscribe(self, q: queue.Queue):
        """Unregister a client listener queue upon disconnection."""
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)
                logger.info(f"[SSE Broadcaster] Client disconnected. Active streams: {len(self._subscribers)}")

    def broadcast(self, event_type: str, data: Dict[str, Any]):
        """
        Broadcast an event to all connected dashboard clients.
        Supported event_types:
          - 'traffic_aggregate'
          - 'detection'
          - 'risk_change'
          - 'alert'
          - 'incident_status'
        """
        with self._lock:
            self._event_sequence += 1
            event_id = self._event_sequence
            payload = {
                "id": event_id,
                "event": event_type,
                "data": data,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            # Cache for reconnection replay
            self._recent_events_cache.append(payload)
            if len(self._recent_events_cache) > self._max_cache:
                self._recent_events_cache.pop(0)

            subscribers_snapshot = list(self._subscribers)

        # Distribute to queues outside lock
        for q in subscribers_snapshot:
            try:
                q.put_nowait(payload)
            except queue.Full:
                # Client is falling behind, drop stale items or unsubscribe
                try:
                    q.get_nowait()
                    q.put_nowait(payload)
                except Exception:
                    pass

    @property
    def active_client_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


# Global singleton broadcaster instance
broadcaster = EventBroadcaster()
