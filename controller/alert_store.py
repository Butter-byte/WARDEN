"""In-memory store for detector alerts and controller events (quarantine,
release, mobility). Pure Python so it can be unit-tested without Ryu."""

import collections
import threading
import time


class AlertStore:
    REQUIRED = ("detector", "mac", "message")

    def __init__(self, max_alerts=500, max_events=200):
        self._alerts = collections.deque(maxlen=max_alerts)
        self._events = collections.deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._seq = 0

    def add_alert(self, data, now=None):
        if not isinstance(data, dict):
            raise ValueError("alert must be a JSON object")
        for key in self.REQUIRED:
            if not data.get(key):
                raise ValueError("missing '%s'" % key)
        with self._lock:
            self._seq += 1
            alert = {
                "id": self._seq,
                "detector": str(data["detector"]),
                "severity": str(data.get("severity", "medium")),
                "mac": str(data["mac"]).lower(),
                "message": str(data["message"]),
                "action": str(data.get("action", "none")),
                "ts": float(data.get("ts") or (now if now is not None else time.time())),
                "received_at": now if now is not None else time.time(),
            }
            self._alerts.append(alert)
            return alert

    def list_alerts(self, limit=100):
        with self._lock:
            return list(self._alerts)[::-1][:max(1, int(limit))]

    def counts(self):
        with self._lock:
            out = {}
            for a in self._alerts:
                out[a["detector"]] = out.get(a["detector"], 0) + 1
            return out

    def clear_alerts(self):
        with self._lock:
            self._alerts.clear()

    def add_event(self, kind, text, mac=None, now=None):
        with self._lock:
            self._seq += 1
            event = {"id": self._seq, "kind": kind, "text": text, "mac": mac,
                     "ts": now if now is not None else time.time()}
            self._events.append(event)
            return event

    def list_events(self, limit=50):
        with self._lock:
            return list(self._events)[::-1][:max(1, int(limit))]
