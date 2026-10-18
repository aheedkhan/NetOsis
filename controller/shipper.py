"""Honeypot -> controller telemetry shipping (runs on each honeypot CT).

Design rules, in order of importance:
  1. Never block or crash an attacker's session. Everything is queued and sent
     from a background thread; on any failure the batch is dropped (the same
     events are already in the local telemetry.jsonl, so nothing is lost).
  2. Stdlib only (urllib), same as the LLM client.
  3. Authenticated with a shared token so only honeypots can write to the SOC.

Env:
  NETOSIS_CONTROLLER_URL   http://192.168.40.31:8000
  NETOSIS_INGEST_TOKEN     shared secret (same value in controller/.env)
  NETOSIS_SENSOR_NAME      defaults to the host YAML hostname
  NETOSIS_SHIP=0           turn shipping off
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from telemetry.schema.events import TelemetryEvent
from telemetry.storage.jsonl import JsonlTelemetryStore


def shipping_enabled() -> bool:
    return os.environ.get("NETOSIS_SHIP", "1").strip().lower() not in {"0", "false", "no", "off"}


class Shipper:
    def __init__(self, sensor: str, sensor_ip: str, *, ctid: int | None = None, demo: bool = False) -> None:
        self.sensor = sensor
        self.demo = demo
        self.sensor_ip = sensor_ip
        self.ctid = ctid
        self.url = os.environ.get("NETOSIS_CONTROLLER_URL", "http://192.168.40.31:8000").rstrip("/") + "/v1/ingest"
        self.token = os.environ.get("NETOSIS_INGEST_TOKEN", "")
        self._q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=4000)
        self._started = time.time()
        self._sessions = 0
        self._lock = threading.Lock()
        self._last_err = 0.0
        self._last_state: dict[str, float] = {}
        threading.Thread(target=self._run, name="netosis-shipper", daemon=True).start()
        threading.Thread(target=self._heartbeat, name="netosis-heartbeat", daemon=True).start()

    # ---- producers (called from session threads; must be instant) --------------

    def event(self, event: dict[str, Any]) -> None:
        self._put({"kind": "event", "data": event})

    def state(self, actor_id: str, profile_fn, graph_fn=None, *, force: bool = False) -> None:
        """Latest profile + graph snapshot; at most one per actor per second.

        Takes callables so the (copying) snapshot work is skipped when the
        rate limit says no. Never raises into the session thread.
        """
        now = time.monotonic()
        with self._lock:
            if not force and now - self._last_state.get(actor_id, 0.0) < 1.0:
                return
            self._last_state[actor_id] = now
        try:
            profile = profile_fn()
            graph = graph_fn() if graph_fn else None
        except Exception as exc:  # snapshotting must not break a live shell
            print(f"  [ship-error] snapshot: {exc!r}")
            return
        self._put({"kind": "state", "actor_id": actor_id, "profile": profile, "graph": graph})

    def session_opened(self) -> None:
        with self._lock:
            self._sessions += 1

    def session_closed(self) -> None:
        with self._lock:
            self._sessions = max(0, self._sessions - 1)

    def _put(self, item: dict[str, Any]) -> None:
        try:
            self._q.put_nowait(item)
        except queue.Full:
            pass  # local jsonl still has it

    # ---- background ------------------------------------------------------------

    def _post(self, body: dict[str, Any]) -> bool:
        body["sensor"] = {"name": self.sensor, "ip": self.sensor_ip, "ctid": self.ctid}
        if self.demo:
            body["demo"] = True  # scripts/soc_demo.py: the SOC labels these "Demo data"
        req = urllib.request.Request(
            self.url,
            data=json.dumps(body).encode(),
            method="POST",
            headers={"Content-Type": "application/json", "X-Netosis-Token": self.token},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, OSError, ValueError) as exc:
            now = time.monotonic()
            if now - self._last_err > 60:  # one line a minute, not one per event
                self._last_err = now
                print(f"  [ship-error] {self.url}: {exc}")
            return False

    def _run(self) -> None:
        while True:
            first = self._q.get()
            batch = [first]
            deadline = time.monotonic() + 0.4  # coalesce bursts
            while len(batch) < 100 and time.monotonic() < deadline:
                try:
                    batch.append(self._q.get(timeout=0.1))
                except queue.Empty:
                    break
            events = [b["data"] for b in batch if b["kind"] == "event"]
            states = {}
            for b in batch:
                if b["kind"] == "state":
                    states[b["actor_id"]] = b  # newest wins
            body: dict[str, Any] = {"events": events}
            if states:
                body["profiles"] = [s["profile"] for s in states.values()]
                graphs = [s["graph"] for s in states.values() if s["graph"]]
                if graphs:
                    body["graph"] = graphs[-1]
            self._post(body)

    def _heartbeat(self) -> None:
        while True:
            with self._lock:
                sessions = self._sessions
            self._post({"heartbeat": {"started": self._started, "sessions": sessions}})
            time.sleep(20)


_SHIPPER: Shipper | None = None
_SHIPPER_LOCK = threading.Lock()


def get_shipper(sensor: str, sensor_ip: str, ctid: int | None = None) -> Shipper | None:
    """One shipper per process (None when shipping is turned off)."""
    global _SHIPPER
    if not shipping_enabled():
        return None
    with _SHIPPER_LOCK:
        if _SHIPPER is None:
            _SHIPPER = Shipper(sensor, sensor_ip, ctid=ctid)
        return _SHIPPER


class ShippingTelemetryStore(JsonlTelemetryStore):
    """Writes locally (source of truth) and ships a copy to the controller."""

    def __init__(self, path: str | Path, shipper: Shipper | None) -> None:
        super().__init__(path)
        self.shipper = shipper

    def append(self, event: TelemetryEvent) -> None:
        super().append(event)
        if self.shipper is not None:
            self.shipper.event(event.to_dict())
