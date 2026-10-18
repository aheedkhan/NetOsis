from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer

import pytest

from controller import app as controller_app
from controller.shipper import Shipper, ShippingTelemetryStore, shipping_enabled
from controller.soc import SocStore
from telemetry.schema.events import TelemetryEvent


def _event(cmd: str = "ls") -> TelemetryEvent:
    return TelemetryEvent(
        timestamp=datetime.now(timezone.utc).isoformat(), session_id="s1", actor_id="actor-9.9.9.9",
        source_ip="9.9.9.9", target_host="ent-web-01", target_ip="192.168.30.10",
        event_type="command", command=cmd, result="", technique="T1083",
    )


def _wait(cond, timeout: float = 6.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def live_controller(tmp_path, monkeypatch):
    monkeypatch.setenv("NETOSIS_INGEST_TOKEN", "tok123")
    controller_app.STORE = SocStore(tmp_path / "soc")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), controller_app.Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("NETOSIS_CONTROLLER_URL", f"http://127.0.0.1:{srv.server_address[1]}")
    yield controller_app.STORE
    srv.shutdown()
    controller_app.STORE = None


def test_events_arrive_authenticated_and_tagged_with_sensor(live_controller: SocStore, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NETOSIS_INGEST_TOKEN", "tok123")
    shipper = Shipper("ent-web-01", "192.168.30.10", ctid=102)
    store = ShippingTelemetryStore(tmp_path / "t.jsonl", shipper)

    store.append(_event("cat /etc/shadow"))

    assert _wait(lambda: any(e["command"] == "cat /etc/shadow" for e in live_controller.events))
    ev = next(e for e in live_controller.events if e["command"] == "cat /etc/shadow")
    assert ev["sensor"] == "ent-web-01"
    # the local file stays the source of truth
    assert "cat /etc/shadow" in (tmp_path / "t.jsonl").read_text()
    # heartbeat registers the sensor as online with its CTID
    assert _wait(lambda: live_controller.sensors.get("ent-web-01", {}).get("ctid") == 102)


def test_wrong_token_is_rejected_not_stored(live_controller: SocStore, monkeypatch, tmp_path) -> None:
    # Shipper and controller share this process's environment, so let the shipper
    # read its (wrong) token first, then put the controller's real token back.
    monkeypatch.setenv("NETOSIS_INGEST_TOKEN", "not-the-token")
    shipper = Shipper("evil-sensor", "10.0.0.1")
    monkeypatch.setenv("NETOSIS_INGEST_TOKEN", "tok123")
    shipper.event(_event("id").to_dict())
    time.sleep(1.5)
    assert len(live_controller.events) == 0
    assert "evil-sensor" not in live_controller.sensors


def test_dead_controller_never_blocks_or_raises(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("NETOSIS_CONTROLLER_URL", "http://127.0.0.1:9")  # nothing listens
    monkeypatch.setenv("NETOSIS_INGEST_TOKEN", "x")
    shipper = Shipper("ent-web-01", "192.168.30.10")
    store = ShippingTelemetryStore(tmp_path / "t.jsonl", shipper)

    start = time.perf_counter()
    for i in range(200):
        store.append(_event(f"cmd{i}"))
    shipper.state("actor-9.9.9.9", lambda: {"actor_id": "actor-9.9.9.9"}, lambda: {"nodes": [], "edges": []})
    elapsed = time.perf_counter() - start

    assert elapsed < 1.0  # 200 appends + a snapshot, with the controller down
    assert len((tmp_path / "t.jsonl").read_text().splitlines()) == 200


def test_snapshot_errors_do_not_reach_the_session(monkeypatch) -> None:
    monkeypatch.setenv("NETOSIS_CONTROLLER_URL", "http://127.0.0.1:9")
    shipper = Shipper("ent-web-01", "192.168.30.10")

    def boom():
        raise RuntimeError("profile exploded")

    shipper.state("actor-1", boom, boom)  # must not raise


def test_state_is_rate_limited_per_actor(monkeypatch) -> None:
    monkeypatch.setenv("NETOSIS_CONTROLLER_URL", "http://127.0.0.1:9")
    shipper = Shipper("ent-web-01", "192.168.30.10")
    calls = []
    for _ in range(5):
        shipper.state("actor-1", lambda: calls.append(1) or {"actor_id": "actor-1"})
    assert len(calls) == 1  # the other four were skipped before doing any work
    shipper.state("actor-1", lambda: calls.append(1) or {"actor_id": "actor-1"}, force=True)
    assert len(calls) == 2


def test_shipping_can_be_switched_off(monkeypatch) -> None:
    monkeypatch.setenv("NETOSIS_SHIP", "0")
    assert shipping_enabled() is False
    monkeypatch.setenv("NETOSIS_SHIP", "1")
    assert shipping_enabled() is True
