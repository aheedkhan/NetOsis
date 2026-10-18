from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer

import pytest

from controller import app as controller_app
from controller.soc import SocStore
from deception.runtime.persona import classify


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ev(ip: str, host: str, etype: str, cmd: str = "", technique: str | None = None, **extra) -> dict:
    return {
        "timestamp": _ts(), "session_id": f"s-{ip}", "actor_id": f"actor-{ip}", "source_ip": ip,
        "target_host": host, "target_ip": "192.168.30.10", "event_type": etype, "command": cmd,
        "result": "", "technique": technique, "technique_name": None, "extra": extra,
    }


SENSOR = {"name": "ent-web-01", "ip": "192.168.30.10", "ctid": 102}


# --------------------------------------------------------------------------- persona


def test_persona_primary_is_most_serious() -> None:
    p = classify(["nmap 1.1.1.1", "cat /etc/shadow", "ssh dba@192.168.10.10"])
    assert p.id == "lateral_mover"
    assert {"lateral_mover", "credential_hunter", "scanner"} <= set(p.tags)


def test_persona_brute_forcer_never_got_a_shell() -> None:
    p = classify([], auth_failures=40)
    assert p.id == "brute_forcer"


def test_persona_feeds_the_llm_context() -> None:
    from deception.runtime.actor_profile import ActorProfile

    prof = ActorProfile(actor_id="actor-9.9.9.9", source_ip="9.9.9.9",
                        commands=["cat /etc/shadow", "history"])
    text = prof.to_rag_text(is_current=True)
    assert "CURRENT ATTACKER" in text
    assert "credential hunter" in text.lower()
    other = prof.to_rag_text(is_current=False)
    assert "OTHER attacker" in other


# --------------------------------------------------------------------------- store


@pytest.fixture
def store(tmp_path) -> SocStore:
    return SocStore(tmp_path)


def test_ingest_builds_actor_alerts_attack_and_graph(store: SocStore) -> None:
    ip = "203.0.113.7"
    events = [_ev(ip, "ent-web-01", "auth_failure", extra_user=1) for _ in range(4)]
    for e in events:
        e["extra"] = {"username": "root"}
    events += [
        _ev(ip, "ent-web-01", "auth_success", extra=None),
        _ev(ip, "ent-web-01", "command", "cat /etc/shadow", "T1003.008", risk_category="Credential_attack"),
        _ev(ip, "ent-web-01", "command", "cat Documents/VPN.txt", "T1005", risk_category="Canary_interaction"),
        _ev(ip, "finance-db-01", "lateral_movement", "ssh dba@192.168.10.10", "T1021.004",
            risk_category="Lateral_movement", from_host="ent-web-01"),
    ]
    profile = {"actor_id": f"actor-{ip}", "source_ip": ip, "commands": ["cat /etc/shadow", "ssh dba@192.168.10.10"],
               "categories": ["Credential_attack", "Lateral_movement"], "risk_score": 14.0, "level": "CRITICAL",
               "canary_hits": 1}
    assert store.ingest({"sensor": SENSOR, "events": events, "profiles": [profile],
                         "heartbeat": {"started": 1.0, "sessions": 1}}) == len(events)

    [actor] = store.actors()
    assert actor["ip"] == ip and actor["level"] == "CRITICAL"
    assert actor["persona"]["id"] == "lateral_mover"
    assert actor["auth_failures"] == 4 and actor["usernames"] == ["root"]
    assert set(actor["hosts"]) == {"ent-web-01", "finance-db-01"}

    kinds = {a["kind"] for a in store.alerts()}
    assert {"login-after-guessing", "canary", "credential", "lateral-movement"} <= kinds

    cols = {c["tactic"]: c["techniques"] for c in store.attack()["tactics"]}
    assert any(t["id"] == "T1003.008" for t in cols["Credential Access"])
    assert any(t["id"] == "T1021.004" for t in cols["Lateral Movement"])

    g = store.graph()
    ids = {n["id"] for n in g["nodes"]}
    assert f"actor:{ip}" in ids and "host:finance-db-01" in ids and "technique:T1003.008" in ids
    assert any(e["relation"] == "lateral" and e["source"] == "host:ent-web-01" for e in g["edges"])

    ov = store.overview()
    assert ov["kpis"]["sessions_live"] == 1 and ov["critical"] >= 2 and ov["sensors_online"] == 1
    assert ov["kpis"]["sources"] == 1 and ov["kpis"]["commands"] == 2
    assert set(ov["definitions"]) == set(ov["kpis"])  # every KPI shown carries its definition
    assert ov["mode"] == "live"

    net = {h["name"]: h for v in store.network()["vlans"] for h in v["hosts"]}
    assert net["ent-web-01"]["online"] is True
    assert net["finance-db-01"]["online"] is False  # no heartbeat -> powered off


def test_bruteforcer_without_shell_still_gets_an_actor(store: SocStore) -> None:
    for _ in range(12):
        e = _ev("198.51.100.9", "ent-web-01", "auth_failure")
        e["extra"] = {"username": "admin"}
        store.ingest({"sensor": SENSOR, "events": [e]})
    [actor] = store.actors()
    assert actor["persona"]["id"] == "brute_forcer"
    assert actor["level"] == "MEDIUM"


def test_restart_keeps_history(tmp_path) -> None:
    a = SocStore(tmp_path)
    a.ingest({"sensor": SENSOR, "events": [_ev("1.2.3.4", "ent-web-01", "command", "ls", "T1083")]})
    a._save_state(force=True)
    b = SocStore(tmp_path)
    assert b.seq == 1 and len(b.events) == 1
    assert b.events_after(0)[0]["command"] == "ls"


def test_garbage_events_are_ignored(store: SocStore) -> None:
    assert store.ingest({"sensor": SENSOR, "events": ["nope", {"no": "timestamp"}, 5]}) == 0


# --------------------------------------------------------------------------- HTTP


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("NETOSIS_INGEST_TOKEN", "s3cret")
    controller_app.STORE = SocStore(tmp_path)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), controller_app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    controller_app.STORE = None


def _post(url: str, body: dict, token: str | None) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-Netosis-Token"] = token
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_ingest_requires_token(server: str) -> None:
    body = {"sensor": SENSOR, "events": [_ev("1.1.1.1", "ent-web-01", "command", "ls", "T1083")]}
    assert _post(f"{server}/v1/ingest", body, None)[0] == 401
    assert _post(f"{server}/v1/ingest", body, "wrong")[0] == 401
    code, data = _post(f"{server}/v1/ingest", body, "s3cret")
    assert code == 200 and data["stored"] == 1


def test_api_roundtrip_and_spa(server: str) -> None:
    _post(f"{server}/v1/ingest", {"sensor": SENSOR, "events": [_ev("1.1.1.1", "ent-web-01", "command", "ls", "T1083")]}, "s3cret")
    with urllib.request.urlopen(f"{server}/api/events?after=0", timeout=5) as r:
        evs = json.loads(r.read())
    assert evs[0]["command"] == "ls" and evs[0]["sensor"] == "ent-web-01"
    with urllib.request.urlopen(f"{server}/api/actors", timeout=5) as r:
        assert json.loads(r.read())[0]["ip"] == "1.1.1.1"
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{server}/api/nope", timeout=5)
    assert exc.value.code == 404


def test_static_path_traversal_blocked(server: str) -> None:
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{server}/..%2f..%2fetc%2fpasswd", timeout=5)
    assert exc.value.code in {404, 503}


# --------------------------------------------------------------------------- grounding


def test_private_and_documentation_ips_are_never_geolocated(store: SocStore) -> None:
    store.ingest({"sensor": SENSOR, "events": [_ev("172.30.227.2", "ent-web-01", "command", "id", "T1033"),
                                               _ev("203.0.113.24", "ent-web-01", "command", "id", "T1033")]})
    g = store.geo()
    assert g["points"] == []  # Kali is internal; a documentation IP without demo flag has no fixture
    assert g["unmapped"]["internal"] == 1 and g["unmapped"]["reserved"] == 1


def test_demo_batches_are_labelled_and_get_fixture_locations(store: SocStore) -> None:
    store.ingest({"sensor": SENSOR, "demo": True,
                  "events": [_ev("203.0.113.24", "ent-web-01", "command", "id", "T1033")]})
    assert store.overview()["mode"] == "demo"
    [p] = store.geo()["points"]
    assert p["demo"] is True and p["source"] == "demo" and p["arc"] is True
    assert p["dest"]["source"] == "demo"  # demo arcs end at the demo site, never at a live one


def test_live_arcs_need_a_configured_site(store: SocStore, monkeypatch) -> None:
    import controller.geo as geomod
    monkeypatch.setattr(geomod, "locate", lambda ip, demo=False: {
        "ip": ip, "kind": "public", "mapped": True, "source": "test", "lat": 1.0, "lng": 2.0, "country": "X"})
    store.ingest({"sensor": SENSOR, "events": [_ev("8.8.8.8", "ent-web-01", "command", "id", "T1033")]})
    monkeypatch.delenv("NETOSIS_SITE_LAT", raising=False)
    assert store.geo()["points"][0]["arc"] is False
    monkeypatch.setenv("NETOSIS_SITE_LAT", "10"); monkeypatch.setenv("NETOSIS_SITE_LNG", "20")
    assert store.geo()["points"][0]["arc"] is True


def test_window_applies_to_every_view(store: SocStore) -> None:
    old = _ev("1.1.1.1", "ent-web-01", "command", "ls", "T1083")
    old["timestamp"] = "2020-01-01T00:00:00+00:00"
    store.ingest({"sensor": SENSOR, "events": [old, _ev("2.2.2.2", "ent-web-01", "command", "id", "T1033")]})
    assert store.overview(3600)["kpis"]["sources"] == 1
    assert [a["ip"] for a in store.actors(3600)] == ["2.2.2.2"]
    assert len(store.sessions(3600)) == 1
    assert store.attack(3600)["total_events"] == 1
    assert store.overview(None)["kpis"]["sources"] == 2


def test_previous_window_trend_is_real_or_absent(store: SocStore) -> None:
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    store.ingest({"sensor": SENSOR, "events": [_ev("2.2.2.2", "ent-web-01", "command", "id", "T1033")]})
    # no history before this hour: no comparison is offered, rather than a made-up one
    assert store.overview(3600)["previous"] is None
    prev = _ev("1.1.1.1", "ent-web-01", "command", "ls", "T1083")
    prev["timestamp"] = (now - timedelta(minutes=90)).isoformat()
    oldest = _ev("3.3.3.3", "ent-web-01", "command", "w", "T1033")
    oldest["timestamp"] = (now - timedelta(hours=3)).isoformat()
    store.ingest({"sensor": SENSOR, "events": [prev, oldest]})
    ov = store.overview(3600)
    assert ov["previous"]["sources"] == 1 and ov["previous"]["commands"] == 1
    assert ov["kpis"]["sources"] == 1
    assert store.overview(None)["previous"] is None


def test_deception_events_feed_ladder_and_sessions(store: SocStore) -> None:
    ev = _ev("9.9.9.9", "ent-web-01", "deception_action", "cat notes.txt")
    ev["extra"] = {"action": "D01", "name": "expose_fake_host", "reason": "score 3 >= D01 threshold 3"}
    store.ingest({"sensor": SENSOR, "events": [ev]})
    d = store.deception()
    if d.get("policy_error") is None:
        assert next(s for s in d["ladder"] if s["id"] == "D01")["fired"] == 1
    assert d["history"][0]["extra"]["action"] == "D01"
    assert store.sessions()[0]["deception"] == ["D01"]
    assert store.overview()["kpis"]["deception"] == 1


def test_pipeline_ships_a_deception_event_when_a_rung_fires(tmp_path) -> None:
    import uuid
    from pathlib import Path as P
    from attack_graph.model.graph import AttackGraph
    from deception.runtime.host import Session, VirtualHost
    from deception.runtime.pipeline import VerticalSlicePipeline
    from deception.runtime.profile_store import ProfileStore
    from telemetry.storage.jsonl import JsonlTelemetryStore

    root = P(__file__).resolve().parents[2]
    tstore = JsonlTelemetryStore(tmp_path / "t.jsonl")
    s = Session(host=VirtualHost.load(root / "deception/hosts/enterprise-web.yml"), session_id=str(uuid.uuid4()))
    p = VerticalSlicePipeline(session=s, store=tstore, graph=AttackGraph(),
                              second_host_path=root / "deception/hosts/finance-db.yml",
                              profile_store=ProfileStore(tmp_path / "profiles"))
    for line in ("whoami", "pwd", "ls", "cat notes.txt"):
        p.run_command(line)
    fired = [e for e in tstore.read_all() if e["event_type"] == "deception_action"]
    assert fired and fired[0]["extra"]["action"] == "D01"
    assert len(p.events) == 4  # the deception event does not feed back into the risk score


def _agent(name: str, ip: str, flows: list[dict], role: str = "honeypot") -> dict:
    return {"agent": {"name": name, "role": role, "version": "1"},
            "host": {"addresses": [ip], "cpu_pct": 12.5, "mem": {"total": 100, "used": 40}},
            "services": {"netosis-ssh": "active"}, "tcp": {"listening": [2222], "flows": flows}}


def test_agents_build_the_live_topology(store: SocStore) -> None:
    # Kali comes in through the firewall; ent-web-01 relays to finance-db-01; both report it
    assert store.agent_report(_agent("ent-web-01", "192.168.30.10", [
        {"dir": "in", "peer": "172.30.227.2", "port": 2222, "count": 1},
        {"dir": "out", "peer": "192.168.10.10", "port": 2222, "count": 1},
        {"dir": "out", "peer": "192.168.40.31", "port": 8000, "count": 1},
    ]))
    assert store.agent_report(_agent("finance-db-01", "192.168.10.10", [
        {"dir": "in", "peer": "192.168.30.10", "port": 2222, "count": 1},
    ]))
    net = store.network()
    kinds = {(f["from"], f["to"]): f["kind"] for f in net["live_flows"]}
    assert kinds[("outside", "ent-web-01")] == "attack"
    assert kinds[("ent-web-01", "finance-db-01")] == "pivot"
    assert kinds[("ent-web-01", "controller")] == "telemetry"
    assert len([f for f in net["live_flows"] if f["kind"] == "pivot"]) == 1  # reported twice, counted once
    web = next(h for v in net["vlans"] for h in v["hosts"] if h["name"] == "ent-web-01")
    assert web["online"] and web["agent"]["cpu_pct"] == 12.5 and web["agent"]["connections_in"] == 1
    assert net["agents"] == {"online": 2, "total": 2}


def test_agent_report_rejects_garbage(store: SocStore) -> None:
    assert store.agent_report({}) is False
    assert store.agent_report({"agent": "x"}) is False
    assert store.agent_report({"agent": {"name": "n"}, "tcp": {"flows": ["bad", {"dir": "sideways"}]}}) is True
    assert store.agents_table()[0]["flows"] == []
