from __future__ import annotations

import importlib.util
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from controller import app
from controller.signing import H_NODE, H_SIG, H_TS, Verifier, auth_headers, node_key, sign

ROOT = Path(__file__).resolve().parents[2]
MASTER = "master-secret"


def _agent_module():
    spec = importlib.util.spec_from_file_location("netosis_agent", ROOT / "agent" / "netosis_agent.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _headers(node: str, path: str, body: bytes, *, key: str | None = None, ts: int | None = None) -> dict:
    t = str(ts if ts is not None else int(time.time()))
    return {H_NODE: node, H_TS: t, H_SIG: sign(key or node_key(MASTER, node), t, "POST", path, body)}


def test_agent_copy_of_sign_matches_controller() -> None:
    agent = _agent_module()
    assert agent.sign("k", "1700000000", "POST", "/v1/agent", b"{}") == sign("k", "1700000000", "POST", "/v1/agent", b"{}")


def test_verifier_accepts_good_and_rejects_bad() -> None:
    v = Verifier(MASTER)
    body = b'{"x": 1}'
    assert v.verify(_headers("ent-web-01", "/v1/ingest", body), "POST", "/v1/ingest", body) == "ent-web-01"
    # edited body, other path, stale clock, another node's key, master used as key
    assert v.verify(_headers("ent-web-01", "/v1/ingest", body), "POST", "/v1/ingest", b'{"x": 2}') is None
    assert v.verify(_headers("ent-web-01", "/v1/ingest", body), "POST", "/v1/pivot/wake", body) is None
    assert v.verify(_headers("ent-web-01", "/v1/ingest", body, ts=int(time.time()) - 600), "POST", "/v1/ingest", body) is None
    assert v.verify(_headers("ent-web-01", "/v1/ingest", body, key=node_key(MASTER, "finance-db-01")),
                    "POST", "/v1/ingest", body) is None
    assert v.verify({}, "POST", "/v1/ingest", body) is None


def test_verifier_blocks_replay_and_unknown_nodes() -> None:
    v = Verifier(MASTER, {"ent-web-01"})
    h = _headers("ent-web-01", "/v1/agent", b"{}")
    assert v.verify(h, "POST", "/v1/agent", b"{}") == "ent-web-01"
    assert v.verify(h, "POST", "/v1/agent", b"{}") is None  # same request again
    assert v.verify(_headers("kali", "/v1/agent", b"{}"), "POST", "/v1/agent", b"{}") is None


def test_auth_headers_never_carry_the_key(monkeypatch) -> None:
    key = node_key(MASTER, "ent-web-01")
    monkeypatch.setenv("NETOSIS_NODE_KEY", key)
    monkeypatch.setenv("NETOSIS_NODE_NAME", "ent-web-01")
    h = auth_headers("POST", "/v1/ingest", b"{}")
    assert key not in json.dumps(h) and MASTER not in json.dumps(h)
    assert "X-Netosis-Token" not in h


@pytest.fixture
def server(monkeypatch, tmp_path):
    monkeypatch.setenv("NETOSIS_INGEST_TOKEN", MASTER)
    monkeypatch.setenv("NETOSIS_SOC_DIR", str(tmp_path))
    monkeypatch.setattr(app, "STORE", None)
    started = []

    def start(surface: str = "all") -> str:
        srv = ThreadingHTTPServer(("127.0.0.1", 0), type("H", (app.Handler,), {"surface": surface}))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        started.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    yield start
    for srv in started:
        srv.shutdown()


def _post(url: str, path: str, payload: dict, headers: dict) -> int:
    body = json.dumps(payload).encode()
    hdrs = {"Content-Type": "application/json", **headers}
    if callable(headers.get(H_SIG)):
        hdrs = {"Content-Type": "application/json", **headers[H_SIG](body)}
    req = urllib.request.Request(url + path, data=body, method="POST", headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def _signed(node: str, path: str):
    return {H_SIG: lambda body: _headers(node, path, body)}


def test_signed_agent_report_and_identity_binding(server) -> None:
    url = server()
    report = {"agent": {"name": "ent-web-01", "role": "honeypot"}, "host": {}, "tcp": {}}
    assert _post(url, "/v1/agent", report, _signed("ent-web-01", "/v1/agent")) == 200
    # a valid node claiming to be another node is refused
    assert _post(url, "/v1/agent", report, _signed("ops-app-01", "/v1/agent")) == 403
    ingest = {"sensor": {"name": "finance-db-01"}, "events": []}
    assert _post(url, "/v1/ingest", ingest, _signed("ent-web-01", "/v1/ingest")) == 403
    assert _post(url, "/v1/agent", report, {}) == 401


def test_ingest_port_serves_no_dashboard(server) -> None:
    url = server("ingest")
    for path in ("/api/overview", "/api/events", "/", "/index.html"):
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(url + path, timeout=5)
        assert exc_info.value.code == 404
    with urllib.request.urlopen(url + "/healthz", timeout=5) as resp:
        assert resp.status == 200
