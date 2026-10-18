from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from controller.app import ALLOWED_CTIDS, Handler, _wake_ctid
from controller.proxmox import ProxmoxClient, ProxmoxError
from http.server import ThreadingHTTPServer


def test_allowlist_blocks_non_honeypot_ctid(monkeypatch) -> None:
    # 100 is the Jbox — never a valid pivot target, even with valid creds.
    monkeypatch.setenv("PROXMOX_HOST", "127.0.0.1:1")
    monkeypatch.setenv("PROXMOX_TOKEN_ID", "x@pve!y")
    monkeypatch.setenv("PROXMOX_TOKEN_SECRET", "z")
    result = _wake_ctid(100)
    assert result["ok"] is False
    assert "allowlist" in result["error"]


def test_wake_without_credentials_fails_gracefully(monkeypatch) -> None:
    for key in ("PROXMOX_HOST", "PROXMOX_TOKEN_ID", "PROXMOX_TOKEN_SECRET"):
        monkeypatch.delenv(key, raising=False)
    result = _wake_ctid(next(iter(ALLOWED_CTIDS)))
    assert result["ok"] is False
    assert "PROXMOX_HOST" in result["error"] or "PROXMOX_TOKEN" in result["error"]


def test_proxmox_client_from_env_requires_all_three(monkeypatch) -> None:
    monkeypatch.delenv("PROXMOX_HOST", raising=False)
    monkeypatch.delenv("PROXMOX_TOKEN_ID", raising=False)
    monkeypatch.delenv("PROXMOX_TOKEN_SECRET", raising=False)
    with pytest.raises(ProxmoxError):
        ProxmoxClient.from_env()


TOKEN = "test-token"


@pytest.fixture
def running_server(monkeypatch):
    monkeypatch.setenv("NETOSIS_INGEST_TOKEN", TOKEN)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def test_healthz(running_server: str) -> None:
    with urllib.request.urlopen(f"{running_server}/healthz", timeout=5) as resp:
        assert json.loads(resp.read())["ok"] is True


def test_sandbox_not_implemented_yet(running_server: str) -> None:
    req = urllib.request.Request(f"{running_server}/v1/sandbox/run", data=b"{}", method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=5)
    assert exc_info.value.code == 501


def test_wake_rejects_disallowed_ctid_over_http(running_server: str, monkeypatch) -> None:
    req = urllib.request.Request(
        f"{running_server}/v1/pivot/wake",
        data=json.dumps({"ctid": 101}).encode(),  # 101 = OPNsense, never allowed
        method="POST",
        headers={"Content-Type": "application/json", "X-Netosis-Token": TOKEN},
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=5)
    assert exc_info.value.code == 502
    body = json.loads(exc_info.value.read())
    assert body["ok"] is False
    assert "allowlist" in body["error"]


def test_wake_missing_ctid_is_400(running_server: str) -> None:
    req = urllib.request.Request(
        f"{running_server}/v1/pivot/wake", data=b"{}", method="POST",
        headers={"Content-Type": "application/json", "X-Netosis-Token": TOKEN},
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=5)
    assert exc_info.value.code == 400


def test_wake_and_agent_require_the_lab_token(running_server: str) -> None:
    for path, body in (("/v1/pivot/wake", {"ctid": 104}), ("/v1/agent", {"agent": {"name": "x"}})):
        req = urllib.request.Request(f"{running_server}{path}", data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 401
