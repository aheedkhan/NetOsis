#!/usr/bin/env python3
"""NetOsis controller + SOC dashboard server — runs on the SOC VM (192.168.40.31).

Two listeners, so the firewall can give each side only what it needs:
  :8001 ingest     the nodes (honeypots + agents) — /v1/* and /healthz, nothing else
  :8000 dashboard  the analyst (Jbox) — /api/* and the UI; /v1/* only from loopback
(NETOSIS_INGEST_PORT=0 serves everything on one port, for local runs.)

Node-facing (every write is authenticated, see controller/signing.py):
  POST /v1/ingest        batch of events / profile + graph snapshots / heartbeat
  POST /v1/agent         node-agent report (live CPU/mem/connections)
  POST /v1/pivot/wake    {"ctid": 104} -> make sure that honeypot CT is running
  POST /v1/sandbox/run   501 until the real sandbox exists (client falls back to its mock)

Analyst-facing (read-only):
  GET  /api/overview /api/actors /api/events /api/alerts /api/attack /api/graph /api/network
  GET  /api/stream       server-sent events: every new telemetry event, live
  GET  /                 the dashboard (built from soc/ into soc/dist)

Only CTIDs in ALLOWED_CTIDS can be power-controlled, so a compromised honeypot
still cannot ask the controller to touch the firewall, the Jbox, Kali or itself.
"""

from __future__ import annotations

import hmac
import json
import mimetypes
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from controller.proxmox import ProxmoxClient, ProxmoxError  # noqa: E402
from controller.signing import Verifier  # noqa: E402
from controller.soc import SocStore, parse_window  # noqa: E402

ALLOWED_CTIDS = {102, 104, 105}  # ent-web-01, finance-db-01, ops-app-01 — see topology.yml
DIST = ROOT / "soc" / "dist"
MAX_BODY = 2 * 1024 * 1024

STORE: SocStore | None = None


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip().strip("'\""))


def get_store() -> SocStore:
    global STORE
    if STORE is None:
        STORE = SocStore(Path(os.environ.get("NETOSIS_SOC_DIR", ROOT / "data" / "soc")))
    return STORE


def _wake_ctid(ctid: int, *, wait_timeout: float = 25.0) -> dict:
    if ctid not in ALLOWED_CTIDS:
        return {"ok": False, "error": f"ctid {ctid} not in allowlist"}
    try:
        px = ProxmoxClient.from_env()
    except ProxmoxError as exc:
        return {"ok": False, "error": str(exc)}
    try:
        status = px.ct_status(ctid)
        if status != "running":
            print(f"[*] ctid={ctid} status={status} -> starting")
            px.ct_start(ctid)
        deadline = time.monotonic() + wait_timeout
        while time.monotonic() < deadline:
            status = px.ct_status(ctid)
            if status == "running":
                # CT reports running almost instantly; give netosis-ssh a
                # moment to finish systemd start before the relay retries.
                time.sleep(3)
                return {"ok": True, "status": status}
            time.sleep(1)
        return {"ok": False, "error": f"timed out waiting for ctid {ctid} (last status={status})"}
    except ProxmoxError as exc:
        return {"ok": False, "error": str(exc)}


def _token_ok(presented: str) -> bool:
    expected = os.environ.get("NETOSIS_INGEST_TOKEN", "")
    if not expected:
        return os.environ.get("NETOSIS_INGEST_ALLOW_NO_TOKEN", "") == "1"
    return hmac.compare_digest(presented.encode(), expected.encode())


_VERIFIER: Verifier | None = None


def get_verifier() -> Verifier:
    """Built lazily from the environment (tests set it with monkeypatch)."""
    global _VERIFIER
    master = os.environ.get("NETOSIS_INGEST_TOKEN", "")
    nodes = {n.strip() for n in os.environ.get("NETOSIS_NODES", "").split(",") if n.strip()} or None
    if _VERIFIER is None or _VERIFIER.master != master or _VERIFIER.nodes != nodes:
        _VERIFIER = Verifier(master, nodes)
    return _VERIFIER


def _is_loopback(ip: str) -> bool:
    return ip in ("127.0.0.1", "::1") or ip.startswith("127.")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    surface = "all"  # "dashboard" | "ingest" | "all" (one port, local runs and tests)

    # ---- helpers -------------------------------------------------------------

    def _json(self, code: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _raw(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            return b""
        if length <= 0 or length > MAX_BODY:
            return b""
        return self.rfile.read(length)

    @staticmethod
    def _parse(raw: bytes) -> dict:
        try:
            data = json.loads(raw.decode()) if raw else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _auth(self, raw: bytes) -> tuple[bool, str | None]:
        """(allowed, node). A signed request names its node; the legacy shared
        token names none and, with NETOSIS_REQUIRE_SIGNED=1, only works from
        this machine (scripts/soc_demo.py, tests)."""
        node = get_verifier().verify(self.headers, "POST", urlparse(self.path).path, raw)
        if node:
            return True, node
        if _token_ok(self.headers.get("X-Netosis-Token", "")):
            if os.environ.get("NETOSIS_REQUIRE_SIGNED", "") == "1" and not _is_loopback(self.client_address[0]):
                return False, None
            return True, None
        return False, None

    def _static(self, path: str) -> None:
        if not DIST.is_dir():
            self._json(503, {"ok": False, "error": "dashboard not built — run scripts/soc-dashboard-setup.sh"})
            return
        rel = path.lstrip("/") or "index.html"
        target = (DIST / rel).resolve()
        if DIST.resolve() not in target.parents and target != DIST.resolve():
            self._json(404, {"ok": False, "error": "not found"})
            return
        if not target.is_file():
            if "." in Path(rel).name:  # a missing asset is a 404, not the app shell
                self._json(404, {"ok": False, "error": "not found"})
                return
            target = DIST / "index.html"  # single-page-app fallback
        data = target.read_bytes()
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text/") else ""))
        self.send_header("Content-Length", str(len(data)))
        immutable = "/assets/" in f"/{rel}"
        self.send_header("Cache-Control", "public, max-age=31536000, immutable" if immutable else "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _stream(self, after: int) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        store = get_store()
        try:
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            while True:
                fresh = store.wait_for_events(after, timeout=15)
                if not fresh:
                    self.wfile.write(b": ping\n\n")
                else:
                    for ev in fresh:
                        after = max(after, ev["seq"])
                        self.wfile.write(f"id: {ev['seq']}\nevent: ev\ndata: {json.dumps(ev)}\n\n".encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    # ---- routes --------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        url = urlparse(self.path)
        qs = parse_qs(url.query)
        store = get_store()
        one = lambda k, d=None: qs.get(k, [d])[0]  # noqa: E731
        window = parse_window(one("window"))
        try:
            limit = max(1, min(int(one("limit", "200")), 2000))
            after = int(one("after", "0"))
        except ValueError:
            self._json(400, {"ok": False, "error": "limit/after must be integers"})
            return
        routes = {
            "/api/overview": lambda: store.overview(window),
            "/api/actors": lambda: store.actors(window),
            "/api/sessions": lambda: store.sessions(window),
            "/api/alerts": lambda: store.alerts(limit, window),
            "/api/attack": lambda: store.attack(window),
            "/api/graph": lambda: store.graph(window),
            "/api/network": lambda: store.network(window),
            "/api/geo": lambda: store.geo(window),
            "/api/deception": lambda: store.deception(window),
            "/api/ai": lambda: store.ai(window),
            "/api/health": lambda: store.health(),
            "/api/agents": lambda: store.agents_table(),
            "/api/events": lambda: store.events_after(
                after, limit, actor=one("actor"), sensor=one("sensor"), window=window,
                q=one("q"), event_type=one("type"), session=one("session")),
        }
        if url.path == "/healthz":
            self._json(200, {"ok": True})
        elif self.surface == "ingest":
            self._json(404, {"ok": False, "error": "not found"})  # nodes never see the dashboard
        elif url.path in routes:
            self._json(200, routes[url.path]())
        elif url.path == "/api/stream":
            self._stream(int(qs.get("after", [str(store.seq)])[0]))
        elif url.path.startswith("/api/") or url.path.startswith("/v1/"):
            self._json(404, {"ok": False, "error": "not found"})
        else:
            self._static(url.path)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if self.surface == "dashboard" and not _is_loopback(self.client_address[0]):
            self._json(404, {"ok": False, "error": "not found"})  # nodes use the ingest port
            return
        if path == "/v1/sandbox/run":
            self._json(501, {"ok": False, "error": "sandbox not implemented yet — mock fallback expected"})
            return
        if path not in ("/v1/ingest", "/v1/agent", "/v1/pivot/wake"):
            self._json(404, {"ok": False, "error": "not found"})
            return
        raw = self._raw()
        allowed, node = self._auth(raw)
        ip = self.client_address[0]
        if not allowed:
            claimed = self.headers.get("X-Netosis-Node") or None
            self_test = _is_loopback(ip) and self.headers.get("X-Netosis-Probe") == "lab-verify"
            if not self_test:  # scripts/lab-verify.sh checks refusal from this machine; don't list it
                get_store().auth_rejected(ip, path, "bad, stale or replayed signature" if claimed else "no valid signature", claimed)
            self._json(401, {"ok": False, "error": "bad or missing signature"})
            return
        data = self._parse(raw)
        if not data.get("demo") and not (isinstance(data.get("agent"), dict) and data["agent"].get("demo")):
            get_store().auth_seen(node, path, ip)
        if path == "/v1/ingest":
            sensor = data.get("sensor") if isinstance(data.get("sensor"), dict) else {}
            if node and sensor.get("name") not in (None, node):
                get_store().auth_rejected(ip, path, f"posed as {str(sensor.get('name'))[:40]}", node)
                self._json(403, {"ok": False, "error": "a node may only report as itself"})
                return
            if node:
                data["sensor"] = {**sensor, "name": node}
            stored = get_store().ingest(data)
            self._json(200, {"ok": True, "stored": stored})
            return
        if path == "/v1/agent":
            agent = data.get("agent") if isinstance(data.get("agent"), dict) else {}
            if node and agent.get("name") != node:
                get_store().auth_rejected(ip, path, f"posed as {str(agent.get('name'))[:40]}", node)
                self._json(403, {"ok": False, "error": "a node may only report as itself"})
                return
            ok = get_store().agent_report(data)
            self._json(200 if ok else 400, {"ok": ok})
            return
        # /v1/pivot/wake powers on a CT: only authenticated nodes, only allowlisted CTIDs
        try:
            ctid = int(data.get("ctid"))
        except (TypeError, ValueError):
            self._json(400, {"ok": False, "error": "ctid required"})
            return
        print(f"[*] wake ctid={ctid} requested by {node or 'token'}")
        result = _wake_ctid(ctid)
        self._json(200 if result.get("ok") else 502, result)

    def log_message(self, fmt: str, *args) -> None:  # quieter, timestamped like the honeypot
        if self.path.startswith(("/api/stream", "/v1/ingest", "/v1/agent")):
            return  # one line per event would drown the log
        print(f"[*] {self.address_string()} {fmt % args}")


def _serve(bind: str, port: int, surface: str) -> ThreadingHTTPServer:
    handler = type(f"{surface.title()}Handler", (Handler,), {"surface": surface})
    server = ThreadingHTTPServer((bind, port), handler)
    server.daemon_threads = True  # long-lived SSE clients must not block shutdown
    return server


def main(argv: list[str] | None = None) -> int:
    _load_dotenv(ROOT / "controller" / ".env")
    port = int(os.environ.get("NETOSIS_CONTROLLER_PORT", "8000"))
    ingest_port = int(os.environ.get("NETOSIS_INGEST_PORT", "8001"))
    bind = os.environ.get("NETOSIS_CONTROLLER_BIND", "0.0.0.0")
    if not os.environ.get("NETOSIS_INGEST_TOKEN"):
        print("[!] NETOSIS_INGEST_TOKEN not set — /v1/* will refuse every node")
    if ingest_port and ingest_port != port:
        dashboard = _serve(bind, port, "dashboard")
        ingest = _serve(bind, ingest_port, "ingest")
        threading.Thread(target=ingest.serve_forever, name="ingest", daemon=True).start()
        print(f"[*] ingest    on {bind}:{ingest_port}  (nodes; ctids={sorted(ALLOWED_CTIDS)})")
    else:
        dashboard = _serve(bind, port, "all")
    signed = os.environ.get("NETOSIS_REQUIRE_SIGNED", "") == "1"
    print(f"[*] dashboard on {bind}:{port}  ({'built' if DIST.is_dir() else 'not built'}; "
          f"{'signed node requests required' if signed else 'shared token still accepted'})")
    try:
        dashboard.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down")
        get_store()._save_state(force=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
