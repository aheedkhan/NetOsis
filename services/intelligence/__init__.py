"""Intelligence plane HTTP service — timelines, profiles, milestone reports."""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import unquote

from cs.intelligence import (
    actor_attack_graph,
    actor_profile,
    attack_graph_overview,
    dashboard_bundle,
    deception_state,
    fetch_decision_activity,
    load_events,
    load_events_cached,
    milestone_report,
    siem_analytics,
    timeline,
)
from cs.tinyhttp import serve

LOG_PATH = Path(os.environ.get("CS_LOG_PATH", "/data/events.jsonl"))
DASHBOARD = Path(os.environ.get("CS_DASHBOARD_DIR", "/dashboard"))
DECISION_HOST = os.environ.get("CS_DECISION_HOST", "10.200.1.11")
DECISION_PORT = int(os.environ.get("CS_DECISION_PORT", "9000"))
EVENT_TAIL = int(os.environ.get("CS_EVENT_TAIL", "15000"))
BIND = os.environ.get("CS_BIND", "0.0.0.0")
PORT = int(os.environ.get("CS_PORT", "8090"))

_JSON = {"Content-Type": "application/json"}

_MIME: dict[str, str] = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".ico": "image/x-icon",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".pdf": "application/pdf",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
}


def _events() -> list:
    return load_events_cached(LOG_PATH, EVENT_TAIL)


def _json(data: object) -> tuple[int, dict[str, str], bytes]:
    return 200, _JSON, json.dumps(data, separators=(",", ":")).encode()


def _serve_static(path: str) -> tuple[int, dict[str, str], bytes] | None:
    """Serve built dashboard assets (JS/CSS) from DASHBOARD dir."""
    rel = path.lstrip("/")
    if not rel or ".." in rel.split("/"):
        return None
    root = DASHBOARD.resolve()
    target = (DASHBOARD / rel).resolve()
    if not str(target).startswith(str(root)) or not target.is_file():
        return None
    mime = _MIME.get(target.suffix.lower(), "application/octet-stream")
    return 200, {"Content-Type": mime}, target.read_bytes()


async def handler(req: dict) -> tuple[int, dict[str, str], bytes]:
    path, method = req["path"], req["method"]
    if method == "GET" and path == "/health":
        return _json({"ok": True})
    if method in ("GET", "HEAD") and path == "/":
        index = DASHBOARD / "index.html"
        if index.exists():
            body = index.read_bytes() if method == "GET" else b""
            return 200, {"Content-Type": "text/html; charset=utf-8"}, body
        body = b"CyberSnare intelligence plane\n" if method == "GET" else b""
        return 200, {"Content-Type": "text/plain"}, body
    if method in ("GET", "HEAD"):
        static = _serve_static(path)
        if static:
            status, headers, body = static
            return status, headers, body if method == "GET" else b""
    if method == "GET" and path == "/v1/dashboard":
        events = _events()
        activity = fetch_decision_activity(DECISION_HOST, DECISION_PORT)
        return _json(dashboard_bundle(events, activity))
    if method == "GET" and path == "/v1/report":
        return _json(milestone_report(_events()))
    if method == "GET" and path == "/v1/analytics":
        return _json(siem_analytics(_events()))
    if method == "GET" and path == "/v1/deception":
        events = _events()
        activity = fetch_decision_activity(DECISION_HOST, DECISION_PORT)
        return _json(deception_state(events, activity))
    if method == "GET" and path == "/v1/graph":
        return _json(attack_graph_overview(_events()))
    if method == "GET" and path == "/v1/graph/actor":
        actor_key = None
        if "key=" in req.get("query", ""):
            actor_key = unquote(req["query"].split("key=")[1].split("&")[0])
        if not actor_key:
            return 400, _JSON, json.dumps({"error": "key required"}).encode()
        return _json(actor_attack_graph(_events(), actor_key))
    if method == "GET" and path == "/v1/timeline":
        n = 100
        if "n=" in req.get("query", ""):
            try:
                n = int(req["query"].split("n=")[1].split("&")[0])
            except ValueError:
                pass
        actor = None
        if "actor=" in req.get("query", ""):
            actor = unquote(req["query"].split("actor=")[1].split("&")[0])
        events = _events()
        if actor:
            events = [e for e in events if (e.get("session") or {}).get("actor_key") == actor]
        return _json({"timeline": timeline(events, max_items=n)})
    if method == "GET" and path.startswith("/v1/profile/"):
        actor_key = unquote(path.removeprefix("/v1/profile/").strip("/"))
        return _json(actor_profile(_events(), actor_key))
    return 404, {"Content-Type": "text/plain"}, b"not found\n"


async def main() -> None:
    server = await serve(BIND, PORT, handler, name="intelligence")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
