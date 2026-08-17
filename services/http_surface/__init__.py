"""Observe-only HTTP surface. Fake portal. Login always fails. Auth is closed."""

from __future__ import annotations

import asyncio
import html
import os
import uuid
from urllib.parse import parse_qs

from cs.events import new_event
from cs.ingest import emit_bg
from cs.tinyhttp import json_body, wait_http, serve

BIND = os.environ.get("CS_BIND", "0.0.0.0")
PORT = int(os.environ.get("CS_PORT", "8080"))
DEST_IP = os.environ.get("CS_SELF_IP", "10.200.2.11")
LOGGER_HOST = os.environ.get("CS_LOGGER_HOST", "10.200.1.10")
LOGGER_PORT = int(os.environ.get("CS_LOGGER_PORT", "8088"))
PERSONA = os.environ.get("CS_HTTP_PERSONA", "NexusCorp Employee Portal")

PAGE = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Sign in · {html.escape(PERSONA)}</title></head>
<body>
  <h1>{html.escape(PERSONA)}</h1>
  <p>Sign in with your corporate account.</p>
  <form method="post" action="/login">
    <label>Username <input name="username" autocomplete="username"></label>
    <label>Password <input name="password" type="password"></label>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>
"""


def emit_http(req: dict, action: str, user_name: str | None = None) -> None:
    peer = req.get("peer") or (None, None)
    src_ip = peer[0] if peer else None
    src_port = peer[1] if isinstance(peer, tuple) and len(peer) > 1 else None
    headers = req.get("headers") or {}
    ua = headers.get("user-agent")
    event = new_event(
        dataset="cybersnare.http.request",
        action=action,
        category=["web", "authentication"] if user_name else ["web"],
        capability="http",
        source_ip=src_ip,
        source_port=src_port,
        dest_ip=DEST_IP,
        dest_port=PORT,
        dest_service="http",
        session_id=str(uuid.uuid4()),
        user_name=user_name,
        ua_signature=ua,
        tactic_id="TA0001" if user_name else "TA0043",
        tactic_name="Initial Access" if user_name else "Reconnaissance",
        technique_id="T1078" if user_name else "T1595",
        technique_name="Valid Accounts" if user_name else "Active Scanning",
        engage_activity="EAC0003",
        extra={
            "http": {
                "request": {
                    "method": req.get("method"),
                    "path": req.get("path"),
                    "header_order": req.get("header_order"),
                }
            }
        },
    )
    emit_bg(event)


def parse_login(req: dict) -> str | None:
    ctype = (req.get("headers") or {}).get("content-type", "")
    if "application/json" in ctype:
        try:
            payload = json_body(req) or {}
            return payload.get("username") or payload.get("user")
        except Exception:
            return None
    try:
        form = parse_qs(req.get("body", b"").decode("utf-8", errors="replace"))
        vals = form.get("username") or form.get("user") or []
        return vals[0] if vals else None
    except Exception:
        return None


async def handler(req: dict) -> tuple[int, dict[str, str], bytes]:
    path, method = req["path"], req["method"]
    if method == "GET" and path == "/health":
        return 200, {"Content-Type": "text/plain"}, b"ok\n"
    if method == "POST" and path in ("/login", "/admin/login", "/wp-login.php"):
        user = parse_login(req)
        emit_http(req, "http-auth-rejected", user_name=user)
        return (
            401,
            {"Content-Type": "text/plain", "WWW-Authenticate": 'Basic realm="NexusCorp"'},
            b"invalid credentials\n",
        )
    emit_http(req, "http-request")
    if path in ("/", "/login", "/admin", "/admin/", "/index.html"):
        return 200, {"Content-Type": "text/html; charset=utf-8"}, PAGE.encode()
    return 404, {"Content-Type": "text/plain"}, b"not found\n"


async def main() -> None:
    await wait_http(LOGGER_HOST, LOGGER_PORT, "/health")
    server = await serve(BIND, PORT, handler, name="http-surface")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
