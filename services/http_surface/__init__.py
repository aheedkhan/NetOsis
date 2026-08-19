"""Observe-only HTTP/HTTPS surface. Fake portal. Login always fails. Auth is closed."""

from __future__ import annotations

import asyncio
import html
import os
import ssl
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

from cs.events import new_event
from cs.ingest import emit_bg
from cs.tinyhttp import json_body, wait_http, serve

BIND = os.environ.get("CS_BIND", "0.0.0.0")
PORT = int(os.environ.get("CS_PORT", "8080"))
HTTPS_PORT = int(os.environ.get("CS_HTTPS_PORT", "8443"))
DEST_IP = os.environ.get("CS_SELF_IP", "10.200.2.10")
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
    local = req.get("local") or (None, None)
    src_ip = peer[0] if peer else None
    src_port = peer[1] if isinstance(peer, tuple) and len(peer) > 1 else None
    dest_port = local[1] if isinstance(local, tuple) and len(local) > 1 else PORT
    tls = bool(req.get("tls"))
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
        dest_port=dest_port,
        dest_service="https" if tls else "http",
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
            },
            "tls": {"established": tls},
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


def lab_ssl_context() -> ssl.SSLContext:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "portal.nexuscorp.lab")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_path = "/tmp/cs-lab.crt"
    key_path = "/tmp/cs-lab.key"
    with open(cert_path, "wb") as fh:
        fh.write(cert_pem)
    with open(key_path, "wb") as fh:
        fh.write(key_pem)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


async def main() -> None:
    await wait_http(LOGGER_HOST, LOGGER_PORT, "/health")
    http = await serve(BIND, PORT, handler, name="http-surface")
    https = await serve(
        BIND, HTTPS_PORT, handler, name="https-surface", ssl=lab_ssl_context()
    )
    async with http, https:
        await asyncio.gather(http.serve_forever(), https.serve_forever())


if __name__ == "__main__":
    asyncio.run(main())
