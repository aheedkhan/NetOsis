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
from cs.manifest import auth_mode, manifest_id, poll_forever, wait_ready
from cs.tinyhttp import json_body, wait_http, serve

DECISION_HOST = os.environ.get("CS_DECISION_HOST", "10.200.1.11")
DECISION_PORT = int(os.environ.get("CS_DECISION_PORT", "9000"))

BIND = os.environ.get("CS_BIND", "0.0.0.0")
HTTPS_PORT = int(os.environ.get("CS_HTTPS_PORT", "8443"))
DEST_IP = os.environ.get("CS_SELF_IP", "10.200.2.10")
LOGGER_HOST = os.environ.get("CS_LOGGER_HOST", "10.200.1.10")
LOGGER_PORT = int(os.environ.get("CS_LOGGER_PORT", "8088"))
PERSONA = os.environ.get("CS_HTTP_PERSONA", "NexusCorp Secure Access")

SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}

PAGE = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in · {html.escape(PERSONA)}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; background: #0b1220; color: #e8eef8; margin: 0; }}
    main {{ max-width: 28rem; margin: 4rem auto; padding: 2rem; border: 1px solid #24324a; border-radius: 12px; background: #111a2b; }}
    h1 {{ font-size: 1.25rem; margin: 0 0 0.5rem; }}
    p {{ color: #9fb0cc; font-size: 0.9rem; }}
    label {{ display: block; margin: 1rem 0 0.35rem; font-size: 0.85rem; }}
    input {{ width: 100%; box-sizing: border-box; padding: 0.6rem; border-radius: 6px; border: 1px solid #334155; background: #0b1220; color: #e8eef8; }}
    button {{ margin-top: 1.25rem; width: 100%; padding: 0.7rem; border: 0; border-radius: 6px; background: #2563eb; color: white; font-weight: 600; cursor: pointer; }}
    .badge {{ display: inline-block; margin-top: 1rem; font-size: 0.75rem; color: #86efac; }}
  </style>
</head>
<body>
  <main>
    <h1>{html.escape(PERSONA)}</h1>
    <p>TLS 1.3 required. Corporate SSO and MFA enforced for all sessions.</p>
    <form method="post" action="/login">
      <label>Username <input name="username" autocomplete="username" required></label>
      <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
      <button type="submit">Sign in securely</button>
    </form>
    <div class="badge">🔒 Connection encrypted end-to-end</div>
  </main>
</body>
</html>
"""


def emit_http(req: dict, action: str, user_name: str | None = None) -> None:
    peer = req.get("peer") or (None, None)
    local = req.get("local") or (None, None)
    src_ip = peer[0] if peer else None
    src_port = peer[1] if isinstance(peer, tuple) and len(peer) > 1 else None
    dest_port = local[1] if isinstance(local, tuple) and len(local) > 1 else HTTPS_PORT
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
        dest_service="https",
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
    headers = dict(SECURE_HEADERS)
    if method == "GET" and path == "/health":
        return 200, headers | {"Content-Type": "text/plain"}, b"ok\n"
    if method == "POST" and path in ("/login", "/admin/login", "/wp-login.php"):
        user = parse_login(req)
        web_auth = auth_mode("https") if auth_mode("https") != "closed" else auth_mode("http")
        if web_auth == "open" and user in ("guest", "admin"):
            emit_http(req, "http-auth-accepted", user_name=user)
            return (
                200,
                headers | {"Content-Type": "text/html; charset=utf-8"},
                b"<html><body><h1>Welcome</h1><p>Session active.</p></body></html>",
            )
        emit_http(req, "http-auth-rejected", user_name=user)
        return (
            401,
            headers | {"Content-Type": "text/plain", "WWW-Authenticate": 'Basic realm="NexusCorp"'},
            b"invalid credentials\n",
        )
    emit_http(req, "http-request")
    if path in ("/", "/login", "/admin", "/admin/", "/index.html"):
        return 200, headers | {"Content-Type": "text/html; charset=utf-8"}, PAGE.encode()
    return 404, headers | {"Content-Type": "text/plain"}, b"not found\n"


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
    await wait_ready(DECISION_HOST, DECISION_PORT)
    poll_task = asyncio.create_task(poll_forever(DECISION_HOST, DECISION_PORT))
    https = await serve(
        BIND, HTTPS_PORT, handler, name="https-surface", ssl=lab_ssl_context()
    )
    async with https:
        try:
            await https.serve_forever()
        finally:
            poll_task.cancel()


if __name__ == "__main__":
    asyncio.run(main())
