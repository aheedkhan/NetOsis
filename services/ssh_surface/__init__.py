"""Observe-only SSH surface. Version exchange, then close. Authentication is closed."""

from __future__ import annotations

import asyncio
import os
import uuid

from cs.events import new_event
from cs.ingest import emit_bg
from cs.tinyhttp import wait_http

BIND = os.environ.get("CS_BIND", "0.0.0.0")
PORT = int(os.environ.get("CS_PORT", "2222"))
BANNER = os.environ.get(
    "CS_SSH_BANNER", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"
)
DEST_IP = os.environ.get("CS_SELF_IP", "10.200.2.10")
LOGGER_HOST = os.environ.get("CS_LOGGER_HOST", "10.200.1.10")
LOGGER_PORT = int(os.environ.get("CS_LOGGER_PORT", "8088"))


async def handle(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    peer = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else None
    src_port = peer[1] if peer else None
    session_id = str(uuid.uuid4())
    client_version = None
    try:
        writer.write((BANNER + "\r\n").encode("ascii"))
        await writer.drain()
        raw = await asyncio.wait_for(reader.readline(), timeout=8)
        line = raw.decode("latin1", errors="replace").strip()
        if line.startswith("SSH-"):
            client_version = line[:255]
    except Exception:
        pass
    event = new_event(
        dataset="cybersnare.ssh.banner",
        action="ssh-banner-exchange",
        category=["network", "intrusion_detection"],
        capability="ssh",
        source_ip=src_ip,
        source_port=src_port,
        dest_ip=DEST_IP,
        dest_port=PORT,
        dest_service="ssh",
        session_id=session_id,
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        engage_activity="EAC0003",
        extra={
            "ssh": {
                "server_version": BANNER,
                "client_version": client_version,
                "auth": "closed",
            }
        },
    )
    emit_bg(event)
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


async def main() -> None:
    await wait_http(LOGGER_HOST, LOGGER_PORT, "/health")
    server = await asyncio.start_server(handle, BIND, PORT)
    print(f"ssh-surface listening on {BIND}:{PORT} auth=closed", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
