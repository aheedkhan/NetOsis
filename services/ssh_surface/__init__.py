"""SSH surface: real KEX, authentication always refused."""

from __future__ import annotations

import asyncio
import os
import signal
import uuid

import asyncssh

from cs.events import new_event
from cs.ingest import emit_bg
from cs.tinyhttp import wait_http

BIND = os.environ.get("CS_BIND", "0.0.0.0")
PORT = int(os.environ.get("CS_PORT", "2222"))
BANNER = os.environ.get(
    "CS_SSH_BANNER", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"
)
SERVER_VERSION = BANNER.removeprefix("SSH-2.0-")
DEST_IP = os.environ.get("CS_SELF_IP", "10.200.2.10")
LOGGER_HOST = os.environ.get("CS_LOGGER_HOST", "10.200.1.10")
LOGGER_PORT = int(os.environ.get("CS_LOGGER_PORT", "8088"))


def _emit(
    src_ip: str | None,
    src_port: int | None,
    username: str | None,
    client_version: str | None,
    action: str,
) -> None:
    emit_bg(
        new_event(
            dataset="cybersnare.ssh.auth",
            action=action,
            category=["network", "authentication"],
            capability="ssh",
            source_ip=src_ip,
            source_port=src_port,
            dest_ip=DEST_IP,
            dest_port=PORT,
            dest_service="ssh",
            session_id=str(uuid.uuid4()),
            user_name=username,
            tactic_id="TA0001",
            tactic_name="Initial Access",
            technique_id="T1078",
            technique_name="Valid Accounts",
            engage_activity="EAC0003",
            extra={
                "ssh": {
                    "server_version": BANNER,
                    "client_version": client_version,
                    "auth": "closed",
                }
            },
        )
    )


class ClosedAuthServer(asyncssh.SSHServer):
    def __init__(self) -> None:
        self._peer: tuple | None = None
        self._client_version: str | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername")
        self._peer = peer if isinstance(peer, tuple) else None
        try:
            self._client_version = conn.get_extra_info("client_version")
        except Exception:
            self._client_version = None

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def kbdint_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        src_ip = self._peer[0] if self._peer else None
        src_port = self._peer[1] if self._peer else None
        _emit(src_ip, src_port, username, self._client_version, "ssh-auth-rejected")
        return False

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        src_ip = self._peer[0] if self._peer else None
        src_port = self._peer[1] if self._peer else None
        _emit(src_ip, src_port, username, self._client_version, "ssh-auth-rejected")
        return False


async def main() -> None:
    await wait_http(LOGGER_HOST, LOGGER_PORT, "/health")
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    await asyncssh.create_server(
        ClosedAuthServer,
        BIND,
        PORT,
        server_host_keys=[host_key],
        server_version=SERVER_VERSION,
    )
    print(f"ssh-surface listening on {BIND}:{PORT} kex=on auth=closed", flush=True)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()


if __name__ == "__main__":
    asyncio.run(main())
