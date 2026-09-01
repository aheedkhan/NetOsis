"""SSH surface: real KEX, auth per manifest (closed or L2 restricted shell)."""

from __future__ import annotations

import asyncio
import os
import signal
import uuid

import asyncssh

from cs.events import new_event
from cs.ingest import emit_bg
from cs.manifest import auth_mode, manifest_id, poll_forever, wait_ready
from cs.restricted_shell import handle_line, load_users
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
DECISION_HOST = os.environ.get("CS_DECISION_HOST", "10.200.1.11")
DECISION_PORT = int(os.environ.get("CS_DECISION_PORT", "9000"))

ALLOWED = load_users()


def _emit(
    src_ip: str | None,
    src_port: int | None,
    username: str | None,
    client_version: str | None,
    action: str,
    *,
    auth_state: str,
    extra: dict | None = None,
) -> None:
    payload = {
        "ssh": {
            "server_version": BANNER,
            "client_version": client_version,
            "auth": auth_state,
        }
    }
    if extra:
        payload.update(extra)
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
            engage_activity="EAC0005" if auth_state == "open" else "EAC0003",
            extra=payload,
        )
    )


class AdaptiveSSHServer(asyncssh.SSHServer):
    def __init__(self) -> None:
        self._peer: tuple | None = None
        self._client_version: str | None = None
        self._username: str | None = None
        self._authed = False

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername")
        self._peer = peer if isinstance(peer, tuple) else None
        try:
            self._client_version = conn.get_extra_info("client_version")
        except Exception:
            self._client_version = None

    def begin_auth(self, username: str) -> bool:
        self._username = username
        return True

    def password_auth_supported(self) -> bool:
        return True

    def kbdint_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def _src(self) -> tuple[str | None, int | None]:
        if not self._peer:
            return None, None
        return self._peer[0], self._peer[1]

    def validate_password(self, username: str, password: str) -> bool:
        src_ip, src_port = self._src()
        if auth_mode("ssh") != "open":
            _emit(
                src_ip,
                src_port,
                username,
                self._client_version,
                "ssh-auth-rejected",
                auth_state="closed",
            )
            return False
        if ALLOWED.get(username) != password:
            _emit(
                src_ip,
                src_port,
                username,
                self._client_version,
                "ssh-auth-rejected",
                auth_state="open",
            )
            return False
        _emit(
            src_ip,
            src_port,
            username,
            self._client_version,
            "ssh-auth-accepted",
            auth_state="open",
        )
        self._authed = True
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        src_ip, src_port = self._src()
        _emit(
            src_ip,
            src_port,
            username,
            self._client_version,
            "ssh-auth-rejected",
            auth_state=auth_mode("ssh"),
        )
        return False

    def session_requested(self) -> asyncssh.SSHServerSession | None:
        if auth_mode("ssh") != "open" or not self._authed:
            return None
        return RestrictedShellSession(self._username or "guest", self._src())


class RestrictedShellSession(asyncssh.SSHServerSession):
    def __init__(self, username: str, peer: tuple[str | None, int | None]) -> None:
        self._username = username
        self._peer = peer
        self._chan: asyncssh.SSHServerSessionChannel | None = None
        self._buf = ""
        self._exec_cmd = ""

    def connection_made(self, chan: asyncssh.SSHServerSessionChannel) -> None:
        self._chan = chan

    def shell_requested(self) -> bool:
        return True

    def exec_requested(self, command: str) -> bool:
        self._exec_cmd = command
        return True

    def pty_requested(
        self, term: str, size: tuple, modes: bytes
    ) -> bool:
        return True

    def session_started(self) -> None:
        if not self._chan:
            return
        if self._exec_cmd:
            result = handle_line(self._exec_cmd.strip(), emit=self._emit_command)
            if result and result != "logout\n":
                self._chan.write(result.replace("\n", "\r\n"))
            self._chan.exit(0)
            return
        self._chan.write(f"\r\nWelcome {self._username}@intranet-web-01\r\n$ ")

    def data_received(self, data: str, datatype: asyncssh.DataType) -> None:
        if not self._chan:
            return
        self._buf += data.replace("\r", "")
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            result = handle_line(line, emit=self._emit_command)
            if result == "logout\n":
                self._chan.write("\r\n")
                self._chan.exit(0)
                return
            if result:
                self._chan.write(result.replace("\n", "\r\n"))
            self._chan.write("$ ")

    def _emit_command(self, cmd: str) -> None:
        src_ip, src_port = self._peer
        dataset = "cybersnare.shell.command"
        lower = cmd.lower()
        if any(
            probe in lower
            for probe in ("/proc/", "dmesg", "systemd-detect-virt", "virt-what", "lscpu")
        ):
            dataset = "cybersnare.shell.vm_check"
        elif "passwd" in lower and "shadow" in lower:
            dataset = "cybersnare.shell.proc_read"
        emit_bg(
            new_event(
                dataset=dataset,
                action="shell-command",
                category=["process"],
                capability="shell",
                source_ip=src_ip,
                source_port=src_port,
                dest_ip=DEST_IP,
                dest_port=PORT,
                dest_service="ssh",
                session_id=str(uuid.uuid4()),
                user_name=self._username,
                tactic_id="TA0002",
                tactic_name="Execution",
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                engage_activity="EAC0005",
                extra={"shell": {"command": cmd, "manifest_id": manifest_id()}},
            )
        )


async def main() -> None:
    await wait_http(LOGGER_HOST, LOGGER_PORT, "/health")
    await wait_ready(DECISION_HOST, DECISION_PORT)
    poll_task = asyncio.create_task(poll_forever(DECISION_HOST, DECISION_PORT))

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(
        AdaptiveSSHServer,
        BIND,
        PORT,
        server_host_keys=[host_key],
        server_version=SERVER_VERSION,
    )
    print(
        f"ssh-surface listening on {BIND}:{PORT} kex=on auth=manifest-driven",
        flush=True,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    poll_task.cancel()
    server.close()
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
