"""SSH surface: real KEX, auth per manifest (closed or L2 restricted shell)."""

from __future__ import annotations

import asyncio
import os
import signal
import uuid

import asyncssh

from cs import shell_llm
from cs.events import new_event
from cs.ingest import emit_bg
from cs.manifest import auth_mode, level as manifest_level, manifest_id, poll_forever, wait_ready
from cs.restricted_shell import CommandResult, FileTouch, RestrictedShell, load_users
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
        # One id for the whole session, not one per command — the previous
        # version generated a fresh uuid4() on every line, so no two commands
        # from the same login were ever correlated by session_id downstream
        # (the pattern matcher and timeline both group by it).
        self._session_id = str(uuid.uuid4())
        self._shell = RestrictedShell(level=manifest_level())
        # asyncssh's session callbacks (data_received, session_started) are
        # plain synchronous methods — see cs.shell_llm's module docstring for
        # why the LLM fallback cannot run inline on them. While a fallback
        # call is in flight, further typed lines queue in _buf rather than
        # being processed out of order; _drain_buffer() resumes them once the
        # pending task finishes and writes its own output.
        self._llm_busy = False
        self._exec_mode = False

    def connection_made(self, chan: asyncssh.SSHServerSessionChannel) -> None:
        self._chan = chan

    def eof_received(self) -> bool:
        # A non-interactive `ssh host cmd` client closes its stdin (sends
        # EOF) right after the exec request, well before any reply arrives.
        # asyncssh's default eof_received() returns False, which tears the
        # channel down immediately on that EOF — fatal for the LLM fallback,
        # whose reply is written from an asyncio task seconds later, long
        # after this callback fires. Returning True keeps the channel half
        # open (write-only) so that reply still has somewhere to land.
        return True

    def shell_requested(self) -> bool:
        return True

    def exec_requested(self, command: str) -> bool:
        self._exec_cmd = command
        self._exec_mode = True
        return True

    def pty_requested(
        self, term: str, size: tuple, modes: bytes
    ) -> bool:
        return True

    def session_started(self) -> None:
        if not self._chan:
            return
        if self._exec_mode:
            self._dispatch(self._exec_cmd.strip())
            return
        self._chan.write(f"\r\nWelcome {self._username}@intranet-web-01\r\n$ ")

    def data_received(self, data: str, datatype: asyncssh.DataType) -> None:
        if not self._chan:
            return
        self._buf += data.replace("\r", "")
        self._drain_buffer()

    def _drain_buffer(self) -> None:
        if self._llm_busy or not self._chan:
            return
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if self._dispatch(line):
                return  # logout, or an async fallback now owns the channel

    def _dispatch(self, line: str) -> bool:
        """Run one line. Returns True if the caller should stop draining
        _buf — either the session is ending, or an async LLM task now owns
        writing the response and will resume draining itself when it's done."""
        if not line.strip():
            if self._exec_mode:
                self._chan.exit(0)
            else:
                self._chan.write("$ ")
            return True
        # A live escalation mid-session (a decision-plane transition while
        # the attacker is already connected) has to open the deeper
        # filesystem immediately, the same way the manifest already reopens
        # other capabilities without requiring a fresh connection.
        self._shell.set_level(manifest_level())
        result = self._shell.handle_line(line)

        if result.needs_llm and shell_llm.ENABLED:
            self._llm_busy = True
            asyncio.create_task(self._run_llm_fallback(line, result))
            return True

        self._emit_command(line, result.touch, vm_check=result.vm_check)
        if result.logout:
            self._chan.write("\r\n")
            self._chan.exit(0)
            return True
        if self._exec_mode:
            if result.output:
                self._chan.write(result.output.replace("\n", "\r\n"))
            self._chan.exit(0)
            return True
        if result.output:
            self._chan.write(result.output.replace("\n", "\r\n"))
        self._chan.write("$ ")
        return False

    async def _run_llm_fallback(self, line: str, fallback: CommandResult) -> None:
        cwd = self._shell.cwd
        listing = self._shell.listing_names()
        text = await shell_llm.improvise(line, cwd, listing)
        self._llm_busy = False
        if not self._chan:
            return
        output = f"{text}\n" if text else fallback.output
        self._emit_command(line, None, vm_check=False, llm_generated=bool(text))
        if self._exec_mode:
            if output:
                self._chan.write(output.replace("\n", "\r\n"))
            self._chan.exit(0)
            return
        if output:
            self._chan.write(output.replace("\n", "\r\n"))
        self._chan.write("$ ")
        self._drain_buffer()

    def _emit_command(
        self,
        cmd: str,
        touch: FileTouch | None,
        *,
        vm_check: bool = False,
        llm_generated: bool = False,
    ) -> None:
        src_ip, src_port = self._peer
        dataset = "cybersnare.shell.command"
        technique_id, technique_name = "T1059", "Command and Scripting Interpreter"
        tactic_id, tactic_name = "TA0002", "Execution"
        engage_activity = "EAC0005"

        if vm_check:
            dataset = "cybersnare.shell.vm_check"
            technique_id, technique_name = "T1497", "Virtualization/Sandbox Evasion"
            tactic_id, tactic_name = "TA0005", "Defense Evasion"
        elif touch and touch.sensitivity == "honeytoken":
            # The single strongest piece of evidence this surface can produce:
            # the operator read the planted credentials file. Mapped to
            # Unsecured Credentials rather than generic execution so it shows
            # up distinctly in the ATT&CK breakdown, not folded into "ran a
            # command" like everything else.
            dataset = "cybersnare.shell.file_access"
            technique_id, technique_name = "T1552.001", "Unsecured Credentials: Credentials In Files"
            tactic_id, tactic_name = "TA0006", "Credential Access"
            engage_activity = "EAC0009"
        elif touch and touch.sensitivity == "sensitive":
            dataset = "cybersnare.shell.file_access"
            technique_id, technique_name = "T1083", "File and Directory Discovery"
            tactic_id, tactic_name = "TA0007", "Discovery"
        elif touch and touch.action == "list":
            dataset = "cybersnare.shell.file_access"
            technique_id, technique_name = "T1083", "File and Directory Discovery"
            tactic_id, tactic_name = "TA0007", "Discovery"
        elif touch and touch.action == "search":
            dataset = "cybersnare.shell.file_access"
            technique_id, technique_name = "T1083", "File and Directory Discovery"
            tactic_id, tactic_name = "TA0007", "Discovery"
        elif touch and touch.action == "read":
            dataset = "cybersnare.shell.file_access"
            technique_id, technique_name = "T1005", "Data from Local System"
            tactic_id, tactic_name = "TA0009", "Collection"

        shell_extra: dict = {"command": cmd, "manifest_id": manifest_id()}
        if touch:
            shell_extra["file_access"] = {
                "paths": touch.paths,
                "action": touch.action,
                "sensitivity": touch.sensitivity,
            }
        if llm_generated:
            # A command outside the scripted dispatch table is itself weak
            # evidence of a more capable operator — someone who only ever
            # runs whoami/ls/cat never exercises this path at all.
            shell_extra["llm_generated"] = True

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
                session_id=self._session_id,
                user_name=self._username,
                tactic_id=tactic_id,
                tactic_name=tactic_name,
                technique_id=technique_id,
                technique_name=technique_name,
                engage_activity=engage_activity,
                extra={"shell": shell_extra},
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
