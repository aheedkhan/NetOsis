#!/usr/bin/env python3
"""Public SSH honeypot front-door for the NetOsis fake shell.

Accepts a weak decoy password (default admin / admin123) so login looks
like a real misconfigured host — not "any password works." Drops the peer
into VerticalSlicePipeline (deterministic cmds + RAG/Qwen fallback).
Telemetry + attack graph persist under --data-dir.

Example:
  NETOSIS_LLM_MODE=qwen NETOSIS_LLM_MODEL=qwen2.5:3b \\
    python scripts/ssh_honeypot.py --port 2222 --bind 0.0.0.0
"""

from __future__ import annotations

import argparse
import hashlib
import os
import select
import socket
import sys
import threading
import uuid
from pathlib import Path

import paramiko

# Ensure repo root is importable when run as a script
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from attack_graph.model.graph import AttackGraph
from controller.client import wake_ctid
from controller.shipper import ShippingTelemetryStore, get_shipper
from deception.runtime.host import Session, VirtualHost
from deception.runtime.pipeline import VerticalSlicePipeline
from telemetry.schema.events import TelemetryEvent, utc_now_iso
from telemetry.storage.jsonl import JsonlTelemetryStore


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip("'").strip('"')
        # Force NetOsis LLM/RAG settings from .env so a stale shell env cannot pin mock.
        if key.startswith("NETOSIS_"):
            os.environ[key] = val
        else:
            os.environ.setdefault(key, val)


class HoneypotInterface(paramiko.ServerInterface):
    def __init__(
        self,
        peer_ip: str = "0.0.0.0",
        store: JsonlTelemetryStore | None = None,
        target_host: str = "",
        target_ip: str = "",
    ) -> None:
        super().__init__()
        self.username = "admin"
        self.peer_ip = peer_ip
        self.store = store
        self.target_host = target_host
        self.target_ip = target_ip
        self.connection_id = str(uuid.uuid4())
        self.exec_command: str | None = None
        self.request_event = threading.Event()

    def _log_auth(self, username: str, success: bool) -> None:
        # Login attempts are the bulk of real Internet traffic — record them.
        if self.store is None:
            return
        self.store.append(
            TelemetryEvent(
                timestamp=utc_now_iso(),
                session_id=self.connection_id,
                actor_id=f"actor-{self.peer_ip}",
                source_ip=self.peer_ip,
                target_host=self.target_host,
                target_ip=self.target_ip,
                event_type="auth_success" if success else "auth_failure",
                command="",
                result="",
                technique="T1078" if success else "T1110",
                technique_name="Valid Accounts" if success else "Brute Force",
                technique_confidence=0.6 if success else 0.5,
                behavior="ssh_login",
                extra={"username": username[:64]},
            )
        )

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        # Weak decoy creds only — rejects random guesses so scanners don't
        # flag "accepts any password." Password value is never logged.
        expect_user = os.environ.get("NETOSIS_SSH_USER", "admin")
        expect_pass = os.environ.get("NETOSIS_SSH_PASSWORD", "admin123")
        if (username or "") == expect_user and password == expect_pass:
            self.username = username
            self._log_auth(username, True)
            return paramiko.AUTH_SUCCESSFUL
        self._log_auth(username or "", False)
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self.request_event.set()
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        # Bots mostly use `ssh host 'cmd'` instead of an interactive shell.
        self.exec_command = command.decode("utf-8", errors="ignore").strip()
        self.request_event.set()
        return True


def _run_safely(pipeline: VerticalSlicePipeline, cmd: str, peer_ip: str):
    """Run one command; any internal error looks like a normal shell failure."""
    try:
        result, event, decision = pipeline.run_command(cmd)
    except Exception as exc:
        print(f"  [error] {peer_ip} cmd={cmd!r}: {exc!r}")
        name = cmd.split(" ", 1)[0]
        return f"bash: {name}: command not found\n", 127, None
    out = (result.stdout or "") + (result.stderr or "")
    tag = "llm" if getattr(result, "llm_fallback", False) else "det"
    print(
        f"  [{tag}] {peer_ip} cmd={cmd!r} action={decision.action} "
        f"tech={event.technique} score={decision.risk_score}"
    )
    return out, result.exit_code, getattr(result, "pivot_target", None)


def _ctid_for(ip: str) -> int | None:
    """This sensor's Proxmox CTID, from the shared topology (None if unknown)."""
    try:
        from deception.network.theater import load_topology

        host = load_topology().hosts.get(ip)
        return host.ctid if host else None
    except Exception:
        return None


def _read_line(channel, prompt_text: str, *, echo: bool = True) -> str | None:
    """One line of raw input over the channel; None on disconnect/Ctrl-C."""
    channel.send(prompt_text)
    buf = ""
    while True:
        try:
            raw = channel.recv(1)
        except OSError:
            return None
        if not raw:
            return None
        char = raw.decode("utf-8", errors="ignore")
        if char in ("\r", "\n"):
            channel.send("\r\n")
            return buf
        if char == "\x03":
            channel.send("^C\r\n")
            return None
        if char in {"\x7f", "\b"}:
            if buf:
                buf = buf[:-1]
                if echo:
                    channel.send("\b \b")
            continue
        if ord(char) >= 32:
            buf += char
            if echo:
                channel.send(char)


def _pump(local_channel, remote_channel) -> None:
    """Bidirectional raw byte relay once the real second-hop session is up."""
    while True:
        try:
            r, _w, _x = select.select([local_channel, remote_channel], [], [], 1.0)
        except OSError:
            return
        if local_channel in r:
            try:
                data = local_channel.recv(4096)
            except OSError:
                return
            if not data:
                return
            remote_channel.send(data)
        if remote_channel in r:
            try:
                data = remote_channel.recv(4096)
            except OSError:
                return
            if not data:
                return
            local_channel.send(data)


def _log_lateral_movement(
    pipeline: VerticalSlicePipeline,
    graph: AttackGraph,
    graph_lock: threading.Lock,
    graph_path: Path,
    peer_ip: str,
    target_hostname: str,
    target_ip: str,
    user: str,
) -> None:
    session = pipeline.session
    event = TelemetryEvent(
        timestamp=utc_now_iso(),
        session_id=session.session_id,
        actor_id=session.actor_id,
        source_ip=peer_ip,
        target_host=target_hostname,
        target_ip=target_ip,
        event_type="lateral_movement",
        command=f"ssh {user}@{target_ip}",
        result="",
        technique="T1021.004",
        technique_name="Remote Services: SSH",
        technique_confidence=0.9,
        behavior="ssh_pivot",
        extra={"risk_category": "Lateral_movement", "from_host": session.host.hostname},
    )
    pipeline.store.append(event)
    with graph_lock:
        actor = f"actor:{session.actor_id}"
        host_node = f"host:{target_hostname}"
        graph.add_node(host_node, type="HOST", ip=target_ip, hostname=target_hostname, visible=True)
        graph.add_edge(actor, host_node, "lateral_movement", via="ssh_pivot")
        graph.save(graph_path)


def _handle_pivot(
    channel,
    pivot: dict,
    peer_ip: str,
    pipeline: VerticalSlicePipeline,
    graph: AttackGraph,
    graph_lock: threading.Lock,
    graph_path: Path,
) -> None:
    """Real second-hop relay: attacker's bytes go to an actual SSH client
    dialed out to the other honeypot's real sensor — that sensor's own
    check_auth_password() decides success/failure, same as real lateral
    movement. If the target CT is powered off (saving power), wake it via
    the controller first and retry before giving up."""
    ip = pivot["ip"]
    port = int(pivot.get("port", 2222))
    hostname = pivot.get("hostname", ip)
    ctid = pivot.get("ctid")
    user = pivot.get("requested_user") or pipeline.session.user

    def _tcp_up() -> bool:
        try:
            with socket.create_connection((ip, port), timeout=1.5):
                return True
        except OSError:
            return False

    if not _tcp_up():
        if not ctid:
            channel.send(f"ssh: connect to host {ip} port 22: No route to host\r\n")
            return
        print(f"  [pivot] {peer_ip} -> {hostname} ({ip}) ctid={ctid} offline — waking")
        woke = wake_ctid(ctid)
        if not woke or not _tcp_up():
            channel.send(f"ssh: connect to host {ip} port 22: Connection timed out\r\n")
            return

    fingerprint = hashlib.sha256(f"{hostname}{ip}".encode()).hexdigest()[:47]
    answer = _read_line(
        channel,
        f"The authenticity of host '{hostname} ({ip})' can't be established.\r\n"
        f"ED25519 key fingerprint is SHA256:{fingerprint}.\r\n"
        "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
    )
    if answer is None or answer.strip().lower() not in {"yes", "y"}:
        channel.send("Host key verification failed.\r\n")
        return

    client: paramiko.SSHClient | None = None
    for _attempt in range(3):
        password = _read_line(channel, f"{user}@{ip}'s password: ", echo=False)
        if password is None:
            return
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                ip, port=port, username=user, password=password,
                timeout=10, banner_timeout=10, auth_timeout=10,
                look_for_keys=False, allow_agent=False,
            )
            break
        except paramiko.AuthenticationException:
            channel.send("Permission denied, please try again.\r\n")
            client = None
            continue
        except (paramiko.SSHException, OSError) as exc:
            print(f"  [pivot-error] {peer_ip} -> {hostname}: {exc!r}")
            channel.send(f"ssh: connect to host {ip} port {port}: Connection refused\r\n")
            return
    if client is None:
        channel.send(f"{user}@{ip}: Permission denied (publickey,password).\r\n")
        return

    print(f"  [pivot] {peer_ip} -> {hostname} ({ip}) as {user!r} — relaying")
    _log_lateral_movement(pipeline, graph, graph_lock, graph_path, peer_ip, hostname, ip, user)
    try:
        remote = client.invoke_shell(term="xterm")
        _pump(channel, remote)
    finally:
        client.close()


def handle_connection(
    client_sock: socket.socket,
    host_key: paramiko.PKey,
    data_dir: Path,
    host_yaml: Path,
    second_host: Path,
    graph: AttackGraph,
    graph_lock: threading.Lock,
) -> None:
    try:
        peer_ip = client_sock.getpeername()[0]
    except OSError:
        peer_ip = "0.0.0.0"

    graph_path = data_dir / "attack_graph.json"
    vhost = VirtualHost.load(host_yaml)
    shipper = get_shipper(vhost.hostname, vhost.ip, _ctid_for(vhost.ip))
    store = ShippingTelemetryStore(data_dir / "telemetry.jsonl", shipper)

    transport = paramiko.Transport(client_sock)
    # Believable OpenSSH banner for nmap -sV / banner grab (not LLM).
    transport.local_version = os.environ.get(
        "NETOSIS_SSH_BANNER",
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
    )
    transport.add_server_key(host_key)
    server = HoneypotInterface(
        peer_ip=peer_ip, store=store, target_host=vhost.hostname, target_ip=vhost.ip
    )

    try:
        transport.start_server(server=server)
    except (paramiko.SSHException, EOFError, OSError):
        client_sock.close()
        return

    channel = transport.accept(20)
    if channel is None:
        transport.close()
        return
    server.request_event.wait(10)

    session = Session(
        host=vhost,
        session_id=server.connection_id,
        actor_id=f"actor-{peer_ip}",
        source_ip=peer_ip,
        user=server.username,
    )
    pipeline = VerticalSlicePipeline(
        session=session,
        store=store,
        graph=graph,
        second_host_path=second_host,
    )

    def prompt() -> str:
        return session.shell_prompt()

    def save_graph() -> None:
        with graph_lock:
            graph.save(graph_path)
        if shipper is not None:
            shipper.state(
                session.actor_id,
                lambda: pipeline.profile.summary(),
                lambda: graph.to_dict(),
            )

    if shipper is not None:
        shipper.session_opened()

    if server.exec_command is not None:
        try:
            out, code, pivot = _run_safely(pipeline, server.exec_command, peer_ip)
            if pivot:
                # Non-interactive `ssh host 'cmd'` pivoting needs a password
                # prompt over a channel bots using this form never read from —
                # match real OpenSSH's behavior with no interactive tty.
                out = "Pseudo-terminal will not be allocated because stdin is not a terminal.\n"
                code = 255
            if out:
                channel.sendall(out)
            channel.send_exit_status(code)
            save_graph()
        except OSError:
            pass
        finally:
            if shipper is not None:
                shipper.session_closed()
            channel.close()
            transport.close()
        return

    try:
        channel.send(f"Welcome to {vhost.os}\r\n")
        channel.send(prompt())
        buf = ""
        escape = ""
        while True:
            try:
                raw = channel.recv(1)
            except OSError:
                break
            if not raw:
                break
            try:
                char = raw.decode("utf-8", errors="ignore")
            except Exception:
                continue

            # Swallow ANSI escape sequences (arrow keys etc.) instead of
            # appending "[A" to the command buffer.
            if escape:
                escape += char
                if len(escape) > 1 and (char.isalpha() or char == "~" or len(escape) > 8):
                    escape = ""
                continue
            if char == "\x1b":
                escape = char
                continue

            if char in ("\r", "\n"):
                if char == "\r":
                    channel.send("\r\n")
                cmd = buf.strip()
                buf = ""
                if cmd in {"exit", "quit", "logout"}:
                    channel.send("logout\r\n")
                    break
                if cmd:
                    out, _code, pivot = _run_safely(pipeline, cmd, peer_ip)
                    if pivot:
                        _handle_pivot(channel, pivot, peer_ip, pipeline, graph, graph_lock, graph_path)
                    elif out:
                        channel.send(out.replace("\n", "\r\n"))
                    save_graph()
                channel.send(prompt())
            elif char == "\x03":
                channel.send("^C\r\n")
                buf = ""
                channel.send(prompt())
            elif char in {"\x7f", "\b"}:
                if buf:
                    buf = buf[:-1]
                    channel.send("\b \b")
            elif char == "\x04":  # Ctrl-D
                break
            elif ord(char) >= 32:
                buf += char
                channel.send(char)
    finally:
        if shipper is not None:
            shipper.session_closed()
        try:
            channel.close()
        except Exception:
            pass
        transport.close()


def main(argv: list[str] | None = None) -> int:
    _load_dotenv(ROOT / ".env")

    parser = argparse.ArgumentParser(description="NetOsis SSH honeypot front-door")
    parser.add_argument("--port", type=int, default=int(os.environ.get("NETOSIS_SSH_PORT", "2222")))
    parser.add_argument(
        "--bind",
        default=os.environ.get("NETOSIS_SSH_BIND", "0.0.0.0"),
        help="Bind address (default 0.0.0.0 for lab exposure)",
    )
    parser.add_argument("--data-dir", type=Path, default=Path(os.environ.get("NETOSIS_DATA_DIR", ROOT / "data")))
    parser.add_argument(
        "--host-yaml",
        type=Path,
        default=Path(os.environ.get("NETOSIS_HOST_CONFIG", ROOT / "deception/hosts/enterprise-web.yml")),
    )
    parser.add_argument(
        "--second-host",
        type=Path,
        default=Path(os.environ.get("NETOSIS_SECOND_HOST", ROOT / "deception/hosts/finance-db.yml")),
    )
    args = parser.parse_args(argv)
    args.data_dir.mkdir(parents=True, exist_ok=True)

    key_path = args.data_dir / "ssh_host_rsa_key"
    if not key_path.exists():
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(key_path))
        print(f"[*] Generated host key → {key_path}")
    else:
        key = paramiko.RSAKey.from_private_key_file(str(key_path))

    mode = os.environ.get("NETOSIS_LLM_MODE", "mock")
    model = os.environ.get("NETOSIS_LLM_MODEL", "qwen2.5:3b")
    print(f"[*] LLM mode={mode} model={model}")
    print(f"[*] Host YAML={args.host_yaml}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    sock.listen(50)
    print(f"[*] Honeypot listening on {args.bind}:{args.port}")
    user = os.environ.get("NETOSIS_SSH_USER", "admin")
    print(f"[*] Connect: ssh {user}@<server-ip> -p {args.port}  (password: decoy, see NETOSIS_SSH_PASSWORD)")

    graph_path = args.data_dir / "attack_graph.json"
    graph = AttackGraph.load(graph_path)
    graph_lock = threading.Lock()

    try:
        while True:
            client, addr = sock.accept()
            client.settimeout(600)  # drop idle/stalled connections
            print(f"[*] Connection from {addr[0]}:{addr[1]}")
            threading.Thread(
                target=handle_connection,
                args=(
                    client, key, args.data_dir, args.host_yaml, args.second_host,
                    graph, graph_lock,
                ),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down")
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
