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
import os
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
from deception.runtime.host import Session, VirtualHost
from deception.runtime.pipeline import VerticalSlicePipeline
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
    def __init__(self) -> None:
        super().__init__()
        self.username = "admin"

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
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        return True


def handle_connection(
    client_sock: socket.socket,
    host_key: paramiko.PKey,
    data_dir: Path,
    host_yaml: Path,
    second_host: Path,
) -> None:
    transport = paramiko.Transport(client_sock)
    # Believable OpenSSH banner for nmap -sV / banner grab (not LLM).
    transport.local_version = os.environ.get(
        "NETOSIS_SSH_BANNER",
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
    )
    transport.add_server_key(host_key)
    server = HoneypotInterface()

    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        client_sock.close()
        return

    channel = transport.accept(20)
    if channel is None:
        transport.close()
        return

    store = JsonlTelemetryStore(data_dir / "telemetry.jsonl")
    graph_path = data_dir / "attack_graph.json"
    graph = AttackGraph.load(graph_path) if graph_path.exists() else AttackGraph()

    try:
        peer = client_sock.getpeername()
        peer_ip = peer[0]
    except OSError:
        peer_ip = "0.0.0.0"

    vhost = VirtualHost.load(host_yaml)
    session = Session(
        host=vhost,
        session_id=str(uuid.uuid4()),
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

    try:
        channel.send(f"Welcome to {vhost.os}\r\n")
        channel.send(prompt())
        buf = ""
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

            if char in ("\r", "\n"):
                if char == "\r":
                    channel.send("\r\n")
                cmd = buf.strip()
                buf = ""
                if cmd in {"exit", "quit", "logout"}:
                    channel.send("logout\r\n")
                    break
                if cmd:
                    result, event, decision = pipeline.run_command(cmd)
                    out = (result.stdout or "") + (result.stderr or "")
                    if out:
                        channel.send(out.replace("\n", "\r\n"))
                    if getattr(result, "llm_fallback", False):
                        print(
                            f"  [llm] {peer_ip} cmd={cmd!r} "
                            f"action={decision.action} tech={event.technique}"
                        )
                    else:
                        print(
                            f"  [det] {peer_ip} cmd={cmd!r} "
                            f"action={decision.action} score={decision.risk_score}"
                        )
                    graph.save(graph_path)
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

    try:
        while True:
            client, addr = sock.accept()
            print(f"[*] Connection from {addr[0]}:{addr[1]}")
            threading.Thread(
                target=handle_connection,
                args=(client, key, args.data_dir, args.host_yaml, args.second_host),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down")
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
