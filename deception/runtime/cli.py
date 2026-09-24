from __future__ import annotations

import argparse
import os
import sys
import uuid
from pathlib import Path

from deception.command_engine.engine import execute
from deception.runtime.host import Session, VirtualHost

ROOT = Path(__file__).resolve().parents[2]


def default_host_path() -> Path:
    env = os.environ.get("NETOSIS_HOST_CONFIG")
    if env:
        return Path(env)
    return ROOT / "deception" / "hosts" / "enterprise-web.yml"


def build_session(host_path: Path | None = None) -> Session:
    path = host_path or default_host_path()
    host = VirtualHost.load(path)
    return Session(
        host=host,
        session_id=str(uuid.uuid4()),
        actor_id="actor-local",
        source_ip="127.0.0.1",
    )


def run_repl(session: Session) -> int:
    host = session.host
    print(f"NetOsis fake shell — {host.hostname} ({host.ip}) as {session.user}")
    print("Commands: pwd, ls, cat, whoami, cd. Ctrl-D or 'exit' to quit.")
    while True:
        try:
            line = input(f"{session.user}@{host.hostname}:{session.cwd}$ ")
        except EOFError:
            print()
            break
        if line.strip() in {"exit", "logout", "quit"}:
            break
        result = execute(session, line)
        if result.stdout:
            sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NetOsis deterministic fake shell")
    parser.add_argument(
        "--host",
        type=Path,
        default=None,
        help="Path to virtual host YAML",
    )
    args = parser.parse_args(argv)
    session = build_session(args.host)
    return run_repl(session)


if __name__ == "__main__":
    raise SystemExit(main())
