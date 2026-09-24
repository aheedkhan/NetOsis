from __future__ import annotations

import shlex
from dataclasses import dataclass

from deception.runtime.host import Session, VirtualHost


@dataclass
class CommandResult:
    stdout: str
    stderr: str = ""
    exit_code: int = 0
    command: str = ""


def _resolve(cwd: str, target: str) -> str:
    if target.startswith("/"):
        path = target
    else:
        path = f"{cwd.rstrip('/')}/{target}" if cwd != "/" else f"/{target}"
    parts: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts) if parts else "/"


def _exists(host: VirtualHost, path: str) -> bool:
    if path in host.filesystem:
        return True
    if path == "/":
        return True
    prefix = path if path.endswith("/") else path + "/"
    return any(k.startswith(prefix) or k == path for k in host.filesystem)


def _is_dir(host: VirtualHost, path: str) -> bool:
    meta = host.filesystem.get(path)
    if meta and meta.get("type") == "dir":
        return True
    if path == "/":
        return True
    prefix = path.rstrip("/") + "/"
    return any(k.startswith(prefix) for k in host.filesystem if k != path)


def _list_dir(host: VirtualHost, path: str) -> list[str]:
    if path == "/":
        children: set[str] = set()
        for key in host.filesystem:
            if key == "/":
                continue
            name = key.lstrip("/").split("/")[0]
            if name:
                children.add(name)
        return sorted(children)
    prefix = path.rstrip("/") + "/"
    names: set[str] = set()
    for key in host.filesystem:
        if not key.startswith(prefix):
            continue
        rest = key[len(prefix) :]
        if not rest:
            continue
        names.add(rest.split("/")[0])
    return sorted(names)


def _read_file(host: VirtualHost, path: str) -> str | None:
    meta = host.filesystem.get(path)
    if not meta or meta.get("type") != "file":
        return None
    content = meta.get("content", "")
    return content if isinstance(content, str) else str(content)


def execute(session: Session, line: str) -> CommandResult:
    """Run one shell line against virtual host state (deterministic)."""
    line = line.strip()
    if not line:
        return CommandResult(stdout="", command="")

    try:
        parts = shlex.split(line)
    except ValueError as exc:
        return CommandResult(stdout="", stderr=f"sh: {exc}\n", exit_code=2, command=line)

    cmd = parts[0]
    args = parts[1:]
    host = session.host

    if cmd == "pwd":
        return CommandResult(stdout=session.cwd + "\n", command=line)

    if cmd == "whoami":
        return CommandResult(stdout=session.user + "\n", command=line)

    if cmd == "ls":
        target = args[0] if args else session.cwd
        path = _resolve(session.cwd, target)
        if not _exists(host, path):
            return CommandResult(
                stdout="",
                stderr=f"ls: cannot access '{target}': No such file or directory\n",
                exit_code=2,
                command=line,
            )
        if _is_dir(host, path):
            names = _list_dir(host, path)
            out = "\n".join(names) + ("\n" if names else "")
            return CommandResult(stdout=out, command=line)
        return CommandResult(stdout=path.rsplit("/", 1)[-1] + "\n", command=line)

    if cmd == "cat":
        if not args:
            return CommandResult(
                stdout="",
                stderr="cat: missing file operand\n",
                exit_code=1,
                command=line,
            )
        path = _resolve(session.cwd, args[0])
        if not _exists(host, path):
            return CommandResult(
                stdout="",
                stderr=f"cat: {args[0]}: No such file or directory\n",
                exit_code=1,
                command=line,
            )
        if _is_dir(host, path):
            return CommandResult(
                stdout="",
                stderr=f"cat: {args[0]}: Is a directory\n",
                exit_code=1,
                command=line,
            )
        content = _read_file(host, path)
        if content is None:
            return CommandResult(
                stdout="",
                stderr=f"cat: {args[0]}: No such file or directory\n",
                exit_code=1,
                command=line,
            )
        if content and not content.endswith("\n"):
            content += "\n"
        return CommandResult(stdout=content, command=line)

    if cmd == "cd":
        target = args[0] if args else host.default_cwd()
        path = _resolve(session.cwd, target)
        if not _exists(host, path) or not _is_dir(host, path):
            return CommandResult(
                stdout="",
                stderr=f"cd: {target}: No such file or directory\n",
                exit_code=1,
                command=line,
            )
        session.cwd = path
        return CommandResult(stdout="", command=line)

    # Deterministic from host.processes / host.network YAML — do not shell out.
    if cmd == "ps":
        procs = host.processes or []
        lines = ["USER       PID CMD"]
        for proc in procs:
            user = str(proc.get("user", "?"))
            pid = str(proc.get("pid", "?"))
            cmd_str = str(proc.get("cmd", ""))
            lines.append(f"{user:<10} {pid:>4} {cmd_str}")
        return CommandResult(stdout="\n".join(lines) + "\n", command=line)

    if cmd == "ip":
        if not args:
            return CommandResult(
                stdout="",
                stderr="Usage: ip addr | ip route\n",
                exit_code=1,
                command=line,
            )
        sub = args[0]
        net = host.network or {}
        if sub in {"addr", "a", "address"}:
            blocks: list[str] = []
            for idx, iface in enumerate(net.get("interfaces") or [], start=1):
                name = iface.get("name", f"eth{idx}")
                addrs = iface.get("addresses") or []
                blocks.append(f"{idx}: {name}: <UP>")
                for addr in addrs:
                    blocks.append(f"    inet {addr}")
            if not blocks:
                blocks = ["1: lo: <UP>", "    inet 127.0.0.1/8"]
            return CommandResult(stdout="\n".join(blocks) + "\n", command=line)
        if sub in {"route", "r"}:
            rows: list[str] = []
            for route in net.get("routes") or []:
                dest = route.get("destination", "default")
                gw = route.get("gateway")
                dev = route.get("dev", "")
                if gw:
                    rows.append(f"{dest} via {gw} dev {dev}")
                else:
                    rows.append(f"{dest} dev {dev} proto kernel scope link")
            if not rows:
                rows = [f"default via {host.gateway} dev eth0"]
            return CommandResult(stdout="\n".join(rows) + "\n", command=line)
        return CommandResult(
            stdout="",
            stderr=f"ip: unknown subcommand '{sub}'\n",
            exit_code=1,
            command=line,
        )

    return CommandResult(
        stdout="",
        stderr=f"{cmd}: command not found\n",
        exit_code=127,
        command=line,
    )
