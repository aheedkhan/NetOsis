from __future__ import annotations

import shlex
from dataclasses import dataclass

from deception.runtime.host import Session, VirtualHost
from deception.llm.fallback import generate_response


@dataclass
class CommandResult:
    stdout: str
    stderr: str = ""
    exit_code: int = 0
    command: str = ""
    llm_fallback: bool = False


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


def _ensure_parent_dirs(host: VirtualHost, path: str) -> None:
    parts = [x for x in path.split("/") if x]
    cur = ""
    for part in parts[:-1]:
        cur = f"{cur}/{part}"
        if cur not in host.filesystem:
            host.filesystem[cur] = {"type": "dir"}


def _rm_path(session: Session, path: str, *, recursive: bool) -> tuple[bool, str]:
    host = session.host
    if path == "/":
        return False, "rm: cannot remove '/'\n"
    if not _exists(host, path):
        return False, f"rm: cannot remove '{path}': No such file or directory\n"
    if _is_dir(host, path) and not recursive:
        kids = _list_dir(host, path)
        if kids:
            return False, f"rm: cannot remove '{path}': Is a directory\n"
    prefix = path if path == "/" else path.rstrip("/")
    to_del = [
        k
        for k in list(host.filesystem)
        if k == prefix or k.startswith(prefix + "/")
    ]
    if not to_del and path in host.filesystem:
        to_del = [path]
    for k in to_del:
        del host.filesystem[k]
        session.note_deleted(k)
    return True, ""


def execute(session: Session, line: str) -> CommandResult:
    """Run one shell line against virtual host state (deterministic)."""
    line = line.strip()
    if not line:
        return CommandResult(stdout="", command="")

    session.begin_mutation_batch()
    original_line = line

    def _narrate(cmd_line: str) -> CommandResult:
        from deception.llm.fallback import narrate_after_mutation

        result = narrate_after_mutation(session, cmd_line)
        result.command = original_line
        return result

    # Simple redirection: echo TEXT > path / >> path (before shlex eats >)
    redir = None
    if ">>" in line or (" > " in line or line.count(">") == 1 and " >" in line):
        import re as _re

        m = _re.match(r"^(.*?)\s*(>>|>)\s*(\S+)\s*$", line)
        if m:
            left, op, dest = m.group(1).strip(), m.group(2), m.group(3)
            redir = (left, op, dest)
            line = left

    try:
        parts = shlex.split(line)
    except ValueError as exc:
        return CommandResult(stdout="", stderr=f"sh: {exc}\n", exit_code=2, command=line)

    if not parts:
        return CommandResult(stdout="", command=line)

    cmd = parts[0]
    args = parts[1:]
    host = session.host

    if cmd == "pwd":
        return CommandResult(stdout=session.cwd + "\n", command=line)

    if cmd == "whoami":
        return CommandResult(stdout=session.user + "\n", command=line)

    if cmd == "id":
        from deception.llm.fake_shell import id_line

        return CommandResult(stdout=id_line(session.user), command=line)

    # Privilege theater — elevate session, no real sudoers.
    if cmd == "sudo":
        rest = args
        if not rest:
            return CommandResult(
                stdout="",
                stderr="usage: sudo -i | sudo su | sudo <cmd>\n",
                exit_code=1,
                command=line,
            )
        if rest in (["-i"], ["su"], ["su", "-"], ["-s"], ["bash"], ["-i", "bash"]) or (
            rest[0] == "su" and len(rest) <= 2
        ):
            session.user = "root"
            session.cwd = "/root"
            if "/root" not in host.filesystem:
                host.filesystem["/root"] = {"type": "dir"}
                session.note_created("/root")
            return CommandResult(stdout="", command=line)
        session.user = "root"
        inner = " ".join(rest)
        return execute(session, inner)

    if cmd == "su":
        session.user = "root"
        session.cwd = "/root"
        if "/root" not in host.filesystem:
            host.filesystem["/root"] = {"type": "dir"}
            session.note_created("/root")
        return CommandResult(stdout="", command=line)

    if cmd in {"apt", "apt-get"}:
        if args and args[0] in {"install", "update", "upgrade"}:
            pkgs = [a for a in args[1:] if not a.startswith("-")] if args[0] == "install" else []
            for pkg in pkgs:
                session.note_package(pkg)
            return _narrate(original_line)
        return CommandResult(
            stdout="apt 2.4.12 (amd64)\nUsage: apt [options] command\n",
            command=line,
        )

    if cmd == "nmap":
        from deception.llm.fake_shell import format_nmap_report, parse_nmap_target

        target = parse_nmap_target(line) or "127.0.0.1"
        return CommandResult(stdout=format_nmap_report(session, target), command=line)

    if cmd == "curl":
        from deception.llm.fake_shell import curl_head_localhost

        joined = " ".join(args)
        if "127.0.0.1" in joined or "localhost" in joined or not args:
            if "-I" in args or "-I" in line:
                return CommandResult(stdout=curl_head_localhost(), command=line)
            return CommandResult(
                stdout="<html><body><h1>Corp Intranet</h1></body></html>\n",
                command=line,
            )
        return CommandResult(
            stdout="",
            stderr="curl: (28) Connection timed out after 5000 milliseconds\n",
            exit_code=28,
            command=line,
        )

    if cmd == "mkdir":
        flags = {a for a in args if a.startswith("-")}
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            return CommandResult(
                stdout="", stderr="mkdir: missing operand\n", exit_code=1, command=line
            )
        parents = "-p" in flags or "--parents" in flags
        for t in targets:
            path = _resolve(session.cwd, t)
            if _exists(host, path):
                if not parents:
                    return CommandResult(
                        stdout="",
                        stderr=f"mkdir: cannot create directory '{t}': File exists\n",
                        exit_code=1,
                        command=line,
                    )
                continue
            if parents:
                _ensure_parent_dirs(host, path)
                # also mark intermediate dirs created
                parts = [x for x in path.split("/") if x]
                cur = ""
                for part in parts:
                    cur = f"{cur}/{part}"
                    if cur not in host.filesystem:
                        host.filesystem[cur] = {"type": "dir"}
                        session.note_created(cur)
                    elif host.filesystem[cur].get("type") != "dir" and cur != path:
                        return CommandResult(
                            stdout="",
                            stderr=f"mkdir: cannot create directory '{t}': Not a directory\n",
                            exit_code=1,
                            command=line,
                        )
            else:
                parent = path.rsplit("/", 1)[0] or "/"
                if parent != "/" and not _exists(host, parent):
                    return CommandResult(
                        stdout="",
                        stderr=f"mkdir: cannot create directory '{t}': No such file or directory\n",
                        exit_code=1,
                        command=line,
                    )
                host.filesystem[path] = {"type": "dir"}
                session.note_created(path)
        return _narrate(original_line)

    if cmd == "touch":
        if not args:
            return CommandResult(
                stdout="", stderr="touch: missing file operand\n", exit_code=1, command=line
            )
        for t in args:
            path = _resolve(session.cwd, t)
            if _exists(host, path) and _is_dir(host, path):
                continue
            if not _exists(host, path):
                _ensure_parent_dirs(host, path)
                parent = path.rsplit("/", 1)[0] or "/"
                if parent != "/" and not _exists(host, parent):
                    return CommandResult(
                        stdout="",
                        stderr=f"touch: cannot touch '{t}': No such file or directory\n",
                        exit_code=1,
                        command=line,
                    )
                host.filesystem[path] = {"type": "file", "content": ""}
                session.note_created(path)
            else:
                meta = host.filesystem.get(path) or {}
                if "content" not in meta:
                    meta["content"] = ""
                    host.filesystem[path] = meta
                session.note_created(path)  # touch existing still a write this turn
        return _narrate(original_line)

    if cmd in {"rm", "rmdir"}:
        recursive = cmd == "rm" and any(a in {"-r", "-rf", "-fr", "--recursive"} for a in args)
        force = cmd == "rm" and any(a in {"-f", "-rf", "-fr"} for a in args)
        targets = [a for a in args if not a.startswith("-")]
        if not targets:
            return CommandResult(
                stdout="", stderr=f"{cmd}: missing operand\n", exit_code=1, command=line
            )
        for t in targets:
            path = _resolve(session.cwd, t)
            if cmd == "rmdir":
                if not _exists(host, path):
                    return CommandResult(
                        stdout="",
                        stderr=f"rmdir: failed to remove '{t}': No such file or directory\n",
                        exit_code=1,
                        command=line,
                    )
                if not _is_dir(host, path):
                    return CommandResult(
                        stdout="",
                        stderr=f"rmdir: failed to remove '{t}': Not a directory\n",
                        exit_code=1,
                        command=line,
                    )
                if _list_dir(host, path):
                    return CommandResult(
                        stdout="",
                        stderr=f"rmdir: failed to remove '{t}': Directory not empty\n",
                        exit_code=1,
                        command=line,
                    )
                del host.filesystem[path]
                session.note_deleted(path)
                continue
            ok, err = _rm_path(session, path, recursive=recursive)
            if not ok and not force:
                return CommandResult(stdout="", stderr=err, exit_code=1, command=line)
        return _narrate(original_line)

    if cmd == "echo":
        text = " ".join(args) + "\n"
        if redir:
            _, op, dest = redir
            path = _resolve(session.cwd, dest)
            parent = path.rsplit("/", 1)[0] or "/"
            if parent != "/" and not _exists(host, parent):
                return CommandResult(
                    stdout="",
                    stderr=f"bash: {dest}: No such file or directory\n",
                    exit_code=1,
                    command=line,
                )
            prev = ""
            if op == ">>" and path in host.filesystem and host.filesystem[path].get("type") == "file":
                prev = str(host.filesystem[path].get("content") or "")
            created = path not in host.filesystem
            host.filesystem[path] = {"type": "file", "content": prev + text}
            session.note_created(path)  # always — write counts for this command's risk/RAG
            return _narrate(original_line)
        return CommandResult(stdout=text, command=line)

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

    return generate_response(session, line)
