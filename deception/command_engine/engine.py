from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Any

from deception.runtime.host import Session, VirtualHost
from deception.command_engine import fscmds, shell
from deception.command_engine.binaries import is_plausible_command
from deception.llm.fallback import generate_response
from deception.network import theater


@dataclass
class CommandResult:
    stdout: str
    stderr: str = ""
    exit_code: int = 0
    command: str = ""
    llm_fallback: bool = False
    # Set by the `ssh` branch when the target is a real pivot sensor; the SSH
    # front-door (scripts/ssh_honeypot.py) uses this to relay the session for
    # real instead of printing theater text. Not yet consumed there (pending).
    pivot_target: dict[str, Any] | None = None


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


def _env_for(session: Session) -> dict[str, str]:
    from deception.system.pack import login_users

    home = next((u["home"] for u in login_users(session.host) if u["name"] == session.user),
                f"/home/{session.user}" if session.user != "root" else "/root")
    return {
        "HOME": home,
        "USER": session.user,
        "LOGNAME": session.user,
        "PWD": session.cwd,
        "HOSTNAME": session.host.hostname,
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SHELL": "/bin/bash",
        "?": "0",
    }


def execute(session: Session, line: str) -> CommandResult:
    """Bash-like entrypoint: splits `;` / `&&` / `||` chains and `|` pipes,
    then dispatches each simple stage to _execute_stage. A plain single
    command (the common case, and every existing caller/test) takes the fast
    path straight into _execute_stage with no behavior change.
    """
    raw = line.strip()
    if not raw:
        return CommandResult(stdout="", command="")

    session.history.append(raw)
    if len(session.history) > 500:
        session.history = session.history[-500:]

    segments = shell.split_chain(raw)
    if len(segments) == 1 and segments[0][0] == "":
        stages = shell.split_pipe(segments[0][1])
        if len(stages) == 1:
            return _execute_stage(session, stages[0])
        return _execute_pipe(session, stages, original=raw)

    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    last = CommandResult(stdout="", command=raw)
    ran_any = False
    for sep, seg in segments:
        if sep == "&&" and last.exit_code != 0:
            continue
        if sep == "||" and last.exit_code == 0:
            continue
        stages = shell.split_pipe(seg)
        last = (
            _execute_stage(session, stages[0])
            if len(stages) == 1
            else _execute_pipe(session, stages, original=seg)
        )
        ran_any = True
        if last.stdout:
            stdout_parts.append(last.stdout)
        if last.stderr:
            stderr_parts.append(last.stderr)
    return CommandResult(
        stdout="".join(stdout_parts),
        stderr="".join(stderr_parts),
        exit_code=last.exit_code if ran_any else 0,
        command=raw,
        llm_fallback=last.llm_fallback,
        pivot_target=last.pivot_target,
    )


def _execute_pipe(session: Session, stages: list[str], *, original: str) -> CommandResult:
    """Run `a | b | c`: first stage is a real command, later stages are text
    filters over its stdout (or, if not a known filter, run normally and
    ignore the piped input — same as real bash for a non-reading command)."""
    env = _env_for(session)
    text = ""
    err = ""
    code = 0
    llm_used = False
    final_redir: shell.Redirects | None = None

    for i, raw_stage in enumerate(stages):
        expanded = shell.expand_vars(raw_stage, env)
        stripped, redir = shell.strip_redirects(expanded)
        if i == len(stages) - 1:
            final_redir = redir
        argv = shell.argv(stripped)
        if not argv:
            continue
        cmd = argv[0]
        if i > 0 and cmd in shell.FILTERS:
            out = shell.apply_filter(cmd, argv[1:], text)
            if out is None:
                out = (text, "", 0)
            text, stage_err, code = out
            err += stage_err
            continue
        result = _execute_stage(session, stripped)
        text = result.stdout
        err += result.stderr
        code = result.exit_code
        llm_used = llm_used or result.llm_fallback

    if final_redir and (final_redir.stdout_file or final_redir.stdout_null):
        if final_redir.stdout_file:
            path = _resolve(session.cwd, final_redir.stdout_file)
            prev = ""
            if (
                final_redir.append
                and path in session.host.filesystem
                and session.host.filesystem[path].get("type") == "file"
            ):
                prev = str(session.host.filesystem[path].get("content") or "")
            session.host.filesystem[path] = fscmds.new_entry(session, "file", prev + text)
            session.note_created(path)
        text = ""

    return CommandResult(stdout=text, stderr=err, exit_code=code, command=original, llm_fallback=llm_used)


def _execute_stage(session: Session, line: str) -> CommandResult:
    """Run one simple (pipe-free) shell command against virtual host state."""
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

    def _run_sandbox(cmd_line: str) -> CommandResult:
        from deception.runtime.sandbox import get_sandbox_client

        sb = get_sandbox_client().run(session, cmd_line)
        text = (sb.stdout or "") + (sb.stderr or "")
        if text and not text.endswith("\n"):
            text += "\n"
        if sb.exit_code != 0:
            return CommandResult(
                stdout="",
                stderr=text,
                exit_code=sb.exit_code,
                command=original_line,
            )
        return CommandResult(stdout=text, stderr="", exit_code=0, command=original_line)

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

    # Phase-1 sandbox: external curl/wget/git clone and ./payloads
    from deception.runtime.sandbox import should_sandbox

    if should_sandbox(original_line):
        return _run_sandbox(original_line)

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
        return _execute_stage(session, inner)

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
        out, err, code = theater.nmap(session, args)
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd == "ping" or cmd == "ping6":
        out, err, code = theater.ping(session, args)
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd in {"nc", "ncat", "netcat"}:
        out, err, code = theater.nc_probe(session, args)
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd == "telnet":
        out, err, code = theater.telnet(session, args)
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd == "dig":
        out, err, code = theater.dig(session, args)
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd in {"nslookup", "host"}:
        out, err, code = theater.nslookup_or_host(session, cmd, args)
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd == "arp":
        if not args or args == ["-a"] or args == ["-an"]:
            out, err, code = theater.arp_table(session)
            return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd == "ssh":
        plain = [a for a in args if not a.startswith("-")]
        if not plain:
            return CommandResult(stdout="usage: ssh [user@]host\n", exit_code=255, command=line)
        target = theater.resolve_ssh_target(session, plain[0])
        if target is None:
            host_part = plain[0].split("@")[-1]
            return CommandResult(
                stdout="", stderr=f"ssh: Could not resolve hostname {host_part}: Name or service not known\n",
                exit_code=255, command=line,
            )
        if not target.reachable:
            return CommandResult(
                stdout="", stderr=f"ssh: connect to host {target.ip} port 22: No route to host\n",
                exit_code=255, command=line,
            )
        if target.is_pivot:
            # Real pivot sensor (another honeypot) — the SSH front-door relays
            # this for real; here we only mark intent, we never open sockets.
            return CommandResult(
                stdout="", command=line,
                pivot_target={
                    "ip": target.ip, "hostname": target.hostname, "port": 2222,
                    "ctid": target.ctid, "requested_user": plain[0].split("@")[0] if "@" in plain[0] else session.user,
                },
            )
        return CommandResult(
            stdout="", stderr=f"{session.user}@{target.ip}: Permission denied (publickey,password).\n",
            exit_code=255, command=line,
        )

    if cmd == "curl":
        from deception.llm.fake_shell import curl_head_localhost

        # Lab-local only (external already sandboxed above)
        joined = " ".join(args)
        plain_args = [a for a in args if not a.startswith("-")]
        if "127.0.0.1" in joined or "localhost" in joined or session.host.ip in joined or not args:
            if "-I" in args or "-I" in line:
                return CommandResult(stdout=curl_head_localhost(), command=line)
            return CommandResult(
                stdout="<html><body><h1>Corp Intranet</h1></body></html>\n",
                command=line,
            )
        if plain_args:
            out, err, code = theater.curl_remote(session, args, plain_args[0])
            return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)
        return CommandResult(
            stdout="",
            stderr="curl: (28) Connection timed out after 5000 milliseconds\n",
            exit_code=28,
            command=line,
        )

    if cmd == "wget":
        return CommandResult(
            stdout="",
            stderr="wget: unable to resolve host address\n",
            exit_code=1,
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
        out, err, code = fscmds.ls(session, args)
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd == "cat":
        if not args:
            return CommandResult(stdout="", stderr="cat: missing file operand\n", exit_code=1, command=line)
        out, err, code = fscmds.cat(session, args)
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd in {"find"}:
        out, err, code = fscmds.find(session, args)
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd in {"grep", "egrep", "fgrep"}:
        gargs = (["-E", *args] if cmd == "egrep" else ["-F", *args] if cmd == "fgrep" else args)
        if any(a in {"-r", "-R", "--recursive"} or (a.startswith("-") and "r" in a[1:] and not a.startswith("--")) for a in gargs):
            out, err, code = fscmds.grep_recursive(session, gargs)
        else:
            res = fscmds.with_files(session, "grep", gargs, None)
            if res is None:
                out, err, code = "", "Usage: grep [OPTION]... PATTERNS [FILE]...\n", 2
            else:
                out, err, code = res
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd in {"head", "tail", "wc", "sort", "uniq", "cut", "awk", "tr", "base64", "nl", "rev", "tac", "sed"}:
        res = fscmds.with_files(session, cmd, args, None)
        if res is None:
            res = shell.apply_filter(cmd, args, "") or ("", "", 0)
        out, err, code = res
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd == "file":
        out, err, code = fscmds.file_cmd(session, args)
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd == "stat":
        out, err, code = fscmds.stat_cmd(session, args)
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd in {"md5sum", "sha1sum", "sha256sum", "sha512sum"}:
        out, err, code = fscmds.hash_cmd(session, cmd, args, None)
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd in {"which", "whereis", "type"}:
        out, err, code = fscmds.which(session, cmd, args)
        return CommandResult(stdout=out, stderr=err, exit_code=code, command=line)

    if cmd == "cd":
        target = args[0] if args else host.default_cwd()
        path = fscmds.follow(host, fscmds.resolve(session.cwd, target))
        if not fscmds.exists(host, path) or not fscmds.is_dir(host, path):
            return CommandResult(
                stdout="", stderr=f"-bash: cd: {target}: No such file or directory\n", exit_code=1, command=line,
            )
        if not fscmds.can_enter(session, path):
            return CommandResult(
                stdout="", stderr=f"-bash: cd: {target}: Permission denied\n", exit_code=1, command=line,
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

    if cmd == "history":
        # bash builtin: the user's saved ~/.bash_history, then this session's
        # commands. `history -c` is accepted silently (it only clears the shell's
        # in-memory list, exactly like bash).
        if args[:1] == ["-c"]:
            session.history.clear()
            return CommandResult(stdout="", command=line)
        from deception.system.pack import login_users

        home = next((u["home"] for u in login_users(host) if u["name"] == session.user),
                    "/root" if session.user == "root" else f"/home/{session.user}")
        saved = str((host.filesystem.get(f"{home}/.bash_history") or {}).get("content") or "")
        lines = [ln for ln in saved.splitlines() if ln.strip()] + list(session.history)
        if args and args[0].isdigit():
            lines = lines[-int(args[0]):] if int(args[0]) else []
            start = max(1, len(saved.splitlines()) + len(session.history) - len(lines) + 1)
        else:
            start = 1
        out = "".join(f"{i:5d}  {ln}\n" for i, ln in enumerate(lines, start))
        return CommandResult(stdout=out, command=line)

    if cmd == "uname":
        facts = host.system or {}
        kernel = facts.get("kernel", "5.15.0-112-generic")
        build = facts.get("kernel_build", "#122-Ubuntu SMP x86_64 GNU/Linux")
        if "-a" in args:
            return CommandResult(
                stdout=f"Linux {host.hostname} {kernel} {build} x86_64 x86_64 x86_64 GNU/Linux\n",
                command=line,
            )
        if "-r" in args:
            return CommandResult(stdout=kernel + "\n", command=line)
        if "-m" in args or "-p" in args or "-i" in args:
            return CommandResult(stdout="x86_64\n", command=line)
        if "-n" in args:
            return CommandResult(stdout=host.hostname + "\n", command=line)
        return CommandResult(stdout="Linux\n", command=line)

    if cmd == "hostname" and not args:
        return CommandResult(stdout=host.hostname + "\n", command=line)
    if cmd == "hostname":
        if "-f" in args:
            return CommandResult(stdout=(host.fqdn or f"{host.hostname}.corp.local") + "\n", command=line)
        if "-i" in args or "-I" in args:
            return CommandResult(stdout=host.ip + "\n", command=line)
        return CommandResult(stdout=host.hostname + "\n", command=line)

    if cmd == "uptime":
        from deception.system import clock

        facts = host.system or {}
        text, _minutes = clock.uptime_text(facts)
        la = facts.get("load", [0.08, 0.11, 0.09])
        return CommandResult(
            stdout=f" {clock.now().strftime('%H:%M:%S')} up {text},  1 user,  "
            f"load average: {la[0]:.2f}, {la[1]:.2f}, {la[2]:.2f}\n",
            command=line,
        )

    if cmd == "date" and not args:
        from deception.system import clock

        return CommandResult(stdout=clock.now().strftime("%a %b %e %H:%M:%S UTC %Y") + "\n", command=line)

    if cmd == "df":
        facts = host.system or {}
        human = "-h" in args
        lines = [f"Filesystem     {'Size' if human else '1K-blocks':>9}  Used Avail Use% Mounted on"]
        for d in facts.get("disks", []):
            size, used = float(d["size_gb"]), float(d["used_gb"])
            avail = max(size - used, 0)
            pct = int(used / size * 100) if size else 0
            if human:
                lines.append(f"{d['dev']:<14} {size:>4.1f}G {used:>4.1f}G {avail:>4.1f}G {pct:>3d}% {d['mount']}")
            else:
                lines.append(
                    f"{d['dev']:<14} {int(size * 1024 * 1024):>9d} {int(used * 1024 * 1024):>6d} "
                    f"{int(avail * 1024 * 1024):>6d} {pct:>3d}% {d['mount']}"
                )
        return CommandResult(stdout="\n".join(lines) + "\n", command=line)

    if cmd == "free":
        facts = host.system or {}
        total = int(facts.get("memory_mb", 3931))
        used = int(facts.get("mem_used_mb", 1180))
        buff = min(total - used - 60, 1780)
        free_mb = max(total - used - buff, 20)
        swap_total = int(facts.get("swap_mb", 2047))
        header = "              total        used        free      shared  buff/cache   available"
        if "-h" in args:
            def _h(m: float) -> str:
                return f"{m}M" if m < 1024 else f"{m / 1024:.1f}G"

            lines = [header,
                     f"Mem:           {_h(total):>5}       {_h(used):>5}       {_h(free_mb):>5}         "
                     f"8.0M       {_h(buff):>5}       {_h(total - used):>5}",
                     f"Swap:          {_h(swap_total):>5}          0B       {_h(swap_total):>5}"]
        else:
            lines = [header,
                     f"Mem:        {total:>7}     {used:>7}     {free_mb:>7}         "
                     f"8     {buff:>7}     {total - used:>7}",
                     f"Swap:       {swap_total:>7}           0     {swap_total:>7}"]
        return CommandResult(stdout="\n".join(lines) + "\n", command=line)

    if not is_plausible_command(cmd):
        return CommandResult(
            stdout="", stderr=f"bash: {cmd}: command not found\n", exit_code=127, command=line
        )
    return generate_response(session, line)
