"""File commands on the virtual filesystem with real Unix permissions.

ls (-l -a -A -h -t -r -d -1 -R), cat, head/tail/wc/sort/... with file args,
grep -r, find (-name -iname -type -perm -user -maxdepth -writable), file,
stat, md5sum/sha256sum, strings, base64, which/whereis/type, cd.
"""

from __future__ import annotations

import hashlib
import math
import posixpath
from typing import TYPE_CHECKING, Any

from deception.command_engine import shell
from deception.system import clock

if TYPE_CHECKING:
    from deception.runtime.host import Session, VirtualHost

# --------------------------------------------------------------------------- paths


def resolve(cwd: str, target: str) -> str:
    path = target if target.startswith("/") else posixpath.join(cwd, target)
    norm = posixpath.normpath(path)
    return "/" + norm.lstrip("/") if norm != "/" else "/"


def follow(host: VirtualHost, path: str) -> str:
    """Resolve symlinks on any path component (/bin/ls -> /usr/bin/ls)."""
    parts = [p for p in path.split("/") if p]
    cur = ""
    for _ in range(8):
        changed = False
        cur = ""
        for i, part in enumerate(parts):
            nxt = f"{cur}/{part}"
            meta = host.filesystem.get(nxt)
            if meta and meta.get("type") == "link":
                tgt = str(meta.get("target", ""))
                base = tgt if tgt.startswith("/") else posixpath.join(cur or "/", tgt)
                parts = [p for p in posixpath.normpath(base).split("/") if p] + parts[i + 1:]
                changed = True
                break
            cur = nxt
        if not changed:
            break
    return cur or "/"


def exists(host: VirtualHost, path: str) -> bool:
    if path == "/" or path in host.filesystem:
        return True
    prefix = path.rstrip("/") + "/"
    return any(k.startswith(prefix) for k in host.filesystem)


def is_dir(host: VirtualHost, path: str) -> bool:
    if path == "/":
        return True
    meta = host.filesystem.get(path)
    if meta is not None:
        return meta.get("type") == "dir"
    prefix = path.rstrip("/") + "/"
    return any(k.startswith(prefix) for k in host.filesystem)


def list_dir(host: VirtualHost, path: str) -> list[str]:
    prefix = "/" if path == "/" else path.rstrip("/") + "/"
    names: set[str] = set()
    for key in host.filesystem:
        if key == path or not key.startswith(prefix):
            continue
        rest = key[len(prefix):]
        if rest:
            names.add(rest.split("/")[0])
    return sorted(names)


def meta_of(host: VirtualHost, path: str) -> dict[str, Any]:
    meta = host.filesystem.get(path)
    if meta is None:
        return {"type": "dir" if is_dir(host, path) else "file", "mode": "0755", "owner": "root", "group": "root"}
    return meta


def read_text(host: VirtualHost, path: str) -> str | None:
    meta = host.filesystem.get(path)
    if not meta or meta.get("type") != "file":
        return None
    if meta.get("binary"):
        return "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00>\x00\x01\x00\x00\x00 \x00\x00\x00"
    content = meta.get("content", "")
    return content if isinstance(content, str) else str(content)


def size_of(host: VirtualHost, path: str) -> int:
    meta = meta_of(host, path)
    if meta.get("type") == "dir":
        return 4096
    if meta.get("type") == "link":
        return len(str(meta.get("target", "")))
    if "size" in meta:
        return int(meta["size"])
    return len(str(meta.get("content", "")).encode())


# --------------------------------------------------------------------------- permissions


def user_groups(session: Session) -> set[str]:
    from deception.system.pack import login_users

    groups = {session.user}
    for u in login_users(session.host):
        if u["name"] == session.user:
            groups.update(u["groups"])
    return groups


def _allowed(session: Session, meta: dict[str, Any], bit: int) -> bool:
    if session.user == "root":
        return True
    if "mode" not in meta:
        # Legacy/attacker-created entries (mkdir, touch, echo redirects, planted
        # deception artifacts) never set a mode — stay unrestricted, same as
        # before permissions existed. Only system-pack files carry real modes.
        return True
    try:
        mode = int(str(meta.get("mode", "0644")), 8)
    except ValueError:
        mode = 0o644
    if meta.get("owner", "root") == session.user:
        return bool(mode & (bit << 6))
    if meta.get("group", "root") in user_groups(session):
        return bool(mode & (bit << 3))
    return bool(mode & bit)


def can_read(session: Session, path: str) -> bool:
    return _allowed(session, meta_of(session.host, path), 4)


def can_write(session: Session, path: str) -> bool:
    return _allowed(session, meta_of(session.host, path), 2)


def can_enter(session: Session, path: str) -> bool:
    """Every directory on the way must be searchable (x)."""
    cur = ""
    for part in [p for p in path.split("/") if p]:
        cur = f"{cur}/{part}"
        if is_dir(session.host, cur) and not _allowed(session, meta_of(session.host, cur), 1):
            return False
    return True


def new_entry(session: Session, kind: str, content: str = "") -> dict[str, Any]:
    """Metadata for files the attacker creates (owned by them, dated now)."""
    meta: dict[str, Any] = {
        "type": kind,
        "owner": session.user,
        "group": session.user,
        "mode": "0755" if kind == "dir" else "0644",
        "mtime": clock.stamp(clock.now()),
    }
    if kind == "file":
        meta["content"] = content
    return meta


# --------------------------------------------------------------------------- ls


def _perm_string(meta: dict[str, Any]) -> str:
    kind = {"dir": "d", "link": "l"}.get(str(meta.get("type")), "-")
    try:
        mode = int(str(meta.get("mode", "0644")), 8)
    except ValueError:
        mode = 0o644
    out = kind
    for shift in (6, 3, 0):
        bits = (mode >> shift) & 7
        out += ("r" if bits & 4 else "-") + ("w" if bits & 2 else "-") + ("x" if bits & 1 else "-")
    out = list(out)
    if mode & 0o4000:
        out[3] = "s" if out[3] == "x" else "S"
    if mode & 0o2000:
        out[6] = "s" if out[6] == "x" else "S"
    if mode & 0o1000:
        out[9] = "t" if out[9] == "x" else "T"
    return "".join(out)


def human(n: float) -> str:
    for unit in ("", "K", "M", "G", "T"):
        if n < 1024 or unit == "T":
            if unit == "":
                return str(int(n))
            return f"{n:.1f}{unit}" if n < 10 else f"{math.ceil(n)}{unit}"
        n /= 1024
    return str(n)


def _columns(names: list[str], width: int = 80) -> str:
    if not names:
        return ""
    col_w = max(len(n) for n in names) + 2
    cols = max(1, width // col_w)
    rows = math.ceil(len(names) / cols)
    lines = []
    for r in range(rows):
        cells = [names[c * rows + r] for c in range(cols) if c * rows + r < len(names)]
        lines.append("".join(n.ljust(col_w) for n in cells[:-1]) + cells[-1])
    return "\n".join(lines) + "\n"


def _long_rows(session: Session, base: str, names: list[str], human_sizes: bool) -> list[str]:
    host = session.host
    rows = []
    for name in names:
        path = base if name in {".", ".."} and base else posixpath.join(base, name)
        if name == "..":
            path = posixpath.dirname(base.rstrip("/")) or "/"
        meta = meta_of(host, path)
        size = size_of(host, path)
        links = 2 + sum(1 for c in list_dir(host, path) if is_dir(host, posixpath.join(path, c))) if meta.get("type") == "dir" else 1
        mtime = clock.ls_time(clock.parse(str(meta.get("mtime", "2023-02-14 09:31"))))
        shown = name
        if meta.get("type") == "link":
            shown = f"{name} -> {meta.get('target')}"
        rows.append([_perm_string(meta), str(links), str(meta.get("owner", "root")),
                     str(meta.get("group", "root")), human(size) if human_sizes else str(size), mtime, shown])
    widths = [max(len(r[i]) for r in rows) for i in range(5)] if rows else []
    out = []
    for r in rows:
        out.append(f"{r[0]} {r[1].rjust(widths[1])} {r[2].ljust(widths[2])} {r[3].ljust(widths[3])} "
                   f"{r[4].rjust(widths[4])} {r[5]} {r[6]}")
    return out


def ls(session: Session, args: list[str]) -> tuple[str, str, int]:
    flags: set[str] = set()
    targets: list[str] = []
    for a in args:
        if a.startswith("--"):
            flags.add({"--all": "a", "--almost-all": "A", "--human-readable": "h"}.get(a, ""))
        elif a.startswith("-") and len(a) > 1:
            flags.update(a[1:])
        else:
            targets.append(a)
    targets = targets or ["."]
    host = session.host
    out: list[str] = []
    err: list[str] = []
    code = 0
    files: list[str] = []
    dirs: list[tuple[str, str]] = []
    for t in targets:
        path = follow(host, resolve(session.cwd, t))
        if not exists(host, path):
            err.append(f"ls: cannot access '{t}': No such file or directory")
            code = 2
            continue
        if is_dir(host, path) and "d" not in flags:
            dirs.append((t, path))
        else:
            files.append(t)
    if files:
        if "l" in flags:
            out.extend(_long_rows(session, session.cwd, files, "h" in flags))
        else:
            out.append(_columns(sorted(files)).rstrip("\n"))
    for t, path in dirs:
        if len(targets) > 1 or "R" in flags:
            out.append(("\n" if out else "") + f"{t}:")
        if not can_read(session, path):
            err.append(f"ls: cannot open directory '{t}': Permission denied")
            code = 2
            continue
        names = list_dir(host, path)
        if "a" not in flags and "A" not in flags:
            names = [n for n in names if not n.startswith(".")]
        if "t" in flags:
            names.sort(key=lambda n: str(meta_of(host, posixpath.join(path, n)).get("mtime", "")), reverse=True)
        if "S" in flags:
            names.sort(key=lambda n: size_of(host, posixpath.join(path, n)), reverse=True)
        if "r" in flags:
            names.reverse()
        if "a" in flags:
            names = [".", "..", *names]
        if "l" in flags:
            blocks = sum(math.ceil(size_of(host, posixpath.join(path, n)) / 4096) * 4
                         for n in names if n not in {".", ".."})
            out.append(f"total {blocks}")
            out.extend(_long_rows(session, path, names, "h" in flags))
        elif "1" in flags:
            out.extend(names)
        elif names:
            out.append(_columns(names).rstrip("\n"))
    text = "\n".join(x for x in out if x is not None)
    return (text + "\n" if text.strip() else ""), ("\n".join(err) + "\n" if err else ""), code


# --------------------------------------------------------------------------- reading files


def read_for(session: Session, prog: str, target: str) -> tuple[str | None, str]:
    """(content, error) with bash-accurate messages."""
    host = session.host
    path = follow(host, resolve(session.cwd, target))
    if not exists(host, path) or not can_enter(session, posixpath.dirname(path)) and not exists(host, path):
        return None, f"{prog}: {target}: No such file or directory\n"
    if not can_enter(session, posixpath.dirname(path)):
        return None, f"{prog}: {target}: Permission denied\n"
    if is_dir(host, path):
        return None, f"{prog}: {target}: Is a directory\n"
    if not can_read(session, path):
        return None, f"{prog}: {target}: Permission denied\n"
    dyn = dynamic_file(session, path)
    if dyn is not None:
        return dyn, ""
    content = read_text(host, path)
    if content is None:
        return None, f"{prog}: {target}: No such file or directory\n"
    session.files_read.append(path)
    return content, ""


def dynamic_file(session: Session, path: str) -> str | None:
    from deception.system.pack import system_facts

    facts = getattr(session.host, "system", None) or system_facts(session.host)
    if path == "/proc/uptime":
        _, minutes = clock.uptime_text(facts)
        return f"{minutes * 60}.42 {minutes * 60 * 1.9:.2f}\n"
    if path == "/proc/loadavg":
        la = facts["load"]
        return f"{la[0]:.2f} {la[1]:.2f} {la[2]:.2f} 1/{len(session.host.processes) + 60} {41000 + len(session.history)}\n"
    if path == "/proc/meminfo":
        total = facts["memory_mb"] * 1024
        used = facts["mem_used_mb"] * 1024
        return (f"MemTotal:       {total:>8} kB\nMemFree:        {total - used - 1849 * 1024:>8} kB\n"
                f"MemAvailable:   {total - used + 400 * 1024:>8} kB\nBuffers:        {98304:>8} kB\n"
                f"Cached:         {1700 * 1024:>8} kB\nSwapTotal:      {facts['swap_mb'] * 1024:>8} kB\n"
                f"SwapFree:       {facts['swap_mb'] * 1024:>8} kB\n")
    if path == "/var/log/auth.log":
        base = read_text(session.host, path) or ""
        return base + "".join(session.auth_log_extra)
    return None


def cat(session: Session, args: list[str]) -> tuple[str, str, int]:
    files = [a for a in args if not a.startswith("-") or a == "-"]
    number = "-n" in args
    if not files:
        return "", "", 0
    out, err, code = [], [], 0
    for f in files:
        content, e = read_for(session, "cat", f)
        if content is None:
            err.append(e)
            code = 1
            continue
        out.append(content)
    text = "".join(out)
    if number:
        text, _, _ = shell.apply_filter("nl", [], text) or (text, "", 0)
    return text, "".join(err), code


def with_files(session: Session, prog: str, args: list[str], stdin: str | None) -> tuple[str, str, int] | None:
    """head/tail/wc/sort/... : read file operands, then apply the text filter."""
    opts_with_value = {"-n", "-c", "-d", "-f", "-k", "-t", "-e"}
    files: list[str] = []
    filt_args: list[str] = []
    skip = False
    pattern_taken = prog not in {"grep", "egrep", "fgrep"}
    for i, a in enumerate(args):
        if skip:
            filt_args.append(a)
            skip = False
            continue
        if a.startswith("-") and len(a) > 1:
            filt_args.append(a)
            if a in opts_with_value:
                skip = True
            continue
        if not pattern_taken:
            filt_args.append(a)
            pattern_taken = True
            continue
        if prog == "awk" and not any(not x.startswith("-") for x in filt_args):
            filt_args.append(a)
            continue
        if prog in {"tr", "tee"}:
            filt_args.append(a)
            continue
        files.append(a)
    if prog == "tee":
        return None
    if not files:
        if stdin is None:
            return None
        return shell.apply_filter(prog, filt_args, stdin)
    outs, errs, code = [], [], 0
    for f in files:
        content, e = read_for(session, prog, f)
        if content is None:
            errs.append(e)
            code = 2 if prog == "grep" else 1
            continue
        res = shell.apply_filter(prog, filt_args, content)
        if res is None:
            return None
        o, e2, c = res
        if prog in {"grep", "egrep"} and len(files) > 1 and o:
            o = "".join(f"{f}:{ln}\n" for ln in o.splitlines())
        if prog == "wc" and o:
            o = o.rstrip("\n") + f" {f}\n"
        outs.append(o)
        errs.append(e2)
        code = c if code == 0 else code
    return "".join(outs), "".join(errs), code


def grep_recursive(session: Session, args: list[str]) -> tuple[str, str, int]:
    flags = [a for a in args if a.startswith("-")]
    plain = [a for a in args if not a.startswith("-")]
    if not plain:
        return "", "Usage: grep [OPTION]... PATTERNS [FILE]...\n", 2
    pattern, roots = plain[0], plain[1:] or ["."]
    only_names = any("l" in f[1:] for f in flags if not f.startswith("--"))
    filt = [f.replace("r", "").replace("R", "").replace("l", "") for f in flags]
    filt = [f for f in filt if f not in {"-", ""}]
    out, err = [], []
    host = session.host
    for root in roots:
        base = follow(host, resolve(session.cwd, root))
        for path in sorted(host.filesystem):
            if not (path == base or path.startswith(base.rstrip("/") + "/")):
                continue
            meta = host.filesystem[path]
            if meta.get("type") != "file" or meta.get("binary") or path.startswith(("/proc", "/usr/")):
                continue
            shown = path if root.startswith("/") else posixpath.relpath(path, session.cwd)
            if not can_enter(session, posixpath.dirname(path)) or not can_read(session, path):
                err.append(f"grep: {shown}: Permission denied")
                continue
            lines, _ = shell.grep_lines([*filt, pattern], str(meta.get("content", "")).splitlines())
            if lines:
                session.files_read.append(path)
                if only_names:
                    out.append(shown)
                else:
                    out.extend(f"{shown}:{ln}" for ln in lines)
    err = list(dict.fromkeys(err))
    return ("\n".join(out) + "\n" if out else ""), ("\n".join(err) + "\n" if err else ""), 0 if out else 1


# --------------------------------------------------------------------------- find


def find(session: Session, args: list[str]) -> tuple[str, str, int]:
    roots: list[str] = []
    i = 0
    while i < len(args) and not args[i].startswith("-") and args[i] not in {"(", "!"}:
        roots.append(args[i])
        i += 1
    roots = roots or ["."]
    preds = args[i:]
    name = iname = ftype = perm = user = None
    maxdepth = 99
    writable = False
    j = 0
    while j < len(preds):
        p = preds[j]
        val = preds[j + 1] if j + 1 < len(preds) else ""
        if p == "-name":
            name, j = val, j + 1
        elif p == "-iname":
            iname, j = val, j + 1
        elif p == "-type":
            ftype, j = val, j + 1
        elif p == "-perm":
            perm, j = val, j + 1
        elif p == "-user":
            user, j = val, j + 1
        elif p == "-maxdepth":
            maxdepth, j = int(val) if val.isdigit() else 99, j + 1
        elif p == "-writable":
            writable = True
        elif p in {"-exec", "-execdir"}:
            break
        j += 1
    host = session.host
    out, err = [], []
    for root in roots:
        base = follow(host, resolve(session.cwd, root))
        if not exists(host, base):
            err.append(f"find: '{root}': No such file or directory")
            continue
        denied: set[str] = set()
        for path in sorted({base, *[k for k in host.filesystem if k.startswith(base.rstrip("/") + "/") or base == "/"]}):
            if path.startswith(("/proc/", "/sys/")) and path != base:
                continue
            if any(path.startswith(d + "/") for d in denied):
                continue
            rel = path[len(base):].strip("/")
            depth = 0 if not rel else rel.count("/") + 1
            if depth > maxdepth:
                continue
            meta = meta_of(host, path)
            if meta.get("type") == "dir" and path != base and not (_allowed(session, meta, 4) and _allowed(session, meta, 1)):
                denied.add(path)
                shown_d = path if root.startswith("/") else "./" + rel
                err.append(f"find: '{shown_d}': Permission denied")
            base_name = posixpath.basename(path) or "/"
            if name and not shell.glob_match(base_name, name):
                continue
            if iname and not shell.glob_match(base_name, iname, ignore_case=True):
                continue
            if ftype and {"f": "file", "d": "dir", "l": "link"}.get(ftype) != meta.get("type"):
                continue
            if perm and not _perm_match(str(meta.get("mode", "0644")), perm):
                continue
            if user and meta.get("owner", "root") != user:
                continue
            if writable and not _allowed(session, meta, 2):
                continue
            shown = path if root.startswith("/") else ("." if not rel else "./" + rel)
            if root not in {".", "./"} and not root.startswith("/"):
                shown = posixpath.join(root, rel) if rel else root
            out.append(shown)
    return ("\n".join(out) + "\n" if out else ""), ("\n".join(err) + "\n" if err else ""), 1 if err else 0


def _perm_match(mode: str, spec: str) -> bool:
    try:
        m = int(mode, 8)
    except ValueError:
        return False
    sym = {"u=s": 0o4000, "g=s": 0o2000, "o=w": 0o002, "o+w": 0o002}
    if spec.lstrip("-/") in sym:
        return bool(m & sym[spec.lstrip("-/")])
    try:
        want = int(spec.lstrip("-/"), 8)
    except ValueError:
        return False
    if spec.startswith("-"):
        return m & want == want
    if spec.startswith("/"):
        return bool(m & want)
    return m & 0o7777 == want


# --------------------------------------------------------------------------- misc


def file_cmd(session: Session, args: list[str]) -> tuple[str, str, int]:
    out = []
    for a in [x for x in args if not x.startswith("-")]:
        path = follow(session.host, resolve(session.cwd, a))
        if not exists(session.host, path):
            out.append(f"{a}: cannot open `{a}' (No such file or directory)")
            continue
        meta = meta_of(session.host, path)
        if meta.get("type") == "dir":
            kind = "directory"
        elif meta.get("binary"):
            kind = ("setuid " if str(meta.get("mode", "")).startswith("4") else "") + \
                "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped"
        else:
            text = str(meta.get("content", ""))
            if not text:
                kind = "empty"
            elif text.startswith("#!"):
                kind = f"{text.split()[0][2:].split('/')[-1]} script, ASCII text executable"
            elif "PRIVATE KEY" in text:
                kind = "OpenSSH private key"
            else:
                kind = "ASCII text"
        out.append(f"{a}: {kind}")
    return "\n".join(out) + "\n", "", 0


def stat_cmd(session: Session, args: list[str]) -> tuple[str, str, int]:
    out, err = [], []
    for a in [x for x in args if not x.startswith("-")]:
        path = follow(session.host, resolve(session.cwd, a))
        if not exists(session.host, path):
            err.append(f"stat: cannot statx '{a}': No such file or directory")
            continue
        meta = meta_of(session.host, path)
        size = size_of(session.host, path)
        mtime = clock.parse(str(meta.get("mtime", "2023-02-14 09:31")))
        uid = {"root": 0}.get(str(meta.get("owner")), 1000)
        kind = {"dir": "directory", "link": "symbolic link"}.get(str(meta.get("type")), "regular file" if size else "regular empty file")
        ts = mtime.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "412345 +0000"
        out.append(
            f"  File: {a}\n  Size: {size:<15} Blocks: {math.ceil(size / 512) * 1 if size else 0:<10} IO Block: 4096   {kind}\n"
            f"Device: 802h/2050d\tInode: {100000 + int(hashlib.md5(path.encode()).hexdigest()[:5], 16)}      Links: 1\n"
            f"Access: ({str(meta.get('mode', '0644')).rjust(4, '0')}/{_perm_string(meta)})  Uid: ({uid:5d}/{str(meta.get('owner')):>8})   Gid: ({uid:5d}/{str(meta.get('group')):>8})\n"
            f"Access: {ts}\nModify: {ts}\nChange: {ts}\n Birth: {ts}"
        )
    return ("\n".join(out) + "\n" if out else ""), ("\n".join(err) + "\n" if err else ""), 1 if err else 0


def hash_cmd(session: Session, prog: str, args: list[str], stdin: str | None) -> tuple[str, str, int]:
    algo = {"md5sum": hashlib.md5, "sha1sum": hashlib.sha1, "sha256sum": hashlib.sha256,
            "sha512sum": hashlib.sha512}[prog]
    files = [a for a in args if not a.startswith("-")]
    if not files:
        return f"{algo((stdin or '').encode()).hexdigest()}  -\n", "", 0
    out, err = [], []
    for f in files:
        content, e = read_for(session, prog, f)
        if content is None:
            err.append(e)
            continue
        out.append(f"{algo(content.encode()).hexdigest()}  {f}")
    return ("\n".join(out) + "\n" if out else ""), "".join(err), 1 if err else 0


def which(session: Session, prog: str, args: list[str]) -> tuple[str, str, int]:
    names = [a for a in args if not a.startswith("-")]
    out, code = [], 0
    builtins = {"cd", "echo", "export", "history", "alias", "type", "pwd", "exit", "source", "unset"}
    for n in names:
        found = next((f"{d}/{n}" for d in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin")
                      if f"{d}/{n}" in session.host.filesystem), None)
        if prog == "type":
            if n in builtins:
                out.append(f"{n} is a shell builtin")
            elif found:
                out.append(f"{n} is {found}")
            else:
                out.append(f"-bash: type: {n}: not found")
                code = 1
        elif prog == "whereis":
            out.append(f"{n}: {found} /usr/share/man/man1/{n}.1.gz" if found else f"{n}:")
        elif found:
            out.append(found)
        else:
            code = 1
    return ("\n".join(out) + "\n" if out else ""), "", code
