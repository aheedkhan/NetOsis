"""
Restricted disposable shell — L2/L3 engage actuator.

Two things changed from the first version of this module. It used to be a
flat, stateless `if/elif` chain: `pwd` always printed `/home/guest` regardless
of any `cd`, because there was no `cd` and no per-session working directory
at all — the shallowest kind of tell a real operator finds in about four
commands. It now wraps a `RestrictedShell` instance per connection, holding
real `cd` state against `cs.virtual_fs.VirtualFS`, so the filesystem the
attacker walks is the layered, level-gated tree that module authors rather
than a handful of hardcoded strings.

Second, every filesystem touch now reports structured metadata — which path,
whether it was a directory listing or a read, and whether the path is tagged
`sensitive` or `honeytoken` — back through `emit`, instead of only the raw
command line. That is what lets the decision plane score "read the
credentials file" differently from "ran ls twice", which the previous
version could not distinguish at all: `emit` only ever saw the command text.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from cs.virtual_fs import Node, VirtualFS

# Lab-only credentials. Override via config/shell-users.json in production builds.
ALLOWED: dict[str, str] = {
    "guest": "nexus2024",
    "admin": "changeme",
}

FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
guest:x:1000:1000:Guest User:/home/guest:/bin/bash
admin:x:1001:1001:Admin:/home/admin:/bin/bash
tomasz:x:1002:1002:Tomasz Wojcik:/home/tomasz:/bin/bash
praghunathan:x:1003:1003:Priya Raghunathan:/home/praghunathan:/bin/bash
"""

FAKE_HOSTNAME = "intranet-web-01"

_VM_CHECK_TOKENS = ("dmesg", "systemd-detect-virt", "virt-what", "lscpu", "/proc/cpuinfo")


def load_users(path: str | None = None) -> dict[str, str]:
    path = path or os.environ.get("CS_SHELL_USERS", "/config/shell-users.json")
    if not os.path.isfile(path):
        return dict(ALLOWED)
    import json

    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, dict) else dict(ALLOWED)


@dataclass
class FileTouch:
    """What one command told the fs about — the decision plane's real evidence."""

    paths: list[str] = field(default_factory=list)
    action: str = "read"  # "list" | "read" | "search"
    sensitivity: str | None = None  # None | "sensitive" | "honeytoken"
    found: bool = True


@dataclass
class CommandResult:
    output: str
    logout: bool = False
    vm_check: bool = False
    touch: FileTouch | None = None
    # Set only for a genuinely unrecognised command (not the deliberate
    # deny-list — nc/python/etc are meant to look present-but-broken, not
    # improvised). The caller (ssh_surface) decides whether to route this
    # through the LLM fallback or just print `output` as-is; RestrictedShell
    # itself stays synchronous and knows nothing about Ollama.
    needs_llm: bool = False


class RestrictedShell:
    """One instance per SSH session. `level` may change mid-session (a live
    escalation to L3 opens the deeper tree immediately, matching how the
    manifest already updates a connected session's other capabilities)."""

    def __init__(self, level: str = "L2") -> None:
        self.level = level
        self.cwd = "/home/guest"

    def set_level(self, level: str) -> None:
        self.level = level

    # -- dispatch -----------------------------------------------------------

    def handle_line(self, line: str) -> CommandResult:
        line = line.strip()
        if not line:
            return CommandResult("")
        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("exit", "logout"):
            return CommandResult("logout\n", logout=True)
        if cmd == "whoami":
            return CommandResult("guest\n")
        if cmd == "id":
            return CommandResult("uid=1000(guest) gid=1000(guest) groups=1000(guest)\n")
        if cmd == "hostname":
            return CommandResult(f"{FAKE_HOSTNAME}\n")
        if cmd == "pwd":
            return CommandResult(f"{self.cwd}\n")
        if cmd == "history":
            return self._cat(["/home/guest/.bash_history"])
        if cmd == "uname":
            flag = args[0] if args else ""
            if flag == "-a":
                return CommandResult(
                    "Linux intranet-web-01 6.8.0-45-generic #45-Ubuntu SMP x86_64 GNU/Linux\n"
                )
            return CommandResult("Linux\n")
        if cmd in ("nc", "ncat", "python", "python3", "gcc", "make", "vim", "nano"):
            # Present, but not usable — a bare-metal decoy would have these
            # missing or broken, not a working compiler an operator could
            # pivot with.
            return CommandResult(f"bash: {cmd}: command not found\n")
        if cmd in ("wget", "curl"):
            host = args[-1] if args else "http://malware.example/payload.sh"
            return CommandResult(
                f"{cmd}: fetching {host} ...\n"
                "# HTTP/1.1 200 OK — payload delivered (sinkhole stage 0)\n"
            )
        if cmd == "cd":
            return self._cd(args)
        if cmd == "ls":
            return self._ls(args)
        if cmd == "cat":
            return self._cat(args)
        if cmd in ("head", "tail"):
            return self._head_tail(cmd, args)
        if cmd == "find":
            return self._find(args)
        if cmd == "grep":
            return self._grep(args)
        if cmd == "file":
            return self._file(args)
        if any(tok in line.lower() for tok in _VM_CHECK_TOKENS):
            return self._vm_check(cmd, args)
        return CommandResult(f"bash: {cmd}: command not found\n", needs_llm=True)

    def listing_names(self) -> list[str]:
        """Names visible in the current directory — the LLM fallback's only
        grounding in the authored tree, so it extends the story instead of
        contradicting it."""
        result = self._fs().resolve(self.cwd, self.cwd)
        if not result.visible or not result.node.is_dir():
            return []
        return sorted(c.name for c in self._fs().listing(result.node))

    # -- filesystem-aware commands ------------------------------------------

    def _fs(self) -> VirtualFS:
        return VirtualFS(self.level)

    def _cd(self, args: list[str]) -> CommandResult:
        target = args[0] if args else "/home/guest"
        fs = self._fs()
        result = fs.resolve(target, self.cwd)
        if not result.visible:
            return CommandResult(f"bash: cd: {target}: No such file or directory\n")
        if not result.node.is_dir():
            return CommandResult(f"bash: cd: {target}: Not a directory\n")
        self.cwd = result.abs_path
        return CommandResult("")

    def _ls(self, args: list[str]) -> CommandResult:
        long = any(a.startswith("-") and "l" in a for a in args)
        targets = [a for a in args if not a.startswith("-")] or ["."]
        fs = self._fs()
        lines: list[str] = []
        touched: list[str] = []
        sensitivity = None
        for target in targets:
            result = fs.resolve(target, self.cwd)
            if not result.visible:
                lines.append(f"ls: cannot access '{target}': No such file or directory")
                continue
            touched.append(result.abs_path)
            if not result.node.is_dir():
                lines.append(result.node.name if not long else fs.ls_line(result.node))
                sensitivity = sensitivity or result.node.sensitivity
                continue
            entries = fs.listing(result.node)
            if long:
                lines.append(f"total {len(entries)}")
                lines.extend(fs.ls_line(c) for c in sorted(entries, key=lambda n: n.name))
            else:
                lines.append("  ".join(sorted(c.name for c in entries)))
        touch = FileTouch(paths=touched, action="list", sensitivity=sensitivity) if touched else None
        return CommandResult(("\n".join(lines) + "\n") if lines else "\n", touch=touch)

    def _cat(self, args: list[str]) -> CommandResult:
        if not args:
            return CommandResult("cat: missing operand\n")
        fs = self._fs()
        out: list[str] = []
        touched: list[str] = []
        sensitivity = None
        for path in args:
            result = fs.resolve(path, self.cwd)
            if not result.visible:
                out.append(f"cat: {path}: No such file or directory")
                continue
            if result.node.is_dir():
                out.append(f"cat: {path}: Is a directory")
                continue
            out.append(result.node.content.rstrip("\n"))
            touched.append(result.abs_path)
            if result.node.sensitivity:
                sensitivity = result.node.sensitivity
        touch = FileTouch(paths=touched, action="read", sensitivity=sensitivity) if touched else None
        return CommandResult("\n".join(out) + "\n", touch=touch)

    def _head_tail(self, cmd: str, args: list[str]) -> CommandResult:
        n = 10
        paths = []
        i = 0
        while i < len(args):
            if args[i] == "-n" and i + 1 < len(args):
                try:
                    n = int(args[i + 1])
                except ValueError:
                    pass
                i += 2
                continue
            if not args[i].startswith("-"):
                paths.append(args[i])
            i += 1
        if not paths:
            return CommandResult(f"{cmd}: missing operand\n")
        fs = self._fs()
        result = fs.resolve(paths[0], self.cwd)
        if not result.visible or result.node.is_dir():
            return CommandResult(f"{cmd}: cannot open '{paths[0]}' for reading: No such file or directory\n")
        lines = result.node.content.splitlines()
        chunk = lines[:n] if cmd == "head" else lines[-n:]
        touch = FileTouch(paths=[result.abs_path], action="read", sensitivity=result.node.sensitivity)
        return CommandResult("\n".join(chunk) + "\n", touch=touch)

    def _find(self, args: list[str]) -> CommandResult:
        start = args[0] if args and not args[0].startswith("-") else self.cwd
        fs = self._fs()
        result = fs.resolve(start, self.cwd)
        if not result.visible:
            return CommandResult(f"find: '{start}': No such file or directory\n")

        found: list[str] = []

        def walk(node: Node, path: str) -> None:
            found.append(path)
            if node.is_dir():
                for child in fs.listing(node):
                    walk(child, path.rstrip("/") + "/" + child.name)

        walk(result.node, result.abs_path)
        touch = FileTouch(paths=[result.abs_path], action="search")
        return CommandResult("\n".join(found) + "\n", touch=touch)

    def _grep(self, args: list[str]) -> CommandResult:
        recursive = any(a in ("-r", "-R", "-ri", "-ir") for a in args)
        rest = [a for a in args if not a.startswith("-")]
        if len(rest) < 1:
            return CommandResult("Usage: grep [OPTION]... PATTERNS [FILE]...\n")
        pattern = rest[0]
        paths = rest[1:] or [self.cwd]
        fs = self._fs()
        matches: list[str] = []
        touched: list[str] = []
        sensitivity = None

        def scan(node: Node, path: str) -> None:
            nonlocal sensitivity
            if node.is_dir():
                if recursive:
                    for child in fs.listing(node):
                        scan(child, path.rstrip("/") + "/" + child.name)
                return
            touched.append(path)
            if node.sensitivity:
                sensitivity = node.sensitivity
            for line in node.content.splitlines():
                if pattern.lower() in line.lower():
                    matches.append(f"{path}:{line}" if len(paths) > 1 or recursive else line)

        for p in paths:
            result = fs.resolve(p, self.cwd)
            if result.visible:
                scan(result.node, result.abs_path)
        touch = FileTouch(paths=touched, action="search", sensitivity=sensitivity) if touched else None
        return CommandResult(("\n".join(matches) + "\n") if matches else "", touch=touch)

    def _file(self, args: list[str]) -> CommandResult:
        if not args:
            return CommandResult("file: missing operand\n")
        fs = self._fs()
        result = fs.resolve(args[0], self.cwd)
        if not result.visible:
            return CommandResult(f"{args[0]}: cannot open: No such file or directory\n")
        kind = "directory" if result.node.is_dir() else "ASCII text"
        return CommandResult(f"{args[0]}: {kind}\n")

    def _vm_check(self, cmd: str, args: list[str]) -> CommandResult:
        if cmd == "dmesg" or (args and "cpuinfo" in " ".join(args)):
            if "cpuinfo" in " ".join([cmd, *args]):
                text = (
                    "processor\t: 0\nvendor_id\t: GenuineIntel\n"
                    "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
                )
            else:
                text = "[    0.000000] Linux version 6.8.0-45-generic\n[    0.041203] BIOS-provided physical RAM map:\n"
        elif cmd == "systemd-detect-virt":
            text = "none\n"
        elif cmd == "virt-what":
            text = ""
        elif cmd == "lscpu":
            text = "Architecture:            x86_64\nCPU(s):                  8\nModel name:              Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
        else:
            text = ""
        return CommandResult(text, vm_check=True)
