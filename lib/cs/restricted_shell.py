"""Restricted disposable shell — L2 engage actuator."""

from __future__ import annotations

import os
from typing import Callable

# Lab-only credentials. Override via config/shell-users.json in production builds.
ALLOWED: dict[str, str] = {
    "guest": "nexus2024",
    "admin": "changeme",
}

FAKE_PASSWD = """root:x:0:0:root:/root:/bin/bash
guest:x:1000:1000:Guest User:/home/guest:/bin/bash
admin:x:1001:1001:Admin:/home/admin:/bin/bash
"""

FAKE_HOSTNAME = "intranet-web-01"


def load_users(path: str | None = None) -> dict[str, str]:
    path = path or os.environ.get("CS_SHELL_USERS", "/config/shell-users.json")
    if not os.path.isfile(path):
        return dict(ALLOWED)
    import json

    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, dict) else dict(ALLOWED)


def handle_line(line: str, emit: Callable[[str], None] | None = None) -> str:
    line = line.strip()
    if not line:
        return ""
    parts = line.split()
    cmd = parts[0].lower()
    args = parts[1:]

    def out(text: str) -> str:
        if emit:
            emit(line)
        return text

    if cmd in ("exit", "logout"):
        return out("logout\n")
    if cmd == "whoami":
        return out("guest\n")
    if cmd == "id":
        return out("uid=1000(guest) gid=1000(guest) groups=1000(guest)\n")
    if cmd == "hostname":
        return out(f"{FAKE_HOSTNAME}\n")
    if cmd == "pwd":
        return out("/home/guest\n")
    if cmd == "uname":
        flag = args[0] if args else ""
        if flag == "-a":
            return out("Linux intranet-web-01 6.8.0-45-generic #45-Ubuntu SMP x86_64 GNU/Linux\n")
        return out("Linux\n")
    if cmd == "ls":
        target = args[0] if args else "."
        if target in (".", "/home/guest", "home"):
            return out("documents  downloads  .bashrc\n")
        if target in ("/etc", "etc"):
            return out("passwd  group  hostname  os-release\n")
        return out(f"ls: cannot access '{target}': No such file or directory\n")
    if cmd == "cat":
        if not args:
            return out("cat: missing operand\n")
        path = args[0]
        if path == "/etc/passwd":
            return out(FAKE_PASSWD)
        if path == "/etc/hostname":
            return out(f"{FAKE_HOSTNAME}\n")
        if path in ("/proc/version", "proc/version"):
            return out("Linux version 6.8.0-45-generic (build@ubuntu) (gcc) #45 SMP\n")
        if path.startswith("/proc/") or path.startswith("proc/"):
            return out(f"cat: {path}: Permission denied\n")
        return out(f"cat: {path}: No such file or directory\n")
    if cmd in ("wget", "curl"):
        host = args[0] if args else "http://malware.example/payload.sh"
        return out(
            f"{cmd}: fetching {host} ...\n"
            "# HTTP/1.1 200 OK — payload delivered (sinkhole stage 0)\n"
        )
    if cmd in ("nc", "ncat", "bash", "sh", "python", "python3"):
        return out(f"{cmd}: command not found\n")
    return out(f"{cmd}: command not found\n")
