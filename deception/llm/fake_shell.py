"""Fake shell theater for apt / nmap / curl — lore only, never real I/O."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from deception.runtime.host import Session

_LORE = Path(__file__).resolve().parents[1] / "lore" / "recon_targets.yml"


def load_recon_targets() -> dict[str, Any]:
    if not _LORE.is_file():
        return {"always_visible": [], "when_exposed": []}
    with _LORE.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def visible_targets(session: Session) -> list[dict[str, Any]]:
    data = load_recon_targets()
    out = list(data.get("always_visible") or [])
    exposed = set(session.exposed_hosts or [])
    for entry in data.get("when_exposed") or []:
        if entry.get("hostname") in exposed:
            out.append(entry)
    return out


def _find_target(session: Session, needle: str) -> dict[str, Any] | None:
    needle = needle.strip()
    for t in visible_targets(session):
        if t.get("ip") == needle or t.get("hostname") == needle:
            return t
        host = str(t.get("hostname") or "")
        if host.startswith(needle + ".") or host.split(".")[0] == needle:
            return t
    return None


def format_nmap_report(session: Session, target_ip: str) -> str:
    """Plausible nmap -sV stdout for one IP/hostname from lore."""
    t = _find_target(session, target_ip)
    if t is None:
        return (
            f"Starting Nmap 7.80 ( https://nmap.org )\n"
            f"Note: Host seems down.\n"
            f"Nmap done: 1 IP address (0 hosts up) scanned in 3.01 seconds\n"
        )
    ip = t.get("ip", target_ip)
    hostname = t.get("hostname", "")
    ports = t.get("ports") or []
    lines = [
        "Starting Nmap 7.80 ( https://nmap.org ) at 2024-06-12 14:22 UTC",
        f"Nmap scan report for {hostname} ({ip})" if hostname else f"Nmap scan report for {ip}",
        "Host is up (0.00042s latency).",
    ]
    if not ports:
        lines.append("All 1000 scanned ports on this host are filtered")
    else:
        closed = max(0, 1000 - len(ports))
        lines.append(f"Not shown: {closed} closed ports")
        lines.append("PORT     STATE SERVICE    VERSION")
        for p in ports:
            port = p.get("port")
            state = p.get("state", "open")
            service = p.get("service", "unknown")
            version = p.get("version", "")
            left = f"{port}/tcp"
            lines.append(f"{left:<8} {state:<5} {service:<10} {version}".rstrip())
    lines.append("Service detection performed.")
    lines.append("Nmap done: 1 IP address (1 host up) scanned in 1.84 seconds")
    return "\n".join(lines) + "\n"


def parse_nmap_target(command: str) -> str | None:
    """Best-effort: last IPv4 or hostname-looking token after nmap."""
    try:
        parts = command.split()
    except Exception:
        return None
    if not parts or parts[0] != "nmap":
        return None
    ip_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
    for tok in reversed(parts[1:]):
        if tok.startswith("-"):
            continue
        if ip_re.match(tok) or "." in tok or tok.replace("-", "").isalnum():
            return tok
    return "127.0.0.1"


def apt_already_newest(packages: list[str]) -> str:
    pkgs = " ".join(packages) if packages else "nmap"
    return (
        "Reading package lists... Done\n"
        "Building dependency tree... Done\n"
        "Reading state information... Done\n"
        f"{pkgs} is already the newest version (7.80+dfsg1-2build1).\n"
        "0 upgraded, 0 newly installed, 0 to remove and 12 not upgraded.\n"
    )


def curl_head_localhost() -> str:
    return (
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.18.0 (Ubuntu)\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 48\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    )


def id_line(user: str) -> str:
    if user == "root":
        return "uid=0(root) gid=0(root) groups=0(root)\n"
    return f"uid=1000({user}) gid=1000({user}) groups=1000({user}),27(sudo)\n"
