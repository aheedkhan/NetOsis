"""An attacker inside the fake shell must find no trace of the real lab:
no NetOsis services or users, no agent, no controller address, no real IPs."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from deception.command_engine.engine import execute
from deception.runtime.host import Session, VirtualHost

ROOT = Path(__file__).resolve().parents[2]
HOSTS = sorted((ROOT / "deception" / "hosts").glob("*.yml"))

RECON = [
    "ps aux", "ps -ef", "top -bn1", "ss -tulpn", "ss -tanp", "netstat -tulpn", "netstat -an",
    "systemctl list-units --type=service", "systemctl status", "cat /etc/passwd", "cat /etc/group",
    "ls -la /etc", "ls -la /opt", "ls -la /usr/local/lib", "ls -la /etc/systemd/system",
    "env", "cat /proc/net/tcp", "ip a", "ip route", "cat /etc/hosts", "crontab -l",
    "journalctl -n 50", "ls /var/log", "cat /etc/resolv.conf", "arp -a", "who", "last",
]
FORBIDDEN = re.compile(
    r"netosis|honeypot|node[-_ ]?agent|netosis-agent|/etc/netosis|8001|192\.168\.40\.|"
    r"x-netosis|ingest|controller\.py|paramiko|ssh_honeypot|ollama|11434",
    re.I,
)


@pytest.mark.parametrize("host", HOSTS, ids=lambda p: p.stem)
def test_recon_commands_show_no_lab_internals(host: Path) -> None:
    session = Session(host=VirtualHost.load(host), session_id="leak-check")
    for cmd in RECON:
        r = execute(session, cmd)
        out = f"{r.stdout}\n{r.stderr}"
        hit = FORBIDDEN.search(out)
        assert hit is None, f"{host.stem}: `{cmd}` reveals {hit.group(0)!r}"
