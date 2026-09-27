from __future__ import annotations

from pathlib import Path

import pytest

from deception.command_engine.engine import execute
from deception.runtime.host import Session, VirtualHost

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / "deception" / "hosts" / "enterprise-web.yml"


@pytest.fixture
def session() -> Session:
    host = VirtualHost.load(HOST)
    return Session(host=host, session_id="test-session")


def test_pwd(session: Session) -> None:
    r = execute(session, "pwd")
    assert r.exit_code == 0
    assert r.stdout.strip() == "/home/admin"


def test_whoami(session: Session) -> None:
    r = execute(session, "whoami")
    assert r.stdout.strip() == "admin"


def test_ls_home(session: Session) -> None:
    r = execute(session, "ls")
    assert r.exit_code == 0
    assert "notes.txt" in r.stdout
    assert ".bashrc" in r.stdout


def test_cat_notes(session: Session) -> None:
    r = execute(session, "cat notes.txt")
    assert r.exit_code == 0
    assert "Deploy checklist" in r.stdout
    assert "finance-db-01" in r.stdout


def test_cd_and_pwd(session: Session) -> None:
    r = execute(session, "cd /var/www/html")
    assert r.exit_code == 0
    r = execute(session, "pwd")
    assert r.stdout.strip() == "/var/www/html"
    r = execute(session, "cat index.html")
    assert "Corp Intranet" in r.stdout


def test_unknown_command_uses_llm_fallback(session: Session) -> None:
    r = execute(session, "nmap 10.0.0.1")
    assert r.llm_fallback is True
    assert r.exit_code == 127
    assert "command not found" in r.stderr


def test_llm_fallback_uname_uses_hostname(session: Session) -> None:
    r = execute(session, "uname -a")
    assert r.llm_fallback is True
    assert r.exit_code == 0
    assert session.host.hostname in r.stdout


def test_ps(session: Session) -> None:
    r = execute(session, "ps")
    assert r.exit_code == 0
    assert "nginx" in r.stdout
    assert "PID" in r.stdout


def test_ip_addr_and_route(session: Session) -> None:
    r = execute(session, "ip addr")
    assert r.exit_code == 0
    assert "192.168.30.10/24" in r.stdout
    r = execute(session, "ip route")
    assert "192.168.30.254" in r.stdout
