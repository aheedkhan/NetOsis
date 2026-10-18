from __future__ import annotations

from pathlib import Path

import pytest

from deception.command_engine.engine import execute
from deception.network import theater
from deception.runtime.host import Session, VirtualHost

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / "deception" / "hosts" / "enterprise-web.yml"


@pytest.fixture
def session() -> Session:
    return Session(host=VirtualHost.load(HOST), session_id="test-session")


# --------------------------------------------------------------------------- pipes / chains


def test_pipe_grep_over_cat(session: Session) -> None:
    r = execute(session, "cat /etc/passwd | grep bash")
    assert r.exit_code == 0
    assert "root:" in r.stdout
    assert "nologin" not in r.stdout


def test_pipe_chain_head_wc(session: Session) -> None:
    r = execute(session, "cat /etc/passwd | wc -l")
    assert r.exit_code == 0
    assert int(r.stdout.strip()) > 20


def test_semicolon_runs_both_regardless(session: Session) -> None:
    r = execute(session, "cat /nope.txt; echo after")
    assert "No such file" in r.stderr
    assert "after" in r.stdout


def test_and_short_circuits_on_failure(session: Session) -> None:
    r = execute(session, "cat /nope.txt && echo should_not_print")
    assert "should_not_print" not in r.stdout


def test_or_runs_on_failure(session: Session) -> None:
    r = execute(session, "cat /nope.txt || echo recovered")
    assert "recovered" in r.stdout


def test_redirect_from_pipe_writes_file(session: Session) -> None:
    r = execute(session, "echo hi there | tr a-z A-Z > /tmp/out.txt")
    assert r.stdout == ""
    r2 = execute(session, "cat /tmp/out.txt")
    assert r2.stdout.strip() == "HI THERE"


# --------------------------------------------------------------------------- permissions


def test_shadow_denied_then_sudo_allows(session: Session) -> None:
    r = execute(session, "cat /etc/shadow")
    assert r.exit_code != 0
    assert "Permission denied" in r.stderr

    r2 = execute(session, "sudo cat /etc/shadow")
    assert r2.exit_code == 0
    assert "root:" in r2.stdout


def test_ls_hides_dotfiles_without_a(session: Session) -> None:
    r = execute(session, "ls")
    assert ".bashrc" not in r.stdout
    r2 = execute(session, "ls -la")
    assert ".bashrc" in r2.stdout
    assert "admin" in r2.stdout  # owner column


# --------------------------------------------------------------------------- find / passwd realism


def test_find_locates_file(session: Session) -> None:
    r = execute(session, 'find /home -name "*.txt"')
    assert "/home/admin/notes.txt" in r.stdout


def test_passwd_has_real_system_accounts(session: Session) -> None:
    r = execute(session, "cat /etc/passwd")
    assert "www-data" in r.stdout
    assert "sshd" in r.stdout
    assert "admin" in r.stdout


# --------------------------------------------------------------------------- network theater


def test_nmap_same_vlan_vs_other_vlan(session: Session) -> None:
    same = execute(session, "nmap -sV 192.168.30.10")
    assert "22/tcp" in same.stdout
    assert "open" in same.stdout

    other = execute(session, "nmap -sV 192.168.10.10")
    assert "seems down" in other.stdout


def test_ping_reachable_same_vlan(session: Session) -> None:
    r = execute(session, "ping -c 2 192.168.30.254")
    assert r.exit_code == 0
    assert "0% packet loss" in r.stdout


def test_ping_other_vlan_unreachable(session: Session) -> None:
    r = execute(session, "ping -c 2 192.168.10.10")
    assert r.exit_code == 1
    assert "100% packet loss" in r.stdout


def test_ssh_pivot_blocked_until_exposed(session: Session) -> None:
    r = execute(session, "ssh dba@192.168.10.10")
    assert r.exit_code == 255
    assert r.pivot_target is None

    session.exposed_hosts.append("finance-db-01")
    r2 = execute(session, "ssh dba@192.168.10.10")
    assert r2.pivot_target == {
        "ip": "192.168.10.10", "hostname": "finance-db-01", "port": 2222,
        "ctid": 104, "requested_user": "dba",
    }


def test_ssh_denied_host_rejects_password(session: Session) -> None:
    # ent-jump-01 is same-VLAN and reachable, but topology marks it ssh: deny.
    r = execute(session, "ssh root@192.168.30.31")
    assert r.exit_code == 255
    assert r.pivot_target is None
    assert "Permission denied" in r.stderr


def test_resolve_ssh_target_matches_nmap() -> None:
    session = Session(host=VirtualHost.load(HOST), session_id="x")
    target = theater.resolve_ssh_target(session, "admin@192.168.30.10")
    assert target is not None
    assert target.is_pivot is True
    assert target.ip == "192.168.30.10"


def test_history_is_a_builtin_not_command_not_found(session: Session) -> None:
    execute(session, "whoami")
    execute(session, "id")
    r = execute(session, "history")
    assert r.exit_code == 0 and r.llm_fallback is False
    assert "command not found" not in r.stdout + r.stderr
    assert r.stdout.rstrip().endswith("history")  # bash lists the history command itself
    assert "whoami" in r.stdout
    assert len(execute(session, "history 2").stdout.splitlines()) == 2
    execute(session, "history -c")
    assert "whoami" not in execute(session, "history").stdout
