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
    r = execute(session, "zzznonsense_cmd_99")
    assert r.llm_fallback is True
    assert r.exit_code == 127
    assert "command not found" in (r.stdout + r.stderr)


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


def test_mkdir_rm_syncs_session_and_rag(session: Session) -> None:
    from deception.llm.rag import retrieve_context

    r = execute(session, "mkdir loot")
    assert r.exit_code == 0
    assert "/home/admin/loot" in session.created_paths
    assert "/home/admin/loot" in session.host.filesystem
    ctx = retrieve_context(session, "ls loot directory")
    assert "loot" in ctx.lower() or "/home/admin/loot" in ctx

    execute(session, "echo secret > loot/flag.txt")
    assert "/home/admin/loot/flag.txt" in session.created_paths
    ctx2 = retrieve_context(session, "flag.txt secret")
    assert "secret" in ctx2 or "flag.txt" in ctx2

    execute(session, "rm -rf loot")
    assert "/home/admin/loot" not in session.host.filesystem
    assert "/home/admin/loot" in session.deleted_paths
    from rag.ingest import build_corpus

    ids = {d.doc_id for d in build_corpus(session)}
    assert "fsdir:/home/admin/loot" not in ids
    assert "fs:/home/admin/loot/flag.txt" not in ids
    assert any(i.startswith("actor.mutations:") for i in ids)


def test_mkdir_narrated_by_llm_but_fs_is_truth(session: Session) -> None:
    r = execute(session, "mkdir grounded_dir")
    assert "/home/admin/grounded_dir" in session.host.filesystem
    assert r.llm_fallback is True
    # Real bash: silent success — mock LLM returns empty
    assert r.stdout == ""
    from deception.llm.rag import retrieve_context

    ctx = retrieve_context(session, "mkdir grounded_dir")
    assert "AUTHORITATIVE MUTATION RECORD" in ctx or "grounded_dir" in ctx
    assert "command_effects" in ctx or "mkdir" in ctx.lower()


def test_file_create_raises_fs_risk() -> None:
    from attack_graph.model.graph import AttackGraph
    from deception.runtime.pipeline import VerticalSlicePipeline
    from deception.runtime.profile_store import ProfileStore
    from mitre.mapper.mapper import _load_mappings
    from policy.engine.engine import clear_rules_cache
    from telemetry.storage.jsonl import JsonlTelemetryStore
    import tempfile
    from pathlib import Path

    clear_rules_cache()
    _load_mappings.cache_clear()
    host = VirtualHost.load(HOST)
    session = Session(host=host, session_id="risk-fs", actor_id="actor-risk-fs-test")
    with tempfile.TemporaryDirectory() as tmp:
        store = JsonlTelemetryStore(Path(tmp) / "t.jsonl")
        pipe = VerticalSlicePipeline(
            session=session,
            store=store,
            graph=AttackGraph(),
            profile_store=ProfileStore(Path(tmp) / "profiles"),
        )
        _, _, decision = pipe.run_command("echo pwned > notes2.txt")
        assert pipe.events[-1].get("risk_category") == "FS_create"
        assert decision.risk_score >= 2

        _, _, d2 = pipe.run_command("mkdir -p /etc/evil")
        assert pipe.events[-1].get("risk_category") == "FS_create_sensitive"
        assert d2.risk_score > decision.risk_score
