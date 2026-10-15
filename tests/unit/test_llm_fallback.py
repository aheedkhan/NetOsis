from __future__ import annotations

import os
from pathlib import Path

from deception.llm.fallback import MockLlmClient, build_system_prompt, generate_response
from deception.llm.rag import retrieve_context
from deception.runtime.host import Session, VirtualHost
from rag.ingest import build_corpus
from rag.retrieval.dense import DenseRetriever
from rag.retrieval.embeddings import HashEmbedder

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / "deception" / "hosts" / "enterprise-web.yml"


def setup_module() -> None:
    os.environ["NETOSIS_EMBED_MODE"] = "hash"


def test_retrieve_context_includes_hostname() -> None:
    session = Session(host=VirtualHost.load(HOST), session_id="t")
    ctx = retrieve_context(session, "cat notes.txt")
    assert "ent-web-01" in ctx
    assert "notes" in ctx.lower() or "Deploy checklist" in ctx


def test_dense_hash_retriever_ranks_files() -> None:
    session = Session(host=VirtualHost.load(HOST), session_id="t")
    corpus = build_corpus(session)
    hits = DenseRetriever(corpus, HashEmbedder()).retrieve("notes deploy checklist", top_k=3)
    assert hits
    assert any("notes" in h.document.doc_id or "notes" in h.document.text.lower() for h in hits)


def test_system_prompt_is_state_constrained() -> None:
    session = Session(host=VirtualHost.load(HOST), session_id="t")
    prompt = build_system_prompt(session, "uname -a")
    assert "ANTI-HALLUCINATION" in prompt or "Never invent" in prompt
    assert "ent-web-01" in prompt


def test_generate_response_accepts_retrieved_context() -> None:
    session = Session(host=VirtualHost.load(HOST), session_id="t")
    ctx = retrieve_context(session, "id")
    result = generate_response(session, "id", ctx, client=MockLlmClient())
    assert result.llm_fallback is True
    assert "admin" in result.stdout
    assert "[llm]" in result.stdout


def test_junk_command_skips_llm() -> None:
    from deception.command_engine.engine import execute

    session = Session(host=VirtualHost.load(HOST), session_id="t")
    r = execute(session, "zzznonsense_cmd_99")
    assert r.llm_fallback is False
    assert r.exit_code == 127
    assert r.stderr == "bash: zzznonsense_cmd_99: command not found\n"


def test_real_binary_goes_to_llm_and_is_marked() -> None:
    from deception.command_engine.engine import execute

    session = Session(host=VirtualHost.load(HOST), session_id="t")
    r = execute(session, "uptime")
    assert r.llm_fallback is True
    assert "[llm]" in r.stdout


class _CountingClient:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.calls += 1
        return f"Filesystem output #{self.calls}"


def test_cache_returns_identical_answer_without_llm(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("NETOSIS_LLM_CACHE", "1")
    monkeypatch.setenv("NETOSIS_DATA_DIR", str(tmp_path))
    session = Session(host=VirtualHost.load(HOST), session_id="t")
    client = _CountingClient()
    first = generate_response(session, "df -h", "", client=client)
    second = generate_response(session, "df  -h", "", client=client)
    assert first.stdout == second.stdout
    assert client.calls == 1
    assert (tmp_path / "llm_cache.json").is_file()


def test_llm_error_is_not_cached(tmp_path, monkeypatch) -> None:
    class _Down:
        def complete(self, system_prompt: str, user_prompt: str) -> str:
            raise RuntimeError("LLM unreachable")

    monkeypatch.setenv("NETOSIS_LLM_CACHE", "1")
    monkeypatch.setenv("NETOSIS_DATA_DIR", str(tmp_path))
    session = Session(host=VirtualHost.load(HOST), session_id="t")
    r = generate_response(session, "df -h", "", client=_Down())
    assert "command not found" in r.stderr
    assert not (tmp_path / "llm_cache.json").exists()


def test_sudo_elevates_and_id_shows_root() -> None:
    from deception.command_engine.engine import execute

    session = Session(host=VirtualHost.load(HOST), session_id="t")
    execute(session, "sudo su")
    assert session.user == "root"
    assert session.shell_prompt().endswith("# ")
    r = execute(session, "id")
    assert "uid=0(root)" in r.stdout


def test_apt_and_nmap_are_theater_not_llm() -> None:
    from deception.command_engine.engine import execute

    session = Session(host=VirtualHost.load(HOST), session_id="t")
    apt = execute(session, "sudo apt install nmap")
    # apt stdout narrated by LLM but grounded; package still profiled
    assert "already the newest" in (apt.stdout + apt.stderr) or apt.llm_fallback
    assert "nmap" in session.packages_attempted
    nm = execute(session, "nmap -sV 192.168.30.10")
    assert nm.llm_fallback is False
    assert "OpenSSH" in nm.stdout
    assert "nginx" in nm.stdout
