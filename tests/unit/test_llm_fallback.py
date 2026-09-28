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


def test_unknown_command_marked_as_llm() -> None:
    from deception.command_engine.engine import execute

    session = Session(host=VirtualHost.load(HOST), session_id="t")
    r = execute(session, "zzznonsense_cmd_99")
    assert r.llm_fallback is True
    blob = r.stdout + r.stderr
    assert "[llm]" in blob
    assert "command not found" in blob


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
