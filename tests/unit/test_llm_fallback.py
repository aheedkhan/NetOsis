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
    assert "Do NOT invent" in prompt
    assert "ent-web-01" in prompt


def test_generate_response_accepts_retrieved_context() -> None:
    session = Session(host=VirtualHost.load(HOST), session_id="t")
    ctx = retrieve_context(session, "id")
    result = generate_response(session, "id", ctx, client=MockLlmClient())
    assert result.llm_fallback is True
    assert "admin" in result.stdout
