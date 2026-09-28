from __future__ import annotations

import os
from pathlib import Path

from deception.runtime.host import Session, VirtualHost
from rag.ingest import build_corpus
from rag.pipeline import run_rag
from rag.retrieval.retriever import LexicalRetriever

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / "deception" / "hosts" / "enterprise-web.yml"


def setup_module() -> None:
    os.environ["NETOSIS_EMBED_MODE"] = "hash"


def test_ingest_builds_identity_and_files() -> None:
    session = Session(host=VirtualHost.load(HOST), session_id="t")
    docs = build_corpus(session)
    ids = {d.doc_id for d in docs}
    assert "host.identity" in ids
    assert any(i.startswith("fs:") for i in ids)
    assert any(i.startswith("fsdir:") for i in ids)
    assert "corpus:network_topology" in ids
    assert "corpus:internal_tools" in ids
    assert "corpus:system_architecture" in ids


def test_static_corpus_retrievable() -> None:
    session = Session(host=VirtualHost.load(HOST), session_id="t")
    retriever = LexicalRetriever(build_corpus(session))
    hits = retriever.retrieve("VLAN 10 Finance gateway 192.168.10.254", top_k=5)
    joined = " ".join(h.document.text for h in hits)
    assert "192.168.10" in joined or "Finance" in joined


def test_retriever_finds_network_for_ip_query() -> None:
    session = Session(host=VirtualHost.load(HOST), session_id="t")
    retriever = LexicalRetriever(build_corpus(session))
    hits = retriever.retrieve("ip addr eth0 route gateway", top_k=3)
    assert hits
    joined = " ".join(h.document.text for h in hits)
    assert "192.168.30" in joined or "eth0" in joined


def test_run_rag_prompt_contains_evidence() -> None:
    session = Session(host=VirtualHost.load(HOST), session_id="t")
    rag = run_rag(session, "uname -a", top_k=3)
    assert "retrieved evidence" in rag.system_prompt
    assert session.host.hostname in rag.system_prompt
