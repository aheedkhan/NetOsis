"""High-level RAG helper for the LLM fallback (Antigravity Phase 3 contract).

Indexes the virtual filesystem / host state with a local embedding model
(all-MiniLM-L6-v2 when available) and returns a context string for Qwen 7B.
"""

from __future__ import annotations

import os
import re

from deception.runtime.host import Session
from rag.ingest import RagDocument, build_corpus
from rag.retrieval.dense import DenseRetriever
from rag.retrieval.embeddings import get_embedder
from rag.retrieval.retriever import LexicalRetriever, ScoredDocument


def _merge_hits(*groups: list[ScoredDocument], top_k: int) -> list[ScoredDocument]:
    best: dict[str, ScoredDocument] = {}
    for group in groups:
        for hit in group:
            doc_id = hit.document.doc_id
            prev = best.get(doc_id)
            if prev is None or hit.score > prev.score:
                best[doc_id] = hit
    merged = sorted(best.values(), key=lambda h: h.score, reverse=True)
    return merged[:top_k]


def _forced_file_hits(corpus: list[RagDocument], command: str) -> list[ScoredDocument]:
    """If the command names a path/basename, pin those file docs into context."""
    tokens = set(re.findall(r"[A-Za-z0-9_./-]+", command))
    forced: list[ScoredDocument] = []
    for doc in corpus:
        if doc.metadata.get("type") != "file":
            continue
        path = str(doc.metadata.get("path") or "")
        base = path.rsplit("/", 1)[-1]
        if path in tokens or base in tokens or any(t in path for t in tokens if len(t) > 3):
            forced.append(ScoredDocument(document=doc, score=1.0))
    return forced


def retrieve_context(
    session: Session,
    command: str,
    *,
    top_k: int | None = None,
) -> str:
    """Embed + retrieve relevant virtual-host evidence for an unknown command."""
    k = top_k or int(os.environ.get("NETOSIS_RAG_TOP_K", "4"))
    corpus = build_corpus(session)
    query = (
        f"{command} cwd={session.cwd} user={session.user} "
        f"host={session.host.hostname} ip={session.host.ip} "
        f"files filesystem notes config"
    )

    mode = os.environ.get("NETOSIS_RETRIEVER", "hybrid").lower()
    dense_hits: list[ScoredDocument] = []
    lexical_hits: list[ScoredDocument] = []

    if mode in {"dense", "hybrid", "auto"}:
        dense_hits = DenseRetriever(corpus, get_embedder()).retrieve(query, top_k=k)
    if mode in {"lexical", "hybrid", "auto"}:
        lexical_hits = LexicalRetriever(corpus).retrieve(query, top_k=k)

    forced = _forced_file_hits(corpus, command)
    hits = _merge_hits(forced, dense_hits, lexical_hits, top_k=max(k, len(forced) + k))
    hits = hits[: max(k, 1)]

    if not hits:
        hits = LexicalRetriever(corpus).retrieve(session.host.hostname, top_k=1)

    return "\n\n".join(
        f"[{i + 1}] ({h.document.doc_id}, score={h.score:.3f})\n{h.document.text}"
        for i, h in enumerate(hits)
    )
