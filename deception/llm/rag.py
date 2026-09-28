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


def _forced_mutation_hits(
    corpus: list[RagDocument], session: Session
) -> list[ScoredDocument]:
    """Always pin THIS attacker's profile + created paths into RAG context."""
    created = set(session.created_paths or [])
    actor = session.actor_id
    forced: list[ScoredDocument] = []
    for doc in corpus:
        meta = doc.metadata or {}
        if meta.get("type") == "actor_profile" and meta.get("actor_id") == actor:
            forced.append(ScoredDocument(document=doc, score=1.1))
            continue
        if doc.doc_id.startswith(f"actor.mutations:{actor}") or doc.doc_id == "actor.mutations":
            forced.append(ScoredDocument(document=doc, score=1.05))
            continue
        path = str(meta.get("path") or "")
        if path and path in created:
            forced.append(ScoredDocument(document=doc, score=1.02))
    return forced


def _forced_effects_hits(corpus: list[RagDocument], command: str) -> list[ScoredDocument]:
    """Pin real-system command-effect lore for create/delete/write/apt."""
    name = (command.strip().split() or [""])[0].lower()
    if name not in {
        "mkdir",
        "touch",
        "rm",
        "rmdir",
        "echo",
        "apt",
        "apt-get",
        "chmod",
        "chown",
        "cp",
        "mv",
    }:
        return []
    forced: list[ScoredDocument] = []
    for doc in corpus:
        if doc.doc_id in {"corpus:command_effects", "corpus:shell_behavior"}:
            forced.append(ScoredDocument(document=doc, score=1.2))
        if doc.doc_id.startswith("mutation.authority"):
            forced.append(ScoredDocument(document=doc, score=1.3))
    return forced


def retrieve_context(
    session: Session,
    command: str,
    *,
    top_k: int | None = None,
    include_mutation_authority: bool = True,
) -> str:
    """Embed + retrieve relevant virtual-host evidence for an unknown command."""
    from deception.llm.grounding import mutation_authority_block
    from rag.ingest import RagDocument as RD

    k = top_k or int(os.environ.get("NETOSIS_RAG_TOP_K", "4"))
    corpus = build_corpus(session)
    if include_mutation_authority and (
        session.last_created or session.last_deleted or session.last_packages
    ):
        corpus = list(corpus) + [
            RD(
                doc_id="mutation.authority",
                text=mutation_authority_block(session, command),
                metadata={"type": "mutation_authority", "actor_id": session.actor_id},
            )
        ]
    query = (
        f"{command} cwd={session.cwd} user={session.user} "
        f"host={session.host.hostname} ip={session.host.ip} "
        f"files filesystem notes config mkdir touch rm apt command effects"
    )

    mode = os.environ.get("NETOSIS_RETRIEVER", "hybrid").lower()
    dense_hits: list[ScoredDocument] = []
    lexical_hits: list[ScoredDocument] = []

    if mode in {"dense", "hybrid", "auto"}:
        dense_hits = DenseRetriever(corpus, get_embedder()).retrieve(query, top_k=k)
    if mode in {"lexical", "hybrid", "auto"}:
        lexical_hits = LexicalRetriever(corpus).retrieve(query, top_k=k)

    forced = _forced_file_hits(corpus, command)
    mutations = _forced_mutation_hits(corpus, session)
    effects = _forced_effects_hits(corpus, command)
    hits = _merge_hits(
        effects,
        mutations,
        forced,
        dense_hits,
        lexical_hits,
        top_k=max(k, len(forced) + len(mutations) + len(effects) + k),
    )
    hits = hits[: max(k + len(mutations) + len(effects), 1)]

    if not hits:
        hits = LexicalRetriever(corpus).retrieve(session.host.hostname, top_k=1)

    return "\n\n".join(
        f"[{i + 1}] ({h.document.doc_id}, score={h.score:.3f})\n{h.document.text}"
        for i, h in enumerate(hits)
    )
