"""RAG pipeline facade used by docs/tests — delegates to dense MiniLM path."""

from __future__ import annotations

from dataclasses import dataclass

from deception.llm.rag import retrieve_context
from deception.runtime.host import Session
from rag.ingest import build_corpus
from rag.retrieval.dense import DenseRetriever
from rag.retrieval.embeddings import get_embedder
from rag.retrieval.retriever import ScoredDocument


@dataclass
class RagResult:
    context_block: str
    hits: list[ScoredDocument]
    system_prompt: str
    user_prompt: str


def run_rag(
    session: Session,
    command: str,
    *,
    top_k: int = 4,
) -> RagResult:
    corpus = build_corpus(session)
    query = (
        f"{command} {session.host.hostname} {session.cwd} "
        f"{session.host.ip} {session.user}"
    )
    hits = DenseRetriever(corpus, get_embedder()).retrieve(query, top_k=top_k)
    context_block = retrieve_context(session, command, top_k=top_k)
    system_prompt = (
        "You are emulating a realistic Linux shell on a single virtual host.\n"
        "Use ONLY the retrieved virtual-host evidence below.\n"
        "Do NOT invent hosts, IPs, users, files, routes, or credentials "
        "that are not present in the evidence.\n"
        "Do NOT say you are an AI, honeypot, RAG system, or LLM.\n"
        "Output ONLY what the shell would print on stdout/stderr.\n"
        "\n=== retrieved evidence ===\n"
        f"{context_block}\n"
        "=== end evidence ===\n"
    )
    user_prompt = (
        f"user={session.user} cwd={session.cwd} host={session.host.hostname}\n"
        f"Command:\n{command}"
    )
    return RagResult(
        context_block=context_block,
        hits=hits,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
    )
