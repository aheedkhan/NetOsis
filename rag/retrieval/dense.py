"""Dense vector retrieval over ingested virtual-host documents."""

from __future__ import annotations

import math

from rag.ingest import RagDocument
from rag.retrieval.embeddings import Embedder
from rag.retrieval.retriever import ScoredDocument


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


class DenseRetriever:
    """Embed corpus once, retrieve by cosine similarity."""

    def __init__(self, documents: list[RagDocument], embedder: Embedder) -> None:
        self.documents = documents
        self.embedder = embedder
        texts = [d.text for d in documents]
        self._vectors = embedder.embed(texts) if texts else []

    def retrieve(self, query: str, *, top_k: int = 4) -> list[ScoredDocument]:
        if not self.documents:
            return []
        q = self.embedder.embed([query])[0]
        scored: list[ScoredDocument] = []
        for doc, vec in zip(self.documents, self._vectors, strict=True):
            score = _cosine(q, vec)
            # Path hint boost when attacker names a file
            path = str(doc.metadata.get("path") or "")
            if path and path.lower() in query.lower():
                score += 0.15
            if score > 0:
                scored.append(ScoredDocument(document=doc, score=score))
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored[:top_k]
