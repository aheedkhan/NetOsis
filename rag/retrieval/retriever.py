"""Lightweight lexical retriever (TF-IDF style).

Maps to NVIDIA RAG Blueprint retrieve stage without requiring NeMo Embed NIM /
Elasticsearch. Swap-in dense embeddings later via the same Retriever protocol.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from rag.ingest import RagDocument


_TOKEN = re.compile(r"[a-z0-9_./:-]+", re.I)


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN.findall(text)]


@dataclass
class ScoredDocument:
    document: RagDocument
    score: float


class LexicalRetriever:
    """In-memory sparse retrieval over a document corpus."""

    def __init__(self, documents: list[RagDocument]) -> None:
        self.documents = documents
        self._docs_tokens: list[list[str]] = [_tokenize(d.text) for d in documents]
        df: Counter[str] = Counter()
        for tokens in self._docs_tokens:
            for term in set(tokens):
                df[term] += 1
        self._df = df
        self._n = max(len(documents), 1)

    def _tfidf(self, tokens: list[str]) -> dict[str, float]:
        tf = Counter(tokens)
        length = max(len(tokens), 1)
        vec: dict[str, float] = {}
        for term, count in tf.items():
            idf = math.log((1 + self._n) / (1 + self._df.get(term, 0))) + 1.0
            vec[term] = (count / length) * idf
        return vec

    @staticmethod
    def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
        if not a or not b:
            return 0.0
        dot = sum(v * b.get(k, 0.0) for k, v in a.items())
        na = math.sqrt(sum(v * v for v in a.values()))
        nb = math.sqrt(sum(v * v for v in b.values()))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)

    def retrieve(self, query: str, *, top_k: int = 4) -> list[ScoredDocument]:
        q = self._tfidf(_tokenize(query))
        scored: list[ScoredDocument] = []
        for doc, tokens in zip(self.documents, self._docs_tokens, strict=True):
            score = self._cosine(q, self._tfidf(tokens))
            # Light keyword boost for exact path / hostname hits
            ql = query.lower()
            if doc.metadata.get("path") and str(doc.metadata["path"]).lower() in ql:
                score += 0.5
            if score > 0:
                scored.append(ScoredDocument(document=doc, score=score))
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored[:top_k]
