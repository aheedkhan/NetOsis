"""Local embedding backends for NetOsis RAG.

Prefer sentence-transformers/all-MiniLM-L6-v2 when installed.
Fall back to a deterministic hash embedder so CI works offline.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from functools import lru_cache
from typing import Protocol


_TOKEN = re.compile(r"[a-z0-9_./:-]+", re.I)


class Embedder(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]: ...


class HashEmbedder:
    """Offline bag-of-tokens hash embedding (no model download)."""

    def __init__(self, dims: int = 256) -> None:
        self.dims = dims

    def embed(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for text in texts:
            vec = [0.0] * self.dims
            tokens = _TOKEN.findall(text.lower())
            if not tokens:
                out.append(vec)
                continue
            for tok in tokens:
                digest = hashlib.sha256(tok.encode("utf-8")).digest()
                idx = int.from_bytes(digest[:4], "big") % self.dims
                sign = 1.0 if digest[4] % 2 == 0 else -1.0
                vec[idx] += sign
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            out.append([v / norm for v in vec])
        return out


class MiniLMEmbedder:
    """sentence-transformers/all-MiniLM-L6-v2 wrapper."""

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2") -> None:
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(model_name)

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = self._model.encode(texts, normalize_embeddings=True)
        return [list(map(float, row)) for row in vectors]


@lru_cache(maxsize=2)
def _cached_minilm(model_name: str) -> MiniLMEmbedder:
    return MiniLMEmbedder(model_name)


def get_embedder() -> Embedder:
    """
    NETOSIS_EMBED_MODE:
      auto  — MiniLM if importable, else hash (default)
      minilm — require sentence-transformers
      hash  — offline hash embedder only
    """
    mode = os.environ.get("NETOSIS_EMBED_MODE", "auto").lower()
    model = os.environ.get(
        "NETOSIS_EMBED_MODEL",
        "sentence-transformers/all-MiniLM-L6-v2",
    )
    if mode == "hash":
        return HashEmbedder()
    if mode in {"minilm", "auto"}:
        try:
            return _cached_minilm(model)
        except Exception:
            if mode == "minilm":
                raise
            return HashEmbedder()
    return HashEmbedder()
