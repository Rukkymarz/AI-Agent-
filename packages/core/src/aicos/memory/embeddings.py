"""Embedding abstraction. Production: OllamaEmbedder (bge-m3 / nomic-embed-text / jina).

HashingEmbedder is a deterministic, dependency-free embedder for tests and air-gapped
smoke runs. It is lexical, not semantic — never use it for production retrieval.
"""

from __future__ import annotations

import hashlib
import math
import re
from itertools import pairwise
from typing import Protocol

_TOKEN = re.compile(r"[a-z0-9]+")


class Embedder(Protocol):
    @property
    def dim(self) -> int: ...
    @property
    def model(self) -> str: ...
    async def embed(self, texts: list[str]) -> list[list[float]]: ...


class HashingEmbedder:
    def __init__(self, dim: int = 384) -> None:
        self._dim = dim

    @property
    def dim(self) -> int:
        return self._dim

    @property
    def model(self) -> str:
        return f"hashing-{self._dim}"

    def _one(self, text: str) -> list[float]:
        vec = [0.0] * self._dim
        tokens = _TOKEN.findall(text.lower())
        grams = tokens + [f"{a}_{b}" for a, b in pairwise(tokens)]
        for g in grams:
            h = int.from_bytes(hashlib.blake2b(g.encode(), digest_size=8).digest(), "big")
            vec[h % self._dim] += 1.0 if (h >> 63) & 1 else -1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._one(t) for t in texts]


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)
