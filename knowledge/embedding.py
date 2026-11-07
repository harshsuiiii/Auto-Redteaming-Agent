"""Offline, deterministic text embedding.

The RAG layer (06_RAG_KNOWLEDGE.md) needs embeddings, but we don't want a heavyweight
model download or network dependency in a sandboxed, offline-first project. This is a
hashing bag-of-(token + char-trigram) embedding: deterministic, dependency-free, and
good enough for the lexical overlap between an endpoint's param names (``file``,
``path``, ``id``, ``q``, ``url``) and payload/technique keywords.

``embed`` matches the pluggable ``embedding_fn`` signature used by ingest/retrieve, so a
stronger model (e.g. a sentence-transformer) can be swapped in without touching the
rest of the pipeline.
"""
from __future__ import annotations

import hashlib
import math
import re

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _features(text: str):
    for tok in _TOKEN_RE.findall(text.lower()):
        yield tok
        for i in range(len(tok) - 2):          # char trigrams for subword overlap
            yield tok[i:i + 3]


def embed(text: str, dim: int = 256) -> list[float]:
    vec = [0.0] * dim
    for feat in _features(text):
        h = int(hashlib.md5(feat.encode()).hexdigest(), 16)
        vec[h % dim] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]
