"""Retrieval over the ChromaDB knowledge base (06_RAG_KNOWLEDGE.md).

Query the vuln_class-scoped collection using the endpoint's shape (param names, types,
locations, URL) as the query text, and return the top-k payload/technique snippets to
inject into the Attacker Agent's prompt as extra context.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from schemas.models import Endpoint, VulnClass
from knowledge.embedding import embed as default_embed
from knowledge.ingest import DEFAULT_DATA_DIR, build_knowledge_base, collection_name

EmbeddingFn = Callable[[str], list[float]]


def _query_text(endpoint: Endpoint) -> str:
    parts = [endpoint.url, endpoint.method]
    for p in endpoint.params:
        parts.append(f"{p.name} {p.location} {p.type}")
    return " ".join(parts)


def retrieve_context(vuln_class: VulnClass, endpoint: Endpoint, k: int = 5, *,
                     client: Any, embedding_fn: EmbeddingFn) -> list[str]:
    try:
        col = client.get_collection(name=collection_name(vuln_class))
    except Exception:
        return []  # no collection for this class
    res = col.query(query_embeddings=[embedding_fn(_query_text(endpoint))], n_results=k)
    docs = res.get("documents") or [[]]
    return docs[0]


class KnowledgeRetriever:
    """Bound (client + embedding_fn) retriever, callable as ``(vuln_class, endpoint, k)``."""

    def __init__(self, client: Any, embedding_fn: EmbeddingFn = default_embed):
        self.client = client
        self.embedding_fn = embedding_fn

    def __call__(self, vuln_class: VulnClass, endpoint: Endpoint, k: int = 5) -> list[str]:
        return retrieve_context(vuln_class, endpoint, k,
                                client=self.client, embedding_fn=self.embedding_fn)

    @classmethod
    def build(cls, *, embedding_fn: EmbeddingFn = default_embed,
              data_dir: str | Path = DEFAULT_DATA_DIR, persist_directory: str | None = None):
        """Create a Chroma client, ingest the corpus, and return a ready retriever."""
        import chromadb
        from chromadb.config import Settings
        settings = Settings(anonymized_telemetry=False)  # offline: no telemetry callouts
        client = (chromadb.PersistentClient(path=persist_directory, settings=settings)
                  if persist_directory else chromadb.EphemeralClient(settings=settings))
        build_knowledge_base(client, embedding_fn, data_dir)
        return cls(client, embedding_fn)
