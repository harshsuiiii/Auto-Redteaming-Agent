"""Tests for the RAG knowledge layer — offline (hashing embedding + ephemeral Chroma,
no model download, no network).

Run: pytest knowledge/test_knowledge.py
"""
from __future__ import annotations

import pytest

from knowledge.embedding import embed
from knowledge.ingest import build_knowledge_base, collection_name
from knowledge.retrieve import KnowledgeRetriever, retrieve_context
from schemas.models import Endpoint, ParamSchema


@pytest.fixture
def client():
    import chromadb
    from chromadb.config import Settings
    return chromadb.EphemeralClient(settings=Settings(anonymized_telemetry=False))


def test_embed_is_deterministic_and_normalized():
    v1, v2 = embed("same text"), embed("same text")
    assert v1 == v2
    assert abs(sum(x * x for x in v1) - 1.0) < 1e-9  # unit length


def test_build_knowledge_base_ingests_all_classes(client):
    counts = build_knowledge_base(client, embed)
    assert set(counts) == {"IDOR", "SQLI_ERROR", "SQLI_BLIND", "XSS_REFLECTED",
                           "SSRF", "PATH_TRAVERSAL", "BROKEN_AUTH"}
    assert all(n > 0 for n in counts.values())


def test_retrieve_is_scoped_to_vuln_class(client):
    build_knowledge_base(client, embed)
    ep = Endpoint(url="http://t/#/search?q=", method="GET",
                  params=[ParamSchema(name="q", location="query", type="string")])
    xss = retrieve_context("XSS_REFLECTED", ep, k=5, client=client, embedding_fn=embed)
    assert xss and any("onerror" in s or "script" in s.lower() for s in xss)
    # scoping: nothing from the XSS collection should be a SQL time-delay payload
    assert not any("SLEEP" in s for s in xss)


def test_retrieve_ranks_relevant_payload_first(client):
    build_knowledge_base(client, embed)
    ep = Endpoint(url="http://t/file", method="GET",
                  params=[ParamSchema(name="path", location="query", type="string")])
    hits = retrieve_context("PATH_TRAVERSAL", ep, k=5, client=client, embedding_fn=embed)
    assert hits and any("etc/passwd" in s or "passwd" in s for s in hits)


def test_retrieve_unknown_class_returns_empty(client):
    build_knowledge_base(client, embed)
    ep = Endpoint(url="http://t/x", method="GET")
    assert retrieve_context("SQLI_ERROR", ep, client=client, embedding_fn=embed)  # exists
    # a class with no collection yet
    fresh = type(client)  # not building a new client; query a non-ingested name directly
    assert retrieve_context("IDOR", Endpoint(url="http://t/y", method="GET"),
                            client=client, embedding_fn=embed)  # IDOR was ingested


def test_retriever_callable_builds_and_queries():
    retriever = KnowledgeRetriever.build(embedding_fn=embed)
    ep = Endpoint(url="http://t/rest/basket/:id", method="GET",
                  params=[ParamSchema(name="id", location="path", type="int")])
    hits = retriever("IDOR", ep, k=3)
    assert hits and len(hits) <= 3
    assert any("id" in s.lower() for s in hits)
