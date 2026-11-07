# RAG & Knowledge Base — `knowledge/`

**Build this after the core Recon→Attack→Verify loop works for at least one vuln
class.** This is a precision-improvement layer, not a dependency for the base system —
treat it as an ablation study for your evaluation chapter (precision with vs. without
RAG).

## Purpose
Give the Attacker Agent retrieval access to payload templates and technique context so
its hypotheses are informed by known attack patterns rather than generated purely from
the model's parametric knowledge.

## Data sources

| Source | Content | License note |
|---|---|---|
| SecLists | Payload wordlists (XSS, SQLi, path traversal) | Public, widely used in security tooling |
| GTFOBins | Technique descriptions (less directly applicable to web, useful for command injection context) | Public |
| MITRE ATT&CK | Technique descriptions, especially the Web Application sub-techniques | Public |

## Ingestion pipeline (`ingest.py`)

```python
def ingest_source(source_path: str, collection_name: str, embedding_fn) -> None:
    """
    1. Load raw entries (one payload/technique per chunk — don't chunk mid-payload).
    2. Attach metadata: {vuln_class, source, technique_id (if MITRE)}.
    3. Embed and upsert into ChromaDB collection.
    """
```

Keep separate collections per vuln class (e.g. `xss_payloads`, `sqli_payloads`,
`mitre_techniques`) rather than one giant collection — retrieval precision is much
better when you can scope the query to `hypothesis.vuln_class` before searching.

## Retrieval (`retrieve.py`)

```python
def retrieve_context(vuln_class: VulnClass, endpoint: Endpoint, k: int = 5) -> list[str]:
    """
    Query the vuln_class-scoped collection using the endpoint's param names/types as
    the query text. Return top-k payload templates / technique snippets to inject
    into the Attacker Agent's prompt as additional context.
    """
```

## Integration point

In the Attacker Agent prompt (`03_AGENTS.md`), add an optional context block:

```
Relevant known techniques/payloads for this vuln class (retrieved, not exhaustive):
{retrieved_context}

Use these as inspiration, not a fixed menu — adapt to the specific endpoint shape.
```

## Evaluation hook

Run your benchmark suite (`evals/run_benchmark.py`) twice per target: once with RAG
context injected, once without. Compare precision/recall and average retries-to-success
per vuln class. This comparison is a clean, legitimate research contribution for a
capstone report — document it explicitly as an ablation study.
