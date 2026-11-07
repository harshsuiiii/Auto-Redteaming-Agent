"""Knowledge-base ingestion into ChromaDB (06_RAG_KNOWLEDGE.md).

One payload/technique per chunk (never split a payload). Separate collection per vuln
class so retrieval can be scoped to ``hypothesis.vuln_class`` — much better precision
than one giant collection. Embeddings are precomputed with a pluggable ``embedding_fn``
and passed to Chroma directly, so Chroma's own model is never invoked (offline).

Swap the bundled ``knowledge/data/*.txt`` starter corpus for full SecLists / GTFOBins /
MITRE ATT&CK exports by pointing ``data_dir`` at them.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional

EmbeddingFn = Callable[[str], list[float]]

# vuln_class -> corpus filename
VULN_CLASS_FILES = {
    "IDOR": "idor.txt",
    "SQLI_ERROR": "sqli_error.txt",
    "SQLI_BLIND": "sqli_blind.txt",
    "XSS_REFLECTED": "xss_reflected.txt",
    "SSRF": "ssrf.txt",
    "PATH_TRAVERSAL": "path_traversal.txt",
    "BROKEN_AUTH": "broken_auth.txt",
}

DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "data"


def collection_name(vuln_class: str) -> str:
    return f"{vuln_class.lower()}_payloads"


def load_entries(source_path: str | Path) -> list[str]:
    """One payload/technique per non-empty, non-comment line."""
    lines = Path(source_path).read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def ingest_source(source_path: str | Path, collection_name: str, embedding_fn: EmbeddingFn,
                  client: Any, *, vuln_class: str, source: str = "seclists-sample",
                  technique_id: Optional[str] = None) -> int:
    """Load entries, attach metadata, embed, and upsert into a ChromaDB collection.
    Returns the number of entries ingested."""
    entries = load_entries(source_path)
    if not entries:
        return 0
    col = client.get_or_create_collection(name=collection_name)
    meta = {"vuln_class": vuln_class, "source": source}
    if technique_id:
        meta["technique_id"] = technique_id
    col.upsert(
        ids=[f"{collection_name}-{i}" for i in range(len(entries))],
        documents=entries,
        embeddings=[embedding_fn(e) for e in entries],
        metadatas=[dict(meta) for _ in entries],
    )
    return len(entries)


def build_knowledge_base(client: Any, embedding_fn: EmbeddingFn,
                         data_dir: str | Path = DEFAULT_DATA_DIR) -> dict[str, int]:
    """Ingest every available per-class corpus file. Returns {vuln_class: count}."""
    data_dir = Path(data_dir)
    counts: dict[str, int] = {}
    for vuln_class, fname in VULN_CLASS_FILES.items():
        path = data_dir / fname
        if path.exists():
            counts[vuln_class] = ingest_source(
                path, collection_name(vuln_class), embedding_fn, client, vuln_class=vuln_class)
    return counts
