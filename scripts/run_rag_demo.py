"""Phase 6 demo: the RAG knowledge layer (06_RAG_KNOWLEDGE.md).

Part 1 (always runs, offline, no key): build the ChromaDB knowledge base and show
scoped top-k retrieval of payloads/techniques for a representative endpoint per vuln
class.

Part 2 (optional, needs an LLM key): the ablation SWITCH — run the Attacker Agent on
one endpoint with RAG off vs on, showing the retrieved payloads enter the prompt. The
full with-RAG vs without-RAG precision/recall TABLE is produced by the Phase 8
benchmark; this demonstrates the plumbing that feeds it.

Usage:  python scripts/run_rag_demo.py
        (optional LLM ablation: set AUTOREDTEAM_LLM_BASE_URL/_MODEL + key)
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")

from knowledge.retrieve import KnowledgeRetriever  # noqa: E402
from schemas.models import Endpoint, ParamSchema  # noqa: E402

REPRESENTATIVE = {
    "IDOR": Endpoint(url="http://t/rest/basket/:id", method="GET",
                     params=[ParamSchema(name="id", location="path", type="int")]),
    "SQLI_ERROR": Endpoint(url="http://t/rest/user/login", method="POST",
                           params=[ParamSchema(name="email", location="body", type="string")]),
    "XSS_REFLECTED": Endpoint(url="http://t/#/search?q=", method="GET",
                              params=[ParamSchema(name="q", location="query", type="string")]),
    "PATH_TRAVERSAL": Endpoint(url="http://t/file", method="GET",
                               params=[ParamSchema(name="path", location="query", type="string")]),
    "SSRF": Endpoint(url="http://t/rest/fetch", method="GET",
                     params=[ParamSchema(name="url", location="query", type="string")]),
    "BROKEN_AUTH": Endpoint(url="http://t/rest/basket/:id", method="GET",
                            params=[ParamSchema(name="id", location="path", type="int")]),
}


async def main() -> int:
    print("=== Part 1: scoped retrieval from the knowledge base (offline) ===\n")
    retriever = KnowledgeRetriever.build()
    for vc, ep in REPRESENTATIVE.items():
        hits = retriever(vc, ep, k=3)
        print(f"{vc} (endpoint {ep.url}):")
        for h in hits:
            print(f"   - {h}")
        print()

    # Part 2: optional LLM ablation plumbing.
    key = os.environ.get("GROQ_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not key:
        print("=== Part 2 (LLM ablation): skipped — no LLM key in env ===")
        print("Set a key + AUTOREDTEAM_LLM_BASE_URL/_MODEL to run the with/without-RAG attacker.")
        return 0

    from core.agents import attacker
    ep = REPRESENTATIVE["IDOR"]
    ep = ep.model_copy(update={"params": [ParamSchema(name="id", location="path", type="int", sample_value="6")]})
    auth = {"auth_token": "demo", "own_resource_id": 6, "hint": "ids are sequential"}

    print("\n=== Part 2: Attacker ablation on", ep.url, "===")
    for label, ctx in (("WITHOUT RAG", None),
                       ("WITH RAG", [f"[IDOR] {s}" for s in retriever('IDOR', ep, k=5)])):
        h = await attacker.attack(ep, [], auth_context=auth,
                                  allowed_vuln_classes=["IDOR"], retrieved_context=ctx)
        print(f"\n[{label}] vuln_class={h.vuln_class}  attack_url={h.payload.url}")
        print(f"            rationale: {h.rationale[:140]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
