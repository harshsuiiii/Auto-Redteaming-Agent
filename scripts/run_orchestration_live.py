"""Phase 4 live check: one call runs the whole LangGraph pipeline against the real
sandboxed Juice Shop and produces a verified finding — zero manual intervention
(08_BUILD_ROADMAP.md, Phase 4).

Usage:
    AUTOREDTEAM_LLM_BASE_URL=https://api.groq.com/openai/v1 \
    AUTOREDTEAM_LLM_MODEL=openai/gpt-oss-120b \
    GROQ_API_KEY=gsk_... \
    python scripts/run_orchestration_live.py [base_url]

LangSmith tracing is optional: set LANGCHAIN_TRACING_V2=true + LANGCHAIN_API_KEY and
the run is traced automatically. Either way the full attempt_history and the per-run
JSONL wire log provide a local reasoning trace.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from core.orchestration import graph  # noqa: E402

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3000"
LOG_PATH = Path(__file__).resolve().parents[1] / "logs" / f"orchestration-{int(time.time())}.jsonl"


async def main() -> int:
    tracing = os.environ.get("LANGCHAIN_TRACING_V2") == "true" and bool(os.environ.get("LANGCHAIN_API_KEY"))
    print(f"target       : {BASE_URL}")
    print(f"model        : {graph_model()}")
    print(f"langsmith    : {'on' if tracing else 'off (optional)'}")
    print(f"wire log     : {LOG_PATH}\n")

    final = await graph.run(BASE_URL, log_path=LOG_PATH)

    print(f"run_id       : {final.run_id}")
    print(f"requests used: {final.request_count} / {final.request_cap}")
    print(f"attempts     : {len(final.attempt_history)}")
    print(f"findings     : {len(final.verified_findings)}")
    for i, f in enumerate(final.verified_findings, 1):
        v = f.verification
        print(f"\n--- finding {i} ---")
        print(f"  vuln_class : {v.hypothesis.vuln_class}")
        print(f"  endpoint   : {v.hypothesis.endpoint.url}")
        print(f"  attack url : {v.hypothesis.payload.url}")
        print(f"  exploited  : {v.is_exploited}  ({v.confidence})")
        print(f"  poc_steps  :")
        for step in f.poc_steps:
            print(f"     - {step}")

    ok = any(f.verification.is_exploited and f.verification.confidence == "deterministic"
             for f in final.verified_findings)
    print("\nRESULT:", "PASS — single-call run produced a verified IDOR finding, no human in the loop"
          if ok else "no verified finding (see above)")
    return 0 if ok else 1


def graph_model() -> str:
    from core.agents import attacker
    base = os.environ.get("AUTOREDTEAM_LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL") or "OpenAI default"
    return f"{attacker.DEFAULT_MODEL} @ {base}"


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
