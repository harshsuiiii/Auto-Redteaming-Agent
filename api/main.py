"""FastAPI app (Phase 7) — start a red-team run, poll its status, fetch findings.

Runs execute asynchronously as background tasks; state is kept in-memory (durable
persistence is a later infra upgrade). The attacker/remediation LLM is configured via
environment (OpenAI-compatible: OPENAI_API_KEY or GROQ_API_KEY + AUTOREDTEAM_LLM_*),
so start the server with those set.

Run:  uvicorn api.main:app --port 8000
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from core.agents import attacker
from core.orchestration import graph
from core.orchestration.state import default_deps
from evals import ground_truth, metrics, run_benchmark
from evals import results as eval_results
from schemas.models import Finding

app = FastAPI(title="AutoRedTeam API", version="0.8.0")

# run_id -> run record. In-memory by design for now (see module docstring).
RUNS: dict[str, dict] = {}
# Keep strong refs to background tasks so they aren't garbage-collected mid-run.
_TASKS: set = set()
LOG_DIR = Path(__file__).resolve().parents[1] / "logs"

# The attacker agent (and any LLM-driven run) needs an OpenAI-compatible key, read the
# same way OpenAIToolClient reads it. Missing it is a configuration problem, so we return
# a clear 400 up front instead of letting a raw OpenAIError surface as a 500.
_NO_LLM_KEY_MSG = (
    "No LLM key configured. Agent/LLM runs need GROQ_API_KEY (or OPENAI_API_KEY) set in the "
    "API server's environment — stop the server and relaunch uvicorn with the key exported. "
    "For a no-LLM run, use engine mode instead."
)


def _llm_key_present() -> bool:
    return bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("GROQ_API_KEY"))


class StartRunRequest(BaseModel):
    target_base_url: str
    request_cap: int = 500
    max_retries: int = 3
    use_rag: bool = False


class RunStatus(BaseModel):
    run_id: str
    status: str  # pending | running | completed | error
    target_base_url: str
    findings_count: int = 0
    attempts: int = 0
    request_count: int = 0
    error: Optional[str] = None


def _status(run_id: str) -> RunStatus:
    r = RUNS[run_id]
    return RunStatus(
        run_id=run_id, status=r["status"], target_base_url=r["target"],
        findings_count=len(r["findings"]), attempts=r["attempts"],
        request_count=r["request_count"], error=r["error"],
    )


async def _execute(run_id: str, req: StartRunRequest) -> None:
    RUNS[run_id]["status"] = "running"
    try:
        retriever = None
        if req.use_rag:
            from knowledge.retrieve import KnowledgeRetriever
            retriever = KnowledgeRetriever.build()
        deps = default_deps(req.target_base_url,
                            log_path=LOG_DIR / f"{run_id}.jsonl", retriever=retriever)
        final = await graph.run(req.target_base_url, deps=deps,
                                request_cap=req.request_cap, max_retries=req.max_retries)
        RUNS[run_id].update(status="completed", findings=final.verified_findings,
                            attempts=len(final.attempt_history), request_count=final.request_count)
    except Exception as exc:  # surface failures to the client instead of crashing the task
        RUNS[run_id].update(status="error", error=f"{type(exc).__name__}: {exc}")


@app.post("/runs", response_model=RunStatus)
async def start_run(req: StartRunRequest) -> RunStatus:
    # A run always drives the LLM attacker, so a missing key can never succeed — fail fast
    # with an actionable message rather than starting a run that errors out.
    if not _llm_key_present():
        raise HTTPException(status_code=400, detail=_NO_LLM_KEY_MSG)
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    RUNS[run_id] = {"status": "pending", "target": req.target_base_url,
                    "findings": [], "attempts": 0, "request_count": 0, "error": None}
    task = asyncio.create_task(_execute(run_id, req))
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)
    return _status(run_id)


@app.get("/runs/{run_id}", response_model=RunStatus)
async def get_run(run_id: str) -> RunStatus:
    if run_id not in RUNS:
        raise HTTPException(status_code=404, detail="unknown run_id")
    return _status(run_id)


@app.get("/runs/{run_id}/findings", response_model=list[Finding])
async def get_findings(run_id: str) -> list[Finding]:
    if run_id not in RUNS:
        raise HTTPException(status_code=404, detail="unknown run_id")
    return RUNS[run_id]["findings"]


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


# --------------------------------------------------------------------------- #
# Benchmark / evals (Phase 8 visual layer)
# --------------------------------------------------------------------------- #

class BenchmarkRequest(BaseModel):
    target_base_url: str = "http://127.0.0.1:3000"
    mode: str = "engine"              # "engine" (fast, no LLM, deterministic) | "agent"
    include_scenarios: bool = True


@app.get("/benchmark/snapshots")
async def list_benchmark_snapshots() -> list[dict]:
    """Saved benchmark results (bundled snapshots + any live runs), newest first."""
    out = []
    for p in eval_results.list_snapshots():
        try:
            r = eval_results.load(p)
        except Exception:
            continue  # skip a malformed file rather than 500 the whole list
        out.append({"name": p.stem, "label": r.label, "target": r.target, "model": r.model,
                    "mode": r.mode, "created_at": r.created_at.isoformat(),
                    "in_scope_recall": r.overall_in_scope.recall,
                    "in_scope_precision": r.overall_in_scope.precision})
    out.sort(key=lambda d: d["created_at"], reverse=True)
    return out


@app.get("/benchmark/snapshots/{name}", response_model=eval_results.BenchmarkResult)
async def get_benchmark_snapshot(name: str) -> eval_results.BenchmarkResult:
    path = eval_results.RESULTS_DIR / f"{name}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="unknown snapshot")
    return eval_results.load(path)


@app.post("/benchmark", response_model=eval_results.BenchmarkResult)
async def run_benchmark_now(req: BenchmarkRequest) -> eval_results.BenchmarkResult:
    """Run a benchmark against the live sandbox and save it as a snapshot. Engine mode is
    fast and deterministic (ideal for a demo click); agent mode exercises the LLM."""
    base = req.target_base_url
    agent = req.mode == "agent"
    if agent and not _llm_key_present():
        raise HTTPException(status_code=400, detail=_NO_LLM_KEY_MSG)
    gt = ground_truth.for_target("juice-shop")
    try:
        findings = await run_benchmark.run_autoredteam(base, agent_driven=agent)
        scen = await run_benchmark.run_scenarios(base) if req.include_scenarios else []
    except Exception as exc:  # LLM/network/sandbox failure — clear 502, not a bare 500
        raise HTTPException(status_code=502,
                            detail=f"Benchmark run failed: {type(exc).__name__}: {exc}")
    in_scope = metrics.score(findings, gt, in_scope_only=True)
    all_v = metrics.score(findings, gt, in_scope_only=False)
    result = eval_results.BenchmarkResult.from_report(
        label=f"Live {req.mode} run {time.strftime('%Y-%m-%d %H:%M')}", target=base,
        model=attacker.DEFAULT_MODEL, mode=req.mode,
        in_scope=in_scope, all_vulns=all_v, findings=findings, scenarios=scen,
        notes=[f"{req.mode} mode, scored against Juice Shop ground truth"])
    eval_results.save(result, eval_results.RESULTS_DIR / f"live-{int(time.time())}.json")
    return result
