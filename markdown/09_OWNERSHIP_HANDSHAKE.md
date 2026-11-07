# Ownership / Division of Labor (if working with a collaborator or a second AI agent)

This document only applies if the project is split across two owners (e.g. one person
+ AI agent owning infra/orchestration, another owning agent intelligence/verification).
If you're building solo, ignore this file or use it as a personal module checklist.

## Domain A — Infrastructure & Orchestration
Owns:
- `core/orchestration/graph.py`, `core/orchestration/state.py` (`RedTeamState` graph
  mechanics — edges, routing, retry-loop *control flow*, not retry *decision logic*)
- `core/sandbox/controller.py` (`SandboxController`)
- `api/main.py` (FastAPI)
- `dashboard/app.py` (Streamlit)
- State persistence (`AsyncPostgresSaver`), tracing infra (LangSmith wiring, optional
  OpenTelemetry)

## Domain B — Agent Intelligence, Verification, Research
Owns:
- `core/agents/` (Recon, Attacker, Verifier-agent-fallback, Reporter — prompts + LLM
  calls, and *retry decision logic*: what to try next, not when the loop stops)
- `core/verifier/` (deterministic execution engine, per `04_VERIFIER_ENGINE.md`)
- `knowledge/`, `evals/` (RAG, benchmarking, metrics)

## Shared, jointly owned
- `schemas/models.py` — **changes require both parties' sign-off.** Treat this file
  like a public API; a PR touching it should be reviewed by whoever owns the consuming
  side before merge.

## Handshake contract (binding interface between domains)

```python
# Domain B provides this function; Domain A's graph calls it as a node.
async def verify_payload(hypothesis: Hypothesis) -> VerificationResult:
    """
    Dispatches to the correct core/verifier/* module based on hypothesis.vuln_class.
    MUST be async — do not block the LangGraph event loop.
    Returns VerificationResult per schemas/models.py — NOT a flat dict with a fixed
    response_code field; different vuln classes populate different evidence fields.
    """
```

```python
# Domain A provides this; Domain B's verifier modules call it to reach the target.
class SandboxController:
    async def start(self, target_image: str, run_id: str) -> SandboxHandle: ...
    async def stop(self, handle: SandboxHandle) -> None: ...

class SandboxHandle(BaseModel):
    base_url: str           # reachable URL Domain B's httpx/Playwright clients use
    network_name: str
    run_id: str
```

## Explicit edge-case resolutions (confirm before Phase 1)

1. **`verify_payload` is `async` and returns the full `VerificationEvidence` model**,
   not a fixed-field dict — required for XSS (DOM snapshot), blind SQLi (timing
   array), and SSRF (callback flag) to work without a schema rewrite later.
2. **Playwright execution context is Domain B's responsibility** (it's a verification
   tool). Domain A's `SandboxController` only guarantees network isolation and exposes
   a reachable `base_url` — it does not manage the browser instance.
3. **Retry *mechanics* (graph edges, `max_retries` enforcement) are Domain A's;
   retry *decision logic* (what to try differently) is Domain B's**, living inside the
   Attacker Agent's reasoning over `attempt_history`. Neither side duplicates this.
4. **`RedTeamState` is defined once, in `schemas/models.py`**, not independently by
   either domain — both sides consume the same class.
5. **ZAP/SonarQube comparative-eval tooling needs to actually run somewhere** — that's
   Domain A's container-lifecycle responsibility, even though the comparison scripts
   themselves (`evals/`) are Domain B's. Flag and schedule this explicitly, don't let
   it surface as a Week 15 surprise.
6. **Build order takes priority over stack completeness.** Durable persistence
   (`AsyncPostgresSaver`) and tracing (OpenTelemetry) are correct long-term choices but
   should be added in Phase 4+ (per `08_BUILD_ROADMAP.md`), once the core loop is
   proven — not built upfront in Week 1–2 before any agent has run successfully.
