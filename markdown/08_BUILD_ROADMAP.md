# Build Roadmap

**Rule for the coding agent: do not skip ahead.** Each phase has an explicit
"done when" condition. Do not start Phase N+1 until Phase N's condition is met and
tested.

---

## Phase 0 — Environment (Week 1)
- [ ] Install stack: Python 3.11+, Docker, docker-compose, `langgraph`,
      `langchain-core`, `httpx`, `playwright` (+ `playwright install`), `pydantic`,
      LLM SDK (`anthropic`/`openai`), `chromadb`, `fastapi`, `uvicorn`, `streamlit`,
      `cvss`.
- [ ] Create `schemas/models.py` from `02_SCHEMAS.md` verbatim.
- [ ] Stand up `docker-compose.sandbox.yml` from `05_SANDBOX_SETUP.md`; confirm Juice
      Shop and DVWA start and are reachable, and are NOT reachable from outside the
      isolated network.

**Done when:** `docker compose -f docker-compose.sandbox.yml up` gives you a running,
isolated Juice Shop you can `curl` from your orchestrator process but not from an
unrelated host.

---

## Phase 1 — Manual Verifier, No LLM (Weeks 1–2)
- [ ] Implement `core/verifier/idor.py` per `04_VERIFIER_ENGINE.md`.
- [ ] Write a hand-crafted `Hypothesis` object for a known Juice Shop IDOR case.
- [ ] Call `idor.verify()` directly (no agent, no graph) and confirm it correctly
      returns `is_exploited=True` with evidence.
- [ ] Write a unit test with a mocked httpx response proving the verifier logic works
      without Docker running at all.

**Done when:** you can run `pytest core/verifier/test_idor.py` green, and separately
confirm a live, hand-written IDOR hypothesis against the real sandboxed Juice Shop
returns a correct, evidenced verdict.

---

## Phase 2 — Recon Agent (Weeks 3–4)
- [ ] Implement `core/agents/recon.py`: OpenAPI parser path + crawler fallback path.
- [ ] Run against Juice Shop, confirm `AttackSurfaceMap` contains real endpoints with
      correct param schemas.

**Done when:** `recon(juice_shop_url)` returns a non-trivial `AttackSurfaceMap` you can
manually spot-check against the app's actual API surface.

---

## Phase 3 — Attacker Agent, IDOR only (Weeks 5–6)
- [ ] Implement `core/agents/attacker.py` with the IDOR-relevant portion of the system
      prompt from `03_AGENTS.md`.
- [ ] Manually wire: `recon()` output → feed one endpoint → `attacker()` →
      `idor.verify()`. No LangGraph yet — plain function calls.
- [ ] Confirm the Attacker Agent can independently (without being told the answer)
      hypothesize the known IDOR case from Phase 1 and have it verify as exploited.

**Done when:** the fully agent-driven (not hand-written) hypothesis for the known IDOR
case verifies successfully, end to end, with no human in the loop.

---

## Phase 4 — Orchestration (Weeks 7–8)
- [ ] Implement `core/orchestration/graph.py` per the control flow in
      `01_ARCHITECTURE.md`.
- [ ] Implement the retry edge: on verification failure, loop back to the Attacker
      Agent with updated `attempt_history`, respecting `max_retries`.
- [ ] Implement the request-budget guard from `05_SANDBOX_SETUP.md`.
- [ ] Swap state persistence from in-memory to `AsyncPostgresSaver` **only once the
      above is working** — this is an infra upgrade, not a Phase 4 prerequisite.
- [ ] Wire LangSmith tracing.

**Done when:** a full run against Juice Shop, started from a single API call, produces
at least one verified IDOR finding with zero manual intervention, and you can see the
full reasoning trace in LangSmith.

---

## Phase 5 — Expand Vuln Classes (Weeks 9–11)
- [ ] Implement `xss.py` (Playwright-based) — this is the highest-effort addition.
- [ ] Implement `sqli.py` (both error-based and blind/timing-based).
- [ ] Implement `ssrf.py` (requires standing up an internal callback listener).
- [ ] Implement `path_traversal.py` and `broken_auth.py`.
- [ ] Extend the Attacker Agent's system prompt to cover all vuln classes.

**Done when:** at least 4 of the 6 vuln classes have at least one true-positive
confirmed finding against Juice Shop or DVWA.

---

## Phase 6 — RAG Layer (Weeks 12–13)
- [ ] Implement `knowledge/ingest.py` and `knowledge/retrieve.py` per
      `06_RAG_KNOWLEDGE.md`.
- [ ] Ingest SecLists/GTFOBins/MITRE data.
- [ ] Wire retrieval into the Attacker Agent prompt as optional context.
- [ ] Run the benchmark suite with and without RAG context for the ablation comparison.

**Done when:** you have a precision/recall table comparing with-RAG vs without-RAG.

---

## Phase 7 — Reporter Agent, API, Dashboard (Week 14)
- [ ] Implement `core/agents/reporter.py` (CVSS via `cvss` lib + LLM remediation text).
- [ ] Implement `api/main.py` (FastAPI) exposing run-start, run-status, and
      findings-retrieval endpoints.
- [ ] Implement `dashboard/app.py` (Streamlit) consuming the API, with live trace view
      if time permits.

**Done when:** you can start a run from the dashboard and see a generated report with
CVSS score, PoC, and remediation text for a real finding.

---

## Phase 8 — Benchmarking & Metrics (Week 15)
- [ ] Build `evals/ground_truth.py` from Juice Shop/DVWA documented vulnerabilities.
- [ ] Run AutoRedTeam and OWASP ZAP against the same targets, same time budget.
- [ ] Compute precision, recall, FP rate, ReAct efficiency per `07_EVALUATION.md`.

**Done when:** you have the full comparison table populated with real numbers.

---

## Phase 9 — Write-up & Defense Prep (Week 16)
- [ ] Dissertation write-up, including the scope-limitation honesty section from
      `07_EVALUATION.md`.
- [ ] Prepare a live demo run against Juice Shop for the defense.
- [ ] Prepare answers for likely questions: how deterministic verification avoids
      false positives, how sandbox isolation prevents real-world harm, and why
      business-logic vulnerabilities are explicitly out of scope.
