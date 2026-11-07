# Architecture

## Layered system diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         PRESENTATION LAYER                          │
│                    Streamlit dashboard (FastAPI client)              │
└───────────────────────────────┬───────────────────────────────────┘
                                 │ REST / WebSocket
┌───────────────────────────────▼───────────────────────────────────┐
│                        ORCHESTRATION LAYER                          │
│                    LangGraph state machine (engine.py)              │
│  State: RedTeamState (see 02_SCHEMAS.md)                             │
└──────┬─────────┬──────────┬──────────┬──────────┬───────────────────┘
       ▼          ▼          ▼          ▼          ▼
   ┌───────┐  ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐
   │ Recon │  │Attacker│ │Verifier│ │Reporter│ │  Memory  │
   │ Agent │  │ Agent  │ │ Agent  │ │ Agent  │ │(ChromaDB)│
   └───┬───┘  └───┬────┘ └───┬────┘ └───┬────┘ └────┬─────┘
       └──────────┴────┬─────┴──────────┴───────────┘
┌───────────────────────▼───────────────────────────────────────────┐
│                      EXECUTION / TOOL LAYER                         │
│   httpx (async) │ Playwright (headless) │ Docker SDK │ CVSS lib     │
└───────────────────────┬───────────────────────────────────────────┘
                         │ network-isolated
┌───────────────────────▼───────────────────────────────────────────┐
│                    SANDBOX LAYER (Docker bridge network)            │
│         Target container (Juice Shop / DVWA / WebGoat)              │
│         No egress except to orchestrator — fully isolated           │
└───────────────────────────────────────────────────────────────────┘
```

## Control flow (LangGraph graph)

```
recon_node → hypothesis_node → verify_node ─┬→ (success) → report_node → END
                    ▲                        │
                    └────(fail, retry<max)────┘
                                             │
                                   (fail, retry==max) → discard_node → hypothesis_node (next endpoint)
```

Each node is a pure function `(RedTeamState) -> RedTeamState`. This is a hard
requirement: nodes must be unit-testable with a synthetic state dict and no live LLM or
network call required for the test to run (mock the LLM/HTTP client at the boundary).

## Tech stack

| Layer | Choice | Notes |
|---|---|---|
| Orchestration | LangGraph | Cyclic, stateful agent graph with retries |
| State persistence | In-memory dict for Phase 1–3; `AsyncPostgresSaver` from Phase 4 onward | Don't build durable persistence before the loop is proven |
| LLM | Claude or GPT-4-class via API, function-calling / tool-use mode | Structured output only — never parse free text between agents |
| Local LLM fallback | Ollama (Llama 3 / Qwen 2.5) | Only if offline operation is a hard requirement |
| HTTP execution | `httpx` (async) | Async-compatible with LangGraph's event loop |
| Browser verification | Playwright (headless, Python) | Required for real XSS verification (DOM execution, not string reflection) |
| Sandbox control | `docker-py` (Docker SDK for Python) | Programmatic container lifecycle |
| Network isolation | Custom Docker bridge network, egress-restricted | Safety control + prompt-injection mitigation |
| Vector DB | ChromaDB | RAG over SecLists / GTFOBins / MITRE ATT&CK |
| Backend API | FastAPI | Async-native, matches httpx/LangGraph |
| Dashboard | Streamlit | Fast to build; sufficient for a capstone demo |
| Tracing | LangSmith (required), OpenTelemetry (optional, later) | LangSmith for ReAct-efficiency metric; OTel is a stretch goal |
| CVSS scoring | `cvss` Python library | Deterministic — never have the LLM compute the score |
| Targets | OWASP Juice Shop, DVWA, WebGoat | Juice Shop has documented known vulns — usable as labeled ground truth |

## Module boundaries (repo layout)

```
autoredteam/
├── core/
│   ├── agents/              # Recon, Attacker, Verifier (reasoning), Reporter — prompts + LLM calls
│   │   ├── recon.py
│   │   ├── attacker.py
│   │   ├── verifier_agent.py   # LLM-judged fallback only
│   │   └── reporter.py
│   ├── verifier/             # Deterministic execution engine — the core IP
│   │   ├── idor.py
│   │   ├── sqli.py
│   │   ├── xss.py
│   │   ├── ssrf.py
│   │   ├── path_traversal.py
│   │   └── broken_auth.py
│   ├── orchestration/
│   │   ├── graph.py           # LangGraph definition
│   │   └── state.py           # RedTeamState
│   └── sandbox/
│       └── controller.py      # SandboxController (docker-py lifecycle)
├── knowledge/                 # ChromaDB ingestion + retrieval
│   ├── ingest.py
│   └── retrieve.py
├── evals/                     # Benchmarking, metrics
│   ├── run_benchmark.py
│   └── metrics.py
├── schemas/
│   └── models.py              # SHARED Pydantic models — single source of truth
├── api/
│   └── main.py                 # FastAPI app
├── dashboard/
│   └── app.py                  # Streamlit app
└── docs/                       # (this folder)
```

## Safety / isolation requirements (binding, not optional)

1. Target container: **no outbound network access** except the orchestrator's interface.
2. Agent HTTP/browser tools are scoped to an **allowlist of the target domain only**.
3. Every run uses a **fresh, ephemeral Docker network**, destroyed after the run.
4. **Hard cap on requests per run** (configurable, default 500) to prevent runaway loops.
5. **Full request/response logging** for every tool call and every LLM call — required
   for reproducibility and for the evaluation chapter.
6. Any content read back from the target (HTTP responses, error pages) is **untrusted
   data**, never treated as instructions to the agent — guard against the target itself
   attempting prompt injection against the Attacker/Verifier agents.
