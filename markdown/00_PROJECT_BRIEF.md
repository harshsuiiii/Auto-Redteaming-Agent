# AutoRedTeam — Project Brief

## What this is
AutoRedTeam is an autonomous multi-agent system that performs execution-verified
penetration testing against sandboxed web applications. It is a 10-credit final-year
capstone project. It is **not** a tool for attacking real, non-consented targets — every
target in this repo is a locally-run, intentionally-vulnerable application
(OWASP Juice Shop, DVWA, WebGoat) inside an isolated Docker network.

## The core idea
Traditional static scanners (SAST/DAST) produce ~80-90% false positives because they
pattern-match code shape rather than proving exploitability. Manual human red-teaming is
accurate but slow and expensive. AutoRedTeam closes this gap: a team of specialized LLM
agents reasons about likely vulnerabilities *and* executes real proof-of-concept attacks
against a sandboxed copy of the target. **A finding is only ever reported if it was
demonstrated to work, not inferred from a pattern.**

## Agent roles
1. **Recon Agent** — maps the target's attack surface (endpoints, params, forms, auth).
2. **Attacker Agent** — reasons (ReAct pattern) about plausible vulnerabilities per
   endpoint and generates structured, executable hypotheses.
3. **Verifier Agent / Engine** — actually executes the hypothesis against the sandboxed
   target and returns a deterministic or LLM-judged success/fail verdict with evidence.
4. **Reporter Agent** — turns verified findings into a report: CVSS score, PoC,
   remediation suggestion.

## Non-negotiable design principles
- **Verification is execution-grounded.** No finding is reported without a successful,
  reproducible PoC.
- **Agent boundaries are schema boundaries.** Every inter-agent message is a typed
  Pydantic model (see `02_SCHEMAS.md`). No free-text parsing between agents.
- **Deterministic verification wherever possible.** Each `VerificationResult` carries a
  `confidence: "deterministic" | "llm_judged"` field. Deterministic checks (regex,
  timing, DOM state) are preferred over LLM judgment calls.
- **Sandbox isolation is mandatory.** The target container has no outbound network
  access except back to the orchestrator. This is both a safety control and a defense
  against prompt injection via malicious HTTP responses.
- **Build order: verifier before orchestration.** Prove the execution/verification
  harness works with hand-written hypotheses before wiring any LLM agent to it.

## Document index
| File | Purpose |
|---|---|
| `01_ARCHITECTURE.md` | System layers, component diagram, tech stack |
| `02_SCHEMAS.md` | All Pydantic contracts — the source of truth for inter-agent messages |
| `03_AGENTS.md` | System prompts and I/O specs for each agent |
| `04_VERIFIER_ENGINE.md` | Per-vuln-class verification logic |
| `05_SANDBOX_SETUP.md` | Docker sandbox, network isolation, target setup |
| `06_RAG_KNOWLEDGE.md` | ChromaDB knowledge base design |
| `07_EVALUATION.md` | Metrics, benchmarking methodology |
| `08_BUILD_ROADMAP.md` | Week-by-week build order for the coding agent to follow |
| `09_OWNERSHIP_HANDSHAKE.md` | Division of labor between collaborators (if applicable) |

## How a coding agent should use these docs
Read `01_ARCHITECTURE.md` and `02_SCHEMAS.md` first — they are binding contracts.
Then follow `08_BUILD_ROADMAP.md` in order; do not skip ahead to orchestration or RAG
before the Phase 1 verifier (see roadmap) is working and tested. Every new module should
import types from the shared schema file, never redefine them locally.
