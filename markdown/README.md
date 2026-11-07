# AutoRedTeam — Docs for Coding Agents

This folder is the build spec for AutoRedTeam. If you are a coding agent (Claude Code,
Cursor, etc.) picking up this repo, **read the files in this order**:

1. `docs/00_PROJECT_BRIEF.md` — what this is and the non-negotiable design principles
2. `docs/01_ARCHITECTURE.md` — system layers, diagram, tech stack, repo layout
3. `docs/02_SCHEMAS.md` — the binding Pydantic contracts; import, never redefine
4. `docs/03_AGENTS.md` — system prompts and I/O for Recon/Attacker/Verifier/Reporter
5. `docs/04_VERIFIER_ENGINE.md` — deterministic execution logic per vuln class
6. `docs/05_SANDBOX_SETUP.md` — Docker isolation, egress rules, request budgets
7. `docs/06_RAG_KNOWLEDGE.md` — ChromaDB knowledge layer (build after core loop works)
8. `docs/07_EVALUATION.md` — metrics, ground truth, comparative benchmarking
9. `docs/08_BUILD_ROADMAP.md` — **the actual week-by-week build order — follow this**
10. `docs/09_OWNERSHIP_HANDSHAKE.md` — only relevant if split across collaborators

## The one rule that matters most
**Build the verifier before the agents, and the agents before the orchestration.**
`08_BUILD_ROADMAP.md` enforces this with explicit "done when" conditions per phase —
do not let a coding agent skip ahead to LangGraph wiring or RAG before Phase 1's
manual, no-LLM IDOR verifier is tested and working against a real sandboxed target.

## Safety note
Every target in this project is a locally-run, intentionally-vulnerable application
(OWASP Juice Shop, DVWA, WebGoat) inside an isolated Docker network with no outbound
internet access. This project is not designed or intended to target any system you do
not own or have explicit authorization to test.
