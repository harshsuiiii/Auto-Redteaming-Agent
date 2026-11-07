"""Orchestration state & dependencies.

``RedTeamState`` is defined once, in schemas/models.py (09_OWNERSHIP_HANDSHAKE.md) —
re-exported here for convenience, never redefined.

The graph needs runtime scratch that the binding schema does not carry (the endpoint
worklist, a cursor, the auth context, a termination reason). Rather than change the
shared schema, these live under reserved ``_rt_*`` keys inside ``target_config``
(typed ``dict[str, Any]``). Flagged for review as candidate first-class fields.

Node dependencies (LLM, verifiers, recon, HTTP client factory, target adapter) are
injected via ``OrchestrationDeps`` so every node is a pure function of (state) that is
unit-testable with fakes at the boundary.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

import httpx

from schemas.models import RedTeamState  # noqa: F401  (re-export)
from core.sandbox.client import make_scoped_client
from core.orchestration.targets import JuiceShopAdapter, TargetAdapter

# Reserved runtime-scratch keys inside RedTeamState.target_config.
CANDIDATES = "_rt_candidates"
CURSOR = "_rt_cursor"
AUTH = "_rt_auth_context"
TERMINATED = "_rt_terminated"


@dataclass
class OrchestrationDeps:
    base_url: str
    adapter: TargetAdapter
    attack_fn: Callable[..., Awaitable[Any]]
    verifiers: dict[str, Callable[..., Awaitable[Any]]]
    recon_fn: Callable[..., Awaitable[Any]]
    make_client: Callable[[dict, int], httpx.AsyncClient]  # (counter, cap) -> client
    allowed_vuln_classes: list[str] = field(default_factory=lambda: ["IDOR"])
    # Optional RAG retriever: (vuln_class, endpoint, k) -> list[str]. None => RAG off
    # (this is the ablation switch: with-RAG vs without-RAG).
    retriever: Callable[..., list[str]] | None = None
    # Reporter: (VerificationResult) -> Awaitable[Finding]. None => reporter.report
    # with template remediation (offline). default_deps wires LLM remediation if a key.
    reporter_fn: Callable[..., Any] | None = None


def default_deps(base_url: str, *, log_path: Path | None = None,
                 retriever: Callable[..., list[str]] | None = None) -> OrchestrationDeps:
    """Wire the real components (Juice Shop adapter, real recon/attacker/verifiers,
    sandbox-scoped client). Pass ``retriever`` to enable RAG (the ablation switch)."""
    import functools
    from core.agents import attacker, recon, reporter
    from core.verifier import VERIFIERS

    host = urlparse(base_url).hostname or ""
    allowed = {host}

    def make_client(counter: dict, cap: int) -> httpx.AsyncClient:
        return make_scoped_client(base_url, allowed, counter, cap, log_path=log_path)

    reporter_fn = functools.partial(reporter.report,
                                    remediation_llm=reporter.build_remediation_llm_from_env())

    return OrchestrationDeps(
        base_url=base_url,
        adapter=JuiceShopAdapter(base_url),
        attack_fn=attacker.attack,
        verifiers=VERIFIERS,
        recon_fn=recon.recon,
        make_client=make_client,
        retriever=retriever,
        reporter_fn=reporter_fn,
    )
