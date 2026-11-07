"""LangGraph orchestration (01_ARCHITECTURE.md, Phase 4).

Control flow (iterates all curated candidates, one finding per confirmed class):

    recon -> hypothesis -> verify --(exploited)--> report --> discard -> hypothesis (next)
                  ^             |                               |
                  |--(fail,     |                               '--(no candidates left) -> END
                  |  retry<max) |
                  |             |--(fail, retry==max) --> discard --> hypothesis (next endpoint)
                  |                                            |
                  |                                            '--(no endpoints left) --> END
                  '-------------(budget exceeded any time)--------------------------> END

Every node is a pure async function of ``RedTeamState`` returning partial updates, with
all LLM/HTTP boundaries injected via ``OrchestrationDeps`` — so each node is unit-
testable with a synthetic state and fakes, no live model or network required.
"""
from __future__ import annotations

import uuid
from typing import Any

from langgraph.graph import END, START, StateGraph

from schemas.models import RedTeamState, VerificationResult
from core.agents import reporter
from core.sandbox.client import RequestBudgetExceeded
from core.orchestration.state import (
    AUTH, CANDIDATES, CURSOR, TERMINATED, OrchestrationDeps, default_deps,
)


# --------------------------------------------------------------------------- #
# Nodes (factories bound to deps)
# --------------------------------------------------------------------------- #

def make_recon_node(deps: OrchestrationDeps):
    async def recon_node(state: RedTeamState) -> dict[str, Any]:
        counter = {"n": state.request_count}
        client = deps.make_client(counter, state.request_cap)
        try:
            surface = await deps.recon_fn(deps.base_url, http_client=client)
            auth = await deps.adapter.bootstrap(client)
        finally:
            await client.aclose()
        candidates = deps.adapter.candidate_endpoints(surface, auth)
        tc = {**state.target_config, CANDIDATES: candidates, CURSOR: 0, AUTH: auth}
        if not candidates:
            tc[TERMINATED] = "no_candidates"
        return {"attack_surface": surface, "target_config": tc, "request_count": counter["n"]}
    return recon_node


def make_hypothesis_node(deps: OrchestrationDeps):
    async def hypothesis_node(state: RedTeamState) -> dict[str, Any]:
        candidates = state.target_config[CANDIDATES]
        cand = candidates[state.target_config[CURSOR]]
        # A candidate is {endpoint, vuln_class, auth_context}; it pins the attacker to one
        # class and supplies that class's auth (e.g. a forged JWT for broken auth). We fall
        # back to the bootstrapped auth / deps' classes if a candidate omits them.
        endpoint = cand["endpoint"]
        vuln_class = cand.get("vuln_class")
        allowed = [vuln_class] if vuln_class else list(deps.allowed_vuln_classes)
        auth_context = cand.get("auth_context") or state.target_config[AUTH]
        # RAG (ablation switch): retrieve payloads for each candidate class, labelled.
        retrieved_context = None
        if deps.retriever is not None:
            retrieved_context = []
            for vc in allowed:
                for snippet in deps.retriever(vc, endpoint):
                    retrieved_context.append(f"[{vc}] {snippet}")
        hypothesis = await deps.attack_fn(
            endpoint, state.attempt_history,
            auth_context=auth_context,
            allowed_vuln_classes=allowed,
            retrieved_context=retrieved_context,
        )
        return {"current_hypothesis": hypothesis}
    return hypothesis_node


def make_verify_node(deps: OrchestrationDeps):
    async def verify_node(state: RedTeamState) -> dict[str, Any]:
        # Budget guard: hard stop checked before executing any tool.
        if state.request_count >= state.request_cap:
            return {"target_config": {**state.target_config, TERMINATED: "budget"}}

        counter = {"n": state.request_count}
        client = deps.make_client(counter, state.request_cap)
        verifier = deps.verifiers[state.current_hypothesis.vuln_class]
        try:
            result: VerificationResult = await verifier(state.current_hypothesis, client)
        except RequestBudgetExceeded:
            return {"target_config": {**state.target_config, TERMINATED: "budget"},
                    "request_count": counter["n"]}
        finally:
            await client.aclose()

        update: dict[str, Any] = {
            "attempt_history": state.attempt_history + [result],
            "request_count": counter["n"],
        }
        if not result.is_exploited:
            update["retry_count"] = state.retry_count + 1
        return update
    return verify_node


def make_report_node(deps: OrchestrationDeps):
    async def report_node(state: RedTeamState) -> dict[str, Any]:
        result = state.attempt_history[-1]  # the exploited result that routed us here
        reporter_fn = deps.reporter_fn or reporter.report
        finding = await reporter_fn(result)
        return {"verified_findings": state.verified_findings + [finding]}
    return report_node


def make_discard_node(deps: OrchestrationDeps):
    async def discard_node(state: RedTeamState) -> dict[str, Any]:
        tc = {**state.target_config, CURSOR: state.target_config[CURSOR] + 1}
        # Reset per-hypothesis state before moving to the next endpoint.
        return {"target_config": tc, "attempt_history": [], "retry_count": 0,
                "current_hypothesis": None}
    return discard_node


# --------------------------------------------------------------------------- #
# Routers (pure, sync)
# --------------------------------------------------------------------------- #

def route_after_recon(state: RedTeamState) -> str:
    return "terminate" if state.target_config.get(TERMINATED) else "hypothesis"


def route_after_verify(state: RedTeamState) -> str:
    if state.target_config.get(TERMINATED):
        return "terminate"
    if state.attempt_history[-1].is_exploited:
        return "report"
    if state.retry_count < state.max_retries:
        return "hypothesis"
    return "discard"


def route_after_discard(state: RedTeamState) -> str:
    tc = state.target_config
    return "hypothesis" if tc[CURSOR] < len(tc[CANDIDATES]) else "terminate"


# --------------------------------------------------------------------------- #
# Graph assembly
# --------------------------------------------------------------------------- #

def build_graph(deps: OrchestrationDeps):
    g = StateGraph(RedTeamState)
    g.add_node("recon", make_recon_node(deps))
    g.add_node("hypothesis", make_hypothesis_node(deps))
    g.add_node("verify", make_verify_node(deps))
    g.add_node("report", make_report_node(deps))
    g.add_node("discard", make_discard_node(deps))

    g.add_edge(START, "recon")
    g.add_conditional_edges("recon", route_after_recon,
                            {"hypothesis": "hypothesis", "terminate": END})
    g.add_edge("hypothesis", "verify")
    g.add_conditional_edges("verify", route_after_verify,
                            {"report": "report", "hypothesis": "hypothesis",
                             "discard": "discard", "terminate": END})
    # After reporting a finding, advance to the next candidate (reusing discard's cursor
    # advance + per-hypothesis reset) so one run confirms every in-scope class, not just
    # the first. With a single candidate this still yields exactly one finding then ends.
    g.add_edge("report", "discard")
    g.add_conditional_edges("discard", route_after_discard,
                            {"hypothesis": "hypothesis", "terminate": END})
    return g.compile()


async def run(target_base_url: str, deps: OrchestrationDeps | None = None, *,
              request_cap: int = 500, max_retries: int = 3,
              recursion_limit: int = 100, **default_deps_kwargs) -> RedTeamState:
    """Run a full red-team pass from a single call and return the final state."""
    deps = deps or default_deps(target_base_url, **default_deps_kwargs)
    graph = build_graph(deps)
    initial = RedTeamState(
        run_id=f"run-{uuid.uuid4().hex[:8]}",
        target_config={"base_url": target_base_url},
        request_cap=request_cap,
        max_retries=max_retries,
    )
    final = await graph.ainvoke(initial, config={"recursion_limit": recursion_limit})
    return final if isinstance(final, RedTeamState) else RedTeamState(**final)
