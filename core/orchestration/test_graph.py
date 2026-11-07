"""Tests for the LangGraph orchestration — node-level (synthetic state + fakes) and
full-graph integration, all with LLM/HTTP boundaries mocked (no Docker, no model).

Run: pytest core/orchestration/test_graph.py
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Optional

import httpx
import pytest

from core.orchestration import graph as G
from core.orchestration.state import AUTH, CANDIDATES, CURSOR, TERMINATED, OrchestrationDeps
from core.sandbox.client import make_scoped_client
from schemas.models import (
    AttackSurfaceMap, Endpoint, Hypothesis, ParamSchema, Payload,
    RedTeamState, VerificationEvidence, VerificationResult,
)

BASE = "http://target"


def _basket_endpoint(own: str = "6") -> Endpoint:
    return Endpoint(url=f"{BASE}/rest/basket/:id", method="GET",
                    params=[ParamSchema(name="id", location="path", type="int", sample_value=own)],
                    auth_required=True)


def _vr(exploited: bool, status: int = 200) -> VerificationResult:
    h = Hypothesis(vuln_class="IDOR", endpoint=_basket_endpoint(),
                   rationale="r", payload=Payload(method="GET", url=f"{BASE}/rest/basket/1"),
                   success_criteria="sc")
    return VerificationResult(hypothesis=h, is_exploited=exploited, confidence="deterministic",
                              evidence=VerificationEvidence(raw_response_status=status),
                              notes="n")


def _candidate(endpoint: Optional[Endpoint] = None, vuln_class: str = "IDOR") -> dict:
    return {"endpoint": endpoint or _basket_endpoint(), "vuln_class": vuln_class,
            "auth_context": {"auth_token": "T", "own_resource_id": 6, "hint": "h"}}


class _FakeAdapter:
    def __init__(self, candidates: Optional[list[dict]] = None):
        # None => one default IDOR candidate; [] => no candidates (termination path).
        self._candidates = candidates if candidates is not None else [_candidate()]
    async def bootstrap(self, client):
        return {"auth_token": "T", "own_resource_id": 6, "hint": "h"}
    def candidate_endpoints(self, surface, auth):
        return self._candidates


def _dummy_client(*_a, **_k) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))


def _deps(**over) -> OrchestrationDeps:
    base = OrchestrationDeps(
        base_url=BASE,
        adapter=_FakeAdapter(),
        attack_fn=_make_attacker(),
        verifiers={"IDOR": _make_verifier([True])},
        recon_fn=_fake_recon,
        make_client=lambda counter, cap: _dummy_client(),
    )
    return replace(base, **over)


async def _fake_recon(base_url, *, http_client=None, **_):
    return AttackSurfaceMap(target_base_url=base_url,
                            endpoints=[Endpoint(url=f"{base_url}/rest/basket", method="GET")])


def _make_attacker(calls: Optional[list] = None):
    async def attack(endpoint, attempt_history, *, auth_context=None, allowed_vuln_classes=None, **_):
        if calls is not None:
            calls.append({"attempts": len(attempt_history), "auth": auth_context})
        return Hypothesis(vuln_class="IDOR", endpoint=endpoint, rationale="r",
                          payload=Payload(method="GET", url=f"{BASE}/rest/basket/1",
                                          auth_token=(auth_context or {}).get("auth_token")),
                          success_criteria="sc", attempt_number=len(attempt_history) + 1)
    return attack


def _make_verifier(verdicts: list[bool]):
    seq = list(verdicts)
    async def verify(hypothesis, client):
        return _vr(seq.pop(0) if seq else False)
    return verify


# --- node-level ------------------------------------------------------------ #

async def test_recon_node_populates_candidates_and_auth():
    deps = _deps()
    state = RedTeamState(run_id="x", target_config={"base_url": BASE})
    upd = await G.make_recon_node(deps)(state)
    assert upd["attack_surface"].endpoints
    assert upd["target_config"][CURSOR] == 0
    assert upd["target_config"][AUTH]["auth_token"] == "T"
    assert len(upd["target_config"][CANDIDATES]) == 1


async def test_recon_node_terminates_when_no_candidates():
    deps = _deps(adapter=_FakeAdapter(candidates=[]))
    upd = await G.make_recon_node(deps)(RedTeamState(run_id="x", target_config={}))
    assert upd["target_config"][TERMINATED] == "no_candidates"
    assert G.route_after_recon(RedTeamState(run_id="x", target_config=upd["target_config"])) == "terminate"


async def test_verify_node_failure_increments_retry_and_routes():
    deps = _deps(verifiers={"IDOR": _make_verifier([False])})
    state = RedTeamState(run_id="x", target_config={CANDIDATES: [_basket_endpoint()], CURSOR: 0},
                         current_hypothesis=_vr(False).hypothesis, retry_count=0, max_retries=3)
    upd = await G.make_verify_node(deps)(state)
    assert upd["retry_count"] == 1
    assert len(upd["attempt_history"]) == 1
    merged = state.model_copy(update=upd)
    assert G.route_after_verify(merged) == "hypothesis"       # retry (1 < 3)
    merged.retry_count = 3
    assert G.route_after_verify(merged) == "discard"          # exhausted


async def test_verify_node_success_routes_to_report():
    deps = _deps(verifiers={"IDOR": _make_verifier([True])})
    state = RedTeamState(run_id="x", target_config={CANDIDATES: [_basket_endpoint()], CURSOR: 0},
                         current_hypothesis=_vr(True).hypothesis)
    upd = await G.make_verify_node(deps)(state)
    assert "retry_count" not in upd
    assert G.route_after_verify(state.model_copy(update=upd)) == "report"


async def test_verify_node_budget_precheck_terminates():
    deps = _deps()
    state = RedTeamState(run_id="x", target_config={}, request_count=500, request_cap=500,
                         current_hypothesis=_vr(True).hypothesis)
    upd = await G.make_verify_node(deps)(state)
    assert upd["target_config"][TERMINATED] == "budget"


async def test_verify_node_budget_enforced_midflight():
    """A greedy verifier making many requests hits the cap via the scoped client."""
    def handler(_r): return httpx.Response(200, json={"ok": True})
    def make_client(counter, cap):
        return make_scoped_client(BASE, {"target"}, counter, cap,
                                  transport=httpx.MockTransport(handler))

    async def greedy_verify(hypothesis, client):
        for _ in range(10):
            await client.get(f"{BASE}/x")
        return _vr(False)

    deps = _deps(make_client=make_client, verifiers={"IDOR": greedy_verify})
    state = RedTeamState(run_id="x", target_config={}, request_count=0, request_cap=3,
                         current_hypothesis=_vr(False).hypothesis)
    upd = await G.make_verify_node(deps)(state)
    assert upd["target_config"][TERMINATED] == "budget"
    assert upd["request_count"] == 3  # stopped exactly at the cap


async def test_discard_node_resets_and_advances():
    deps = _deps()
    state = RedTeamState(run_id="x", target_config={CANDIDATES: [_basket_endpoint(), _basket_endpoint()], CURSOR: 0},
                         attempt_history=[_vr(False)], retry_count=3)
    upd = await G.make_discard_node(deps)(state)
    assert upd["target_config"][CURSOR] == 1
    assert upd["attempt_history"] == [] and upd["retry_count"] == 0
    assert G.route_after_discard(state.model_copy(update=upd)) == "hypothesis"
    # at the last candidate, terminate
    state2 = state.model_copy(update={"target_config": {CANDIDATES: [_basket_endpoint()], CURSOR: 1}})
    assert G.route_after_discard(state2) == "terminate"


# --- full-graph integration ------------------------------------------------ #

async def test_full_run_success_yields_one_finding():
    deps = _deps(verifiers={"IDOR": _make_verifier([True])})
    final = await G.run(BASE, deps=deps)
    assert len(final.verified_findings) == 1
    assert final.verified_findings[0].verification.is_exploited is True
    # the finding preserves its attempt number; per-candidate history is reset on advance
    assert final.verified_findings[0].verification.hypothesis.attempt_number == 1
    assert final.attempt_history == []


async def test_full_run_retry_then_success():
    calls: list = []
    deps = _deps(attack_fn=_make_attacker(calls),
                 verifiers={"IDOR": _make_verifier([False, True])})
    final = await G.run(BASE, deps=deps)
    assert len(final.verified_findings) == 1
    assert len(calls) == 2                      # attacker ran twice
    assert calls[1]["attempts"] == 1            # 2nd call saw the 1st failure in history


async def test_full_run_all_fail_no_finding_bounded():
    calls: list = []
    deps = _deps(attack_fn=_make_attacker(calls),
                 verifiers={"IDOR": _make_verifier([False, False, False, False, False])})
    final = await G.run(BASE, deps=deps, max_retries=2)
    assert final.verified_findings == []
    assert len(calls) == 2                      # max_retries attempts, then discard -> END


def _make_classpinned_attacker(calls: Optional[list] = None):
    """Attacker that honours the per-candidate pinned class (allowed_vuln_classes[0])."""
    async def attack(endpoint, attempt_history, *, auth_context=None, allowed_vuln_classes=None, **_):
        vc = (allowed_vuln_classes or ["IDOR"])[0]
        if calls is not None:
            calls.append({"vc": vc, "auth": auth_context})
        return Hypothesis(vuln_class=vc, endpoint=endpoint, rationale="r",
                          payload=Payload(method="GET", url=f"{BASE}/x"),
                          success_criteria="sc", attempt_number=len(attempt_history) + 1)
    return attack


async def test_full_run_multiple_candidates_yields_multiple_findings():
    """Option B: one run iterates every curated candidate and reports a finding per class."""
    cands = [
        _candidate(_basket_endpoint(), "IDOR"),
        _candidate(Endpoint(url=f"{BASE}/rest/user/login", method="POST"), "SQLI_ERROR"),
        _candidate(Endpoint(url=f"{BASE}/#/search?q=", method="GET"), "XSS_REFLECTED"),
    ]
    calls: list = []
    deps = _deps(adapter=_FakeAdapter(cands),
                 attack_fn=_make_classpinned_attacker(calls),
                 verifiers={"IDOR": _make_verifier([True]),
                            "SQLI_ERROR": _make_verifier([True]),
                            "XSS_REFLECTED": _make_verifier([True])})
    final = await G.run(BASE, deps=deps)
    assert len(final.verified_findings) == 3                       # one per candidate class
    assert [c["vc"] for c in calls] == ["IDOR", "SQLI_ERROR", "XSS_REFLECTED"]  # pinned per candidate


async def test_full_run_mixed_candidates_only_confirmed_reported():
    """A candidate whose class does not verify is discarded; others still get reported."""
    cands = [_candidate(_basket_endpoint(), "IDOR"),
             _candidate(Endpoint(url=f"{BASE}/rest/user/login", method="POST"), "SQLI_ERROR")]
    deps = _deps(adapter=_FakeAdapter(cands),
                 attack_fn=_make_classpinned_attacker(),
                 verifiers={"IDOR": _make_verifier([True]),
                            "SQLI_ERROR": _make_verifier([False, False, False, False])})
    final = await G.run(BASE, deps=deps, max_retries=2)
    assert len(final.verified_findings) == 1                       # only IDOR confirmed
