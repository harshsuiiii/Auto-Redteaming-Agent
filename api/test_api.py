"""API tests — the run lifecycle with graph.run mocked (no network, no LLM, no Docker).

Run: pytest api/test_api.py
"""
from __future__ import annotations

import httpx
import pytest

from api import main as api
from core.agents import reporter
from schemas.models import (
    Endpoint, Hypothesis, Payload, RedTeamState, VerificationEvidence, VerificationResult,
)


async def _state_with_finding() -> RedTeamState:
    h = Hypothesis(vuln_class="IDOR",
                   endpoint=Endpoint(url="http://t/rest/basket/:id", method="GET"),
                   rationale="r", payload=Payload(method="GET", url="http://t/rest/basket/1"),
                   success_criteria="another user's basket")
    vr = VerificationResult(hypothesis=h, is_exploited=True, confidence="deterministic",
                            evidence=VerificationEvidence(raw_response_status=200), notes="diff")
    finding = await reporter.report(vr)
    return RedTeamState(run_id="x", target_config={}, verified_findings=[finding],
                        attempt_history=[vr], request_count=7)


@pytest.fixture
def client(monkeypatch):
    async def fake_run(target_base_url, deps=None, **_):
        return await _state_with_finding()
    monkeypatch.setattr(api.graph, "run", fake_run)
    transport = httpx.ASGITransport(app=api.app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


async def _wait_completed(client, run_id, tries=50):
    import asyncio
    for _ in range(tries):
        r = await client.get(f"/runs/{run_id}")
        if r.json()["status"] in ("completed", "error"):
            return r.json()
        await asyncio.sleep(0.02)
    raise AssertionError("run did not finish")


async def test_run_lifecycle_and_findings(client, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-dummy-key")  # graph.run is mocked; just satisfy the guard
    async with client:
        start = await client.post("/runs", json={"target_base_url": "http://127.0.0.1:3000"})
        assert start.status_code == 200
        run_id = start.json()["run_id"]
        assert start.json()["status"] in ("pending", "running")

        status = await _wait_completed(client, run_id)
        assert status["status"] == "completed"
        assert status["findings_count"] == 1
        assert status["request_count"] == 7

        findings = await client.get(f"/runs/{run_id}/findings")
        assert findings.status_code == 200
        body = findings.json()
        assert len(body) == 1
        assert body[0]["cvss_vector"].startswith("CVSS:3.1/")
        assert body[0]["cvss_score"] > 0
        assert body[0]["poc_steps"]
        assert body[0]["remediation"]


async def test_unknown_run_404(client):
    async with client:
        assert (await client.get("/runs/nope")).status_code == 404
        assert (await client.get("/runs/nope/findings")).status_code == 404


async def test_runs_requires_llm_key_clear_400(client, monkeypatch):
    """Starting a run with no LLM key gives a clear 400, not a cryptic background error."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    async with client:
        resp = await client.post("/runs", json={"target_base_url": "http://127.0.0.1:3000"})
        assert resp.status_code == 400
        assert "No LLM key" in resp.json()["detail"]


async def test_benchmark_agent_requires_llm_key_clear_400(client, monkeypatch):
    """Agent-mode benchmark with no LLM key returns a clear 400 instead of a raw 500."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    async with client:
        resp = await client.post("/benchmark",
                                 json={"target_base_url": "http://127.0.0.1:3000", "mode": "agent"})
        assert resp.status_code == 400
        assert "No LLM key" in resp.json()["detail"]
        # engine mode needs no key, so it is never blocked by this guard
        # (covered by test_run_benchmark_now_scores_findings)


async def test_benchmark_snapshots_list_and_get(client):
    async with client:
        lst = await client.get("/benchmark/snapshots")
        assert lst.status_code == 200
        names = [s["name"] for s in lst.json()]
        assert "snapshot-01-juiceshop-clean" in names  # bundled snapshot is present

        one = await client.get("/benchmark/snapshots/snapshot-01-juiceshop-clean")
        assert one.status_code == 200
        assert one.json()["overall_in_scope"]["precision"] == 1.0

        assert (await client.get("/benchmark/snapshots/nope")).status_code == 404


async def test_run_benchmark_now_scores_findings(client, monkeypatch, tmp_path):
    """POST /benchmark scores the (mocked) findings and persists a snapshot — no network."""
    h = Hypothesis(vuln_class="IDOR",
                   endpoint=Endpoint(url="http://t/rest/basket/:id", method="GET"),
                   rationale="r", payload=Payload(method="GET", url="http://t/rest/basket/2"),
                   success_criteria="another user's basket")
    vr = VerificationResult(hypothesis=h, is_exploited=True, confidence="deterministic",
                            evidence=VerificationEvidence(raw_response_status=200))
    finding = await reporter.report(vr)

    async def fake_run_autoredteam(base, *, agent_driven=True, **kw):
        return [finding]

    async def fake_run_scenarios(base, **kw):
        return []

    monkeypatch.setattr(api.run_benchmark, "run_autoredteam", fake_run_autoredteam)
    monkeypatch.setattr(api.run_benchmark, "run_scenarios", fake_run_scenarios)
    monkeypatch.setattr(api.eval_results, "RESULTS_DIR", tmp_path)  # don't pollute the repo

    async with client:
        resp = await client.post("/benchmark",
                                 json={"target_base_url": "http://t", "mode": "engine"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["mode"] == "engine"
        assert body["overall_in_scope"]["tp"] == 1
        assert body["findings"][0]["vuln_class"] == "IDOR"
    assert list(tmp_path.glob("live-*.json")), "a snapshot file should have been saved"
