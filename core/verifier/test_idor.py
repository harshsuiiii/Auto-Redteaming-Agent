"""Unit tests for the IDOR verifier using a MOCKED httpx transport — no Docker,
no network. Proves the verifier logic in isolation (Phase 1 done-when condition).

Run: pytest core/verifier/test_idor.py
"""
from __future__ import annotations

import json

import httpx
import pytest

from schemas.models import Endpoint, Hypothesis, ParamSchema, Payload
from core.verifier import idor

BASE = "http://target"


def _hypothesis() -> Hypothesis:
    """A hand-crafted IDOR hypothesis against /rest/basket/:id (own id = 1, attack id = 2)."""
    endpoint = Endpoint(
        url=f"{BASE}/rest/basket/:id",
        method="GET",
        params=[ParamSchema(name="id", location="path", type="int", sample_value="1")],
        auth_required=True,
    )
    return Hypothesis(
        vuln_class="IDOR",
        endpoint=endpoint,
        rationale="Numeric basket id with auth → classic object-level authz gap.",
        payload=Payload(method="GET", url=f"{BASE}/rest/basket/2", auth_token="user1-jwt"),
        success_criteria="Response body contains basket data for a user other than the caller.",
    )


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=BASE)


@pytest.mark.asyncio
async def test_idor_exploited_when_other_users_data_returned():
    """Baseline (own basket) and attack (victim basket) share shape but differ → exploited."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/1"):
            return httpx.Response(200, json={"status": "success", "data": {"id": 1, "UserId": 1, "Products": [{"name": "Apple Juice"}]}})
        return httpx.Response(200, json={"status": "success", "data": {"id": 2, "UserId": 2, "Products": [{"name": "Melon Bike"}]}})

    async with _client(handler) as c:
        result = await idor.verify(_hypothesis(), c)

    assert result.is_exploited is True
    assert result.confidence == "deterministic"
    assert result.evidence.raw_response_status == 200
    assert '"UserId": 2' in result.evidence.raw_response_body or "Melon Bike" in result.evidence.raw_response_body


@pytest.mark.asyncio
async def test_not_exploited_when_identical_placeholder_data():
    """False-positive guard: same body regardless of id must NOT be flagged."""
    identical = {"status": "success", "data": {"id": 0, "UserId": 0, "Products": []}}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=identical)

    async with _client(handler) as c:
        result = await idor.verify(_hypothesis(), c)

    assert result.is_exploited is False
    assert result.confidence == "deterministic"
    assert "identical" in result.notes.lower()


@pytest.mark.asyncio
async def test_not_exploited_when_attack_forbidden():
    """Object-level authz enforced (403 on the victim resource) → not exploited."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/1"):
            return httpx.Response(200, json={"status": "success", "data": {"id": 1}})
        return httpx.Response(403, json={"error": "Forbidden"})

    async with _client(handler) as c:
        result = await idor.verify(_hypothesis(), c)

    assert result.is_exploited is False
    assert result.confidence == "deterministic"
    assert "403" in result.notes


@pytest.mark.asyncio
async def test_defers_to_llm_judge_when_no_reference_param():
    """No reference param with a sample_value → cannot build baseline → llm_judged, False."""
    h = _hypothesis()
    h.endpoint.params = []  # strip the reference param

    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - not reached
        return httpx.Response(200, json={})

    async with _client(handler) as c:
        result = await idor.verify(h, c)

    assert result.is_exploited is False
    assert result.confidence == "llm_judged"
