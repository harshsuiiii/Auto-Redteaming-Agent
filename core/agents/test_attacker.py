"""Unit tests for the Attacker Agent using a FAKE LLM client — no OpenAI key, no
network. Proves prompt wiring, schema validation + local retry, and token injection.

Run: pytest core/agents/test_attacker.py
"""
from __future__ import annotations

from typing import Any, Optional

import pytest

from core.agents import attacker
from schemas.models import Endpoint, ParamSchema, VerificationEvidence, VerificationResult, Hypothesis, Payload


def _basket_endpoint() -> Endpoint:
    return Endpoint(
        url="http://target/rest/basket/:id",
        method="GET",
        params=[ParamSchema(name="id", location="path", type="int", sample_value="6")],
        auth_required=True,
    )


class FakeLLM:
    """Returns queued tool-call argument dicts; records the system prompt it saw."""

    def __init__(self, *responses: dict[str, Any]):
        self._responses = list(responses)
        self.seen_system: list[str] = []
        self.seen_correction: list[Optional[str]] = []

    async def propose(self, *, system: str, tool_schema: dict[str, Any],
                      correction: Optional[str] = None) -> dict[str, Any]:
        self.seen_system.append(system)
        self.seen_correction.append(correction)
        return self._responses.pop(0)


async def test_happy_path_builds_hypothesis_and_injects_token():
    fake = FakeLLM({
        "vuln_class": "IDOR",
        "rationale": "Numeric basket id with auth → object-level authz gap.",
        "payload": {"method": "GET", "url": "http://target/rest/basket/1",
                    "auth_token": "model-guessed-wrong"},
        "success_criteria": "200 with a different basket id than the caller's.",
    })
    endpoint = _basket_endpoint()
    h = await attacker.attack(
        endpoint, [],
        auth_context={"auth_token": "REAL-JWT", "own_basket_id": 6},
        llm_client=fake,
    )
    assert isinstance(h, Hypothesis)
    assert h.vuln_class == "IDOR"
    assert h.endpoint == endpoint                 # attached deterministically
    assert h.payload.url.endswith("/basket/1")
    assert h.payload.auth_token == "REAL-JWT"     # injected, not the model's string
    assert h.attempt_number == 1
    # The real endpoint + auth context were put in front of the model.
    assert "/rest/basket/:id" in fake.seen_system[0]
    assert "own_basket_id" in fake.seen_system[0]


async def test_retries_locally_on_schema_invalid_then_succeeds():
    bad = {"vuln_class": "IDOR", "rationale": "x",
           "payload": {"method": "BREW", "url": "http://target/x"},  # invalid method
           "success_criteria": "y"}
    good = {"vuln_class": "IDOR", "rationale": "fixed",
            "payload": {"method": "GET", "url": "http://target/rest/basket/2"},
            "success_criteria": "200 other basket"}
    fake = FakeLLM(bad, good)

    h = await attacker.attack(_basket_endpoint(), [], llm_client=fake, max_llm_retries=3)
    assert h.payload.method == "GET"
    # Second call carried a correction message referencing the validation error.
    assert fake.seen_correction[0] is None
    assert fake.seen_correction[1] and "schema validation" in fake.seen_correction[1]


async def test_raises_after_exhausting_retries():
    bad = {"vuln_class": "IDOR", "rationale": "x",
           "payload": {"method": "GET"},  # missing required url
           "success_criteria": "y"}
    fake = FakeLLM(bad, bad)
    with pytest.raises(ValueError, match="could not produce a valid Hypothesis"):
        await attacker.attack(_basket_endpoint(), [], llm_client=fake, max_llm_retries=2)


async def test_retrieved_context_injected_into_prompt():
    good = {"vuln_class": "IDOR", "rationale": "r",
            "payload": {"method": "GET", "url": "http://target/rest/basket/1"},
            "success_criteria": "sc"}
    fake = FakeLLM(good)
    await attacker.attack(_basket_endpoint(), [], llm_client=fake,
                          retrieved_context=["[IDOR] Increment a numeric object id"])
    assert "Increment a numeric object id" in fake.seen_system[0]


async def test_attempt_history_surfaced_in_prompt():
    prior = VerificationResult(
        hypothesis=Hypothesis(
            vuln_class="IDOR", endpoint=_basket_endpoint(),
            rationale="first try", payload=Payload(method="GET", url="http://target/rest/basket/1"),
            success_criteria="sc"),
        is_exploited=False, confidence="deterministic",
        evidence=VerificationEvidence(raw_response_status=403),
        notes="Attack request returned 403.",
    )
    good = {"vuln_class": "IDOR", "rationale": "changed id based on 403",
            "payload": {"method": "GET", "url": "http://target/rest/basket/2"},
            "success_criteria": "200 other basket"}
    fake = FakeLLM(good)

    h = await attacker.attack(_basket_endpoint(), [prior], llm_client=fake)
    assert h.attempt_number == 2
    assert "403" in fake.seen_system[0]  # prior failure evidence is visible to the model
