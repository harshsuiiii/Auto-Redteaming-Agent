"""Unit tests for the Reporter Agent — deterministic CVSS + PoC, LLM-only remediation
(fake LLM, no key/network).

Run: pytest core/agents/test_reporter.py
"""
from __future__ import annotations

import pytest

from core.agents import reporter
from schemas.models import (
    Endpoint, Hypothesis, Payload, VerificationEvidence, VerificationResult,
)


def _result(vuln_class="IDOR", exploited=True) -> VerificationResult:
    h = Hypothesis(
        vuln_class=vuln_class,
        endpoint=Endpoint(url="http://t/rest/basket/:id", method="GET"),
        rationale="r",
        payload=Payload(method="GET", url="http://t/rest/basket/1", auth_token="jwt",
                        body={"x": 1}),
        success_criteria="returns another user's basket",
    )
    return VerificationResult(hypothesis=h, is_exploited=exploited, confidence="deterministic",
                             evidence=VerificationEvidence(raw_response_status=200),
                             notes="body differs from baseline")


def test_cvss_is_deterministic_per_class():
    _, sqli_score, sqli_sev = reporter.score_cvss("SQLI_ERROR")
    assert sqli_score == 9.8 and sqli_sev == "critical"
    _, xss_score, xss_sev = reporter.score_cvss("XSS_REFLECTED")
    assert xss_sev == "medium"
    vector, idor_score, idor_sev = reporter.score_cvss("IDOR")
    assert vector.startswith("CVSS:3.1/") and idor_sev in ("medium", "high")


def test_poc_steps_are_deterministic_from_payload_and_evidence():
    steps = reporter.build_poc_steps(_result())
    assert any("GET http://t/rest/basket/1" in s for s in steps)
    assert any("bearer token" in s for s in steps)
    assert any("Request body" in s for s in steps)
    assert any("HTTP 200" in s for s in steps)


async def test_report_uses_template_remediation_without_llm():
    finding = await reporter.report(_result("IDOR"))
    assert finding.cvss_vector.startswith("CVSS:3.1/")
    assert finding.cvss_score > 0
    assert "authorization" in finding.remediation.lower()
    assert finding.verification.is_exploited is True


async def test_report_uses_llm_remediation_when_provided():
    class FakeLLM:
        async def remediate(self, *, vuln_class, endpoint_url, evidence_summary):
            assert vuln_class == "SQLI_ERROR"
            return "Use parameterized queries. [from-llm]"
    finding = await reporter.report(_result("SQLI_ERROR"), remediation_llm=FakeLLM())
    assert finding.remediation == "Use parameterized queries. [from-llm]"
    assert finding.severity == "critical"


async def test_report_rejects_unexploited_result():
    with pytest.raises(ValueError, match="confirmed"):
        await reporter.report(_result(exploited=False))
