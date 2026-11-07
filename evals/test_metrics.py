"""Unit tests for benchmark metrics (pure, no infra).

Run: pytest evals/test_metrics.py
"""
from __future__ import annotations

from evals import metrics
from schemas.models import (
    Endpoint, Finding, Hypothesis, Payload, VerificationEvidence, VerificationResult,
)


def _finding(vuln_class, url, *, confidence="deterministic", attempt=1) -> Finding:
    h = Hypothesis(vuln_class=vuln_class,
                   endpoint=Endpoint(url=url, method="GET"),
                   rationale="r", payload=Payload(method="GET", url=url),
                   success_criteria="sc", attempt_number=attempt)
    vr = VerificationResult(hypothesis=h, is_exploited=True, confidence=confidence,
                            evidence=VerificationEvidence(raw_response_status=200))
    return Finding(verification=vr, cvss_vector="CVSS:3.1/..", cvss_score=6.5,
                   severity="medium", poc_steps=["x"], remediation="y")


GT = [
    {"target": "t", "vuln_class": "IDOR", "endpoint": "/rest/basket/:id", "confirmed": True, "in_scope": True},
    {"target": "t", "vuln_class": "SQLI_ERROR", "endpoint": "/rest/user/login", "confirmed": True, "in_scope": True},
    {"target": "t", "vuln_class": "SSRF", "endpoint": "/rest/track", "confirmed": True, "in_scope": False},
]


def test_precision_recall_fp_rate_basic():
    assert metrics.precision(3, 1) == 0.75
    assert metrics.recall(3, 1) == 0.75
    assert metrics.fp_rate(3, 1) == 0.25
    assert metrics.precision(0, 0) == 0.0  # no divide-by-zero


def test_finding_matches_uses_class_and_endpoint():
    f = _finding("IDOR", "http://t/rest/basket/:id")
    assert metrics.finding_matches(f, GT[0]) is True
    assert metrics.finding_matches(f, GT[1]) is False  # wrong class
    # same endpoint, different class must not match the IDOR entry
    f_auth = _finding("BROKEN_AUTH", "http://t/rest/basket/1")
    assert metrics.finding_matches(f_auth, GT[0]) is False


def test_score_tp_fp_fn():
    findings = [
        _finding("IDOR", "http://t/rest/basket/5"),          # TP
        _finding("SQLI_ERROR", "http://t/rest/user/login"),  # TP
        _finding("XSS_REFLECTED", "http://t/#/search"),      # FP (not in GT)
    ]
    rep = metrics.score(findings, GT, in_scope_only=True)
    assert rep.overall.tp == 2
    assert rep.overall.fp == 1
    # in-scope GT has IDOR + SQLI_ERROR (both matched) => fn 0
    assert rep.overall.fn == 0
    assert abs(rep.overall.precision - 2/3) < 1e-9


def test_score_false_negative_when_in_scope_missed():
    findings = [_finding("IDOR", "http://t/rest/basket/5")]  # only IDOR found
    rep = metrics.score(findings, GT, in_scope_only=True)
    assert rep.overall.tp == 1
    assert rep.overall.fn == 1  # SQLI_ERROR missed
    assert rep.overall.recall == 0.5
    assert any(m["vuln_class"] == "SQLI_ERROR" for m in rep.missed)


def test_out_of_scope_counts_against_recall_only_when_included():
    findings = [_finding("IDOR", "http://t/rest/basket/5"),
                _finding("SQLI_ERROR", "http://t/rest/user/login")]
    in_scope = metrics.score(findings, GT, in_scope_only=True)
    assert in_scope.overall.recall == 1.0           # both in-scope found
    full = metrics.score(findings, GT, in_scope_only=False)
    assert full.overall.fn == 1                     # SSRF (out-of-scope) missed
    assert full.overall.recall == 2/3


def test_fp_rate_by_confidence_and_duplicates():
    findings = [
        _finding("IDOR", "http://t/rest/basket/5", confidence="deterministic"),
        _finding("IDOR", "http://t/rest/basket/9", confidence="deterministic"),  # duplicate TP target -> ignored
        _finding("XSS_REFLECTED", "http://t/x", confidence="llm_judged"),         # FP (llm_judged)
    ]
    rep = metrics.score(findings, GT, in_scope_only=True)
    assert rep.overall.tp == 1 and rep.overall.fp == 1  # 2nd IDOR ignored, XSS is FP
    assert rep.fp_rate_by_confidence["deterministic"] == 0.0
    assert rep.fp_rate_by_confidence["llm_judged"] == 1.0


def test_avg_attempts_to_success():
    findings = [_finding("IDOR", "http://t/a", attempt=1), _finding("SQLI_ERROR", "http://t/b", attempt=3)]
    assert metrics.avg_attempts_to_success(findings) == 2.0
