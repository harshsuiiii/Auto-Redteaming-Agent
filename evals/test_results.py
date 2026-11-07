"""Unit tests for the serializable benchmark results (pure, no infra).

Run: pytest evals/test_results.py
"""
from __future__ import annotations

from evals import metrics, results
from schemas.models import (
    Endpoint, Finding, Hypothesis, Payload, VerificationEvidence, VerificationResult,
)


def _finding(vuln_class, url, *, confidence="deterministic", attempt=1,
             severity="medium", cvss=6.5) -> Finding:
    h = Hypothesis(vuln_class=vuln_class, endpoint=Endpoint(url=url, method="GET"),
                   rationale="r", payload=Payload(method="GET", url=url),
                   success_criteria="sc", attempt_number=attempt)
    vr = VerificationResult(hypothesis=h, is_exploited=True, confidence=confidence,
                            evidence=VerificationEvidence(raw_response_status=200))
    return Finding(verification=vr, cvss_vector="CVSS:3.1/..", cvss_score=cvss,
                   severity=severity, poc_steps=["x"], remediation="y")


GT = [
    {"target": "t", "vuln_class": "IDOR", "endpoint": "/rest/basket/:id", "confirmed": True, "in_scope": True},
    {"target": "t", "vuln_class": "SQLI_ERROR", "endpoint": "/rest/user/login", "confirmed": True, "in_scope": True},
    {"target": "t", "vuln_class": "SSRF", "endpoint": "/rest/track", "confirmed": True, "in_scope": False},
]


def test_score_brief_precomputes_rates():
    sc = metrics.ScoreCard(tp=3, fp=1, fn=0)
    b = results.ScoreBrief.from_scorecard(sc, "IDOR")
    assert (b.label, b.tp, b.fp, b.fn) == ("IDOR", 3, 1, 0)
    assert b.precision == 0.75 and b.fp_rate == 0.25 and b.recall == 1.0


def test_finding_brief_from_finding():
    fb = results.FindingBrief.from_finding(
        _finding("SQLI_ERROR", "http://t/login", confidence="deterministic",
                 attempt=2, severity="critical", cvss=9.8))
    assert fb.vuln_class == "SQLI_ERROR" and fb.severity == "critical"
    assert fb.cvss_score == 9.8 and fb.attempt_number == 2


def test_from_report_builds_full_result():
    findings = [_finding("IDOR", "http://t/rest/basket/5"),
                _finding("SQLI_ERROR", "http://t/rest/user/login", severity="critical", cvss=9.8)]
    in_scope = metrics.score(findings, GT, in_scope_only=True)
    all_v = metrics.score(findings, GT, in_scope_only=False)
    r = results.BenchmarkResult.from_report(
        label="t", target="http://t", model="m", mode="engine",
        in_scope=in_scope, all_vulns=all_v, findings=findings)
    assert r.overall_in_scope.recall == 1.0          # both in-scope found
    assert r.overall_all.fn == 1                      # SSRF (out-of-scope) missed
    assert {c.label for c in r.per_class} == {"IDOR", "SQLI_ERROR"}
    assert len(r.findings) == 2
    assert any(m["vuln_class"] == "SSRF" for m in r.missed)


def test_save_load_round_trip(tmp_path):
    r = results.BenchmarkResult(label="rt", target="http://t", model="m",
                                overall_in_scope=results.ScoreBrief(tp=4, precision=1.0, recall=1.0))
    p = results.save(r, tmp_path / "x.json")
    loaded = results.load(p)
    assert loaded.label == "rt" and loaded.overall_in_scope.tp == 4
    assert loaded.model_dump() == r.model_dump()


def test_list_and_load_latest(tmp_path):
    import datetime as dt
    older = results.BenchmarkResult(label="old", target="t", model="m",
                                    created_at=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc))
    newer = results.BenchmarkResult(label="new", target="t", model="m",
                                    created_at=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
    results.save(older, tmp_path / "a.json")
    results.save(newer, tmp_path / "b.json")
    assert len(results.list_snapshots(tmp_path)) == 2
    assert results.load_latest(tmp_path).label == "new"


def test_load_all_skips_malformed(tmp_path):
    results.save(results.BenchmarkResult(label="ok", target="t", model="m"), tmp_path / "ok.json")
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    loaded = results.load_all(tmp_path)
    assert len(loaded) == 1 and loaded[0].label == "ok"


def test_bundled_snapshot_is_valid_and_consistent():
    """The shipped snapshot must load and tell a self-consistent story."""
    snap = results.RESULTS_DIR / "snapshot-01-juiceshop-clean.json"
    assert snap.exists(), "run scripts/make_snapshots.py to generate the bundled snapshot"
    r = results.load(snap)
    assert r.overall_in_scope.precision == 1.0 and r.overall_in_scope.recall == 1.0
    assert r.overall_all.fn == 3                      # three honest out-of-scope misses
    assert len(r.findings) == 4
    # scenario sweep carries both true positives and correct non-alarms
    kinds = {s.kind for s in r.scenarios}
    assert {"tp", "true_negative", "fp_guard"} <= kinds
    assert all(s.passed for s in r.scenarios if s.passed is not None)
