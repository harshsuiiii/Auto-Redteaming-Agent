"""Generate the bundled benchmark snapshot(s) shipped in evals/results/.

These let the dashboard show a rich result even with no sandbox/LLM running (for a
presentation). The numbers are the REAL, documented results from this project's live
runs (see REPORT.md) — engine-mode in-scope P/R=1.00, all-vulns recall=4/7, agent-mode
3-seed variance, RAG ablation, and the ZAP passive head-to-head. CVSS/severity are
computed by the actual reporter so they match the live system exactly.

Run (offline, no network):  python scripts/make_snapshots.py
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.agents import reporter  # noqa: E402
from evals import results  # noqa: E402

CREATED = dt.datetime(2026, 10, 28, 15, 0, tzinfo=dt.timezone.utc)  # a real run date

IN_SCOPE = ["IDOR", "SQLI_ERROR", "BROKEN_AUTH", "XSS_REFLECTED"]
OUT_OF_SCOPE = [("SQLI_BLIND", "/rest/products/search"),
                ("PATH_TRAVERSAL", "/ftp"), ("SSRF", "/rest/track-order")]
ENDPOINTS = {"IDOR": "/rest/basket/2", "SQLI_ERROR": "/rest/user/login",
             "BROKEN_AUTH": "/rest/basket/1", "XSS_REFLECTED": "/#/search"}


def _finding_brief(cls: str, *, attempt: int = 1) -> results.FindingBrief:
    _vec, score, sev = reporter.score_cvss(cls)   # exact, same as the live reporter
    return results.FindingBrief(vuln_class=cls, endpoint=ENDPOINTS[cls], severity=sev,
                                cvss_score=score, confidence="deterministic",
                                attempt_number=attempt)


def _class_card(cls: str) -> results.ScoreBrief:
    return results.ScoreBrief(label=cls, tp=1, fp=0, fn=0, precision=1.0, recall=1.0, fp_rate=0.0)


def build_clean_run() -> results.BenchmarkResult:
    findings = [_finding_brief(c) for c in IN_SCOPE]
    matched = [{"target": "juice-shop", "vuln_class": c, "endpoint": ENDPOINTS[c],
                "in_scope": True} for c in IN_SCOPE]
    missed = [{"target": "juice-shop", "vuln_class": c, "endpoint": ep, "in_scope": False}
              for c, ep in OUT_OF_SCOPE]

    scenarios = [
        results.ScenarioOutcome(name="idor_other_basket", vuln_class="IDOR",
            endpoint="/rest/basket/:id", expected_exploited=True, actual_exploited=True,
            passed=True, kind="tp", confidence="deterministic", severity="medium",
            cvss_score=reporter.score_cvss("IDOR")[1],
            description="read another user's basket by swapping a sequential id",
            note="attack 200 shares baseline JSON shape but different data — confirmed."),
        results.ScenarioOutcome(name="sqli_error_login", vuln_class="SQLI_ERROR",
            endpoint="/rest/user/login", expected_exploited=True, actual_exploited=True,
            passed=True, kind="tp", confidence="deterministic", severity="critical",
            cvss_score=reporter.score_cvss("SQLI_ERROR")[1],
            description="break login SQL with a lone quote to leak a DB error",
            note="SequelizeDatabaseError signature present for injection, absent for baseline."),
        results.ScenarioOutcome(name="broken_auth_forged_jwt", vuln_class="BROKEN_AUTH",
            endpoint="/rest/basket/1", expected_exploited=True, actual_exploited=True,
            passed=True, kind="tp", confidence="deterministic", severity="high",
            cvss_score=reporter.score_cvss("BROKEN_AUTH")[1],
            description="forged alg:none admin JWT accepted on a protected route",
            note="unsigned admin JWT flipped 401 -> 200 on /rest/basket/1."),
        results.ScenarioOutcome(name="xss_reflected_search", vuln_class="XSS_REFLECTED",
            endpoint="/#/search", expected_exploited=True, actual_exploited=True,
            passed=True, kind="tp", confidence="deterministic", severity="medium",
            cvss_score=reporter.score_cvss("XSS_REFLECTED")[1],
            description="reflected XSS via the SPA search query parameter",
            note="img-onerror marker executed in real Chromium (Playwright DOM check)."),
        results.ScenarioOutcome(name="idor_own_basket_safe", vuln_class="IDOR",
            endpoint="/rest/basket/:id", expected_exploited=False, actual_exploited=False,
            passed=True, kind="true_negative", confidence="deterministic",
            description="accessing the user's OWN basket is legitimate; must not be flagged",
            note="attack and baseline bodies identical — correctly NOT flagged as IDOR."),
        results.ScenarioOutcome(name="sqli_benign_login_guard", vuln_class="SQLI_ERROR",
            endpoint="/rest/user/login", expected_exploited=False, actual_exploited=False,
            passed=True, kind="fp_guard", confidence="deterministic",
            description="a benign failed login returns 401 but no DB error; must not be flagged",
            note="401 with no DB-error signature — correctly NOT flagged as SQLi."),
        # honest out-of-scope misses (documented vulns the system is not designed to verify)
        *[results.ScenarioOutcome(name=f"{c.lower()}_out_of_scope", vuln_class=c, endpoint=ep,
            expected_exploited=True, actual_exploited=None, passed=None, kind="false_negative",
            in_scope=False, description="documented vuln outside AutoRedTeam's deterministic scope",
            note={"SQLI_BLIND": "SQLite has no SLEEP(); time-based detection cannot fire here.",
                  "PATH_TRAVERSAL": "no OS file-read oracle available in this sandbox.",
                  "SSRF": "needs an out-of-band callback listener not provisioned here."}[c])
          for c, ep in OUT_OF_SCOPE],
    ]

    return results.BenchmarkResult(
        schema_version=1,
        label="Juice Shop — representative live run (engine + agent)",
        target="http://127.0.0.1:3000",
        model="openai/gpt-oss-120b (Groq)",
        mode="mixed",
        created_at=CREATED,
        overall_in_scope=results.ScoreBrief(label="overall", tp=4, fp=0, fn=0,
                                            precision=1.0, recall=1.0, fp_rate=0.0),
        overall_all=results.ScoreBrief(label="overall", tp=4, fp=0, fn=3,
                                       precision=1.0, recall=round(4 / 7, 4), fp_rate=0.0),
        per_class=[_class_card(c) for c in IN_SCOPE],
        fp_rate_by_confidence={"deterministic": 0.0, "llm_judged": 0.0},
        avg_attempts_to_success=1.0,
        agent_recall=results.SeedStat(mean=1.0, stddev=0.0, n=3, values=[1.0, 1.0, 1.0]),
        agent_precision=results.SeedStat(mean=1.0, stddev=0.0, n=3, values=[1.0, 1.0, 1.0]),
        agent_attempts=results.SeedStat(mean=1.08, stddev=0.12, n=3, values=[1.0, 1.0, 1.25]),
        matched=matched, missed=missed, false_positives=[], findings=findings,
        scenarios=scenarios,
        rag_ablation=[
            results.AblationRow(label="without RAG", recall=1.0, precision=1.0, avg_attempts=1.08),
            results.AblationRow(label="with RAG", recall=1.0, precision=1.0, avg_attempts=1.0),
        ],
        zap=results.ZapComparison(
            ran=True, mode="passive", total_alerts=238, mapped_in_scope_classes=[],
            autoredteam_confirmed=4,
            note="ZAP passive: 238 raw alerts (170 Medium / 68 Informational), 0 mapped to an "
                 "in-scope class, none PoC-backed. AutoRedTeam: 4 confirmed, all PoC-backed."),
        notes=[
            "Engine mode (deterministic verifier on canonical payloads): in-scope P/R = 1.00, FP-rate = 0.00.",
            "Agent mode (LLM attacker), 3 seeds: recall 1.00±0.00, precision 1.00±0.00, attempts 1.08±0.12.",
            "All-vulns recall = 4/7 (0.57): three documented classes are honestly out of deterministic scope.",
            "RAG ablation: no accuracy delta on this saturated in-scope set (ablation-on-easy-set limitation).",
            "ZAP head-to-head was passive-only (host RAM); active-vs-active is a higher-RAM stretch goal.",
        ],
    )


def main() -> int:
    results.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = results.save(build_clean_run(), results.RESULTS_DIR / "snapshot-01-juiceshop-clean.json")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
