"""Benchmark runner (07_EVALUATION.md).

* ``run_autoredteam`` drives the real agent + verifier + reporter across the in-scope
  vuln classes and returns the verified Findings (optionally with the RAG knowledge
  base enabled, for the ablation).
* ``run_zap_baseline`` runs OWASP ZAP (spider + active scan) against the same target
  via its API and maps alerts to our vuln classes — the comparative baseline. It runs
  only when a ZAP instance is reachable; otherwise the AutoRedTeam column is produced
  on its own and the exact ZAP command is printed.

CLI:  python -m evals.run_benchmark [base_url]
      (LLM via env: GROQ_API_KEY/OPENAI_API_KEY + AUTOREDTEAM_LLM_*; ZAP via ZAP_API_URL)
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import time
import uuid
from pathlib import Path
from statistics import mean, pstdev
from urllib.parse import urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")

from core.agents import attacker, reporter  # noqa: E402
from core.orchestration.targets import JuiceShopAdapter  # noqa: E402
from core.sandbox.client import make_scoped_client  # noqa: E402
from core.verifier import VERIFIERS  # noqa: E402
from evals import ground_truth, metrics, results, scenarios  # noqa: E402
from schemas.models import Endpoint, Finding, Hypothesis, ParamSchema, Payload  # noqa: E402


def _forge_none_jwt(data: dict) -> str:
    b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
    h = b(json.dumps({"typ": "JWT", "alg": "none"}).encode())
    p = b(json.dumps({"data": data, "iat": int(time.time()), "exp": int(time.time()) + 3600}).encode())
    return f"{h}.{p}."


def _probes(base: str, auth: dict) -> list[dict]:
    own = int(auth["own_resource_id"])
    victim = 1 if own != 1 else 2
    forged = _forge_none_jwt({"id": 1, "email": "admin@juice-sh.op"})
    return [
        {"vuln_class": "IDOR",
         "endpoint": Endpoint(url=f"{base}/rest/basket/:id", method="GET", auth_required=True,
                              params=[ParamSchema(name="id", location="path", type="int", sample_value=str(own))]),
         "auth_context": {"auth_token": auth["auth_token"], "own_resource_id": own,
                          "hint": "basket ids are small sequential integers; use one != own"},
         # canonical payload for engine mode (no LLM)
         "prepared": Payload(method="GET", url=f"{base}/rest/basket/{victim}", auth_token=auth["auth_token"])},
        {"vuln_class": "SQLI_ERROR",
         "endpoint": Endpoint(url=f"{base}/rest/user/login", method="POST"),
         "auth_context": {},
         "prepared": Payload(method="POST", url=f"{base}/rest/user/login", body={"email": "'", "password": "x"})},
        {"vuln_class": "XSS_REFLECTED",
         "endpoint": Endpoint(url=f"{base}/#/search?q=", method="GET"),
         "auth_context": {},
         "prepared": Payload(method="GET", url=f"{base}/#/search?q=<script>x</script>")},
        {"vuln_class": "BROKEN_AUTH",
         "endpoint": Endpoint(url=f"{base}/rest/basket/1", method="GET", auth_required=True),
         "auth_context": {"auth_token": forged, "own_resource_id": 1,
                          "hint": "an unsigned (alg:none) admin JWT is provided; target /rest/basket/1"},
         "prepared": Payload(method="GET", url=f"{base}/rest/basket/1", auth_token=forged)},
    ]


async def _hypothesis_for(probe: dict, history: list, ctx, *, agent_driven: bool) -> Hypothesis:
    cls, ep, actx = probe["vuln_class"], probe["endpoint"], probe["auth_context"]
    if agent_driven:
        return await attacker.attack(ep, history, auth_context=actx,
                                     allowed_vuln_classes=[cls], retrieved_context=ctx)
    # Engine mode: canonical prepared payload, no LLM — fully reproducible.
    return Hypothesis(vuln_class=cls, endpoint=ep, rationale="[engine] canonical payload",
                      payload=probe["prepared"], success_criteria="canonical probe",
                      attempt_number=len(history) + 1)


async def run_autoredteam(base: str, *, use_rag: bool = False, agent_driven: bool = True,
                          max_attempts: int = 2, request_cap: int = 500) -> list[Finding]:
    """agent_driven=True measures the full system (LLM attacker); False (engine mode)
    uses canonical payloads to measure the deterministic verifier reproducibly."""
    retriever = None
    if use_rag and agent_driven:
        from knowledge.retrieve import KnowledgeRetriever
        retriever = KnowledgeRetriever.build()

    counter = {"n": 0}
    allowed_hosts = {urlparse(base).hostname or ""}
    findings: list[Finding] = []
    attempts = 1 if not agent_driven else max_attempts

    async with make_scoped_client(base, allowed_hosts, counter, request_cap) as client:
        auth = await JuiceShopAdapter(base).bootstrap(client)
        for probe in _probes(base, auth):
            cls, ep = probe["vuln_class"], probe["endpoint"]
            ctx = [f"[{cls}] {s}" for s in retriever(cls, ep)] if retriever else None
            history: list = []
            for _ in range(attempts):
                h = await _hypothesis_for(probe, history, ctx, agent_driven=agent_driven)
                verifier = VERIFIERS[cls]
                res = await verifier(h) if cls == "XSS_REFLECTED" else await verifier(h, client)
                history.append(res)
                if res.is_exploited:
                    findings.append(await reporter.report(res, remediation_llm=None))
                    break
    return findings


async def run_scenarios(base: str, *, request_cap: int = 500) -> list[results.ScenarioOutcome]:
    """Run every named scenario in ENGINE MODE (canonical payload, no LLM) and record
    expected-vs-actual verdicts. Deterministic and reproducible — this is what gives the
    dashboard its variety of end results (TP, honest miss, and correct non-alarms)."""
    counter = {"n": 0}
    allowed_hosts = {urlparse(base).hostname or ""}
    outcomes: list[results.ScenarioOutcome] = []
    async with make_scoped_client(base, allowed_hosts, counter, request_cap) as client:
        auth = await JuiceShopAdapter(base).bootstrap(client)
        for sc in scenarios.build_scenarios(base, auth):
            verifier = VERIFIERS[sc.vuln_class]
            h = sc.hypothesis()
            try:
                res = await (verifier(h) if sc.vuln_class == "XSS_REFLECTED" else verifier(h, client))
                sev = cvss = None
                if res.is_exploited:
                    fnd = await reporter.report(res, remediation_llm=None)
                    sev, cvss = fnd.severity, fnd.cvss_score
                outcomes.append(results.ScenarioOutcome(
                    name=sc.name, vuln_class=sc.vuln_class, endpoint=sc.endpoint.url,
                    expected_exploited=sc.expected_exploited, actual_exploited=res.is_exploited,
                    passed=(res.is_exploited == sc.expected_exploited), kind=sc.kind,
                    in_scope=sc.in_scope, confidence=res.confidence, severity=sev,
                    cvss_score=cvss, description=sc.description, note=res.notes or ""))
            except Exception as exc:  # scenario infra failure (e.g. no chromium) — surface, don't crash
                outcomes.append(results.ScenarioOutcome(
                    name=sc.name, vuln_class=sc.vuln_class, endpoint=sc.endpoint.url,
                    expected_exploited=sc.expected_exploited, actual_exploited=None, passed=None,
                    kind=sc.kind, in_scope=sc.in_scope, description=sc.description,
                    note=f"error: {type(exc).__name__}: {exc}"))
    return outcomes


# --------------------------------------------------------------------------- #
# OWASP ZAP comparative baseline
# --------------------------------------------------------------------------- #

_ZAP_CLASS_MAP = [
    ("sql injection", "SQLI_ERROR"),
    ("cross site scripting", "XSS_REFLECTED"),
    ("path traversal", "PATH_TRAVERSAL"),
    ("remote file", "PATH_TRAVERSAL"),
    ("server side request", "SSRF"),
    ("idor", "IDOR"),
    ("authentication", "BROKEN_AUTH"),
]


def _zap_alert_to_class(name: str) -> str | None:
    low = name.lower()
    return next((cls for kw, cls in _ZAP_CLASS_MAP if kw in low), None)


async def run_zap_baseline(target_url: str, zap_api_url: str, *, api_key: str = "",
                           phase_timeout: float = 420.0, ajax_max_minutes: int = 3,
                           include_ajax: bool = True, active: bool = True) -> list[dict]:
    """ZAP spider + AJAX spider (fair SPA coverage) + active scan, then collect alerts.
    ``include_ajax=False`` skips the headless-browser AJAX spider (much lower memory).

    Resilient to ZAP dropping idle connections while it is busy (e.g. slow/blocked
    external telemetry calls): every API call retries on a transport error, so the
    server-side scan keeps running and we keep polling it to completion."""
    async def _get(z, path, **params):
        params["apikey"] = api_key
        last = None
        for _ in range(5):
            try:
                return (await z.get(path, params=params)).json()
            except httpx.TransportError as exc:  # disconnect / read timeout while ZAP busy
                last = exc
                await asyncio.sleep(2)
        raise last

    async def _poll_pct(z, path, scan_id):
        deadline = asyncio.get_event_loop().time() + phase_timeout
        while asyncio.get_event_loop().time() < deadline:
            if (await _get(z, path, scanId=scan_id))["status"] == "100":
                return
            await asyncio.sleep(3)

    async def _poll_ajax(z):
        deadline = asyncio.get_event_loop().time() + phase_timeout
        while asyncio.get_event_loop().time() < deadline:
            if (await _get(z, "/JSON/ajaxSpider/view/status/"))["status"] != "running":
                return
            await asyncio.sleep(3)

    async def _poll_pscan(z):  # wait for the passive-scan queue to drain
        deadline = asyncio.get_event_loop().time() + phase_timeout
        while asyncio.get_event_loop().time() < deadline:
            if int((await _get(z, "/JSON/pscan/view/recordsToScan/"))["recordsToScan"]) == 0:
                return
            await asyncio.sleep(2)

    async with httpx.AsyncClient(base_url=zap_api_url, timeout=180) as z:
        # Fail doomed external calls fast (sandbox egress is slow/blocked) so they don't
        # clog ZAP's threads; clear any stale scans from a previous aborted run.
        for path, params in (("/JSON/network/action/setConnectionTimeout/", {"Integer": 5}),
                             ("/JSON/ascan/action/stopAllScans/", {}),
                             ("/JSON/spider/action/stopAllScans/", {})):
            try:
                await _get(z, path, **params)
            except Exception:
                pass
        await _get(z, "/JSON/core/action/accessUrl/", url=target_url)
        # 1. traditional spider
        sid = (await _get(z, "/JSON/spider/action/scan/", url=target_url))["scan"]
        await _poll_pct(z, "/JSON/spider/view/status/", sid)
        # 2. AJAX spider (headless browser) — fair SPA coverage, but memory-heavy.
        #    Tolerate browser issues; skip entirely when include_ajax=False (low memory).
        if include_ajax:
            try:
                await _get(z, "/JSON/ajaxSpider/action/setOptionMaxDuration/", Integer=ajax_max_minutes)
                await _get(z, "/JSON/ajaxSpider/action/scan/", url=target_url)
                await _poll_ajax(z)
            except Exception as exc:
                print(f"  [zap] AJAX spider skipped ({type(exc).__name__}): {exc}")
        else:
            print("  [zap] AJAX spider disabled (low-memory mode)")
        # 3. active scan (the memory-heavy phase) — skipped in passive-only mode, where
        #    we instead let the passive scanner finish analysing the spidered traffic.
        if active:
            aid = (await _get(z, "/JSON/ascan/action/scan/", url=target_url))["scan"]
            await _poll_pct(z, "/JSON/ascan/view/status/", aid)
        else:
            await _poll_pscan(z)
        alerts = (await _get(z, "/JSON/core/view/alerts/", baseurl=target_url))["alerts"]
    return alerts


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def _print_scorecard(title: str, report: metrics.BenchmarkReport) -> None:
    o = report.overall
    print(f"\n{title}")
    print(f"  TP={o.tp}  FP={o.fp}  FN={o.fn}  "
          f"precision={o.precision:.2f}  recall={o.recall:.2f}  fp_rate={o.fp_rate:.2f}")
    print(f"  avg attempts-to-success (ReAct efficiency): {report.avg_attempts_to_success:.2f}")
    print(f"  FP-rate by confidence: deterministic={report.fp_rate_by_confidence['deterministic']:.2f}  "
          f"llm_judged={report.fp_rate_by_confidence['llm_judged']:.2f}")
    print("  per-class:")
    for cls, sc in sorted(report.per_class.items()):
        print(f"    {cls:16} TP={sc.tp} FP={sc.fp} FN={sc.fn} "
              f"prec={sc.precision:.2f} rec={sc.recall:.2f}")
    if report.missed:
        print("  missed (false negatives):", ", ".join(f"{m['vuln_class']}@{m['endpoint']}"
              + ("" if m.get("in_scope", True) else " [out-of-scope]") for m in report.missed))


def _fmt(xs: list[float]) -> str:
    if not xs:
        return "n/a"
    return f"{mean(xs):.2f}" + (f" ± {pstdev(xs):.2f}" if len(xs) > 1 else "")


async def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3000"
    seeds = int(os.environ.get("BENCH_SEEDS", "3"))
    gt = ground_truth.for_target("juice-shop")
    print(f"target: {base}\nmodel : {attacker.DEFAULT_MODEL}\nagent seeds: {seeds}")

    # ENGINE MODE — canonical payloads, no LLM: measures the verifier, fully reproducible.
    print("\n=== Engine mode (deterministic verifier, canonical payloads, no LLM) ===")
    eng = await run_autoredteam(base, agent_driven=False)
    print("  verified:", [f.verification.hypothesis.vuln_class for f in eng])
    eng_all = metrics.score(eng, gt, in_scope_only=False)
    eng_scope = metrics.score(eng, gt, in_scope_only=True)
    _print_scorecard("Scored vs ALL documented vulns (incl. out-of-scope):", eng_all)
    _print_scorecard("Scored vs IN-SCOPE vulns only:", eng_scope)

    # AGENT MODE — full system (LLM attacker), multi-seed for variance.
    print(f"\n=== Agent mode (LLM attacker) — {seeds} seeds ===")
    recalls, precisions, attempts, class_hits = [], [], [], []
    for i in range(seeds):
        f = await run_autoredteam(base, agent_driven=True)
        r = metrics.score(f, gt, in_scope_only=True)
        recalls.append(r.overall.recall)
        precisions.append(r.overall.precision)
        attempts.append(r.avg_attempts_to_success)
        found = sorted({x.verification.hypothesis.vuln_class for x in f})
        class_hits.append(found)
        print(f"  seed {i+1}: recall={r.overall.recall:.2f} precision={r.overall.precision:.2f} "
              f"avg_attempts={r.avg_attempts_to_success:.2f} found={found}")
    print(f"  -> in-scope recall={_fmt(recalls)}  precision={_fmt(precisions)}  "
          f"avg_attempts={_fmt(attempts)}  (n={seeds})")

    # RAG ablation (agent mode, single seed each — note LLM variance from above).
    print("\n=== RAG ablation (agent mode) ===")
    f_norag = await run_autoredteam(base, agent_driven=True, use_rag=False)
    f_rag = await run_autoredteam(base, agent_driven=True, use_rag=True)
    rn = metrics.score(f_norag, gt, in_scope_only=True)
    rr = metrics.score(f_rag, gt, in_scope_only=True)
    print(f"  without RAG: recall={rn.overall.recall:.2f} precision={rn.overall.precision:.2f} "
          f"avg_attempts={rn.avg_attempts_to_success:.2f}")
    print(f"  with RAG   : recall={rr.overall.recall:.2f} precision={rr.overall.precision:.2f} "
          f"avg_attempts={rr.avg_attempts_to_success:.2f}")

    rep_scope = eng_scope  # engine-mode scorecard is the reproducible reference for the summary

    # Scenario sweep (engine mode) — TP + correct non-alarms, for the variety story.
    print("\n=== Scenario sweep (engine mode: expected vs actual) ===")
    scen = await run_scenarios(base)
    for s in scen:
        mark = "ok " if s.passed else ("?? " if s.passed is None else "XX ")
        act = "n/a" if s.actual_exploited is None else ("exploited" if s.actual_exploited else "safe")
        print(f"  {mark}{s.name:26} expect={'exploited' if s.expected_exploited else 'safe':9} actual={act}")

    # Comparative baseline (OWASP ZAP), only if reachable.
    zap_url = os.environ.get("ZAP_API_URL")
    zap = results.ZapComparison(autoredteam_confirmed=rep_scope.overall.tp)
    print("\n=== Head-to-head vs OWASP ZAP ===")
    if zap_url:
        try:
            alerts = await run_zap_baseline(base, zap_url, api_key=os.environ.get("ZAP_API_KEY", ""))
            zap_classes = {c for a in alerts if (c := _zap_alert_to_class(a.get("alert", "")))}
            zap_tp = len(zap_classes & {g["vuln_class"] for g in gt})
            zap = results.ZapComparison(
                ran=True, mode="active" if os.environ.get("ZAP_PASSIVE_ONLY") != "1" else "passive",
                total_alerts=len(alerts), mapped_in_scope_classes=sorted(zap_classes),
                autoredteam_confirmed=rep_scope.overall.tp,
                note=f"{len(alerts)} raw alerts, {zap_tp} mapped to in-scope classes, none PoC-backed")
            print(f"  ZAP alerts: {len(alerts)} | mapped classes: {sorted(zap_classes)} | TP vs GT: {zap_tp}")
        except Exception as exc:
            zap.note = f"ZAP run failed: {exc}"
            print(f"  ZAP run failed: {exc}")
    else:
        print("  ZAP not run (set ZAP_API_URL to enable). Runner is code-complete; to run:")
        print("    docker run -u zap -p 8090:8090 zaproxy/zap-stable zap.sh -daemon \\")
        print("      -host 0.0.0.0 -port 8090 -config api.disablekey=true")
        print("    ZAP_API_URL=http://127.0.0.1:8090 python -m evals.run_benchmark \\")
        print("      http://host.docker.internal:3000")
    print(f"\n  AutoRedTeam: TP={rep_scope.overall.tp} FP={rep_scope.overall.fp} "
          f"precision={rep_scope.overall.precision:.2f} (deterministic FP-rate="
          f"{rep_scope.fp_rate_by_confidence['deterministic']:.2f})")

    # Assemble a durable, JSON-serialisable result for the dashboard.
    def _stat(xs: list[float]) -> results.SeedStat:
        return results.SeedStat(mean=round(mean(xs), 4) if xs else 0.0,
                                stddev=round(pstdev(xs), 4) if len(xs) > 1 else 0.0,
                                n=len(xs), values=[round(x, 4) for x in xs])

    result = results.BenchmarkResult.from_report(
        label=f"Live benchmark {time.strftime('%Y-%m-%d %H:%M')}", target=base,
        model=attacker.DEFAULT_MODEL, mode="mixed", in_scope=eng_scope, all_vulns=eng_all,
        findings=eng,
        agent_recall=_stat(recalls), agent_precision=_stat(precisions), agent_attempts=_stat(attempts),
        rag_ablation=[
            results.AblationRow(label="without RAG", recall=round(rn.overall.recall, 4),
                                precision=round(rn.overall.precision, 4),
                                avg_attempts=round(rn.avg_attempts_to_success, 4)),
            results.AblationRow(label="with RAG", recall=round(rr.overall.recall, 4),
                                precision=round(rr.overall.precision, 4),
                                avg_attempts=round(rr.avg_attempts_to_success, 4)),
        ],
        scenarios=scen, zap=zap,
        notes=[f"engine mode = deterministic verifier on canonical payloads (reproducible)",
               f"agent mode = {len(recalls)} LLM seeds; mean ± stddev shown",
               "in-scope recall is scored against the classes AutoRedTeam is designed to verify"],
    )
    out = results.save(result, results.RESULTS_DIR / f"live-{int(time.time())}.json")
    print(f"\n  saved benchmark result -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
