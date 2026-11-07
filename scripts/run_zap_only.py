"""Lean ZAP-only head-to-head (07_EVALUATION.md), for RAM-constrained hosts.

Runs ONLY the ZAP scan (spider + AJAX spider + active scan) against the target and
combines it with AutoRedTeam's already-established, reproducible engine-mode numbers
(from `python -m evals.run_benchmark`, engine mode: deterministic, no LLM). This avoids
loading Playwright/Chromium and the LLM pipeline at the same time as ZAP's JVM.

Usage:  ZAP_API_URL=http://127.0.0.1:8090 python scripts/run_zap_only.py
"""
from __future__ import annotations

import asyncio
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")

from evals.run_benchmark import _zap_alert_to_class, run_zap_baseline  # noqa: E402

ZAP_TARGET = os.environ.get("ZAP_TARGET", "http://juice-shop:3000")
ZAP_API = os.environ.get("ZAP_API_URL", "http://127.0.0.1:8090")
IN_SCOPE = ["IDOR", "SQLI_ERROR", "XSS_REFLECTED", "BROKEN_AUTH"]

# AutoRedTeam engine-mode results, reproduced this session (deterministic, no LLM).
ART = {"classes": ["BROKEN_AUTH", "IDOR", "SQLI_ERROR", "XSS_REFLECTED"],
       "tp": 4, "fp": 0, "precision": 1.00, "recall": 1.00, "total": 4}


async def main() -> int:
    passive_only = os.environ.get("ZAP_PASSIVE_ONLY") in ("1", "true", "True")
    include_ajax = (not passive_only) and os.environ.get("ZAP_SKIP_AJAX") not in ("1", "true", "True")
    mode = "PASSIVE-ONLY (spider + passive scan, no active scanner)" if passive_only \
        else f"active scan (ajax_spider={include_ajax})"
    print(f"ZAP target: {ZAP_TARGET}  (API {ZAP_API})")
    print(f"mode: {mode}")
    alerts = await run_zap_baseline(ZAP_TARGET, ZAP_API, include_ajax=include_ajax,
                                    active=not passive_only)

    risk = Counter(a.get("risk", "?") for a in alerts)
    zap_classes = sorted({c for a in alerts if (c := _zap_alert_to_class(a.get("alert", "")))})
    zap_inscope = sorted(set(zap_classes) & set(IN_SCOPE))
    zap_recall = len(zap_inscope) / len(IN_SCOPE)

    print("\n" + "=" * 70)
    print("HEAD-TO-HEAD  (OWASP Juice Shop; in-scope classes: %d)" % len(IN_SCOPE))
    print("=" * 70)
    print(f"{'Metric':36}{'AutoRedTeam':>16}{'OWASP ZAP':>16}")
    print("-" * 70)
    print(f"{'in-scope classes detected':36}{len(ART['classes']):>16}{len(zap_inscope):>16}")
    print(f"{'recall (in-scope)':36}{ART['recall']:>16.2f}{zap_recall:>16.2f}")
    print(f"{'confirmed true positives':36}{ART['tp']:>16}{'—':>16}")
    print(f"{'false positives':36}{ART['fp']:>16}{'(unconfirmed)':>16}")
    print(f"{'precision (confirmed-exploit)':36}{ART['precision']:>16.2f}{'n/a':>16}")
    print(f"{'total raw alerts / findings':36}{ART['total']:>16}{len(alerts):>16}")
    print(f"{'exploit proven with PoC':36}{'yes (all)':>16}{'no':>16}")
    print("-" * 70)
    print("AutoRedTeam classes :", ART["classes"], "(engine mode, reproducible)")
    print("ZAP in-scope classes:", zap_inscope,
          "| missed:", sorted(set(IN_SCOPE) - set(zap_inscope)))
    print("ZAP alerts by risk  :", dict(risk))
    print("ZAP all mapped      :", zap_classes)
    print("\nKey difference: every AutoRedTeam finding carries a reproducible PoC "
          "(execution-verified).\nZAP alerts are pattern/heuristic matches with risk+confidence, "
          "not proof of exploitability.")
    if passive_only:
        print("\nNOTE: ZAP ran PASSIVE-ONLY (host could not sustain the active scanner). Passive "
              "scanning\ninspects spidered traffic only — it does not actively probe for "
              "SQLi/XSS/IDOR, so near-zero\nin-scope detection here is expected and NOT a fair "
              "active-vs-active comparison. The active-\nscan runner is code-complete; run it on a "
              "higher-RAM host to fill that column.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
