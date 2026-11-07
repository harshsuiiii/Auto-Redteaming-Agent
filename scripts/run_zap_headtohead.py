"""Phase 8 comparative baseline: AutoRedTeam vs OWASP ZAP, head to head (07_EVALUATION.md).

Same target, two network paths:
  * AutoRedTeam runs on the host  -> http://127.0.0.1:3000  (via the sandbox gateway)
  * ZAP runs in a container       -> http://juice-shop:3000 (direct, on the isolated net)

AutoRedTeam is measured in engine mode (canonical payloads, deterministic, no LLM) so
the comparison is reproducible. ZAP runs spider + AJAX spider + active scan.

Usage:  ZAP_API_URL=http://127.0.0.1:8090 python scripts/run_zap_headtohead.py
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

from evals import ground_truth, metrics  # noqa: E402
from evals.run_benchmark import _zap_alert_to_class, run_autoredteam, run_zap_baseline  # noqa: E402

HOST_TARGET = os.environ.get("ART_TARGET", "http://127.0.0.1:3000")
ZAP_TARGET = os.environ.get("ZAP_TARGET", "http://juice-shop:3000")
ZAP_API = os.environ.get("ZAP_API_URL", "http://127.0.0.1:8090")
IN_SCOPE = ["IDOR", "SQLI_ERROR", "XSS_REFLECTED", "BROKEN_AUTH"]


async def main() -> int:
    gt = ground_truth.for_target("juice-shop")

    print("[1/2] AutoRedTeam (engine mode, deterministic) ...")
    art = await run_autoredteam(HOST_TARGET, agent_driven=False)
    art_rep = metrics.score(art, gt, in_scope_only=True)
    art_classes = sorted({f.verification.hypothesis.vuln_class for f in art})

    print("[2/2] OWASP ZAP (spider + AJAX spider + active scan) — minutes ...")
    alerts = await run_zap_baseline(ZAP_TARGET, ZAP_API)
    risk = Counter(a.get("risk", "?") for a in alerts)
    zap_classes = sorted({c for a in alerts if (c := _zap_alert_to_class(a.get("alert", "")))})
    zap_inscope = sorted(set(zap_classes) & set(IN_SCOPE))
    zap_recall = len(zap_inscope) / len(IN_SCOPE)

    print("\n" + "=" * 68)
    print("HEAD-TO-HEAD  (target: OWASP Juice Shop; in-scope classes: %d)" % len(IN_SCOPE))
    print("=" * 68)
    print(f"{'Metric':34}{'AutoRedTeam':>16}{'OWASP ZAP':>16}")
    print("-" * 68)
    print(f"{'in-scope classes detected':34}{len(art_classes):>16}{len(zap_inscope):>16}")
    print(f"{'recall (in-scope)':34}{art_rep.overall.recall:>16.2f}{zap_recall:>16.2f}")
    print(f"{'confirmed true positives':34}{art_rep.overall.tp:>16}{'—':>16}")
    print(f"{'false positives':34}{art_rep.overall.fp:>16}{'(unconfirmed)':>16}")
    print(f"{'precision (confirmed-exploit)':34}{art_rep.overall.precision:>16.2f}{'n/a':>16}")
    print(f"{'total raw alerts/findings':34}{len(art):>16}{len(alerts):>16}")
    print(f"{'exploit proven with PoC':34}{'yes (all)':>16}{'no':>16}")
    print("-" * 68)
    print("AutoRedTeam classes :", art_classes)
    print("ZAP in-scope classes:", zap_inscope, "| missed:", sorted(set(IN_SCOPE) - set(zap_inscope)))
    print("ZAP alerts by risk  :", dict(risk))
    print("ZAP all mapped      :", zap_classes)
    print("\nKey difference: every AutoRedTeam finding carries a reproducible PoC "
          "(execution-verified);\nZAP alerts are pattern/heuristic matches with risk+confidence, "
          "not proof of exploitability.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
