"""Benchmark metrics (07_EVALUATION.md).

Pure, deterministic scoring so the numbers are reproducible and unit-testable:
precision / recall / false-positive rate (overall, per class, and broken out by the
``deterministic`` vs ``llm_judged`` confidence tier), plus ReAct loop efficiency
(average attempts-to-success).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean

from schemas.models import Finding


def precision(tp: int, fp: int) -> float:
    return tp / (tp + fp) if (tp + fp) else 0.0


def recall(tp: int, fn: int) -> float:
    return tp / (tp + fn) if (tp + fn) else 0.0


def fp_rate(tp: int, fp: int) -> float:
    return fp / (tp + fp) if (tp + fp) else 0.0


def _core(endpoint: str) -> str:
    """Comparable core of a ground-truth endpoint (drop :id template, query, trailing /)."""
    return endpoint.split(":")[0].split("?")[0].rstrip("/")


def finding_matches(finding: Finding, gt: dict) -> bool:
    h = finding.verification.hypothesis
    return h.vuln_class == gt["vuln_class"] and _core(gt["endpoint"]) in h.endpoint.url


@dataclass
class ScoreCard:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float: return precision(self.tp, self.fp)
    @property
    def recall(self) -> float: return recall(self.tp, self.fn)
    @property
    def fp_rate(self) -> float: return fp_rate(self.tp, self.fp)


@dataclass
class BenchmarkReport:
    overall: ScoreCard
    per_class: dict[str, ScoreCard]
    fp_rate_by_confidence: dict[str, float]      # "deterministic" / "llm_judged"
    avg_attempts_to_success: float
    matched_truth: list[dict] = field(default_factory=list)
    false_positives: list[Finding] = field(default_factory=list)
    missed: list[dict] = field(default_factory=list)      # false negatives (in-scope)


def avg_attempts_to_success(findings: list[Finding]) -> float:
    attempts = [f.verification.hypothesis.attempt_number for f in findings]
    return mean(attempts) if attempts else 0.0


def score(findings: list[Finding], ground_truth: list[dict], *,
          in_scope_only: bool = False) -> BenchmarkReport:
    truth = [g for g in ground_truth if g.get("confirmed", True)]
    if in_scope_only:
        truth = [g for g in truth if g.get("in_scope", True)]

    matched_idx: set[int] = set()
    overall = ScoreCard()
    per_class: dict[str, ScoreCard] = {}
    conf_tp = {"deterministic": 0, "llm_judged": 0}
    conf_fp = {"deterministic": 0, "llm_judged": 0}
    false_positives: list[Finding] = []

    def card(cls: str) -> ScoreCard:
        return per_class.setdefault(cls, ScoreCard())

    for f in findings:
        cls = f.verification.hypothesis.vuln_class
        conf = f.verification.confidence
        hit = next((i for i, g in enumerate(truth) if finding_matches(f, g)), None)
        if hit is None:
            overall.fp += 1
            card(cls).fp += 1
            conf_fp[conf] = conf_fp.get(conf, 0) + 1
            false_positives.append(f)
        elif hit not in matched_idx:
            matched_idx.add(hit)
            overall.tp += 1
            card(cls).tp += 1
            conf_tp[conf] = conf_tp.get(conf, 0) + 1
        # a duplicate finding for an already-matched truth entry is ignored (not an FP)

    missed = [g for i, g in enumerate(truth) if i not in matched_idx]
    for g in missed:
        overall.fn += 1
        card(g["vuln_class"]).fn += 1

    fp_rate_by_conf = {
        tier: fp_rate(conf_tp.get(tier, 0), conf_fp.get(tier, 0))
        for tier in ("deterministic", "llm_judged")
    }

    return BenchmarkReport(
        overall=overall,
        per_class=per_class,
        fp_rate_by_confidence=fp_rate_by_conf,
        avg_attempts_to_success=avg_attempts_to_success(findings),
        matched_truth=[truth[i] for i in sorted(matched_idx)],
        false_positives=false_positives,
        missed=missed,
    )
