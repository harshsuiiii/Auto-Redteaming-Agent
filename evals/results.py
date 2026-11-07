"""Serializable benchmark results (Phase 8 visual layer).

The benchmark runner historically only printed to the terminal. This module turns a
run into a durable, JSON-serialisable ``BenchmarkResult`` so the dashboard can render
it as charts/tables, and so a presentation always has data even when the live sandbox
and LLM are down (bundled snapshots in ``evals/results/``).

Pure data + (de)serialisation only — no network, no LLM, fully unit-testable.
``from_report`` adapts the existing ``metrics.BenchmarkReport`` so there is a single
source of scoring truth.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from evals import metrics
from schemas.models import Finding

RESULTS_DIR = Path(__file__).resolve().parent / "results"


class ScoreBrief(BaseModel):
    """A scorecard flattened for display (precision/recall/fp_rate precomputed so the
    JSON is self-contained and the UI never has to recompute)."""
    label: str = "overall"        # "overall" or a vuln class
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    fp_rate: float = 0.0

    @classmethod
    def from_scorecard(cls, sc: metrics.ScoreCard, label: str = "overall") -> "ScoreBrief":
        return cls(label=label, tp=sc.tp, fp=sc.fp, fn=sc.fn,
                   precision=round(sc.precision, 4), recall=round(sc.recall, 4),
                   fp_rate=round(sc.fp_rate, 4))


class FindingBrief(BaseModel):
    """Just the fields the dashboard shows for a finding (full Findings live elsewhere)."""
    vuln_class: str
    endpoint: str
    severity: str
    cvss_score: float
    confidence: str
    attempt_number: int

    @classmethod
    def from_finding(cls, f: Finding) -> "FindingBrief":
        h = f.verification.hypothesis
        return cls(vuln_class=h.vuln_class, endpoint=h.endpoint.url, severity=f.severity,
                   cvss_score=f.cvss_score, confidence=f.verification.confidence,
                   attempt_number=h.attempt_number)


class SeedStat(BaseModel):
    """mean ± stddev of a metric across agent-mode seeds (shows the result is not luck)."""
    mean: float
    stddev: float
    n: int
    values: list[float] = Field(default_factory=list)


class AblationRow(BaseModel):
    label: str                    # e.g. "without RAG" / "with RAG"
    recall: float
    precision: float
    avg_attempts: float


class ZapComparison(BaseModel):
    """AutoRedTeam vs OWASP ZAP — the noise/precision story for the viva."""
    ran: bool = False
    mode: str = "not_run"         # "active" | "passive" | "not_run"
    total_alerts: int = 0
    mapped_in_scope_classes: list[str] = Field(default_factory=list)
    autoredteam_confirmed: int = 0        # PoC-backed, deterministic findings
    note: str = ""


class ScenarioOutcome(BaseModel):
    """One named scenario with its EXPECTED vs ACTUAL verdict — this is what gives the
    results variety (true positives, honest misses, and correct non-alarms)."""
    name: str
    vuln_class: str
    endpoint: str
    expected_exploited: bool
    actual_exploited: Optional[bool] = None    # None => not run (e.g. sandbox down)
    passed: Optional[bool] = None              # actual == expected
    kind: str = "tp"              # tp | true_negative | fp_guard | false_negative
    in_scope: bool = True
    confidence: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    description: str = ""
    note: str = ""


class BenchmarkResult(BaseModel):
    schema_version: int = 1
    label: str                    # human title for the snapshot (shown in the picker)
    target: str
    model: str
    mode: str = "engine"          # engine | agent | mixed
    created_at: dt.datetime = Field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))

    overall_in_scope: ScoreBrief = Field(default_factory=ScoreBrief)
    overall_all: ScoreBrief = Field(default_factory=ScoreBrief)
    per_class: list[ScoreBrief] = Field(default_factory=list)
    fp_rate_by_confidence: dict[str, float] = Field(default_factory=dict)
    avg_attempts_to_success: float = 0.0

    # agent-mode variance across seeds (optional)
    agent_recall: Optional[SeedStat] = None
    agent_precision: Optional[SeedStat] = None
    agent_attempts: Optional[SeedStat] = None

    # breakdowns for the confusion view
    matched: list[dict] = Field(default_factory=list)
    missed: list[dict] = Field(default_factory=list)          # false negatives
    false_positives: list[FindingBrief] = Field(default_factory=list)
    findings: list[FindingBrief] = Field(default_factory=list)

    scenarios: list[ScenarioOutcome] = Field(default_factory=list)
    rag_ablation: list[AblationRow] = Field(default_factory=list)
    zap: Optional[ZapComparison] = None
    notes: list[str] = Field(default_factory=list)

    # ----- adapters -----
    @classmethod
    def from_report(cls, *, label: str, target: str, model: str, mode: str,
                    in_scope: metrics.BenchmarkReport,
                    all_vulns: Optional[metrics.BenchmarkReport] = None,
                    findings: Optional[list[Finding]] = None,
                    **extra) -> "BenchmarkResult":
        per_class = [ScoreBrief.from_scorecard(sc, cls_name)
                     for cls_name, sc in sorted(in_scope.per_class.items())]
        return cls(
            label=label, target=target, model=model, mode=mode,
            overall_in_scope=ScoreBrief.from_scorecard(in_scope.overall),
            overall_all=ScoreBrief.from_scorecard((all_vulns or in_scope).overall),
            per_class=per_class,
            fp_rate_by_confidence={k: round(v, 4) for k, v in in_scope.fp_rate_by_confidence.items()},
            avg_attempts_to_success=round(in_scope.avg_attempts_to_success, 4),
            matched=in_scope.matched_truth,
            missed=(all_vulns or in_scope).missed,
            false_positives=[FindingBrief.from_finding(f) for f in in_scope.false_positives],
            findings=[FindingBrief.from_finding(f) for f in (findings or [])],
            **extra,
        )


# --------------------------------------------------------------------------- #
# persistence
# --------------------------------------------------------------------------- #

def save(result: BenchmarkResult, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


def load(path: Path) -> BenchmarkResult:
    return BenchmarkResult.model_validate_json(Path(path).read_text(encoding="utf-8"))


def list_snapshots(directory: Path = RESULTS_DIR) -> list[Path]:
    directory = Path(directory)
    if not directory.exists():
        return []
    return sorted(directory.glob("*.json"))


def load_all(directory: Path = RESULTS_DIR) -> list[BenchmarkResult]:
    out: list[BenchmarkResult] = []
    for p in list_snapshots(directory):
        try:
            out.append(load(p))
        except Exception:
            continue  # skip a malformed/partial file rather than break the whole view
    return out


def load_latest(directory: Path = RESULTS_DIR) -> Optional[BenchmarkResult]:
    results = load_all(directory)
    if not results:
        return None
    return max(results, key=lambda r: r.created_at)
