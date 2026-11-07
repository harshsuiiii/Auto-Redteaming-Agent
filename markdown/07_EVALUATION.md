# Evaluation & Benchmarking — `evals/`

This is the chapter of your capstone report that needs the most rigor. Define ground
truth and metrics before you start collecting numbers.

## Ground truth

Use **OWASP Juice Shop's documented vulnerability list** as labeled ground truth —
it's an intentionally vulnerable app with a known, published set of challenges/vulns.
For DVWA, use its documented vulnerability categories at each difficulty setting.

Build a ground-truth file:

```python
# evals/ground_truth.py
GROUND_TRUTH = [
    {"target": "juice-shop", "vuln_class": "IDOR", "endpoint": "/rest/basket/:id", "confirmed": True},
    {"target": "juice-shop", "vuln_class": "XSS_REFLECTED", "endpoint": "/#/search", "confirmed": True},
    # ... populate from the app's known vulnerability documentation
]
```

## Metrics

### 1. Precision / Recall (per vuln class and overall)

```python
def precision(true_positives: int, false_positives: int) -> float:
    return true_positives / (true_positives + false_positives) if (true_positives + false_positives) else 0.0

def recall(true_positives: int, false_negatives: int) -> float:
    return true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) else 0.0
```

A `Finding` counts as a true positive if it matches a `GROUND_TRUTH` entry
(`target`, `vuln_class`, `endpoint`); any `Finding` with no ground-truth match is a
false positive; any `GROUND_TRUTH` entry with no matching `Finding` is a false
negative.

### 2. False Positive Rate

```python
fp_rate = false_positives / (true_positives + false_positives)
```

Report this broken out by `confidence` (`deterministic` vs `llm_judged`) — the thesis
of the whole project is that deterministic verification drives this toward zero; show
the numbers honestly even if `llm_judged` findings have a higher FP rate.

### 3. ReAct Loop Efficiency

```python
avg_retries_to_success = sum(h.attempt_number for h in successful_hypotheses) / len(successful_hypotheses)
```

Pull this from LangSmith traces or your own `attempt_history` logs.

### 4. RAG Ablation

Run the full benchmark with and without the knowledge-retrieval context
(`06_RAG_KNOWLEDGE.md`) injected into the Attacker Agent prompt. Compare precision,
recall, and `avg_retries_to_success` between the two conditions.

## Comparative baseline: OWASP ZAP / SonarQube

```python
# evals/run_benchmark.py
async def run_zap_baseline(target_url: str) -> list[dict]:
    """Run OWASP ZAP's automated scan (via its API) against the same target,
    same time budget, and collect its findings for comparison."""

async def run_autoredteam(target_url: str) -> list[Finding]:
    """Run the full AutoRedTeam pipeline against the same target."""
```

Compare: total findings count, true-positive count against ground truth, false
positive count, and wall-clock time. This head-to-head table is the centerpiece result
of your report.

## Reporting structure for the dissertation

| Metric | AutoRedTeam | OWASP ZAP | SonarQube (if applicable) |
|---|---|---|---|
| True positives (of N ground-truth vulns) | | | |
| False positives | | | |
| False positive rate | | | |
| Precision | | | |
| Recall | | | |
| Avg. time to findings | | | |

Plus a separate table for the RAG ablation (with/without) and the
`deterministic` vs `llm_judged` confidence breakdown.

## Honesty requirement for the write-up

Report the full OWASP Top 10 coverage honestly — this system is strong on IDOR, SQLi,
XSS, SSRF, path traversal, and basic broken-auth, because these have checkable
deterministic success conditions. It is **not** expected to reliably catch complex
multi-step business-logic flaws (e.g. race conditions, workflow-state abuse) — note
this explicitly as a scope limitation, not a failure, since framing it as a known,
principled boundary is more defensible in a viva than silently underperforming on an
unstated claim.
