"""SQL injection verifiers (04_VERIFIER_ENGINE.md).

* ``verify_error_based`` — regex-match known DB error signatures in the response, but
  only count a match that appears for the INJECTED request and NOT for a benign
  baseline (so an app that always shows a generic error is not flagged).
* ``verify_blind`` — statistical timing: N benign vs N time-delay-injected requests;
  flag only when the mean delta is consistent with the injected sleep, beyond noise.

The timing decision is a pure function (``_blind_verdict``) so it is unit-testable
with synthetic sample arrays, no network required.
"""
from __future__ import annotations

import re
import time
from statistics import mean, pstdev
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from schemas.models import Hypothesis, Payload, VerificationEvidence, VerificationResult

SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sqlite3?\.operationalerror",
    r"SQLITE_ERROR",
    r"SequelizeDatabaseError",
    r"sequelize/lib/dialects/\w+/query",   # leaked ORM stack trace == DB error reached
    r"pg_query\(\)",
    r"ORA-\d{5}",
    r"org\.hibernate",
]

_SQL_META = ("'", '"', ";", "--", "/*", " or ", " union ", "sleep(", "pg_sleep", "waitfor delay")
_DELAY_RE = [
    (re.compile(r"sleep\(\s*(\d+)", re.I), 1000),
    (re.compile(r"pg_sleep\(\s*(\d+)", re.I), 1000),
    (re.compile(r"waitfor\s+delay\s+'0*:0*:(\d+)", re.I), 1000),
]


def _is_injection_value(v: Any) -> bool:
    return isinstance(v, str) and any(m in v.lower() for m in _SQL_META)


def _benignize(v: Any) -> Any:
    return "test" if _is_injection_value(v) else v


def _benign_payload(payload: Payload) -> Payload:
    """Return a copy of the payload with SQL-ish values replaced by a benign token."""
    p = payload.model_copy(deep=True)
    if p.body:
        p.body = {k: _benignize(v) for k, v in p.body.items()}
    parsed = urlparse(p.url)
    if parsed.query:
        pairs = [(k, "test" if _is_injection_value(v) else v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
        p.url = urlunparse(parsed._replace(query=urlencode(pairs)))
    return p


async def _send(client: httpx.AsyncClient, payload: Payload) -> httpx.Response:
    headers = dict(payload.headers)
    if payload.auth_token:
        headers.setdefault("Authorization", f"Bearer {payload.auth_token}")
    return await client.request(payload.method, payload.url, headers=headers, json=payload.body)


def _matched_signature(injected: str, baseline: str) -> Optional[str]:
    for sig in SQL_ERROR_SIGNATURES:
        if re.search(sig, injected, re.I) and not re.search(sig, baseline, re.I):
            return sig
    return None


async def verify_error_based(hypothesis: Hypothesis, http_client: httpx.AsyncClient, **_) -> VerificationResult:
    inj = await _send(http_client, hypothesis.payload)
    base = await _send(http_client, _benign_payload(hypothesis.payload))
    matched = _matched_signature(inj.text, base.text)
    evidence = VerificationEvidence(
        raw_response_status=inj.status_code,
        raw_response_body=inj.text[:2000],
        baseline_response_body=base.text[:2000],
        error_signature_matched=matched,
    )
    return VerificationResult(
        hypothesis=hypothesis,
        is_exploited=matched is not None,
        confidence="deterministic",
        evidence=evidence,
        notes=(f"DB error signature {matched!r} present for the injected request but not the "
               "benign baseline." if matched else
               "No DB error signature appeared that was absent from the baseline."),
    )


def _expected_delay_ms(payload: Payload) -> int:
    blob = f"{payload.url} {payload.body}"
    for rx, unit in _DELAY_RE:
        m = rx.search(blob)
        if m:
            return int(m.group(1)) * unit
    return 5000  # default assumption when no explicit delay is parseable


def _blind_verdict(baseline_ms: list[float], payload_ms: list[float],
                   expected_delay_ms: int, noise_k: float = 1.0) -> tuple[bool, str]:
    """Pure timing decision. Exploited iff the payload is slower than baseline by more
    than (expected delay - noise_k * baseline stddev)."""
    if not baseline_ms or not payload_ms:
        return False, "insufficient timing samples"
    b_mean, p_mean = mean(baseline_ms), mean(payload_ms)
    b_sd = pstdev(baseline_ms) if len(baseline_ms) > 1 else 0.0
    delta = p_mean - b_mean
    threshold = expected_delay_ms - noise_k * b_sd
    exploited = delta > 0 and delta >= threshold
    return exploited, (f"delta={delta:.0f}ms vs threshold={threshold:.0f}ms "
                       f"(baseline mean={b_mean:.0f}±{b_sd:.0f}, payload mean={p_mean:.0f})")


async def verify_blind(hypothesis: Hypothesis, http_client: httpx.AsyncClient, *,
                       samples: int = 5, **_) -> VerificationResult:
    benign = _benign_payload(hypothesis.payload)

    async def _timings(p: Payload) -> list[float]:
        out = []
        for _i in range(samples):
            t0 = time.perf_counter()
            await _send(http_client, p)
            out.append((time.perf_counter() - t0) * 1000.0)
        return out

    baseline_ms = await _timings(benign)
    payload_ms = await _timings(hypothesis.payload)
    exploited, note = _blind_verdict(baseline_ms, payload_ms, _expected_delay_ms(hypothesis.payload))
    return VerificationResult(
        hypothesis=hypothesis,
        is_exploited=exploited,
        confidence="deterministic",
        evidence=VerificationEvidence(timing_samples_ms=payload_ms, baseline_response_body=None),
        notes=f"Blind/time-based SQLi timing analysis: {note}.",
    )
