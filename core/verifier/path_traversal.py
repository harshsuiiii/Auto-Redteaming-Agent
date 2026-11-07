"""Path traversal verifier (04_VERIFIER_ENGINE.md).

Sentinel content match: the response must contain the known structure of a requested
OS file (e.g. /etc/passwd's ``root:...:0:0:``), not merely "some file content
appeared". This keeps it to a deterministic, high-confidence signal.
"""
from __future__ import annotations

import re

import httpx

from schemas.models import Hypothesis, VerificationEvidence, VerificationResult

PATH_TRAVERSAL_SENTINELS = {
    "/etc/passwd": r"root:.*:0:0:",
    "win.ini": r"\[fonts\]",
    "/etc/shadow": r"root:[*!$]",
}


async def verify(hypothesis: Hypothesis, http_client: httpx.AsyncClient, **_) -> VerificationResult:
    payload = hypothesis.payload
    headers = dict(payload.headers)
    if payload.auth_token:
        headers.setdefault("Authorization", f"Bearer {payload.auth_token}")
    resp = await http_client.request(payload.method, payload.url, headers=headers, json=payload.body)

    matched_file = None
    for fname, pattern in PATH_TRAVERSAL_SENTINELS.items():
        if re.search(pattern, resp.text, re.MULTILINE):
            matched_file = fname
            break

    return VerificationResult(
        hypothesis=hypothesis,
        is_exploited=matched_file is not None,
        confidence="deterministic",
        evidence=VerificationEvidence(
            raw_response_status=resp.status_code,
            raw_response_body=resp.text[:2000],
            error_signature_matched=matched_file,
        ),
        notes=(f"Response contains the sentinel structure of {matched_file} — arbitrary file "
               "read via traversal confirmed." if matched_file else
               "No OS-file sentinel pattern matched; traversal not confirmed."),
    )
