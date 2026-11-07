"""Broken authentication verifier (04_VERIFIER_ENGINE.md).

Token manipulation/reuse: a protected endpoint should reject a tampered / forged /
wrong-scope token. We first confirm the endpoint IS protected (an unauthenticated
request is rejected), then send the manipulated token. Exploited iff the manipulated
token is accepted (200 with real data) on an endpoint that rejected no-auth.

The two-step check (reject-without, accept-with-tampered) is what prevents flagging an
endpoint that was never protected in the first place.
"""
from __future__ import annotations

import httpx

from schemas.models import Hypothesis, VerificationEvidence, VerificationResult

_ERROR_HINTS = ("error", "forbidden", "unauthorized", "invalid", "denied", "must be logged in")


def _looks_like_error(body: str) -> bool:
    low = body.strip().lower()
    return (not low) or any(h in low for h in _ERROR_HINTS)


async def verify(hypothesis: Hypothesis, http_client: httpx.AsyncClient, **_) -> VerificationResult:
    payload = hypothesis.payload

    # 1. No-auth request: establish that the endpoint is actually protected.
    no_auth = await http_client.request(payload.method, payload.url, json=payload.body)
    protected = no_auth.status_code in (401, 403)

    # 2. Tampered/forged token (as crafted by the attacker in payload.auth_token).
    headers = dict(payload.headers)
    if payload.auth_token:
        headers["Authorization"] = f"Bearer {payload.auth_token}"
    tampered = await http_client.request(payload.method, payload.url, headers=headers, json=payload.body)

    accepted = tampered.status_code == 200 and not _looks_like_error(tampered.text)
    exploited = protected and accepted

    if not protected:
        note = (f"Endpoint returned {no_auth.status_code} without auth — not protected; "
                "a broken-auth verdict would be a false positive.")
    elif exploited:
        note = ("Endpoint rejected the unauthenticated request but ACCEPTED the manipulated "
                "token (200 with data) — broken authentication confirmed.")
    else:
        note = (f"Manipulated token was rejected ({tampered.status_code}) — auth appears to "
                "validate the token correctly.")

    return VerificationResult(
        hypothesis=hypothesis,
        is_exploited=exploited,
        confidence="deterministic",
        evidence=VerificationEvidence(
            raw_response_status=tampered.status_code,
            raw_response_body=tampered.text[:2000],
            baseline_response_body=f"no-auth status={no_auth.status_code}",
        ),
        notes=note,
    )
