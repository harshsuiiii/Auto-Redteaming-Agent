"""SSRF verifier (04_VERIFIER_ENGINE.md).

Out-of-band callback: inject a unique callback URL (reachable only from inside the
sandbox network) as the SSRF target, then confirm the listener received a request
bearing that unique token. Exploited iff the callback fired.

The listener is abstracted behind the ``CallbackListener`` protocol so the check is
unit-testable with a fake; a real listener runs on the orchestrator side, reachable
from the sandbox but never from the public internet.
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any, Optional, Protocol
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from schemas.models import Hypothesis, Payload, VerificationEvidence, VerificationResult


class CallbackListener(Protocol):
    def url_for(self, token: str) -> str: ...
    async def received(self, token: str) -> bool: ...


def _inject_callback(payload: Payload, callback_url: str) -> Payload:
    """Point the SSRF-able parameter at our callback URL (query 'url'/'uri'/first, else body)."""
    p = payload.model_copy(deep=True)
    parsed = urlparse(p.url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if pairs:
        idx = next((i for i, (k, _v) in enumerate(pairs) if k.lower() in ("url", "uri", "target", "dest")), 0)
        pairs[idx] = (pairs[idx][0], callback_url)
        p.url = urlunparse(parsed._replace(query=urlencode(pairs)))
    elif p.body:
        key = next((k for k in p.body if k.lower() in ("url", "uri", "target", "dest")), None)
        if key:
            p.body[key] = callback_url
    return p


async def verify(hypothesis: Hypothesis, http_client: httpx.AsyncClient | None = None, *,
                 listener: Optional[CallbackListener] = None, timeout: float = 5.0,
                 poll_interval: float = 0.25) -> VerificationResult:
    if listener is None:
        raise RuntimeError("SSRF verification requires a sandbox-internal callback listener.")
    if http_client is None:
        raise RuntimeError("SSRF verification requires an http client to send the trigger request.")

    token = uuid.uuid4().hex
    triggered = _inject_callback(hypothesis.payload, listener.url_for(token))
    headers = dict(triggered.headers)
    if triggered.auth_token:
        headers.setdefault("Authorization", f"Bearer {triggered.auth_token}")
    await http_client.request(triggered.method, triggered.url, headers=headers, json=triggered.body)

    deadline = asyncio.get_event_loop().time() + timeout
    hit = False
    while asyncio.get_event_loop().time() < deadline:
        if await listener.received(token):
            hit = True
            break
        await asyncio.sleep(poll_interval)

    return VerificationResult(
        hypothesis=hypothesis,
        is_exploited=hit,
        confidence="deterministic",
        evidence=VerificationEvidence(callback_received=hit, raw_response_body=triggered.url),
        notes=("Out-of-band callback received bearing the unique token — server fetched our "
               "URL (SSRF confirmed)." if hit else
               "No callback received within the timeout; SSRF not confirmed."),
    )
