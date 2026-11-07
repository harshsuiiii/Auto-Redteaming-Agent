"""Reflected / DOM XSS verifier (04_VERIFIER_ENGINE.md).

String reflection in HTML is NOT proof. The payload must actually EXECUTE as JS in a
real DOM. We inject a unique marker payload that, if it runs, sets
``window.__xss_marker`` to a per-run UUID, then read that value back from a headless
browser. Exploited iff the value we read equals the UUID we injected.

The browser is abstracted behind ``browser_probe`` (async ``(url, marker) -> str|None``)
so the decision is unit-testable with a fake; the real probe uses Playwright.
"""
from __future__ import annotations

import uuid
from typing import Awaitable, Callable, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from schemas.models import Hypothesis, VerificationEvidence, VerificationResult

BrowserProbe = Callable[[str, str], Awaitable[Optional[str]]]

# A marker payload that sets window.__xss_marker when it executes. {m} is the UUID.
# An <img onerror> inserted via innerHTML fires in the PAGE's own window (unlike an
# iframe's javascript: URI, which would set the flag on the iframe's window instead).
_MARKER_PAYLOAD = "<img src=x onerror=\"window.__xss_marker='{m}'\">"


def _inject_into_pairs(pairs: list[tuple[str, str]], payload: str) -> list[tuple[str, str]]:
    if not pairs:
        return [("q", payload)]
    idx = next((i for i, (_k, v) in enumerate(pairs) if "<" in v or "script" in v.lower()), 0)
    pairs[idx] = (pairs[idx][0], payload)
    return pairs


def _inject_marker(url: str, marker: str) -> str:
    """Put the marker payload into the injection point. Handles both normal query
    params and hash-routed SPAs where the param lives in the fragment (``#/search?q=``)."""
    payload = _MARKER_PAYLOAD.format(m=marker)
    parsed = urlparse(url)
    # Hash-routed SPA: the param is inside the fragment.
    if "?" in parsed.fragment:
        base_frag, frag_q = parsed.fragment.split("?", 1)
        pairs = _inject_into_pairs(parse_qsl(frag_q, keep_blank_values=True), payload)
        return urlunparse(parsed._replace(fragment=f"{base_frag}?{urlencode(pairs)}"))
    pairs = _inject_into_pairs(parse_qsl(parsed.query, keep_blank_values=True), payload)
    return urlunparse(parsed._replace(query=urlencode(pairs)))


async def _playwright_probe(url: str, marker: str) -> Optional[str]:  # pragma: no cover - needs browser
    from playwright.async_api import async_playwright
    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        try:
            page = await browser.new_page()
            await page.goto(url, wait_until="networkidle")
            await page.wait_for_timeout(1500)
            return await page.evaluate("() => window.__xss_marker || null")
        finally:
            await browser.close()


async def verify(hypothesis: Hypothesis, http_client: httpx.AsyncClient | None = None, *,
                 browser_probe: BrowserProbe | None = None, marker: str | None = None) -> VerificationResult:
    marker = marker or uuid.uuid4().hex
    probe = browser_probe or _playwright_probe
    test_url = _inject_marker(hypothesis.payload.url, marker)

    executed = await probe(test_url, marker)
    exploited = executed == marker
    return VerificationResult(
        hypothesis=hypothesis,
        is_exploited=exploited,
        confidence="deterministic",
        evidence=VerificationEvidence(
            dom_snapshot=f"window.__xss_marker={executed!r} (expected {marker!r})",
            raw_response_body=test_url,
        ),
        notes=("Marker payload executed in the DOM (window state set) — real JS execution, "
               "not mere reflection." if exploited else
               "Marker was not set by execution; reflection without execution is not XSS."),
    )
