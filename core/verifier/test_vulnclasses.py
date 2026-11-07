"""Unit tests for the Phase 5 verifier modules — SQLi (error + blind), XSS, SSRF,
path traversal, broken auth. All boundaries mocked: MockTransport, fake browser probe,
fake callback listener. No Docker, no browser, no real timing.

Run: pytest core/verifier/test_vulnclasses.py
"""
from __future__ import annotations

import httpx
import pytest

from core.verifier import broken_auth, path_traversal, sqli, ssrf, xss
from schemas.models import Endpoint, Hypothesis, ParamSchema, Payload

BASE = "http://target"


def _hyp(vuln_class, url, method="GET", body=None, auth_token=None, params=None) -> Hypothesis:
    return Hypothesis(
        vuln_class=vuln_class,
        endpoint=Endpoint(url=url, method=method, params=params or []),
        rationale="r",
        payload=Payload(method=method, url=url, body=body, auth_token=auth_token),
        success_criteria="sc",
    )


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=BASE)


# --- SQLi error-based ------------------------------------------------------ #

async def test_sqli_error_based_detects_signature_absent_in_baseline():
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode() if request.content else ""
        if "'" in body and "test" not in body.replace("'", ""):
            # injected request leaks an ORM/DB stack trace
            return httpx.Response(500, text="at sequelize/lib/dialects/sqlite/query.js:185")
        return httpx.Response(401, json={"error": "Invalid email or password"})

    h = _hyp("SQLI_ERROR", f"{BASE}/rest/user/login", method="POST",
             body={"email": "'", "password": "x"})
    async with _client(handler) as c:
        res = await sqli.verify_error_based(h, c)
    assert res.is_exploited is True
    assert res.confidence == "deterministic"
    assert "sequelize" in res.evidence.error_signature_matched


async def test_sqli_error_based_not_flagged_when_error_also_in_baseline():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="generic SQLITE_ERROR always shown")

    h = _hyp("SQLI_ERROR", f"{BASE}/rest/user/login", method="POST",
             body={"email": "'", "password": "x"})
    async with _client(handler) as c:
        res = await sqli.verify_error_based(h, c)
    assert res.is_exploited is False  # signature present in baseline too


# --- SQLi blind (pure timing decision) ------------------------------------- #

def test_blind_verdict_flags_consistent_delay():
    baseline = [40, 45, 42, 41, 43]
    payload = [5040, 5050, 5038, 5041, 5039]  # ~5s slower
    exploited, note = sqli._blind_verdict(baseline, payload, expected_delay_ms=5000)
    assert exploited is True


def test_blind_verdict_ignores_jitter():
    baseline = [40, 45, 42, 41, 43]
    payload = [60, 70, 55, 80, 65]  # slower but nowhere near 5s
    exploited, _ = sqli._blind_verdict(baseline, payload, expected_delay_ms=5000)
    assert exploited is False


def test_expected_delay_parsed_from_payload():
    p = Payload(method="GET", url=f"{BASE}/x?id=1' AND SLEEP(7)--")
    assert sqli._expected_delay_ms(p) == 7000


# --- XSS (fake browser probe) ---------------------------------------------- #

async def test_xss_exploited_when_marker_executes():
    async def probe(url, marker):
        assert "iframe" in url or "q=" in url  # marker payload was injected
        return marker  # simulate real execution setting window.__xss_marker

    h = _hyp("XSS_REFLECTED", f"{BASE}/#/search?q=hello")
    res = await xss.verify(h, browser_probe=probe)
    assert res.is_exploited is True
    assert res.confidence == "deterministic"


async def test_xss_not_exploited_on_reflection_without_execution():
    async def probe(url, marker):
        return None  # reflected in HTML but never executed

    h = _hyp("XSS_REFLECTED", f"{BASE}/#/search?q=hello")
    res = await xss.verify(h, browser_probe=probe)
    assert res.is_exploited is False


# --- SSRF (fake listener) -------------------------------------------------- #

class _FakeListener:
    def __init__(self, will_fire: bool):
        self.will_fire = will_fire
        self.seen_url = None
    def url_for(self, token): return f"http://callback.internal/{token}"
    async def received(self, token): return self.will_fire


async def test_ssrf_exploited_when_callback_received():
    listener = _FakeListener(will_fire=True)
    captured = {}
    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200)
    h = _hyp("SSRF", f"{BASE}/rest/fetch?url=http://example.com")
    async with _client(handler) as c:
        res = await ssrf.verify(h, c, listener=listener, timeout=1)
    assert res.is_exploited is True
    assert res.evidence.callback_received is True
    assert "callback.internal" in captured["url"]  # callback URL was injected


async def test_ssrf_not_exploited_when_no_callback():
    listener = _FakeListener(will_fire=False)
    h = _hyp("SSRF", f"{BASE}/rest/fetch?url=http://example.com")
    async with _client(lambda r: httpx.Response(200)) as c:
        res = await ssrf.verify(h, c, listener=listener, timeout=0.5, poll_interval=0.1)
    assert res.is_exploited is False


# --- Path traversal -------------------------------------------------------- #

async def test_path_traversal_matches_etc_passwd_sentinel():
    def handler(_r): return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\n")
    h = _hyp("PATH_TRAVERSAL", f"{BASE}/file?path=../../../../etc/passwd")
    async with _client(handler) as c:
        res = await path_traversal.verify(h, c)
    assert res.is_exploited is True
    assert res.evidence.error_signature_matched == "/etc/passwd"


async def test_path_traversal_not_matched_on_normal_content():
    def handler(_r): return httpx.Response(200, text="just an ordinary file")
    h = _hyp("PATH_TRAVERSAL", f"{BASE}/file?path=readme.txt")
    async with _client(handler) as c:
        res = await path_traversal.verify(h, c)
    assert res.is_exploited is False


# --- Broken auth ----------------------------------------------------------- #

async def test_broken_auth_confirmed_when_protected_but_tampered_accepted():
    def handler(request: httpx.Request) -> httpx.Response:
        if "authorization" not in {k.lower() for k in request.headers}:
            return httpx.Response(401, json={"error": "unauthorized"})
        return httpx.Response(200, json={"username": "admin", "email": "admin@x"})
    h = _hyp("BROKEN_AUTH", f"{BASE}/rest/user/whoami", auth_token="forged.none.jwt")
    async with _client(handler) as c:
        res = await broken_auth.verify(h, c)
    assert res.is_exploited is True


async def test_broken_auth_not_flagged_when_endpoint_unprotected():
    def handler(_r): return httpx.Response(200, json={"public": True})
    h = _hyp("BROKEN_AUTH", f"{BASE}/rest/public", auth_token="forged")
    async with _client(handler) as c:
        res = await broken_auth.verify(h, c)
    assert res.is_exploited is False
    assert "not protected" in res.notes


async def test_broken_auth_not_flagged_when_tampered_rejected():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid token"})
    h = _hyp("BROKEN_AUTH", f"{BASE}/rest/user/whoami", auth_token="forged")
    async with _client(handler) as c:
        res = await broken_auth.verify(h, c)
    assert res.is_exploited is False
