"""Phase 3 live check: fully agent-driven IDOR, end to end (08_BUILD_ROADMAP.md).

Pipeline (plain function calls — NO LangGraph yet):
    recon() -> select the basket endpoint -> attacker() [real OpenAI] -> idor.verify()

The Attacker Agent is NOT told the answer: it is given the endpoint shape + an auth
context (its own token and own basket id) and must independently reason that this is
IDOR and craft a payload pointing at another user's basket. Success = that hypothesis
verifies as exploited, deterministically, with no human in the loop.

Usage:  OPENAI_API_KEY=sk-... python scripts/run_attacker_live.py [base_url]
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Optional

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:  # Windows consoles default to cp1252; target responses/text may be UTF-8.
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from core.agents import attacker, recon  # noqa: E402
from core.verifier import idor  # noqa: E402
from schemas.models import Endpoint, ParamSchema  # noqa: E402

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3000"
# Set AUTOREDTEAM_STUB_LLM=1 to exercise the live plumbing WITHOUT a real LLM call.
# This proves recon->attacker->verify against the real sandbox; it does NOT satisfy
# the Phase 3 done-when, which requires the real model to do the reasoning.
STUB_LLM = bool(os.environ.get("AUTOREDTEAM_STUB_LLM"))


class _StubLLM:
    """Stand-in LLMClient: returns a fixed IDOR hypothesis (no model reasoning)."""

    async def propose(self, *, system: str, tool_schema: dict[str, Any],
                      correction: Optional[str] = None) -> dict[str, Any]:
        return {
            "vuln_class": "IDOR",
            "rationale": "[STUB] numeric basket :id with auth -> object-level authz gap.",
            "payload": {"method": "GET", "url": f"{BASE_URL}/rest/basket/1"},
            "success_criteria": "200 whose basket id/UserId differ from the caller's own.",
        }


async def _register_and_login(client: httpx.AsyncClient) -> tuple[str, int]:
    email = f"redteam+{uuid.uuid4().hex[:8]}@test.local"
    password = "Password123!"
    reg = await client.post("/api/Users/", json={
        "email": email, "password": password, "passwordRepeat": password,
        "securityQuestion": {"id": 1}, "securityAnswer": "test"})
    if reg.status_code not in (200, 201):
        raise RuntimeError(f"Registration failed: {reg.status_code} {reg.text[:200]}")
    login = await client.post("/rest/user/login", json={"email": email, "password": password})
    auth = login.json()["authentication"]
    return auth["token"], int(auth["bid"])


async def main() -> int:
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30) as client:
        # 1. Recon (integration check: the basket resource is in the discovered surface).
        surface = await recon.recon(BASE_URL, http_client=client)
        has_basket = any("/rest/basket" in e.url for e in surface.endpoints)
        print(f"recon endpoints: {len(surface.endpoints)}  (/rest/basket present: {has_basket})")

        # 2. Auth + own-resource context (manual wiring, as Phase 3 permits).
        token, own_bid = await _register_and_login(client)
        print(f"authenticated; own basket id = {own_bid}")

        # The object-level endpoint the agent will reason about.
        endpoint = Endpoint(
            url=f"{BASE_URL}/rest/basket/:id",
            method="GET",
            params=[ParamSchema(name="id", location="path", type="int", sample_value=str(own_bid))],
            auth_required=True,
        )
        auth_context = {
            "auth_token": token,
            "own_resource_id": own_bid,
            "hint": "Basket ids are small sequential integers starting at 1; an id other "
                    "than own_resource_id belongs to a different user.",
        }

        # 3. Attacker Agent — independently proposes the hypothesis.
        if STUB_LLM:
            provider = "STUB — no real LLM"
        else:
            base = os.environ.get("AUTOREDTEAM_LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL") or "OpenAI (default)"
            provider = f"{attacker.DEFAULT_MODEL} @ {base}"
        print(f"\ncalling Attacker Agent ({provider})...")
        hypothesis = await attacker.attack(
            endpoint, [], auth_context=auth_context,
            llm_client=_StubLLM() if STUB_LLM else None,
        )
        print(f"  vuln_class      : {hypothesis.vuln_class}")
        print(f"  attack url      : {hypothesis.payload.url}")
        print(f"  success_criteria: {hypothesis.success_criteria}")
        print(f"  rationale       : {hypothesis.rationale[:160]}")

        # 4. Deterministic verification.
        result = await idor.verify(hypothesis, client)

    print("\n=== VerificationResult ===")
    print(f"  is_exploited : {result.is_exploited}")
    print(f"  confidence   : {result.confidence}")
    print(f"  notes        : {result.notes}")

    ok = (hypothesis.vuln_class == "IDOR" and result.is_exploited
          and result.confidence == "deterministic")
    print("\nRESULT:", "PASS — agent-driven IDOR verified end to end, no human in the loop"
          if ok else "did not confirm (see above)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
