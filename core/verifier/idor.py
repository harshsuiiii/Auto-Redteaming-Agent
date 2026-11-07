"""IDOR (Insecure Direct Object Reference) verifier — the simplest deterministic
check, built first per 04_VERIFIER_ENGINE.md.

Mechanism
---------
Compare the response for the attack payload (another user's resource) against a
*baseline* (the authenticated user's OWN resource, reached with the SAME token).
A finding is only exploited if the attacker's token returns a 200 whose body is
structurally the same as the baseline but with DIFFERENT data — i.e. we actually
read someone else's record, not an error and not identical placeholder data.

Verifier contract (how the baseline is derived)
-----------------------------------------------
``hypothesis.payload`` is the ATTACK request (victim's id). The verifier builds the
baseline request itself by swapping the victim id for the authenticated user's own
id. The own id is taken from the endpoint's reference param ``sample_value``. The
reference param is the path/query param that identifies the object (path templates
use ``:id`` or ``{id}`` placeholders).

No LLM is used. If the evidence is too ambiguous for a deterministic verdict, the
result is returned with ``confidence="llm_judged"`` and ``is_exploited=False`` so a
Verifier Agent (added in a later phase) can adjudicate — absence of proof is never
treated as proof.
"""
from __future__ import annotations

import json
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import httpx

from schemas.models import (
    Hypothesis,
    ParamSchema,
    VerificationEvidence,
    VerificationResult,
)

# Substrings that, if a 200 body is basically just this, mean "no data returned".
_ERROR_HINTS = ("error", "forbidden", "unauthorized", "not found", "invalid token")


def _find_reference_param(hypothesis: Hypothesis) -> Optional[ParamSchema]:
    """Pick the param that identifies the object being referenced.

    Preference order: an explicit path param, then a query param, favouring names
    that look like an id. Returns None if nothing usable is found.
    """
    params = hypothesis.endpoint.params
    candidates = [p for p in params if p.location in ("path", "query") and p.sample_value is not None]
    if not candidates:
        return None

    def score(p: ParamSchema) -> tuple[int, int, int]:
        is_path = p.location == "path"
        name = p.name.lower()
        looks_like_id = name == "id" or name.endswith("id") or name.endswith("_id")
        numeric = p.type.lower() in ("int", "integer", "number")
        return (int(is_path), int(looks_like_id), int(numeric))

    return max(candidates, key=score)


def _build_baseline_url(hypothesis: Hypothesis, ref: ParamSchema, own_id: str) -> str:
    """Return the attack URL rewritten to point at the authenticated user's own id."""
    attack_url = hypothesis.payload.url
    parsed = urlparse(attack_url)

    if ref.location == "query":
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        rebuilt = [(k, own_id if k == ref.name else v) for k, v in pairs]
        return urlunparse(parsed._replace(query=urlencode(rebuilt)))

    # Path param: use the endpoint template's placeholder to locate the id segment.
    template = urlparse(hypothesis.endpoint.url).path
    placeholder = None
    for marker in (f":{ref.name}", f"{{{ref.name}}}"):
        if marker in template:
            placeholder = marker
            break
    if placeholder is None:
        # Fallback: assume the id is the final path segment.
        prefix = parsed.path.rsplit("/", 1)[0] + "/"
        return urlunparse(parsed._replace(path=prefix + own_id))

    pre, post = template.split(placeholder, 1)
    path = parsed.path
    if path.startswith(pre) and path.endswith(post):
        baseline_path = pre + own_id + (post if post else "")
    else:
        baseline_path = path.rsplit("/", 1)[0] + "/" + own_id
    return urlunparse(parsed._replace(path=baseline_path))


def _same_structure(a: Any, b: Any) -> bool:
    """True if a and b have the same JSON shape (keys/types), ignoring leaf values."""
    if isinstance(a, dict) and isinstance(b, dict):
        if set(a.keys()) != set(b.keys()):
            return False
        return all(_same_structure(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        if not a or not b:
            return True  # can't compare empty lists structurally; stay lenient
        return _same_structure(a[0], b[0])
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool)
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return True
    return type(a) is type(b)


def _looks_like_error(body: str) -> bool:
    low = body.strip().lower()
    if not low:
        return True
    return any(h in low for h in _ERROR_HINTS)


async def verify(hypothesis: Hypothesis, http_client: httpx.AsyncClient) -> VerificationResult:
    ref = _find_reference_param(hypothesis)
    evidence = VerificationEvidence()

    if ref is None or ref.sample_value is None:
        return VerificationResult(
            hypothesis=hypothesis,
            is_exploited=False,
            confidence="llm_judged",
            evidence=evidence,
            notes="No reference param with a sample_value (own id) found; cannot build a "
                  "baseline deterministically. Deferred to Verifier Agent.",
        )

    own_id = ref.sample_value
    baseline_url = _build_baseline_url(hypothesis, ref, own_id)

    headers = dict(hypothesis.payload.headers)
    if hypothesis.payload.auth_token:
        headers.setdefault("Authorization", f"Bearer {hypothesis.payload.auth_token}")

    # 1. Baseline — the authenticated user's OWN resource.
    baseline_resp = await http_client.request(
        hypothesis.payload.method, baseline_url, headers=headers, json=hypothesis.payload.body
    )
    # 2. Attack — another user's resource (as proposed by the hypothesis).
    attack_resp = await http_client.request(
        hypothesis.payload.method, hypothesis.payload.url, headers=headers, json=hypothesis.payload.body
    )

    evidence.raw_response_status = attack_resp.status_code
    evidence.raw_response_body = attack_resp.text
    evidence.baseline_response_body = baseline_resp.text

    # Deterministic rules.
    if attack_resp.status_code != 200:
        return VerificationResult(
            hypothesis=hypothesis, is_exploited=False, confidence="deterministic",
            evidence=evidence,
            notes=f"Attack request returned {attack_resp.status_code}, not 200 — "
                  "object-level authorization appears enforced.",
        )

    if _looks_like_error(attack_resp.text):
        return VerificationResult(
            hypothesis=hypothesis, is_exploited=False, confidence="deterministic",
            evidence=evidence, notes="200 but body looks like an error/empty response.",
        )

    # False-positive guard: identical body regardless of id = placeholder data, not IDOR.
    if attack_resp.text == baseline_resp.text:
        return VerificationResult(
            hypothesis=hypothesis, is_exploited=False, confidence="deterministic",
            evidence=evidence,
            notes="Attack and baseline bodies are identical — app returns the same data "
                  "regardless of id; not a real IDOR.",
        )

    # Structural comparison on parsed JSON.
    try:
        attack_json = json.loads(attack_resp.text)
        baseline_json = json.loads(baseline_resp.text)
    except (json.JSONDecodeError, ValueError):
        return VerificationResult(
            hypothesis=hypothesis, is_exploited=False, confidence="llm_judged",
            evidence=evidence,
            notes="200 with differing non-JSON bodies; structural diff inconclusive. "
                  "Deferred to Verifier Agent.",
        )

    if _same_structure(baseline_json, attack_json) and baseline_json != attack_json:
        return VerificationResult(
            hypothesis=hypothesis, is_exploited=True, confidence="deterministic",
            evidence=evidence,
            notes="Attack returned a 200 whose JSON shares the baseline's structure but "
                  "contains different data — confirmed access to another user's resource.",
        )

    return VerificationResult(
        hypothesis=hypothesis, is_exploited=False, confidence="llm_judged",
        evidence=evidence,
        notes="200 with differing bodies but structure did not match the baseline; "
              "ambiguous. Deferred to Verifier Agent.",
    )
