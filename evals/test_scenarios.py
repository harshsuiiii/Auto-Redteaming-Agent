"""Unit tests for the named eval scenarios (pure — no network, no LLM).

Run: pytest evals/test_scenarios.py
"""
from __future__ import annotations

from evals import scenarios
from schemas.models import Hypothesis

AUTH = {"auth_token": "tok", "own_resource_id": 11}
BASE = "http://127.0.0.1:3000"


def _by_name():
    return {s.name: s for s in scenarios.build_scenarios(BASE, AUTH)}


def test_covers_tp_tn_and_fp_guard():
    kinds = {s.kind for s in scenarios.build_scenarios(BASE, AUTH)}
    assert {"tp", "true_negative", "fp_guard"} <= kinds


def test_true_negative_targets_own_resource():
    """The safe IDOR scenario must request the user's OWN id so the verifier sees
    identical baseline/attack bodies and correctly does not flag it."""
    s = _by_name()["idor_own_basket_safe"]
    assert s.expected_exploited is False and s.kind == "true_negative"
    assert s.payload.url.endswith(f"/rest/basket/{AUTH['own_resource_id']}")


def test_tp_idor_targets_a_different_resource():
    s = _by_name()["idor_other_basket"]
    assert s.expected_exploited is True
    assert not s.payload.url.endswith(f"/rest/basket/{AUTH['own_resource_id']}")


def test_fp_guard_login_has_no_sql_metacharacters():
    """The benign-login guard must send clean credentials so no DB error signature appears."""
    s = _by_name()["sqli_benign_login_guard"]
    assert s.expected_exploited is False and s.kind == "fp_guard"
    assert "'" not in s.payload.body["email"] and "'" not in s.payload.body["password"]


def test_hypothesis_builds_valid_model():
    s = _by_name()["idor_other_basket"]
    h = s.hypothesis(attempt_number=2)
    assert isinstance(h, Hypothesis)
    assert h.vuln_class == "IDOR" and h.attempt_number == 2
    assert h.payload is s.payload


def test_forged_jwt_is_alg_none_and_unsigned():
    import base64, json
    s = _by_name()["broken_auth_forged_jwt"]
    header_b64 = s.payload.auth_token.split(".")[0]
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    assert header["alg"] == "none"
    assert s.payload.auth_token.endswith(".")   # empty signature
