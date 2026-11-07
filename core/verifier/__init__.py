"""Deterministic verifier engine.

Orchestration dispatches by ``hypothesis.vuln_class`` to the matching module. All seven
classes are implemented as of Phase 5 (04_VERIFIER_ENGINE.md). Every registered
callable accepts ``(hypothesis, http_client, **kwargs)``; XSS creates a headless
browser internally and SSRF needs a ``listener=`` kwarg supplied by the caller.
"""
from __future__ import annotations

from typing import Callable

from schemas.models import VulnClass
from . import broken_auth, idor, path_traversal, sqli, ssrf, xss

VERIFIERS: dict[VulnClass, Callable] = {
    "IDOR": idor.verify,
    "SQLI_ERROR": sqli.verify_error_based,
    "SQLI_BLIND": sqli.verify_blind,
    "XSS_REFLECTED": xss.verify,
    "SSRF": ssrf.verify,
    "PATH_TRAVERSAL": path_traversal.verify,
    "BROKEN_AUTH": broken_auth.verify,
}
