"""Labeled ground truth for benchmarking (07_EVALUATION.md).

Entries are drawn from the targets' documented/intentional vulnerabilities. A Finding
counts as a true positive if it matches an entry on (target, vuln_class, endpoint);
an entry with no matching Finding is a false negative.

Scope honesty (see 07_EVALUATION.md): AutoRedTeam targets vuln classes with checkable,
deterministic success conditions. Entries flagged ``in_scope=False`` are real target
vulnerabilities the system is NOT designed to catch (e.g. no SLEEP on SQLite, no OS
file read on Juice Shop, SSRF needs an OOB listener). They are kept so recall is
reported honestly rather than against a cherry-picked denominator.
"""
from __future__ import annotations

GROUND_TRUTH: list[dict] = [
    # --- Juice Shop: in-scope, confirmed exploitable earlier in this project ---
    {"target": "juice-shop", "vuln_class": "IDOR",          "endpoint": "/rest/basket/:id",  "confirmed": True, "in_scope": True},
    {"target": "juice-shop", "vuln_class": "SQLI_ERROR",    "endpoint": "/rest/user/login",  "confirmed": True, "in_scope": True},
    {"target": "juice-shop", "vuln_class": "BROKEN_AUTH",   "endpoint": "/rest/basket/:id",  "confirmed": True, "in_scope": True},
    {"target": "juice-shop", "vuln_class": "XSS_REFLECTED", "endpoint": "/#/search",         "confirmed": True, "in_scope": True},

    # --- Juice Shop: real vulns that are out of AutoRedTeam's deterministic scope ---
    # SQLite has no SLEEP(); blind/time-based detection is not expected to fire here.
    {"target": "juice-shop", "vuln_class": "SQLI_BLIND",    "endpoint": "/rest/products/search", "confirmed": True, "in_scope": False},
    # OS-file read / SSRF OOB require infra Juice Shop does not provide in this sandbox.
    {"target": "juice-shop", "vuln_class": "PATH_TRAVERSAL","endpoint": "/ftp",              "confirmed": True, "in_scope": False},
    {"target": "juice-shop", "vuln_class": "SSRF",          "endpoint": "/rest/track-order", "confirmed": True, "in_scope": False},
]


def for_target(target: str, *, in_scope_only: bool = False) -> list[dict]:
    rows = [g for g in GROUND_TRUTH if g["target"] == target and g.get("confirmed", True)]
    if in_scope_only:
        rows = [g for g in rows if g.get("in_scope", True)]
    return rows
