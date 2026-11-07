"""Sandbox-scoped HTTP client (05_SANDBOX_SETUP.md).

Wraps httpx with two binding safety controls enforced at the tool-call boundary:

1. Egress allowlist — every request host must be in ``allowed_hosts`` or it is blocked.
   This is the primary defense against a prompt-injected target response trying to
   redirect the agent outside the sandbox.
2. Request budget — a hard cap (not a soft warning) on outbound requests per run. The
   counter is shared (a mutable dict) so a single verifier making many requests (e.g.
   blind-SQLi timing samples) is still bounded.

Optionally logs every request/response to a per-run JSONL file, which is required for
reproducibility and for generating PoC steps from the real wire log.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import httpx


class SecurityError(Exception):
    """Raised when a request targets a host outside the sandbox allowlist."""


class RequestBudgetExceeded(Exception):
    """Raised when the per-run request cap would be exceeded."""


def make_scoped_client(
    base_url: str,
    allowed_hosts: set[str],
    counter: dict,
    cap: int,
    *,
    log_path: Optional[Path] = None,
    timeout: float = 30.0,
    transport: Optional[httpx.BaseTransport] = None,
) -> httpx.AsyncClient:
    """Return an AsyncClient whose requests are allowlisted, budget-counted, and logged.

    ``counter`` is a mutable ``{"n": int}`` seeded with the run's current request count;
    read ``counter["n"]`` after use to persist the new count back into state.
    """

    async def _on_request(request: httpx.Request) -> None:
        host = request.url.host
        if host not in allowed_hosts:
            raise SecurityError(
                f"Blocked attempt to reach {host!r} — outside sandbox allowlist {allowed_hosts}"
            )
        if counter["n"] >= cap:
            raise RequestBudgetExceeded(f"Request budget of {cap} exceeded")
        counter["n"] += 1

    async def _on_response(response: httpx.Response) -> None:
        if log_path is None:
            return
        await response.aread()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "method": response.request.method,
                "url": str(response.request.url),
                "status": response.status_code,
                "body_truncated": response.text[:500],
            }) + "\n")

    hooks = {"request": [_on_request], "response": [_on_response] if log_path else []}
    return httpx.AsyncClient(base_url=base_url, timeout=timeout, follow_redirects=True,
                             event_hooks=hooks, transport=transport)
