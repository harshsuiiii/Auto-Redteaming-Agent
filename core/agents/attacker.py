"""Attacker Agent — reasons about ONE endpoint (+ prior attempt history) and emits a
single structured Hypothesis (03_AGENTS.md, Phase 3).

Design choices
--------------
* The LLM only decides the fields it should decide: ``vuln_class``, ``rationale``,
  ``payload``, ``success_criteria``. The endpoint and ``attempt_number`` are attached
  deterministically by this module — the agent never re-emits (and so can't corrupt)
  the endpoint it was given.
* Output is produced via tool/function calling with a JSON schema; the arguments are
  validated into Pydantic models. A schema-invalid response is retried LOCALLY (not as
  an agent "attempt") up to ``max_llm_retries``.
* The agent REASONS; it never executes. Only the verifier engine touches the target.
* Phase 3 is IDOR-only (``allowed_vuln_classes``); expand in Phase 5.
* The agent never fabricates an auth token: if an ``auth_context`` token is supplied,
  it is injected into the payload after parsing, so a long JWT is never transcribed
  (and mis-transcribed) by the model.

The OpenAI dependency is isolated behind the ``LLMClient`` protocol so the agent is
fully unit-testable with a fake client (no API key, no network).
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Optional, Protocol

from pydantic import ValidationError

from schemas.models import (
    Endpoint,
    Hypothesis,
    Payload,
    VerificationResult,
    VulnClass,
)

# Works with any OpenAI-compatible endpoint (OpenAI, Groq, Together, local vLLM, ...).
# Set AUTOREDTEAM_LLM_BASE_URL + AUTOREDTEAM_LLM_MODEL + the matching key to switch.
DEFAULT_MODEL = (
    os.environ.get("AUTOREDTEAM_LLM_MODEL")
    or os.environ.get("AUTOREDTEAM_OPENAI_MODEL")
    or "gpt-4o"
)
TOOL_NAME = "propose_hypothesis"

SYSTEM_PROMPT = """\
You are a security researcher analyzing a single API endpoint for exploitable
vulnerabilities. You must output a single structured hypothesis using the provided
tool schema — no prose outside the tool call.

Endpoint under analysis:
{endpoint_json}

Authenticated context available to you (do NOT invent credentials beyond this):
{auth_context_json}

Prior attempts on this endpoint (if any), including why they failed:
{attempt_history_json}

Relevant known techniques/payloads for the candidate vuln classes (retrieved, not
exhaustive — use as inspiration, adapt to this endpoint's shape):
{retrieved_context}

Rules:
- Choose exactly one vuln_class from: {allowed}.
- Base your choice on the endpoint's shape (param names, types, auth requirements),
  not a generic checklist. E.g. a numeric "id" param with auth suggests IDOR; a
  "file"/"path" param suggests path traversal or SSRF.
- For IDOR: craft payload.url so the object reference (e.g. the :id path segment)
  points at a resource that is NOT the authenticated user's own (use a different id
  than the one in the auth context), while still sending the authenticated token.
- For SQLI_ERROR: inject a single UNBALANCED quote that BREAKS the SQL so the DB
  throws a visible error. Prefer a lone quote (e.g. email = "'") over a logically
  valid bypass like ' OR 1=1-- , which often authenticates successfully WITHOUT
  raising any error and so cannot be confirmed error-based.
- For SQLI_BLIND: inject a time-delay clause (e.g. ' AND SLEEP(5)-- ) into the param.
- For XSS_REFLECTED: put an executable payload (script/event-handler/iframe) into the
  parameter whose value is reflected into the page.
- For PATH_TRAVERSAL: set a file/path param to traverse to a known OS file
  (e.g. ../../../../etc/passwd).
- For SSRF: set a url/uri/target param to a URL you want the server to fetch.
- For BROKEN_AUTH: target a protected endpoint with a tampered/forged/wrong-scope
  token in payload.auth_token.
- If attempt_history is non-empty, you MUST produce a materially different payload —
  do not repeat a failed payload verbatim. Explain in `rationale` what you changed
  and why, based on the prior failure's evidence.
- `success_criteria` must describe something checkable (e.g. "response body contains
  an email field not belonging to the authenticated user"), not a vague claim.
- Never fabricate values you don't have (e.g. don't invent a valid auth token —
  reference the one provided in the auth context)."""


class LLMClient(Protocol):
    """Minimal surface the Attacker needs from an LLM. Implemented by OpenAIToolClient
    for production and by fakes in tests."""

    async def propose(self, *, system: str, tool_schema: dict[str, Any],
                       correction: Optional[str] = None) -> dict[str, Any]:
        ...


def _tool_schema(allowed: list[VulnClass]) -> dict[str, Any]:
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    return {
        "name": TOOL_NAME,
        "description": "Propose exactly one exploit hypothesis for the endpoint.",
        "parameters": {
            "type": "object",
            "properties": {
                "vuln_class": {"type": "string", "enum": list(allowed)},
                "rationale": {"type": "string",
                              "description": "Why this vuln_class and payload, grounded in the endpoint shape."},
                "payload": {
                    "type": "object",
                    "properties": {
                        "method": {"type": "string", "enum": methods},
                        "url": {"type": "string", "description": "Absolute URL of the attack request."},
                        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                        "body": {"type": ["object", "null"]},
                        "auth_token": {"type": ["string", "null"]},
                    },
                    "required": ["method", "url"],
                },
                "success_criteria": {"type": "string"},
            },
            "required": ["vuln_class", "rationale", "payload", "success_criteria"],
        },
    }


class OpenAIToolClient:
    """Production LLMClient backed by chat-completions tool calling. Works against any
    OpenAI-compatible endpoint (OpenAI, Groq, Together, local vLLM/Ollama, ...) by
    pointing ``base_url`` at the provider; the OpenAI Python SDK is the transport."""

    def __init__(self, model: str = DEFAULT_MODEL, api_key: Optional[str] = None,
                 base_url: Optional[str] = None, rate_limit_retries: int = 6,
                 rate_limit_backoff: float = 6.0):
        from openai import AsyncOpenAI  # imported lazily so tests need no SDK/key
        base_url = (base_url or os.environ.get("AUTOREDTEAM_LLM_BASE_URL")
                    or os.environ.get("OPENAI_BASE_URL"))
        api_key = (api_key or os.environ.get("OPENAI_API_KEY")
                   or os.environ.get("GROQ_API_KEY"))
        # Let the SDK handle transient retries too; our loop below paces hard TPM caps.
        self._client = AsyncOpenAI(api_key=api_key, base_url=base_url, max_retries=4)
        self._model = model
        self._rl_retries = rate_limit_retries
        self._rl_backoff = rate_limit_backoff

    async def propose(self, *, system: str, tool_schema: dict[str, Any],
                      correction: Optional[str] = None) -> dict[str, Any]:
        from openai import RateLimitError
        messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        if correction:
            messages.append({"role": "user", "content": correction})
        # Back off and retry on provider rate limits (e.g. Groq free-tier TPM cap), so
        # sustained runs (benchmarks) pace themselves instead of crashing.
        for attempt in range(self._rl_retries):
            try:
                resp = await self._client.chat.completions.create(
                    model=self._model,
                    messages=messages,
                    tools=[{"type": "function", "function": tool_schema}],
                    tool_choice="required",  # only one tool offered; portable across providers
                    temperature=0,
                )
                break
            except RateLimitError:
                if attempt == self._rl_retries - 1:
                    raise
                await asyncio.sleep(self._rl_backoff)
        tool_calls = resp.choices[0].message.tool_calls
        if not tool_calls:
            raise ValueError("Model returned no tool call.")
        return json.loads(tool_calls[0].function.arguments)


def _build_system_prompt(endpoint: Endpoint, attempt_history: list[VerificationResult],
                         auth_context: Optional[dict[str, Any]], allowed: list[VulnClass],
                         retrieved_context: Optional[list[str]]) -> str:
    history = [
        {"vuln_class": r.hypothesis.vuln_class, "payload_url": r.hypothesis.payload.url,
         "is_exploited": r.is_exploited, "notes": r.notes}
        for r in attempt_history
    ]
    retrieved = "\n".join(f"- {c}" for c in retrieved_context) if retrieved_context else "(none provided)"
    return SYSTEM_PROMPT.format(
        endpoint_json=endpoint.model_dump_json(indent=2),
        auth_context_json=json.dumps(auth_context or {}, indent=2),
        attempt_history_json=json.dumps(history, indent=2),
        retrieved_context=retrieved,
        allowed=", ".join(allowed),
    )


async def attack(
    endpoint: Endpoint,
    attempt_history: list[VerificationResult] | None = None,
    *,
    auth_context: dict[str, Any] | None = None,
    allowed_vuln_classes: list[VulnClass] | None = None,
    retrieved_context: list[str] | None = None,
    llm_client: LLMClient | None = None,
    max_llm_retries: int = 3,
) -> Hypothesis:
    attempt_history = attempt_history or []
    allowed = allowed_vuln_classes or [
        "IDOR", "SQLI_ERROR", "SQLI_BLIND", "XSS_REFLECTED",
        "SSRF", "PATH_TRAVERSAL", "BROKEN_AUTH",
    ]
    client = llm_client or OpenAIToolClient()
    system = _build_system_prompt(endpoint, attempt_history, auth_context, allowed, retrieved_context)
    tool_schema = _tool_schema(allowed)

    correction: Optional[str] = None
    last_error: Optional[str] = None
    for _ in range(max_llm_retries):
        raw = await client.propose(system=system, tool_schema=tool_schema, correction=correction)
        try:
            payload = Payload(**raw["payload"])
            # Never trust a model-transcribed token: inject the real one if provided.
            if auth_context and auth_context.get("auth_token"):
                payload.auth_token = auth_context["auth_token"]
            return Hypothesis(
                vuln_class=raw["vuln_class"],
                endpoint=endpoint,
                rationale=raw["rationale"],
                payload=payload,
                success_criteria=raw["success_criteria"],
                attempt_number=len(attempt_history) + 1,
            )
        except (ValidationError, KeyError, TypeError) as exc:
            last_error = str(exc)
            correction = (
                "Your previous tool call failed schema validation with: "
                f"{last_error}. Re-emit a corrected, schema-valid tool call."
            )
    raise ValueError(f"Attacker could not produce a valid Hypothesis after "
                     f"{max_llm_retries} attempts. Last error: {last_error}")
