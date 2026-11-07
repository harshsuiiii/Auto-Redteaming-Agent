"""Reporter Agent (03_AGENTS.md, Phase 7).

Turns a confirmed VerificationResult into a Finding. Split of responsibilities:

* CVSS scoring is DETERMINISTIC (the ``cvss`` library) — never computed by an LLM.
* PoC steps are DETERMINISTIC, built from the hypothesis payload and the collected
  evidence, so they are an exact, reproducible record of what was sent and seen.
* Only the ``remediation`` text is LLM-generated (per spec). If no LLM is configured,
  a per-vuln-class template is used so report generation still works fully offline.

The LLM is behind the ``RemediationLLM`` protocol so the Reporter is unit-testable
without a key or network.
"""
from __future__ import annotations

import os
from typing import Optional, Protocol

from cvss import CVSS3

from schemas.models import Finding, VerificationResult, VulnClass

# Deterministic base CVSS 3.1 vectors per vuln class (web-app context).
CVSS_VECTORS: dict[str, str] = {
    "IDOR":           "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "SQLI_ERROR":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "SQLI_BLIND":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "XSS_REFLECTED":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "SSRF":           "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
    "PATH_TRAVERSAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "BROKEN_AUTH":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
}

_SEVERITY_MAP = {"Critical": "critical", "High": "high", "Medium": "medium",
                 "Low": "low", "None": "info"}

_REMEDIATION_TEMPLATES: dict[str, str] = {
    "IDOR": "Enforce object-level authorization on every request: verify the "
            "authenticated principal owns (or may access) the referenced object before "
            "returning it, rather than trusting the id in the request.",
    "SQLI_ERROR": "Use parameterized queries / prepared statements (or the ORM's bound "
                  "parameters) instead of string-concatenating user input into SQL. "
                  "Disable detailed DB error messages in production.",
    "SQLI_BLIND": "Use parameterized queries / prepared statements for all user input. "
                  "Add input validation and least-privilege DB accounts to limit impact.",
    "XSS_REFLECTED": "Context-aware output encoding for all user-controlled data, a strict "
                     "Content-Security-Policy, and avoid sinks like innerHTML / "
                     "bypassSecurityTrustHtml with untrusted input.",
    "SSRF": "Validate and allowlist outbound URLs, resolve and block internal/link-local "
            "ranges, disable unused URL schemes, and do not forward raw user-supplied URLs.",
    "PATH_TRAVERSAL": "Canonicalize and validate file paths against an allowlisted base "
                      "directory; reject traversal sequences; never pass user input directly "
                      "to filesystem APIs.",
    "BROKEN_AUTH": "Verify JWT signatures with a fixed server-side algorithm (reject "
                   "alg:none and algorithm confusion), validate exp/iss/aud, and enforce "
                   "authorization server-side on every protected endpoint.",
}

_REMEDIATION_PROMPT = """Given a confirmed {vuln_class} vulnerability at {endpoint_url} \
with the following evidence: {evidence_summary}

Write a concise, actionable remediation suggestion for a developer. Include a short \
code-level suggestion where appropriate (e.g. parameterized queries for SQLi, output \
encoding for XSS, object-level authorization check for IDOR). Keep it under 150 words. \
Do not include an executive summary or restate the vulnerability."""


class RemediationLLM(Protocol):
    async def remediate(self, *, vuln_class: str, endpoint_url: str, evidence_summary: str) -> str: ...


class OpenAIRemediationClient:
    """Plain (non-tool) chat completion for remediation text. Works with any
    OpenAI-compatible endpoint (OpenAI, Groq, ...)."""

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None,
                 base_url: Optional[str] = None):
        from openai import AsyncOpenAI
        from core.agents.attacker import DEFAULT_MODEL
        base_url = (base_url or os.environ.get("AUTOREDTEAM_LLM_BASE_URL")
                    or os.environ.get("OPENAI_BASE_URL"))
        api_key = (api_key or os.environ.get("OPENAI_API_KEY") or os.environ.get("GROQ_API_KEY"))
        self._client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        self._model = model or DEFAULT_MODEL

    async def remediate(self, *, vuln_class: str, endpoint_url: str, evidence_summary: str) -> str:
        prompt = _REMEDIATION_PROMPT.format(vuln_class=vuln_class, endpoint_url=endpoint_url,
                                            evidence_summary=evidence_summary)
        resp = await self._client.chat.completions.create(
            model=self._model, temperature=0,
            messages=[{"role": "user", "content": prompt}],
        )
        return (resp.choices[0].message.content or "").strip()


def build_remediation_llm_from_env() -> Optional[RemediationLLM]:
    """Return a remediation client if an LLM key is present, else None (template mode)."""
    if os.environ.get("OPENAI_API_KEY") or os.environ.get("GROQ_API_KEY"):
        return OpenAIRemediationClient()
    return None


def score_cvss(vuln_class: VulnClass) -> tuple[str, float, str]:
    vector = CVSS_VECTORS[vuln_class]
    c = CVSS3(vector)
    severity = _SEVERITY_MAP.get(c.severities()[0], "info")
    return vector, float(c.base_score), severity


def _evidence_summary(v: VerificationResult) -> str:
    e = v.evidence
    bits = []
    if e.raw_response_status is not None:
        bits.append(f"HTTP {e.raw_response_status}")
    if e.error_signature_matched:
        bits.append(f"signature={e.error_signature_matched}")
    if e.callback_received is not None:
        bits.append(f"callback_received={e.callback_received}")
    if e.dom_snapshot:
        bits.append(f"dom={e.dom_snapshot}")
    if e.timing_samples_ms:
        bits.append(f"timing_samples_ms={[round(x) for x in e.timing_samples_ms]}")
    if v.notes:
        bits.append(v.notes)
    return "; ".join(bits) or "(no structured evidence)"


def build_poc_steps(v: VerificationResult) -> list[str]:
    """Deterministic, reproducible PoC — from the payload and evidence, not an LLM."""
    p = v.hypothesis.payload
    steps = [f"Send: {p.method} {p.url}"
             + (" with a valid bearer token for an authenticated user" if p.auth_token else "")]
    if p.body:
        steps.append(f"Request body: {p.body}")
    steps.append(f"Observed: {_evidence_summary(v)}")
    steps.append(f"Why it proves {v.hypothesis.vuln_class}: {v.hypothesis.success_criteria}")
    return steps


async def report(verification: VerificationResult, *,
                 remediation_llm: Optional[RemediationLLM] = None) -> Finding:
    if not verification.is_exploited:
        raise ValueError("Reporter only accepts confirmed (is_exploited=True) results.")
    vuln_class = verification.hypothesis.vuln_class
    vector, score, severity = score_cvss(vuln_class)

    if remediation_llm is not None:
        remediation = await remediation_llm.remediate(
            vuln_class=vuln_class,
            endpoint_url=verification.hypothesis.endpoint.url,
            evidence_summary=_evidence_summary(verification),
        )
    else:
        remediation = _REMEDIATION_TEMPLATES.get(vuln_class, "Apply the standard secure "
                                                 "coding control for this vulnerability class.")

    return Finding(
        verification=verification,
        cvss_vector=vector,
        cvss_score=score,
        severity=severity,
        poc_steps=build_poc_steps(verification),
        remediation=remediation,
    )
