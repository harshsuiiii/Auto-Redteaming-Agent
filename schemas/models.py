# schemas/models.py
#
# SINGLE SOURCE OF TRUTH for every inter-agent / inter-layer message.
# Transcribed verbatim from docs 02_SCHEMAS.md. No module may redefine these
# types locally — import from here. Treat any change as a breaking API change
# across the whole system (requires sign-off per 09_OWNERSHIP_HANDSHAKE.md).
from __future__ import annotations
from typing import Literal, Optional, Any
from pydantic import BaseModel, Field
import datetime as dt


# ---------- Recon output ----------

class ParamSchema(BaseModel):
    name: str
    location: Literal["query", "path", "body", "header", "cookie"]
    type: str                      # e.g. "string", "int", "file"
    sample_value: Optional[str] = None

class Endpoint(BaseModel):
    url: str
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"]
    params: list[ParamSchema] = Field(default_factory=list)
    auth_required: bool = False
    response_shape: Optional[dict[str, Any]] = None   # sample response, keys only

class AttackSurfaceMap(BaseModel):
    target_base_url: str
    endpoints: list[Endpoint]
    discovered_at: dt.datetime = Field(default_factory=dt.datetime.utcnow)


# ---------- Attacker output ----------

VulnClass = Literal[
    "IDOR", "SQLI_ERROR", "SQLI_BLIND", "XSS_REFLECTED",
    "SSRF", "PATH_TRAVERSAL", "BROKEN_AUTH",
]

class Payload(BaseModel):
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"]
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[dict[str, Any]] = None
    auth_token: Optional[str] = None

class Hypothesis(BaseModel):
    vuln_class: VulnClass
    endpoint: Endpoint
    rationale: str                  # agent's reasoning, for the report + debugging
    payload: Payload
    success_criteria: str           # natural-language description of what proves this
    attempt_number: int = 1


# ---------- Verifier output ----------

class VerificationEvidence(BaseModel):
    """Vuln-class-specific evidence. Only the relevant fields are populated."""
    raw_response_status: Optional[int] = None
    raw_response_body: Optional[str] = None
    baseline_response_body: Optional[str] = None     # for IDOR diffing
    timing_samples_ms: Optional[list[float]] = None  # for blind SQLi
    dom_snapshot: Optional[str] = None                # for XSS (Playwright)
    callback_received: Optional[bool] = None          # for SSRF (OOB listener)
    error_signature_matched: Optional[str] = None      # for SQLi error-based

class VerificationResult(BaseModel):
    hypothesis: Hypothesis
    is_exploited: bool
    confidence: Literal["deterministic", "llm_judged"]
    evidence: VerificationEvidence
    verified_at: dt.datetime = Field(default_factory=dt.datetime.utcnow)
    notes: Optional[str] = None


# ---------- Reporter output ----------

class Finding(BaseModel):
    verification: VerificationResult
    cvss_vector: str                # e.g. "CVSS:3.1/AV:N/AC:L/..."
    cvss_score: float
    severity: Literal["critical", "high", "medium", "low", "info"]
    poc_steps: list[str]
    remediation: str
    reported_at: dt.datetime = Field(default_factory=dt.datetime.utcnow)


# ---------- Orchestration state (owned jointly — see 09) ----------

class RedTeamState(BaseModel):
    run_id: str
    target_config: dict[str, Any]
    attack_surface: Optional[AttackSurfaceMap] = None
    hypotheses_queue: list[Hypothesis] = Field(default_factory=list)
    current_hypothesis: Optional[Hypothesis] = None
    attempt_history: list[VerificationResult] = Field(default_factory=list)
    verified_findings: list[Finding] = Field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 3
    request_count: int = 0
    request_cap: int = 500
