# Verifier Engine — `core/verifier/`

This is the core IP of the project: deterministic, execution-grounded checks that turn
a `Hypothesis` into a `VerificationResult`. **Build this before any LLM agent exists.**
Test each module with hand-written `Hypothesis` objects first.

## Shared interface

Every vuln-class module exposes the same async function signature:

```python
async def verify(hypothesis: Hypothesis, http_client: httpx.AsyncClient) -> VerificationResult:
    ...
```

Orchestration dispatches by `hypothesis.vuln_class` to the matching module. Keep this
dispatch table in `core/verifier/__init__.py`:

```python
VERIFIERS: dict[VulnClass, Callable] = {
    "IDOR": idor.verify,
    "SQLI_ERROR": sqli.verify_error_based,
    "SQLI_BLIND": sqli.verify_blind,
    "XSS_REFLECTED": xss.verify,
    "SSRF": ssrf.verify,
    "PATH_TRAVERSAL": path_traversal.verify,
    "BROKEN_AUTH": broken_auth.verify,
}
```

---

## IDOR (`idor.py`) — build first, simplest

**Mechanism:** compare the response for the hypothesis payload against a baseline
(authenticated user's own resource) and check for unauthorized data.

```python
async def verify(hypothesis: Hypothesis, http_client: httpx.AsyncClient) -> VerificationResult:
    # 1. Send baseline request (user's own resource, e.g. original id in payload)
    # 2. Send hypothesis.payload (modified id)
    # 3. Diff response bodies — if the modified-id response contains structurally
    #    similar but DIFFERENT personal data (not an error, not identical), flag exploited
    # 4. confidence = "deterministic" if diff logic is unambiguous,
    #    else fall back to Verifier Agent with confidence = "llm_judged"
```

**Success condition:** response status is 200 (not 403/404), AND response body
contains data fields differing from the baseline in a way consistent with
"another user's private data" (e.g. different email/name on what should be a
restricted resource).

**False-positive guard:** if the target returns identical placeholder data regardless
of ID (common in demo apps), this must NOT be flagged — compare field-by-field, not
just "response succeeded."

---

## SQL Injection — error-based (`sqli.py: verify_error_based`)

**Mechanism:** regex match on known DB error signatures in the response body.

Maintain a signature list (extend as needed):
```python
SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sqlite3\.OperationalError",
    r"pg_query\(\)",
    r"ORA-\d{5}",
]
```

**Success condition:** any signature matches in the response AFTER sending a payload
with injected syntax (e.g. `' OR '1'='1`), AND the same signature does NOT appear in
the baseline (unmodified) request — this avoids flagging an app that always shows
generic errors.

---

## SQL Injection — blind/time-based (`sqli.py: verify_blind`)

**Mechanism:** statistical timing delta. Single-sample timing checks are noisy — don't
trust one request.

```python
async def verify_blind(hypothesis, http_client) -> VerificationResult:
    # 1. Send baseline request N times (e.g. N=5), record timings
    # 2. Send payload with time-delay injection (e.g. SLEEP(5)) N times, record timings
    # 3. Compute mean + stddev for both sample sets
    # 4. Flag exploited only if payload mean exceeds baseline mean by > threshold
    #    (e.g. injected delay minus 1 stddev of noise), reducing false positives from
    #    network jitter
```

**Success condition:** statistically significant timing delta consistent with the
injected sleep duration. Store all raw samples in `evidence.timing_samples_ms` for the
report.

---

## Reflected XSS (`xss.py`) — requires Playwright

**Mechanism:** string reflection in HTML is NOT proof — the payload must actually
execute as JavaScript in a real DOM.

```python
async def verify(hypothesis: Hypothesis, browser_context) -> VerificationResult:
    # 1. Inject a unique marker payload, e.g. <script>window.__xss_marker = "UUID"</script>
    #    or an event-handler variant depending on context (attribute vs body)
    # 2. Navigate Playwright headless browser to the crafted URL
    # 3. Check page.evaluate("window.__xss_marker") for the exact UUID
    # 4. is_exploited = True only if the marker was actually SET by execution,
    #    not just present in page.content()
```

**Success condition:** JS execution confirmed via `window` state, not substring match
on HTML source. Store `evidence.dom_snapshot` (serialized relevant DOM state) for the
report.

---

## SSRF (`ssrf.py`)

**Mechanism:** out-of-band callback. Requires a listener reachable only from inside the
sandbox network (not the public internet, to avoid any real-world interaction).

```python
async def verify(hypothesis: Hypothesis, callback_listener) -> VerificationResult:
    # 1. Generate a unique callback URL (listener running on orchestrator side,
    #    reachable from the sandbox network)
    # 2. Send payload referencing that URL as the SSRF target
    #    (e.g. ?url=http://callback-listener:PORT/UUID)
    # 3. Poll callback_listener for a hit on that UUID within a timeout window
    # 4. is_exploited = True iff the callback was received
```

**Success condition:** confirmed inbound request to the listener bearing the unique
token. `evidence.callback_received = True`.

---

## Path Traversal (`path_traversal.py`)

**Mechanism:** sentinel content match.

```python
PATH_TRAVERSAL_SENTINELS = {
    "/etc/passwd": r"root:.*:0:0:",
    "win.ini": r"\[fonts\]",
}
```

**Success condition:** response body contains a sentinel pattern matching the
requested OS file's known structure, not just "any file content appeared."

---

## Broken Authentication (`broken_auth.py`)

**Mechanism:** token manipulation/reuse check — e.g. attempt to access a protected
resource with a tampered, expired, or wrong-scope token and confirm it is still
accepted.

**Success condition:** protected endpoint returns 200 with valid data despite an
invalid/manipulated auth context that should have been rejected.

---

## Shared test harness requirement

For every module above, write a unit test using a **mocked httpx/Playwright response**
before testing against the live sandbox. This lets you validate verifier logic without
needing Docker running, and gives you regression coverage for your report's
reliability claims.
