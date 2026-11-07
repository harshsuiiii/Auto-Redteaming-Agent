# Sandbox Setup — `core/sandbox/`

## Purpose
Every target application runs in an isolated, ephemeral Docker environment. This is
both a safety requirement (no accidental or malicious traffic leaving the sandbox) and
a correctness requirement (clean state per run for reproducible benchmarking).

## `SandboxController` interface

```python
class SandboxController:
    async def start(self, target_image: str, run_id: str) -> SandboxHandle:
        """
        1. Create a fresh, isolated Docker bridge network scoped to this run_id.
        2. Start the target container attached ONLY to that network.
        3. Configure network rules so the container has:
           - NO outbound internet access
           - NO access to other containers except what orchestrator explicitly needs
             (e.g. an SSRF callback listener, if attached)
        4. Wait for target health check (HTTP 200 on root) before returning.
        5. Return a SandboxHandle with the reachable base URL.
        """

    async def stop(self, handle: SandboxHandle) -> None:
        """Tear down container and destroy the network. Always called in a finally
        block — never leave sandboxes running between test runs."""

    async def reset(self, handle: SandboxHandle) -> SandboxHandle:
        """Stop and restart for a clean-state re-run (useful for repeated benchmark
        runs against the same target)."""
```

## docker-compose reference (development)

```yaml
# docker-compose.sandbox.yml
services:
  juice-shop:
    image: bkimminich/juice-shop
    networks:
      - redteam-isolated
    expose:
      - "3000"
    # no "ports:" mapping to host beyond what the orchestrator needs for local dev

  dvwa:
    image: vulnerables/web-dvwa
    networks:
      - redteam-isolated
    expose:
      - "80"

networks:
  redteam-isolated:
    driver: bridge
    internal: true   # no external gateway — critical isolation setting
```

`internal: true` is the key setting — it prevents the network from having a route to
the outside world at all. For local development you'll need a separate bridge (without
`internal: true`) that only the orchestrator process itself uses to reach into the
sandbox network; the target containers stay fully internal.

## Egress allowlisting for the agent's own tools

Even though the target has no outbound access, the **agent's** httpx/Playwright client
(running on the orchestrator side) must also be restricted:

```python
ALLOWED_HOSTS_FOR_RUN = {sandbox_handle.base_url_host}

def guard_url(url: str):
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS_FOR_RUN:
        raise SecurityError(f"Blocked attempt to reach {host} — outside sandbox allowlist")
```

Wrap every tool call (`httpx`, Playwright `page.goto`) with this guard. This is your
primary defense against a prompt-injected response trying to redirect the agent
somewhere outside the sandbox.

## Request budget enforcement

Before every outbound call from any verifier module:

```python
if state.request_count >= state.request_cap:
    raise RequestBudgetExceeded(run_id=state.run_id)
state.request_count += 1
```

This must be enforced at the tool-call boundary, not just checked once per hypothesis —
a single verifier (e.g. blind SQLi's N-sample timing check) can make many requests per
hypothesis.

## Logging requirement

Every request/response pair (method, URL, headers minus secrets, status, truncated
body) must be logged to a per-run log file (`logs/{run_id}.jsonl`). This is required
for:
- Reproducibility in your report
- Debugging agent reasoning failures
- The PoC steps in `Finding.poc_steps`, which should be generated from this log, not
  reconstructed from memory

## Target setup checklist

- [ ] `docker pull bkimminich/juice-shop`
- [ ] `docker pull vulnerables/web-dvwa`
- [ ] `docker pull webgoat/webgoat` (optional, Phase 3+)
- [ ] Confirm each image's known-vulnerability list is documented (Juice Shop has an
      official scoreboard of its intentional vulnerabilities — use this as labeled
      ground truth for precision/recall in `07_EVALUATION.md`)
- [ ] Confirm each container starts cleanly with `internal: true` networking and is
      still reachable from the orchestrator process
