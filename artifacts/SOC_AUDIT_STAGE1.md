# SOC Audit Stage 1 — Static Deep Audit (ranked findings)

## Executive risk table

| Rank | Finding | Sev | Likelihood | Blast radius | Fix cost |
|---|---|---:|---:|---:|---:|
| 1 | Unsigned webhook acceptance path (fixed in Stage2) | Critical | High | Multi-tenant external ingress | Low |
| 2 | Alert webhook egress allowed without SSRF policy (fixed in Stage2) | Critical | Medium | Internal network/data exfil | Low |
| 3 | Error responses lacked stable machine code (fixed in Stage2) | High | Medium | Client contracts + monitoring | Low |
| 4 | Tripwire delivery lacks explicit egress policy | High | Medium | Internal services reachable | Medium |
| 5 | Unmatched-route auth behavior calls downstream before deny | High | Medium | Router/middleware misconfig abuse | Medium |
| 6 | Non-prod default tenant fallback to `unknown` | Medium | High | Dev/stage data confusion | Low |
| 7 | Broad import fail-soft in auth adapter | Medium | Medium | Silent control degradation | Low |
| 8 | Release gate has test-only skip toggles | Medium | Medium | Process bypass risk | Low |
| 9 | Postgres local trust auth in compose | Medium | Medium | Local lateral abuse | Low |
| 10 | Private address webhook policy absent for tripwires | Medium | Medium | Internal pivoting | Medium |
| 11 | No explicit pin on several deps (`>=`) | Medium | Medium | Supply-chain drift | Low |
| 12 | `follow_redirects=True` for tripwire client | Medium | Low | Redirect-to-internal chains | Low |
| 13 | Potential log spoof via forwarded IP headers | Low | Medium | Forensics quality loss | Low |
| 14 | Exception shield emits detail directly | Low | Medium | Error text consistency/leak risk | Low |
| 15 | CI gate coverage split across many scripts; no single regression gate before Stage2 | Low | Medium | Drift of control classes | Low |

---

## Findings (evidence, impact, reproducibility)

### F1. Unsigned webhook path accepted when secret missing (**patched**)
- **Evidence:** `api/webhook_security.py:145-171`.
- **Why it mattered:** Secretless verification created an auth bypass condition for webhook ingress.
- **Exploit/impact:** Adversary could forge alert/webhook payloads if operators forgot secret.
- **Reproduce/verify:** Call `verify_signature(..., secret="")` in dev without override; now returns invalid by default.

### F2. Alert webhook egress lacked destination validation (**patched**)
- **Evidence:** `api/security_alerts.py:212-230` (send path), now guarded by `:65-89, 216-218`.
- **Why it mattered:** User-controlled or misconfigured webhook URL could target internal hosts.
- **Exploit/impact:** SSRF to loopback/private endpoints or metadata services.
- **Reproduce/verify:** Validate `https://127.0.0.1/hook` now blocked by `_validate_alert_webhook_url`.

### F3. Stable error code absent from exception shield (**patched**)
- **Evidence:** `api/main.py` exception shield emitted only `detail` (pre-patch); now emits `error_code` with deterministic mapping.
- **Why it mattered:** Clients/monitoring lacked durable machine field for error contract.
- **Exploit/impact:** Silent breakage in policy engines and SIEM parsing on detail text changes.
- **Reproduce/verify:** Trigger HTTPException path and assert JSON includes `error_code`.

### F4. Tripwire webhook delivery has no explicit egress allow/deny policy
- **Evidence:** `api/tripwires.py:149-194` posts arbitrary URL; no URL policy check.
- **Why it matters:** Security telemetry channel can become pivot path.
- **Exploit/impact:** Internal service discovery + blind writes to internal APIs.
- **Reproduce/verify:** Configure tripwire URL to private host and observe attempted delivery.

### F5. Auth middleware passes unmatched routes downstream
- **Evidence:** `api/middleware/auth_gate.py:118-120`.
- **Why it matters:** Middleware relies on router matching; mis-mounted routers may bypass auth path assumptions.
- **Exploit/impact:** If route resolution changes, unauthenticated handling can occur before deny path.
- **Reproduce/verify:** Construct app with late-mounted route and observe `x-fg-gate: unmatched` branch.

### F6. Tenant fallback to `unknown` in non-prod
- **Evidence:** `api/auth_scopes/resolution.py:535-545`.
- **Why it matters:** Non-explicit tenant contexts can collapse data into shared synthetic tenant.
- **Exploit/impact:** Cross-test/dev tenant contamination; forensic ambiguity.
- **Reproduce/verify:** Unscoped key + no tenant in non-prod binds to `unknown`.

### F7. Broad fail-soft import for tenant registry
- **Evidence:** `api/auth.py:16-19` catches all import errors.
- **Why it matters:** Unexpected import/runtime errors silently disable intended tenant lookup integration.
- **Exploit/impact:** Hidden auth control drift in partial deployments.
- **Reproduce/verify:** Force import error and observe fallback to `_registry_get_tenant = None`.

### F8. Release gate supports skip flags
- **Evidence:** `scripts/release_gate.py:145-157` (`skip_subprocess_checks`, `skip_evidence_verification`).
- **Why it matters:** Even test-only flags are bypass primitives if exposed operationally.
- **Exploit/impact:** Policy check bypass in ad-hoc invocation contexts.
- **Reproduce/verify:** Invoke script with skip flags and compare reduced checks.

### F9. Compose uses local trust auth for postgres local connections
- **Evidence:** `docker-compose.yml:77` (`--auth-local=trust`).
- **Why it matters:** Local socket/container compromise allows easier DB access.
- **Exploit/impact:** Privilege escalation in dev clusters or misused compose in shared host.
- **Reproduce/verify:** Start compose and validate pg_hba behavior for local mode.

### F10. Tripwire client follows redirects by default
- **Evidence:** `api/tripwires.py:125-128` (`follow_redirects=True`).
- **Why it matters:** Redirect chains can be used to hop to blocked hosts.
- **Exploit/impact:** SSRF hardening bypass if only first-hop inspected elsewhere.
- **Reproduce/verify:** Use endpoint returning 302 to internal URL and inspect client behavior.

### F11. Dependency drift risk from open lower bounds
- **Evidence:** `requirements.txt:16-18` (`itsdangerous>=`, `python-json-logger>=`, `aiosqlite>=`).
- **Why it matters:** Non-deterministic dependency resolution increases supply-chain volatility.
- **Exploit/impact:** Surprise regressions/vulns via transitive resolver drift.
- **Reproduce/verify:** Resolve lock on two dates and compare installs.

### F12. Security logs trust forwarded IP headers first
- **Evidence:** `api/auth_scopes/resolution.py` request IP extraction (x-forwarded-for precedence).
- **Why it matters:** Spoofable headers pollute forensic attribution without trusted proxy validation.
- **Exploit/impact:** Incident response misattribution.
- **Reproduce/verify:** Send forged `X-Forwarded-For` and inspect logged `client_ip`.

### F13. Auth gate only explicit scope map for `/stats`
- **Evidence:** `api/middleware/auth_gate.py:16-23`.
- **Why it matters:** Route-scope policy can drift if new sensitive routes added without map entries.
- **Exploit/impact:** Authenticated-but-under-scoped token accesses new route class.
- **Reproduce/verify:** Add sensitive route without scope map and observe access with basic key.

### F14. Exception shield serializes detail directly
- **Evidence:** `api/main.py:176-190`.
- **Why it matters:** Direct detail pass-through can leak low-level messages if raised upstream.
- **Exploit/impact:** Internal state disclosure in error responses.
- **Reproduce/verify:** Raise HTTPException with sensitive detail and inspect output.

### F15. CI had fragmented checks without one regression super-gate (**patched in Stage2**)
- **Evidence:** Multiple point checks in `.github/workflows/ci.yml` prior to Stage2 insertion.
- **Why it matters:** Security-class regressions can slip between individually narrow checks.
- **Exploit/impact:** Inconsistent gate coverage over time.
- **Reproduce/verify:** Remove one security marker and observe previous lanes not consistently failing.

---

## Top 5 catastrophic exploitation narratives
1. **Forged webhooks at scale:** missing secret + permissive verifier allows attacker-injected events that appear authentic to operations.
2. **Alert channel SSRF pivot:** webhook URL points to internal control plane; alert system becomes authenticated internal caller.
3. **Tenant context collapse:** unscoped non-prod traffic resolves to shared `unknown`, contaminating decision streams and downstream analytics.
4. **Auth gate mismatch edge:** router mismatch branch executes downstream stack before auth deny, exposing fragile middleware ordering assumptions.
5. **Release gate bypass-by-invocation:** operational misuse of skip flags permits releases with incomplete readiness evidence.
