# claude_commands.md — FrostGate Core (Enterprise Production Standard)

## PURPOSE
Claude must output ONLY:
1) The exact requested artifact (code/patch/tests/config/migration/spec/script), OR
2) A PR Summary (when explicitly requested).

No commentary. No explanations. No repetition. No advice.
If blocked, respond ONLY:
BLOCKED: <single concise missing input or non-negotiable violation>

Everything produced must meet high-lever enterprise production standards.

---

## GLOBAL OUTPUT RULE
If the user requests: build/generate/write/create/patch/fix/add/update/refactor
→ return ONLY the artifact.

If the user requests: summary/PR summary/changelog/release note
→ return ONLY the PR Summary format below.

Never mix artifact + summary unless the user explicitly requests both.

---

## ENTERPRISE PRODUCTION STANDARD (MANDATORY)

### 1) Security (fail-closed by default)
- Least privilege scopes and explicit authz checks
- Tenant binding enforced (never trust body-provided tenant_id)
- RLS enforced for all tenant-owned tables; policies included
- Strict input validation (prefer schema models; forbid unknown fields)
- Rate limiting / abuse resistance where endpoints can be abused
- Secrets never logged; redact and classify sensitive fields
- Replay/idempotency protection for unsafe replays (TTL, caps, pruning)
- Explicit error mapping (no silent pass, no ambiguous “best effort”)
- Dependency risk awareness (pin versions; avoid dynamic execution)
- Audit logging for sensitive actions (who/what/when/why + trace_id)

### 2) Reliability & Scale
- Deterministic behavior (canonical JSON where hashed/signed)
- Bounded growth (logs, idempotency keys, event history, queues)
- Backpressure and retry policy documented in code when relevant
- Timeouts and circuit breakers for remote dependencies
- Concurrency-safe patterns; avoid global mutable state
- Clear failure mode behavior under partial outages

### 3) Observability & Forensics
- Structured logs (JSON), correlation IDs, consistent fields
- Metrics hooks where applicable (counters/timers) or clear TODO only if requested
- Audit events for security-relevant actions are complete and replayable
- Evidence bundles or hashes where applicable (deterministic fingerprints)

### 4) Quality Gates
- Tests added/updated for invariants and negative cases
- Contract/OpenAPI alignment preserved (contract authority respected)
- CI gates updated if new risk class introduced
- Lint/type checks satisfied; formatting deterministic

### 5) Compatibility & Change Safety
- Migration plan included (upgrade + downgrade if project supports)
- Backward compatibility maintained unless explicitly requested otherwise
- Rollback behavior considered; no irreversible destructive changes by default

If any standard cannot be met due to missing context, respond:
BLOCKED: <missing input>

---

## ARTIFACT RESPONSE RULES

### Code
- New file → full file content only.
- Existing file change → unified diff only.
- No pseudo-code. No placeholders. No “TODO” unless requested.
- Minimal, surgical diffs (avoid drive-by refactors).
- Deterministic formatting and stable ordering.

### Tests
- Provide full test file content (new) or unified diff (existing).
- Assert invariants; include negative tests for security paths.
- Include regression tests for discovered bug class.

### Migrations / DB
- Include RLS enablement and policies for tenant-owned data.
- Include indexes for scale where relevant.
- Include downgrade path if supported; otherwise explicitly block if unsafe.
- Avoid destructive irreversible ops unless explicitly requested.

### Contracts / OpenAPI
- Update authoritative schemas; no legacy refs.
- Ensure runtime app and contract app match.
- Add/adjust contract regression tests if drift risk exists.

---

## PR SUMMARY FORMAT (MANDATORY WHEN REQUESTED)
Title:
Scope:
Problem:
Solution:
Security Impact:
Architectural Impact:
Tenant Isolation Impact:
Reliability/Scale Impact:
Observability/Forensics Impact:
Failure Mode Considerations:
New/Updated Routes:
DB Changes:
RLS Changes:
Contract/OpenAPI Changes:
CI/Gate Changes:
Tests Added:
Backward Compatibility:
Migration/Rollback Plan:
Residual Risks:
Competitive/Moat Impact:

No additional prose.

---

## STRICT INVARIANTS (NON-NEGOTIABLE)
If touching auth/tenant/RLS/migrations/idempotency/events/encryption/audit/OpenAPI/routes/AI:
- explicit tenant resolution (not user-provided)
- fail-closed behavior on guard failures
- structured logs + trace_id
- bounded resource growth (TTL/caps/pruning)
- strict validation (unknown fields rejected where feasible)
- contract authority preserved

Violation → respond:
BLOCKED: <concise reason>

---

## DIFF DISCIPLINE
- Unified diff for modifications.
- No unrelated changes.
- No explanations.
- Keep context tight.

---

## TOKEN DISCIPLINE
- No restating instructions.
- No meta commentary.
- No suggestions unless requested.
- Output only what the user asked for (artifact OR PR summary).

---

## DONE CRITERIA (SELF-CHECK BEFORE OUTPUT)
- Output type matches request (artifact OR PR summary).
- Enterprise standards satisfied.
- No invariant violations.
- Deterministic formatting.
- Minimal blast radius.
- Tests/gates included when risk class changes.

---

## ENTERPRISE SECURITY EXPANSION (MANDATORY REVIEW LAYER)

When generating or reviewing anything, also evaluate:

### 1) Supply Chain
- Are dependencies pinned?
- Are hashes verified where feasible?
- Is dynamic code execution avoided?
- Are build artifacts reproducible?

### 2) Secrets Lifecycle
- Where are secrets stored?
- Is encryption at rest enforced?
- Is KEK rotation defined?
- Is secret access logged?
- Is secret exposure in logs prevented?

### 3) Runtime Isolation
- Does this introduce shared state?
- Are containers truly isolated?
- Are privilege boundaries minimized?
- Are outbound network calls restricted?

### 4) Infrastructure Drift
- Is this configuration reproducible via IaC?
- Are security controls enforceable in CI?
- Could this drift silently in staging/prod?

### 5) Abuse & Economic Attacks
- Can this be resource-exhausted?
- Is there rate limiting?
- Is there cost amplification risk?
- Are retries bounded?

### 6) Incident Readiness
- Is the event auditable?
- Can this action be reconstructed?
- Are logs tamper-evident?
- Is there a forensic story?

If any category is weakened, respond:
BLOCKED: <concise reason>

## EVIDENCE-FIRST RULE (MANDATORY)
Before implementing fixes, Claude must prefer using:
- failing test output
- stack traces
- minimal repro
- file paths and exact function names
- diffs/hunks

If evidence is missing and correctness depends on it:
BLOCKED: <exact missing evidence>

## PATCH SAFETY RULE
Default to the smallest correct change.
No refactors unless explicitly requested or required to fix a security invariant.
Any refactor must include regression tests proving no behavioral change.

## COMMANDS CANON (ONLY USE THESE UNLESS BLOCKED)
- make fg-fast
- make fg-fast-full
- pytest -q
- ruff check .
- mypy .
- python -m tools.ci.guard_no_duplicate_routes
- python -m tools.ci.check_openapi_security_diff

## STOP CONDITIONS
BLOCKED if any of these are required and missing:
- schema/contract authority expectations
- migration direction (upgrade/downgrade policy)
- auth scope model for new endpoint
- tenant resolution source of truth
- existing pattern for similar module

## TEST MINIMUMS
- New route: contract/regression + authz negative test + tenant override test
- New DB table: RLS policy test + migration test
- Security logic: exploit regression test + audit event assertion
- Background worker: idempotency test + retry behavior test

## CODE QUALITY ENFORCEMENT BLOCK (MANDATORY)

All generated or modified code must meet the following standards.

### 1) Required Elements (Always Include)

Every implementation must explicitly include:

- Types  
  - Explicit type hints on all public functions and methods  
  - No untyped public interfaces  
  - No `Any` unless strictly unavoidable  

- Validation  
  - Strict input validation (schema models preferred)  
  - Reject unknown fields where feasible  
  - Enforce bounds, length limits, and structural constraints  
  - Fail fast on invalid input  

- Errors  
  - Explicit error handling (no silent pass)  
  - Deterministic error responses  
  - No broad `except Exception` without re-raise or structured handling  
  - Clear separation between user errors and system errors  

- Logging  
  - Structured logs (JSON-style fields, not string blobs)  
  - Include `trace_id` / correlation ID when available  
  - No secrets in logs  
  - Security-relevant actions must emit audit logs  

- Tests  
  - Positive path tests  
  - Negative tests (invalid input, auth failure, tenant override attempts if applicable)  
  - Security regression test when touching auth/tenant/RLS  
  - Deterministic assertions (no flaky timing-based checks)  

If any element is missing → BLOCKED.

---

### 2) New Module Rules

For any new module:

- Define a clear public interface:
  - Explicit exported functions or classes
  - No implicit side effects on import
  - No hidden globals controlling behavior
- Avoid module-level mutable state
- Inject dependencies instead of hardcoding them
- Make behavior testable without network or external side effects

If module introduces hidden state or implicit coupling → BLOCKED.

---

### 3) Configuration Rules

For any new or modified configuration:

- Explicit environment variable definitions
- Sensible secure defaults (fail-closed)
- No silent fallback to insecure behavior
- Add a “prod unsafe config gate”:
  - If insecure config detected in prod-like mode → raise or hard fail
  - Unsafe flags must require explicit override

Example expectation:
- Dev convenience allowed
- Prod-like environment enforces strict mode automatically

If config can silently weaken security in prod-like → BLOCKED.

---

### 4) Determinism & Cleanliness

- No non-deterministic ordering unless explicitly required
- No unused imports
- No dead code
- No speculative abstractions
- Minimal blast radius changes

---

### DONE CRITERIA (SELF-CHECK)

Before returning code, verify:

- Types are explicit and correct
- Validation is strict and complete
- Errors are deterministic and classified
- Logging is structured and safe
- Tests cover invariant + abuse path
- No hidden globals introduced
- Config cannot fail open in prod-like