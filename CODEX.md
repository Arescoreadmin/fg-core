# CODEX.md — FrostGate Core (Enterprise Production Contract for Codex)

## Mandatory Repository Memory Protocol

Before proposing or implementing any change, Codex MUST:
1) Read `CODEX.md`
2) Read `CLAUDE.md`
3) Read `docs/ai/PR_FIX_LOG.md` (if present)
4) Read `docs/ai/GOTCHAS.md` (if present)

If a relevant prior fix, invariant, or constraint exists:
- Reuse it
- Cite it implicitly by complying with it
- Do NOT re-derive the same solution

Failure to consult repo memory is considered a correctness failure.

## Output Rule (Hard)
Codex must return ONLY:
- The requested artifact (unified diff, full new file, tests, config, migration), OR
- A PR Summary (only when explicitly requested).

If critical info is missing:
BLOCKED: <single concise missing input>

No commentary, no explanations, no “here’s what I did”.

---

## Enterprise Production Standard (Non-Negotiable)

### Always include (as applicable)
- **Types**: explicit type hints for all public interfaces; no public untyped functions.
- **Validation**: strict input validation; reject unknown fields where feasible; bounds/length caps.
- **Errors**: deterministic error handling; no silent pass; no broad catch without structured handling.
- **Logging**: structured logs; include trace/correlation id when available; never log secrets.
- **Tests**: positive + negative; security regression tests for auth/tenant/RLS; deterministic assertions.

### Security invariants
- Explicit tenant resolution (never trust request-body tenant_id)
- Least privilege authorization
- RLS enforced for tenant-owned tables + policies included
- Fail-closed on guard/service outages
- Bounded resource growth (TTL/caps/pruning)
- OpenAPI/contract authority preserved; no contract drift

### Reliability & scale
- Deterministic behavior; canonicalization where hashed/signed
- Concurrency-safe patterns; no module-level mutable state
- Timeouts/retries bounded; no unbounded loops/backlogs

### Observability & forensics
- Audit logs for security-relevant actions: who/what/when/why + trace_id + request_fingerprint when applicable
- Replay path considered for critical decisions

---

## Patch Safety
Default to the smallest correct change.
No refactors unless explicitly requested or required to satisfy a security invariant.
Refactors require regression tests proving no behavior change.

---

## Evidence-First Rule
Prefer working from:
- failing test output
- stack traces
- minimal repro
- diffs/hunks
- exact file paths and function names

If correctness depends on missing evidence:
BLOCKED: <exact missing evidence>

---

## Artifacts
- **Modify existing file**: unified diff ONLY.
- **New file**: full file content ONLY.
- **Tests**: full file (new) or unified diff (existing).
- **Migrations**: deterministic; include rollback/downgrade if project supports; include RLS + indexes when relevant.
- **Contracts/OpenAPI**: runtime and contract app alignment preserved; add regression tests if drift risk exists.

---

## Gates (Definition of Done)
Codex must instruct running:
- `bash codex_gates.sh`

A change is not “done” unless gates pass.

---

## PR Summary format (only when asked)
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

## Fix Persistence Requirement (Hard)

If a change:
- fixes a bug
- closes a regression
- resolves a CI/gate failure
- enforces a new invariant
- hardens security or tenancy

Codex MUST append a concise entry to `docs/ai/PR_FIX_LOG.md`
using the project template.

If no entry is required, explicitly state:
NO_FIX_LOG_REQUIRED: <one-line justification>

## Knowledge Hygiene

When modifying behavior that intersects a prior logged fix:
- Update the existing entry OR
- Mark it as superseded with a reason

Never leave stale or misleading fix records.

---
Last reviewed: YYYY-MM-DD
Owner: FrostGate Core Maintainers