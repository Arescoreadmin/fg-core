# codex_definitions.md — FrostGate Core (Strict Request → Artifact Rules)

## How to ask Codex (copy/paste patterns)

## Hard Preflight (Non-Negotiable)
Before doing anything, Codex MUST read:
- CODEX.md
- CLAUDE.md
- docs/ai/PR_FIX_LOG.md (if exists)
- docs/ai/GOTCHAS.md (if exists)

If a relevant fix/invariant exists, reuse it. Do NOT rediscover it.

## Output Clamp (Hard)
Codex MUST output ONLY the requested artifact.
- If unified diff requested: output unified diff only.
- If full file requested: output full file only.
- If summary requested: output PR Summary only.
No commentary. No explanations. No extra text. No headings.

## Fix Writeback (Hard)
If the change fixes a bug/regression/gate failure or introduces an invariant:
- Append an entry to docs/ai/PR_FIX_LOG.md
OR output:
NO_FIX_LOG_REQUIRED: <one-line reason>
(only when the user explicitly requested no file changes beyond code)

### 1) Patch request (unified diff only)
Request:
- Goal: <one sentence>
- Files allowed: <explicit list>
- Constraints: <caps, no refactor, etc.>
- Evidence: <failing test / stack trace / diff hunk>
Return: unified diff only.

Constraints MUST include:
- Diff budget: <max lines changed> (default 200)
- No refactor unless required for invariant (explicitly justify in PR_FIX_LOG)

Example:
Goal: Fix OpenAPI security 401/403 requirement for GET /planes.
Files allowed: api/main.py, tools/ci/check_openapi_security_diff.py, tests/security/test_openapi_security.py
Evidence: (paste failing gate output)
Return: unified diff only.

---

### 2) New file request (full file only)
Request:
- Create file: path/to/file.py
- Purpose: <one sentence>
- Interface: <function/class signatures required>
- Tests: <required test file path>
Return: full file content only (and test file content if requested).

---

### 3) PR summary request (summary only)
Request:
“Provide PR summary for this diff + test output”
Return: PR Summary format only (no extras).

---

## Default “DONE” checklist Codex must satisfy
- Types present and correct
- Validation strict; unknown fields rejected where feasible
- Deterministic errors
- Structured logging; no secrets
- Tests include negative/security paths as applicable
- No hidden globals introduced
- Config cannot fail open in prod-like
- Contracts/OpenAPI authority preserved
- `bash codex_gates.sh` passes

---

## Stop Conditions (must BLOCK)
BLOCKED if any of these are required and missing:
- tenant resolution source of truth for new/changed endpoints
- auth scope model for new/changed endpoints
- existing pattern location for similar feature (file path)
- migration direction policy (downgrade required or not)
- contract authority expectations (runtime vs contract app)