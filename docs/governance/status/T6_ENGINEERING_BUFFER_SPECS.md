# T6 Engineering Buffer — PR Specifications

**Traceable to:** T6-EXEC-20260804-001 defect list (D-T6-001 through D-T6-006)
**Authored:** 2026-08-04
**Status:** SCOPED — not yet implemented

These five PRs are the complete engineering response to T6. Nothing outside this list may be
merged to fix T6 defects. No scope creep. If a reviewer sees "while we're here" in a PR
description, that work is a separate PR or it doesn't merge.

After all five PRs are merged, run T6-EXEC-20260804-002 against H5, H10, H11, H13, H15, H17.

---

## PR-T6.1 — Post-Commit ORM Lifecycle

**Closes:** D-T6-002, D-T6-006
**Branch:** `fix/t6-post-commit-orm-lifecycle`

### Problem

`api/field_assessment.py` calls `db.commit()` and then accesses ORM attributes or calls
`db.refresh()` in the same request. SQLAlchemy's `expire_on_commit=True` expires all
attributes after commit. The session's RLS context (`SET LOCAL app.tenant_id`) is also
scoped to the transaction and is lost when the transaction commits. Any subsequent attribute
access triggers a lazy SELECT in a new transaction with no RLS context, producing either
`InvalidRequestError` (lazy load blocked) or `ObjectDeletedError` (no rows returned under
empty RLS context).

The data IS committed correctly. Only response serialization fails.

### Affected locations

| Route | File:line | Post-commit access |
|---|---|---|
| `create_engagement_route` | `field_assessment.py` | `db.refresh(eng)` or `eng.*` after commit |
| `create_or_get_questionnaire` | `field_assessment.py:~9270` | `_questionnaire_to_response(q, ...)` — accesses `q.framework`, `q.created_at`, etc. |
| `create_engagement_report_route` | `field_assessment.py:~8563` | `db.refresh(record)` after commit |
| `qa_approve_report_route` | `field_assessment.py:7546` | `eng.status` accessed after `db.commit()` at line 7540 |

### Fix pattern

Capture all values needed for the response **before** `db.commit()`. After commit, do not
access any ORM attribute; construct the response from the captured values.

```python
# BEFORE (broken)
db.commit()
db.refresh(record)                  # RLS lost — ObjectDeletedError
return SomeResponse(id=record.id)   # or: lazy load on expired attr

# AFTER (correct)
record_id = record.id               # capture before commit
status = record.status              # capture before commit
db.commit()
return SomeResponse(id=record_id, status=status)
```

Alternative where the full record is needed for serialization: re-query after commit using
the captured PK, resetting RLS context first via `SET LOCAL` (same pattern used in
`validate_credential` and other read paths).

**Do not use `expire_on_commit=False` globally.** The flag masks latent bugs elsewhere.
Apply the minimal fix at each affected call site.

### Acceptance criteria

- [ ] `POST /field-assessment/engagements` returns 201 with full engagement body (not 500)
- [ ] `POST /field-assessment/engagements/{id}/questionnaires` returns 201 with questionnaire body (not 500)
- [ ] `POST /field-assessment/engagements/{id}/reports` returns 201 with report body (not 500)
- [ ] `POST /field-assessment/engagements/{id}/reports/{report_id}/qa-approve` returns 200 (not 500)
- [ ] All four routes return the same data that would have been returned before the ORM expiry
- [ ] Regression test for each route: POST → assert 2xx → assert body contains expected fields

### Do NOT touch

- Business logic within any of these routes
- Permission enforcement (`require_permission`, `require_scopes`)
- Scan engine code
- Any route not in the table above
- Portal code

---

## PR-T6.2 — Scan Scheduling Authority

**Closes:** D-T6-003
**Branch:** `fix/t6-scan-scheduling-authority`

### Problem

All 9 scan initiation routes in `api/field_assessment.py` follow this broken pattern:

```python
job = create_scan_job(...)          # inserts FaScanJob row
db.commit()                         # job attributes expire; RLS SET LOCAL lost
run_id = job.id                     # ObjectDeletedError — job is expired
background_tasks.add_task(run_scan, run_id=run_id)  # never reached
```

The job row IS committed to the database. The background task is never scheduled because
the `ObjectDeletedError` propagates before `background_tasks.add_task()` is called. Scan
jobs remain in `queued` state indefinitely with no mechanism to advance them.

Secondary effect: the rate limiter counts `queued` jobs as active (correct by design), so
subsequent scan attempts for the same engagement hit `429 RATE_LIMITED` until the stale
jobs are cleared.

### Affected locations

`api/field_assessment.py` — all 9 scan initiation routes:

| `db.commit()` line | `job.id` access | `background_tasks.add_task()` line |
|---|---|---|
| 3505 | 3507 | 3517 |
| 3755 | 3757 | 3767 |
| 4478 | 4480 | 4490 |
| 4680 | 4682 | 4692 |
| 4952 | 4954 | 4964 |
| 5208 | 5210 | 5220 |
| 5463 | 5465 | 5475 |
| 5718 | 5720 | 5730 |
| 5977 | 5979 | 5989 |

Also review: line 9271 (`q.id` after commit), line 10451 and 11187 (`source_scan.id` after
commit) — fix if in scope, otherwise document as follow-on defects.

### Fix

Capture `job.id` (and any other needed attributes) **before** `db.commit()`:

```python
job = create_scan_job(...)
job_id = job.id                             # capture before commit
db.commit()
background_tasks.add_task(run_scan, run_id=job_id)  # uses captured value
```

Apply this pattern at all 9 locations in the table above. No other changes.

### Acceptance criteria

- [ ] `POST /engagements/{id}/scans` (DNS/email, web headers, network scan, and all 6 device-code variants) returns 2xx
- [ ] `FaScanJob` row transitions from `queued` → `running` → `complete` or `failed` (not stuck in `queued`)
- [ ] Background worker executes the scan task
- [ ] Audit event written on scan completion
- [ ] Rate limiter correctly counts only genuinely active jobs (not stuck queued jobs from prior run)
- [ ] H5 rerun: all 3 no-auth scans initiate and complete
- [ ] Regression test for at least one scan route: POST → assert 2xx → assert job reaches terminal state

### Do NOT touch

- Scan business logic (what the scan does, findings it produces)
- Permission enforcement
- Rate limiter thresholds
- `create_scan_job()` internals
- Report or engagement routes
- Portal code

---

## PR-T6.3 — Portal Invitation Routing

**Closes:** D-T6-004
**Branch:** `fix/t6-portal-invitation-routing`

### Problem

`api/notifications/email.py` line 57:

```python
return f"{_invitation_base_url()}?token={raw_token}"
```

The accept-invite URL in the invitation email does not include `tenant_id`. The portal BFF
(`apps/portal/app/api/auth/accept-invite/route.ts` line 59) resolves tenant context as:

```typescript
const tenantId = bodyTenantId || process.env.CORE_TENANT_ID || '';
```

When `tenant_id` is absent from the URL, `bodyTenantId` is empty, and the BFF falls back
to `CORE_TENANT_ID` (the primary production tenant, not the invitee's tenant). The core API
performs RLS lookup under the wrong tenant → `get_invitation_by_token()` returns None → 404
`PORTAL_INVITATION_NOT_FOUND`. The invitation is NOT consumed (failure is at preflight).

### Fix

**In `api/notifications/email.py`:**

Update `build_invitation_url` to accept `tenant_id` and include it in the URL:

```python
def build_invitation_url(raw_token: str, tenant_id: str) -> str:
    base = _invitation_base_url()
    return f"{base}?token={raw_token}&tenant_id={tenant_id}"
```

Update all callers of `build_invitation_url` to pass `tenant_id`. The invitation record
already contains `tenant_id` — no new data needed.

**Verify** that `apps/portal/app/accept-invite/page.tsx` already reads `tenant_id` from
the URL (confirmed: `tenantHint = searchParams.get('tenant_id') ?? ''` at line 29) and
that `completeAccept()` passes it to the BFF body. No portal code changes needed if the
URL is correct.

### Acceptance criteria

- [ ] Email accept-invite URL contains `?token=pni1.{hex64}&tenant_id={tenant_id}`
- [ ] Navigating to that URL (in any browser, no manual cookie manipulation) completes invitation acceptance
- [ ] H8 rerun: single attempt, no cookie-clearing workaround required
- [ ] `portal_user_invitations` row transitions to `accepted` after one attempt
- [ ] Unit test: `build_invitation_url(token, tenant_id)` asserts both params present in output

### Do NOT touch

- Invitation issuance logic (`create_invitation` in `portal_user_authority.py`)
- OIDC flow in the portal BFF (no changes to `oidc/route.ts` or `oidc/callback/route.ts`)
- Auth0 configuration
- Any other email template

---

## PR-T6.4 — Evidence Signing Startup Invariant

**Closes:** D-T6-005
**Branch:** `fix/t6-evidence-signing-startup-invariant`

### Problem (confirmed via Railway log)

`FG_EVIDENCE_SIGNING_KEY_B64` is not set in Railway production. `capture_observation_route`
(line 1916) calls `create_evidence_provenance()` → `_try_sign_new_event()` in
`evidence_provenance.py:505`. `_try_sign_new_event` is intentionally fail-closed in
production — it raises `RuntimeError("evidence_authority.signing_failed: ...")` when the
key is absent. The observation flush succeeds; signing fails before `db.commit()`;
transaction rolls back; 0 records committed.

### Authority decision

Do NOT copy the report QA path's "skip and continue" behavior. Evidence authority signing
is mandatory in production. Unsigned evidence committed silently defeats the purpose of the
evidence authority. The QA path's skip behavior is itself technical debt, not a pattern to
spread.

The correct fix moves the failure from mid-transaction discovery to **deterministic startup
validation** — the same pattern used for `MINISIGN_SECRET_KEY` (PR #539).

**Operational prerequisite (user action, not code):** Set `FG_EVIDENCE_SIGNING_KEY_B64`
in Railway before deploying this PR. Generate:
```
openssl rand -base64 32
```
Value is a 32-byte Ed25519 private key seed, base64-encoded (44 chars). Verify with:
```
python3 -c "import os,base64; b=base64.b64decode('<value>'); assert len(b)==32, f'bad length {len(b)}'"
```

### Fix

**In `api/main.py` (startup validation):** Add `FG_EVIDENCE_SIGNING_KEY_B64` to the
production invariant check alongside `MINISIGN_SECRET_KEY`. Validate: present, non-empty,
valid base64, decodes to exactly 32 bytes. Fail startup with a clear `RuntimeError` if any
check fails.

```python
# In production startup validation:
_signing_key_b64 = os.getenv("FG_EVIDENCE_SIGNING_KEY_B64", "")
if not _signing_key_b64:
    raise RuntimeError("FG_EVIDENCE_SIGNING_KEY_B64 is required in production")
try:
    key_bytes = base64.b64decode(_signing_key_b64)
except Exception:
    raise RuntimeError("FG_EVIDENCE_SIGNING_KEY_B64 must be valid base64")
if len(key_bytes) != 32:
    raise RuntimeError(f"FG_EVIDENCE_SIGNING_KEY_B64 must decode to 32 bytes (got {len(key_bytes)})")
```

**In `_try_sign_new_event` (`evidence_provenance.py`):** Current behavior is correct —
keep fail-closed in production, return `{}` in dev/test. No change to this function.

**In `capture_observation_route` (`field_assessment.py` lines 1939–1940):** Apply
D-T6-002 pattern fix regardless — capture needed attributes before `db.commit()` at line
1938 to prevent a secondary ORM expiry failure once the env var is configured.

**Dev/test mode:** `_try_sign_new_event` already returns `{}` (unsigned) in non-production.
Emit a log warning at WARNING level when signing is skipped: `signing skipped — non-production`.
Do not add a startup assertion in dev/test environments.

### Acceptance criteria

- [ ] Production startup fails with `RuntimeError` if `FG_EVIDENCE_SIGNING_KEY_B64` is absent
- [ ] Production startup fails if value is invalid base64 or decodes to ≠ 32 bytes
- [ ] With key configured: `POST /observations` returns 201 with signed provenance record
- [ ] `FaEvidenceProvenance` row has non-null `signing_key_id` and `signature` fields
- [ ] Dev/test mode: observation succeeds with unsigned provenance (no startup failure)
- [ ] Dev/test mode: WARNING log emitted when signing skipped
- [ ] No unsigned evidence can be committed in production
- [ ] Unit test: startup validation rejects missing key, bad base64, wrong length
- [ ] Integration test: POST observation → assert 201 → assert provenance row signed

### Do NOT touch

- `_try_sign_new_event` fail-closed behavior in production
- Report QA `trust_arc.persist_decision_memory` path (separate system; address separately)
- Any other route
- Permissions

---

## PR-T6.5 — API Contract Enforcement

**Closes:** (not a T6 defect — operational trust invariant; traceable to "Unexpected token `<`"
observed in console during T6)
**Branch:** `fix/t6-api-contract-enforcement`

### Problem

`api/main.py` has a `RequestValidationError` handler (line 523) but no global `Exception`
handler. Unhandled exceptions propagate to FastAPI/Railway's default error page, which
returns HTML. The portal and console BFFs parse every upstream response as JSON — receiving
HTML produces "Unexpected token `<`" in the client, which erodes operator confidence and
obscures the real error.

**Invariant:** Every response from every API endpoint — success or failure — must be
`Content-Type: application/json` with a structured body. No HTML ever.

### Fix

**In `api/main.py`:** Add a global fallback exception handler after the existing
`RequestValidationError` handler:

```python
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    logger.exception("unhandled_exception request_id=%s path=%s", request_id, request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "error_code": "INTERNAL_ERROR",
            "message": "An unexpected error occurred.",
            "request_id": request_id,
        },
    )
```

Rules:
- `message` is never the raw exception message (no internal detail leaked to clients)
- `request_id` must be traceable in Railway logs
- The handler logs the full exception with stack trace (for Railway log investigation)
- HTTP status is always 500 for this handler (not 200, not 422)

**Do not** change any existing structured error response. This handler is a fallback only —
it catches what nothing else catches.

### Acceptance criteria

- [ ] Any unhandled exception in any route returns `Content-Type: application/json`, not `text/html`
- [ ] Response body contains `error_code`, `message`, and `request_id` fields
- [ ] `request_id` appears in Railway logs at ERROR level with full stack trace
- [ ] "Unexpected token `<`" no longer appears in console or portal under any API error condition
- [ ] Existing `RequestValidationError` handler behavior unchanged
- [ ] Unit test: inject an unhandled exception via test client → assert JSON response with 500 + correct fields

### Do NOT touch

- Any existing exception handler
- Any existing error response format (structured errors stay as-is)
- Business logic in any route
- Portal or console BFF code

---

## PR-T6.6 — Portal Session Revocation SQL Fix

**Closes:** D-T6-007
**Branch:** `fix/t6-portal-session-revocation`
**Classification: LAUNCH BLOCKER**

### Problem (confirmed via Railway log)

`revoke_portal_session_by_fingerprint()` PL/pgSQL function fails with:

```
psycopg.errors.AmbiguousColumn: column reference "tenant_id" is ambiguous
LINE 8: tenant_id::TEXT AS tenant_id,
DETAIL: It could refer to either a PL/pgSQL variable or a table column.
```

The RETURNING clause uses `tenant_id::TEXT AS tenant_id` without table qualification.
PostgreSQL cannot resolve whether `tenant_id` refers to the function parameter or the
column in `portal_user_sessions`. The UPDATE may commit (the SET clause uses the primary
key filter `token_fingerprint = p_fingerprint`, which is unambiguous), but the RETURNING
clause fails, causing the entire statement to fail.

BFF `logout/route.ts` is designed fail-open — it clears the `fg_portal_session` cookie
regardless of Core response. The operator sees a redirect to `/login`. The
`portal_user_sessions` row remains `active`. A stolen `pnu1.` token replayed against Core
would authenticate successfully until the 14-day Core TTL expires.

Cookie clearing is browser state management. Server-side revocation is the security control.

### Fix

**New migration** (next available number after 0171): create or replace the function with
all column references table-qualified in the RETURNING clause:

```sql
CREATE OR REPLACE FUNCTION revoke_portal_session_by_fingerprint(p_fingerprint TEXT)
RETURNS TABLE (session_id UUID, tenant_id TEXT, portal_user_id UUID)
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    RETURN QUERY
    UPDATE portal_user_sessions
    SET    status     = 'revoked',
           revoked_at = now()
    WHERE  token_fingerprint = p_fingerprint
      AND  status            = 'active'
    RETURNING
           portal_user_sessions.id                  AS session_id,
           portal_user_sessions.tenant_id::TEXT      AS tenant_id,
           portal_user_sessions.portal_user_id       AS portal_user_id;
END;
$$;
```

Apply the same table-qualification discipline to all other columns in the RETURNING clause.

**Do NOT change the BFF fail-open behavior** — that is correct. The fix is that the Core
revocation succeeds, not that the BFF becomes fail-closed.

### Acceptance criteria

- [ ] Logout calls `revoke_portal_session_by_fingerprint` → HTTP 200 from Core
- [ ] `portal_user_sessions.status` = `revoked` after logout
- [ ] `portal_user_sessions.revoked_at` is set
- [ ] Replaying the revoked `pnu1.` token against Core returns 401 (`SESSION_REVOKED`)
- [ ] Second logout (idempotent) returns 200 (token already revoked → 0 rows updated → BFF still clears cookie)
- [ ] Cross-tenant: token from tenant A cannot be revoked by a request authenticated as tenant B
- [ ] Migration replay passes on PostgreSQL 18 without ambiguity error
- [ ] Unit test for `revoke_session_by_token()` in `portal_user_authority.py`: assert row status = revoked after call

### Do NOT touch

- BFF `logout/route.ts` fail-open cookie clearing behavior
- `portal_user_sessions` table structure
- Other portal user authority functions
- Auth flow

---

## Sequencing

| Order | PR | Blocks T6-second-run H-steps | Prerequisite |
|---|---|---|---|
| 1 | PR-T6.4 | H13 | Set `FG_EVIDENCE_SIGNING_KEY_B64` in Railway first |
| 2 | PR-T6.6 | H18 (launch blocker) | None — DDL migration only |
| 3+4 | PR-T6.1 + PR-T6.2 (parallel) | H15; H5/H10/H11/H17 | None |
| 5 | PR-T6.3 | H8 clean (no workaround) | None |
| 6 | PR-T6.5 | operational trust (does not gate T6 second run) | After T6.1–T6.4 merged |

PR-T6.5 may merge after T6 second run passes — it does not gate launch but should be in
before the Launch Decision Record is signed.

---

## What is NOT in this buffer

- Any new feature
- Any refactor beyond the minimum fix at each site
- `expire_on_commit=False` globally
- Scan engine business logic changes
- Permission changes
- Portal UI changes beyond PR-T6.3's URL fix
- The report QA path's `trust_arc` skip behavior (separate system; address in P1-01 era)

If a reviewer proposes work not traceable to a defect in this document, it goes to a separate
PR after T6 second run.

---

*Revised 2026-08-04 after Railway log analysis:*
*D-T6-005 root cause confirmed (missing env var, not code bug); PR-T6.4 scope changed to startup invariant.*
*D-T6-007 added (portal session revocation SQL ambiguity — launch blocker); PR-T6.6 added.*
*H18 corrected from PARTIAL PASS to FAIL in evidence doc.*
*T6 second run scope: H5, H10, H11, H13, H15, H17, H18 (7 steps).*
