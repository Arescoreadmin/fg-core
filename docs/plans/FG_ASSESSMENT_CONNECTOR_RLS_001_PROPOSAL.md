# FG-ASSESSMENT-CONNECTOR-RLS-001: connector lifecycle and tenant-context assurance

| | |
|---|---|
| **Status** | Proposed workstream. Not authorized, not implemented. `check_customer_one_roadmap.py --work-item FG-ASSESSMENT-CONNECTOR-RLS-001` is fail-closed until the item is registered. |
| **Proposed classification** | P0 customer readiness and tenant-isolation assurance (founder proposal; not a canonical roadmap assignment) |
| **Recorded by** | FG-NIGHTLY-REGRESSION-REPAIR-001, 2026-11-26, on branch `fix/fg-nightly-regression-repair-001` (base `4d15cb820`) |
| **Affected routes** | `run_external_ai_risk_register`, `run_ai_data_access_mapping`, `run_ai_vendor_governance` (all in `api/field_assessment.py`) |

## Summary

Restored nightly CI (run 45890327767) exposed a D-T6-003 violation in `run_external_ai_risk_register`. Investigating it found two wider issues in all three synchronous connector routes:

1. Durable job state does not reach `complete` in two of the three routes.
2. All database work after the first commit runs without re-binding the transaction-scoped tenant context.

FG-NIGHTLY-REGRESSION-REPAIR-001 repairs only the first route's job-id capture and running transition. Everything below remains open.

No cross-tenant data exposure has been reproduced, and none is claimed. Each finding is classified as availability, data integrity, tenant isolation or missing assurance.

## Findings

Line numbers refer to `api/field_assessment.py` on `fix/fg-nightly-regression-repair-001` at `190cb3627`.

### F1: missing running-state transition (data integrity; confirmed)

`DurableJobService.mark_complete` is a compare-and-swap on `status == 'running'` (`services/field_assessment/durable_job_service.py:202-221`). A job that is never marked `running` cannot become `complete`. The call fails silently (rowcount 0, and the return value is ignored).

| Route | Lines | Transitions present |
|---|---|---|
| `run_ai_data_access_mapping` | 14290-14461 | `complete` 14402, `failed` 14439. No `running`. |
| `run_ai_vendor_governance` | 15542-15730 | `complete` 15671, `failed` 15708. No `running`. |
| `run_external_ai_risk_register` | 15180-15380 | `running` 15266, `complete` 15322, `failed` 15358 (repaired in FG-NIGHTLY-REGRESSION-REPAIR-001). |

The failure path still works: `mark_failed` accepts `queued` (`_FAILABLE_STATUSES = ("queued", "running")`).

### F2: durable job state, results and audit disagree (data integrity; confirmed)

After a successful run of either unrepaired route:
- the API returns 200;
- the audit trail records `scan.initiated` and `scan.completed`;
- the durable `FaScanJob` stays `queued` with no `scan_result_id`.

Job-status views, queue and lease logic, and any recovery or reconciliation that trusts `fa_scan_jobs` therefore see work that never finished. A worker that scans for `queued` jobs of these types could also treat them as runnable; this needs to be checked (see F6).

**Reproduction (SQLite test harness, 2026-11-26):** run with the existing route-test helpers from `tests/test_external_ai_risk_register_routes.py`, seeding AI Tool Discovery, then calling mapping (as assessor), the register (as assessor), and vendor governance (as tenant_admin):

```
JOBS  [('ai_data_access_mapping', 'queued', False),
       ('external_ai_risk_register', 'complete', True),   # repaired route
       ('ai_vendor_governance', 'queued', False)]
AUDIT [('ai_data_access_mapping', 'scan.completed'), ('ai_data_access_mapping', 'scan.initiated'),
       ('ai_vendor_governance', 'scan.completed'), ('ai_vendor_governance', 'scan.initiated'),
       ('external_ai_risk_register', 'scan.completed'), ('external_ai_risk_register', 'scan.initiated')]
```

Before the repair, `run_external_ai_risk_register` also produced `('external_ai_risk_register', 'queued', None)`.

### F3: tenant context lost after the initiation commit (tenant isolation / availability; code-confirmed, runtime unreproduced)

`set_tenant_context` (`api/db.py:2048-2061`) runs `set_config('app.tenant_id', :tenant_id, true)`. The setting is transaction-local and is reset at the end of each transaction. `auth_ctx_db_session` (`api/deps.py:94-118`) binds it once, at session creation. The precedent is documented at `api/workforce.py:355-357`: *"set_config(..., true) is transaction-scoped and resets on commit, so post-commit lazy-loads fail RLS."*

Background scanner workers re-bind after every commit (for example `api/field_assessment.py:3712`, `3726`, `3767`). None of the three synchronous routes calls `set_tenant_context` after its first commit.

Repository search found no session-level (`is_local = false`) setting of `app.tenant_id` in application code. A pooled connection therefore should not carry another tenant's context into this work. Without reproduction, a stale-context leak is not claimed.

### F4: database access after the commit (where F3 applies)

Each route commits the job and the `scan.initiated` audit, then performs all of its real work in a new transaction:

| Route | First commit | Post-commit database work |
|---|---|---|
| `run_ai_data_access_mapping` | 14361 | `import_ai_data_access_mapping_scan` 14388, `_auto_link_scan_evidence` 14395, job update 14402, audit 14409, commit 14423; failure path: job update 14439, audit 14442, commit 14452 |
| `run_external_ai_risk_register` | 15262 | job `running` 15266, `db.query(FaExternalAiRiskRecord)` 15277, `import_external_ai_risk_register` 15308, `_auto_link_scan_evidence` 15315, job update 15322, audit 15328, commit 15342; failure path 15358/15361/15371 |
| `run_ai_vendor_governance` | 15620 | `import_ai_vendor_governance` 15657, `_auto_link_scan_evidence` 15664, job update 15671, audit 15678, commit 15692; failure path 15708/15711/15721 |

`fa_scan_jobs` has `ENABLE ROW LEVEL SECURITY` with the policy `tenant_id = current_setting('app.tenant_id', TRUE)` (`migrations/postgres/0079_c6_scanner_containment.sql:77-80`), but not `FORCE`. The expected runtime effect depends on the database role:

- **Table-owner or BYPASSRLS role:** RLS is not applied. The routes work, but the post-commit work has no database-level tenant isolation, only application-level tenant filters. This is missing assurance, not a demonstrated leak.
- **Non-privileged role with RLS enforced:** post-commit reads would return no rows, and inserts and updates would fail `WITH CHECK` (`current_setting` is NULL). The expected result is a 500 and a job left unmarked. That is an availability and data-integrity failure that fails closed, not cross-tenant access.

Which role production uses for these paths has not been verified here (compare audit gap 002).

### F5: no real PostgreSQL RLS coverage for these paths (missing assurance; confirmed)

Route tests run on SQLite, where `set_tenant_context` is a no-op. Neither `run_ai_data_access_mapping` nor `run_ai_vendor_governance` has any route test. `tests/test_d_t6_scan_scheduling_authority.py` is a static AST contract plus a unit regression, with no Postgres. No test executes these routes under a non-privileged role with RLS enforced.

### F6: to verify in the repair (unassessed)

- **Restart and recovery:** what a worker or reaper does with jobs left `queued` by F1.
- **Duplicate execution:** re-running a route creates a new job each time. Idempotency is currently provided by record upsert, not by job identity.
- **Equivalent defects:** whether other synchronous routes (outside these three) that commit and then keep working have the same pattern.

## Customer delivery and security implications

- **Assessment delivery:** operators and customers who rely on job status see these connector runs as never finished, even though findings and records were written. That undermines the "durable, auditable scan job" claim in customer evidence and makes reconciliation unreliable.
- **Auditability:** the audit trail (`scan.completed`) contradicts the job record. Both are customer-facing evidence.
- **Tenant isolation:** isolation for this post-commit work currently rests on application-level filters only. Enabling enforced RLS for the application role, the intended hardening, would make these routes fail until tenant context ownership is fixed. That creates a pressure to keep RLS bypassed.
- **No confirmed exposure:** no cross-tenant read or write has been shown.

## Proposed acceptance criteria

1. **Canonical ownership.** One documented owner for transaction boundaries and tenant context in synchronous connector routes: re-bind after every commit, or avoid committing mid-request. It is applied to all three routes and to any equivalent route found under F6.
2. **Real Postgres tests.** Postgres integration tests run with RLS enabled and `FORCE`d on the touched tables, using a non-privileged application role (no BYPASSRLS, not table owner), for every affected route.
3. **Cross-tenant negatives.** Cross-tenant negative tests under that role show that tenant A cannot read, create or modify tenant B's jobs, records, findings, evidence links or audit events.
4. **Job transitions.** `queued → running → complete` on success, and `queued|running → failed/dead_letter` on failure, are asserted for each route. A no-op compare-and-swap transition is detected (checked return value) rather than ignored.
5. **Durable results.** `scan_result_id` on the job matches the persisted result and the API response.
6. **Rollback and exceptions.** Rollback leaves no partial records. Failure handling still records the failure when the original error was database-related.
7. **Audit consistency.** `scan.completed` and `scan.failed` are emitted only when the matching job transition commits.
8. **Restart and recovery.** Jobs interrupted mid-route are recovered or terminated deterministically and are never re-run unsafely.
9. **Idempotency.** Repeated runs neither duplicate records nor leave orphaned jobs.
10. **Adjacent routes.** Adjacent connector and synchronous routes are inventoried, and equivalent defects are fixed or recorded.
11. **Required CI.** The Postgres RLS tests run in required CI, not only in nightly runs.
12. **No weakening.** No existing test is weakened, and fail-closed behaviour is preserved.
