# FG-ASSESSMENT-CONNECTOR-RLS-001: connector lifecycle and tenant-context assurance

| | |
|---|---|
| **Status** | Authorized by #927 (`e01c467e8`, `FOUNDER_AUTHORIZED` in `next_sequence`); implemented on branch `fix/fg-assessment-connector-rls-001`. See **Implementation and acceptance** below. The original findings are kept as recorded. |
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

## Implementation and acceptance (FG-ASSESSMENT-CONNECTOR-RLS-001, 2026-11-27)

### Pre-fix reproduction on real PostgreSQL

The three routes were called directly under a login role that is `NOSUPERUSER NOBYPASSRLS` and not the table owner. The schema was built like production `init_db()` (ORM `create_all`, then all migrations), and every commit was real.

| Route | Result | Cause |
|---|---|---|
| `run_ai_data_access_mapping` | 500 `MAPPING_FAILED` | `ObjectDeletedError`: the source `FaScanResult`, expired by the initiation commit, is reloaded with no tenant bound, and forced RLS hides it |
| `run_external_ai_risk_register` (with #926) | 500 `RISK_REGISTER_FAILED` | Same cause, via `pr1_scan.id` |
| `run_ai_vendor_governance` | 422 | Its prerequisite never completed |

After these runs:
- Both jobs stayed `queued`, with only `scan.initiated` audited.
- No `scan.failed` was written, because the failure path's writes also ran unbound and the errors were swallowed.
- The mapping 500 body exposed an ORM instance description.

**Classification:** availability and data integrity, failing closed. RLS denied access; no cross-tenant access occurred.

**Ground truth of the schema (resolves F4):** every touched table has RLS enabled **and forced** (from migrations 0094/0095, after ORM creation), with the fail-closed `app.tenant_id` policy from 0111. No RLS migration was needed.

### Canonical ownership (criterion 1)

Ownership follows the L14-ASSURANCE-P1-REPAIR-001 pattern; there is no new framework.
- **Transaction-local binding:** `set_config('app.tenant_id', ..., true)` lasts only for the transaction. After every `db.commit()` or `db.rollback()` that is followed by more database work, the route calls `set_tenant_context(db, tenant_id)` with the server-resolved tenant.
- **Job lifecycle:** `_c6_create_scan_job`, `_c6_update_job_status` (which now returns its compare-and-swap result) and `DurableJobService` remain the job authorities. The audit authority is still `_c6_write_audit_event`.
- **Where the rules are recorded:** the `api/field_assessment.py` section header, enforced by `tools/ci/check_connector_tenant_context.py`.

### Lifecycle after the fix

1. **Preflight:** interrupted runs of this connector (`running`, lease expired) are moved to `dead_letter`, each with a `scan.failed` (`STALE_LEASE_EXPIRED`), tenant-scoped and never re-run. A run that holds a live lease returns 409 `SCAN_ALREADY_RUNNING`.
2. **Initiation commit:** the job is created and claimed `queued → running` (lease set) in the same commit as `scan.initiated`. Then the tenant is re-bound.
3. **Work transaction:** the results, then `complete` (checked), then `scan.completed`, in one commit. A lost transition (for example, the job was cancelled meanwhile) rolls back the results and returns 409 `SCAN_JOB_SUPERSEDED`.
4. **Failure:** rollback, re-bind, then `failed` (checked; non-retryable types become `dead_letter`), with `scan.failed` only if that transition applied, in one commit. The response is a generic 500 with no internals.

### Acceptance matrix

All PostgreSQL tests live in `tests/test_migrations_postgres_replay.py`, which runs in the required **Migrations Replay** job. The guard runs in `fg-fast` (required Guard and fg-required).

| # | Criterion | Evidence |
|---|---|---|
| 1 | Canonical ownership documented and applied | Section above; guard; all three routes plus `_c6_sync_connector_record_failure` |
| 2 | Postgres, RLS enabled and forced, non-owner non-BYPASSRLS role | `test_connector_rls_role_is_restricted_and_rls_is_enforced`. It asserts the role's `rolsuper` and `rolbypassrls` are false, that it owns no touched table, `relrowsecurity` and `relforcerowsecurity` on 10 tables, the fail-closed policy, and a control (unbound and foreign contexts see 0 rows) |
| 3 | Cross-tenant negatives | `test_connector_records_are_isolated_across_tenants`: reads on 10 tables, an UPDATE (0 rows), an INSERT (RLS violation), and a route call against another tenant's engagement (404) |
| 4 | Transitions; compare-and-swap results checked | `test_connectors_complete_under_enforced_rls` (complete, `attempt_count` 1); `test_each_connector_failure_ends_terminal_with_one_audit` (×3); `test_lost_completion_transition_is_detected` (unsuccessful CAS); guard fixtures (ignored results) |
| 5 | `scan_result_id` matches the persisted result and the response | `test_connectors_complete_under_enforced_rls` |
| 6 | Rollback with no partial records; database errors still recorded | `test_connector_database_error_is_still_recorded`; `test_connector_failure_is_recorded_under_rls` |
| 7 | Audit emitted only with a committed transition | Tests 4 and 6; `test_completion_audit_failure_rolls_back_the_transition` (crash consistency) |
| 8 | Interrupted runs terminated deterministically, never re-run | `test_interrupted_run_is_terminated_not_rerun` (tenant-scoped); `test_recover_orphans_cannot_recover_under_enforced_rls` (evaluation) |
| 9 | Idempotency and duplicate execution | `test_repeated_runs_are_idempotent`; `test_live_run_rejects_a_duplicate`; **concurrent admission** (see below): `test_overlapping_admissions_admit_exactly_one`, `test_concurrent_burst_admits_exactly_one`, `test_admission_lock_is_bounded_and_released`, `test_admission_lock_is_tenant_scoped`, `test_expired_lease_supersedes_an_in_flight_run`; unique constraints on the record tables |
| 10 | Adjacent routes inventoried | See below (recorded, not changed) |
| 11 | Tests in required CI | Migrations Replay and fg-fast are both members of `CI Required` / fg-required; no CI configuration change |
| 12 | No weakening | One #926 simulation was refined: it now denies only database reloads, not in-session UPDATE synchronization. It still fails on the original route (mutation-checked) |
| 13 | Static guard with negative fixtures | `tests/tools/test_connector_tenant_context.py`: 6 prohibited patterns fail; valid patterns pass; a real-source mutation fails; the guard cannot pass when it covers nothing. On `main` before the fix it reports 13 violations |

**Mutation check:** against `main`'s pre-fix route and job-service code, the 9 behavioural PostgreSQL tests fail with the reproduced `ObjectDeletedError`. The 4 infrastructure controls pass, as they should: role and RLS, transaction scoping, pooled connections, and `recover_orphans`.

**Transaction and pooling semantics (clarifications):**
- `test_tenant_binding_is_transaction_scoped`: commit, rollback and an aborted transaction each clear the binding, and re-binding restores access.
- `test_pooled_connection_does_not_leak_tenant_context`: one physical connection, reused after tenant A, shows `''` or tenant B and never A's rows.

### Concurrent admission (Codex P2 review on #929)

**Pre-fix reproduction (head `793859a81`, real PostgreSQL, restricted role):** two requests for the same connector and engagement were held at a rendezvous immediately after `has_live_running()`. Both saw no live run, both created and committed a running job, and both executed. The second failed only on the risk-record unique constraint (500), after doing the work. A five-request burst with natural timing did not reproduce the race; the rendezvous test is the reproduction, the burst is a regression check.

**Fix:** `_c6_sync_connector_admission_lock` is the first statement of `_c6_sync_connector_preflight`. It locks the tenant's `fa_engagements` row `FOR UPDATE` (the repo's canonical row-lock pattern, as in `portal`, `stripe_webhooks` and `assessments`) with a transaction-local `lock_timeout` of 5 s. The lock is held from the stale-run and live-run checks through the initiation commit, then released, so it is never held during the connector's work. A request that waits sees the first request's committed running job and gets 409 `SCAN_ALREADY_RUNNING`. A request that cannot get the lock in time gets 409 `SCAN_ADMISSION_BUSY`, with nothing written. Under RLS the row is visible only to its own tenant, so another tenant can neither take nor wait on it. SQLite (local development only) has no row locks and is not serialized. Guard rule 4 enforces the lock-first preflight and preflight-before-job ordering.

| Property | Evidence |
|---|---|
| Exactly one of two overlapping requests is admitted; the other gets a controlled 409 | `test_overlapping_admissions_admit_exactly_one` (fails on `793859a81`: `[200, 500]`, two jobs) |
| Exactly one of five simultaneous requests is admitted | `test_concurrent_burst_admits_exactly_one` |
| Bounded wait, nothing written on contention; lock free during work and after success, 409 and failure | `test_admission_lock_is_bounded_and_released` |
| Tenant isolation: another tenant is not blocked and cannot lock the row | `test_admission_lock_is_tenant_scoped` |
| Lease: a run that outlives its lease is terminated by the next admission and is never also reported complete | `test_expired_lease_supersedes_an_in_flight_run` (outer run 409 `SCAN_JOB_SUPERSEDED`, `STALE_LEASE_EXPIRED` audited, one record) |

The concurrency tests passed 5 of 5 repeated runs locally.

### Failure-detail exposure

**Pre-fix (head `793859a81`):** the failure helper persisted `f"{type(exc).__name__}: {exc}"` as the job's `failure_reason` and the audit `rejection_reason`, and the routes logged `str(exc)`. For a database error that included the SQL text and bound parameters: `[SQL: SELECT CAST(%(m)s AS integer)] [parameters: {'m': '…'}]`.

**Fix:** `_c6_sync_connector_failure_reason` records only a stable code and the exception class (`CONNECTOR_FAILED: DataError`, `HTTP_409: SCAN_…`, `SCAN_JOB_SUPERSEDED`). The route and helper logs carry the job id and exception class only. `test_failure_details_never_persist_or_log` (×2: application and database exception) asserts that a marker in the exception text and bound parameter appears in neither the job record, any audit row (`row_to_json`), the captured log nor the response. It fails on `793859a81`. #926's `test_failed_run_marks_job_failed_with_audit` asserted the raw message was persisted; it now asserts the exact redacted code and the message's absence (stricter, not weaker).

**Recorded, not changed:** other scanners in `api/field_assessment.py` on `main` also persist `str(exc)[:2000]` as `failure_reason` (for example the background scan workers). They are outside this item's routes and need separate authorization.

### `recover_orphans` evaluation

| | |
|---|---|
| Restart recovery | Not provided. `recover_orphans` scans every tenant with no tenant bound, so under forced RLS and a non-BYPASSRLS role it sees nothing. It is also not invoked by application code. No startup recovery was added. |
| Stale-job termination | Provided per connector, tenant-scoped, at the next run (`terminate_stale_running`). It is terminal (`dead_letter`) and audited. |
| Safe retry | Not provided for these scanner types; they are not retryable. A new run is a new job, and the record tables' unique constraints make re-runs idempotent. |

### Adjacent routes (criterion 10: recorded, not changed)

The guard's re-bind rule was applied to all 122 routes in `api/field_assessment.py`. 25 do database work after a commit or rollback without re-binding:

`patch_engagement_route`, `transition_engagement_route`, `ingest_scan_result_route`, `register_document_analysis_route`, `update_observation_route`, `patch_finding_status_route`, `patch_finding_remediation_route`, `create_evidence_link_route`, `create_scan_authorization`, `activate_scan_authorization`, `revoke_scan_authorization`, `approve_customer_authorization`, `promote_engagement_route`, `create_or_get_questionnaire`, `register_artifact_route`, `upload_artifact_route`, `generate_verification_bundle_route`, `update_external_ai_risk_record`, `create_report_version_route`, `submit_report_version_for_review_route`, `approve_report_version_route`, `deliver_report_version_route`, `governed_delivery_route`, `governed_delivery_execute_route`, `supersede_report_version_route`.

These are static candidates; runtime impact has not been verified per route. Under enforced RLS (non-owner, or owner with FORCE, without BYPASSRLS), their post-commit work would fail closed in the same way.

**Inference (unverified, not claimed):** core routes such as `patch_engagement_route` and `transition_engagement_route` would visibly fail under an enforced role. That suggests production connects as a superuser or BYPASSRLS role, in which case FA-table RLS gives no database-level isolation there. Confirming it needs the production database role, which this workstream is not authorized to inspect.

**Recommendation:** a separate, authorized workstream, consisting of an audit of the production role plus the same re-bind repair and Postgres proof for these routes.

### Remaining risks

- Historical sibling-connector jobs left `queued` by the old code are not reconciled. They are production data, and changing them needs founder approval. They still count toward the `_c6_count_active_jobs` concurrency limits used by background scans.
- The production database role and its RLS enforcement are unverified.
- Lease expiry (300 s) during a very long synchronous run lets a concurrent run terminate the live job. The CAS check then rolls the first run back (409) rather than reporting a false completion. Proven by `test_expired_lease_supersedes_an_in_flight_run`. Synchronous connectors do not renew their lease.
- Admission serialization holds on PostgreSQL only; SQLite development databases are not serialized.
- Exception text persisted by other `field_assessment` scanners (recorded above).

