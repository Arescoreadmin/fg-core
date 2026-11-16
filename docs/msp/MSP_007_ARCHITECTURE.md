# MSP-007 architecture

MSP-007 lets a customer share one exact, released assessment report with an approved MSP for a bounded time, and lets that MSP verify and download it. MSP-007 is not a standalone authority. It is one record and one router on top of existing authorities (see `MSP_007_AUTHORITY_AUDIT.md`).

## Components

| Component | File | Role |
|---|---|---|
| Share record | `migrations/postgres/0209_msp_007_report_shares.sql`, `api/db_models_msp.py` `MspReportShare` | One customer decision: MSP, relationship, report id, version, fingerprint, expiry, status |
| Router | `api/msp_reporting.py` (prefix `/admin/msp`) | Shareable-report view, share lifecycle, MSP verify and download, history |
| Verification | `api/field_assessment.py` `report_integrity` | Shared with the canonical verify route |
| Console, customer | `apps/console/components/msp/ReportSharing.tsx` on `/partners` | Report index, share, answer requests, revoke, access history |
| Console, MSP | `apps/console/components/msp/SharedReports.tsx` on `/msp` | Per-customer shared-report index, verify, download, ask for a report |
| Console helpers | `apps/console/lib/mspReporting.js`, `lib/mspApi.ts` | Presentation, validation and the API client |

## Routes

| Method and path | Caller | Purpose |
|---|---|---|
| `GET /admin/msp/reports/shareable` | Customer `tenant_admin` | Own report versions with lifecycle facts, integrity and eligibility |
| `GET /admin/msp/report-shares?party=customer\|msp` | Either party | Own shares. The MSP may filter by customer. MSP rows carry live access state and blockers |
| `POST /admin/msp/report-shares` | Customer `tenant_admin` | Share one exact released version with one MSP |
| `POST /admin/msp/report-shares/requests` | MSP member, entitled | Ask for the report of an engagement the MSP initiated (MSP-003 grant) |
| `POST /admin/msp/report-shares/{id}/approve` | Customer `tenant_admin` | Answer a request with one exact released version |
| `POST /admin/msp/report-shares/{id}/reject` | Customer `tenant_admin` | Decline a request |
| `POST /admin/msp/report-shares/{id}/revoke` | Customer `tenant_admin` | End an active or expired share |
| `POST /admin/msp/report-shares/{id}/withdraw` | MSP member | Withdraw its own pending request |
| `GET /admin/msp/report-shares/{id}/verify` | MSP member, entitled | Lifecycle, integrity (re-verified now), provenance, evidence references. Audited |
| `GET /admin/msp/report-shares/{id}/download` | MSP member, entitled | The canonical report document. Audited |
| `GET /admin/msp/report-shares/{id}/events` | Either party | This share's history, from the caller's own chain |

Every route:

- binds the caller's tenant from the credential (`_caller_tenant_from_auth`) and never from a parameter;
- runs the MSP-002 console delegation binder.

## Share lifecycle

```
customer shares directly          ──────────────► active ──► revoked
MSP requests (MSP-003 grant) ─► requested ─► active ──► revoked
                                   ├─► rejected (customer)
                                   └─► withdrawn (MSP)
active past expires_at ⇒ "expired" (derived; revoke still allowed)
```

- **Concurrency:** every transition is a compare-and-set on `(id, status, version)`, and decisions carry `expected_version`.
- **Rows:** rows are never deleted.
- **Database invariants:**
  - An active or revoked share is bound to `report_id`, `report_version` and `manifest_hash`, with a decision and an expiry later than the decision.
  - At most one active share exists per (customer, MSP, report), through a partial unique index.
  - An MSP-origin row names its grant.

## MSP read path

`evaluate_msp_access` re-derives access on every call. The checks run in this order:

1. **MSP actor:** a bound membership in an active MSP (`resolve_msp_membership`). If this fails, the call returns 403 before anything about the share is disclosed.
2. **Share status:** a requested, rejected, withdrawn, revoked or expired share returns its blocker.
3. **Relationship:** the relationship must be active and delegate `report.read` to this member's role (`resolve_actor_access`). It must also be the same relationship the share was made under.
4. **Customer tenant:** the customer tenant must be active.
5. **Report record:** the report row must still exist in the customer tenant, with the same version and fingerprint.
6. **Report checks:** all through `report_release_view` → `_authoritative_report_state`, `report_integrity` and the provenance trust inputs:
   - the report is FINAL;
   - its content fingerprint verifies;
   - its signature has not failed;
   - its evidence chain has not failed.
7. **Download only:** `enforce_report_export` and the 10 MiB size bound.

The `msp.multi_tenant` entitlement is a route dependency on the MSP request, verify and download routes.

## Rollback

- **Code revert:** reverting the PR removes the router, the Console components and the event types. `report_integrity` is a pure extraction, so the verify route behaves the same either way.
- **Migration 0209:** additive only. Leaving the table in place after a code revert is harmless, because nothing else reads it.
- **Manual drop:** dropping it would be a separate, manual step:

  ```sql
  DROP TABLE msp_report_shares;
  ```

  Do this only after exporting the rows if their history matters. The identity-chain events remain either way.

## Not in MSP-007

The following are not included:

- PDF export for MSPs;
- report content diffs;
- notifications;
- client-portal (`apps/portal`) changes;
- presigned URLs;
- billing for sharing;
- MSP QA or delivery authority;
- bulk export.

See `MSP_007_COMMERCIAL_READINESS.md` for the deferred list.
