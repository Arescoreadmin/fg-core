# MSP-007 canonical authority audit

This audit was done before implementation, against `main` at `408e5565`. For each MSP-007 requirement it records:

- the canonical owner of that requirement;
- what MSP-007 reuses from it;
- the classification (**REUSE**, **EXTEND**, **REPAIR** or **DEFER**);
- the residual risk.

MSP-007 adds one record type, the share, and changes no existing authority's behavior.

## Summary

| Area | Canonical authority | Classification |
|---|---|---|
| Report store | `governance_reports` (`GovernanceReportRecord`, `services/governance/report/versioning.py`) | REUSE |
| Release decision (DRAFT / FINAL) | `api.field_assessment._authoritative_report_state` → `services/field_assessment/report_proof.evaluate_report_state` | REUSE |
| QA approval and rejection | `qa_approve_report_route`, `qa_reject_report_route`, `governance_qa_status` (append-only QA log, independent human) | REUSE |
| Production qualification | `fa_qualification_decisions` (`QUALIFIED`), read inside the release decision | REUSE |
| Result Truth Gate and provenance | `evaluate_engagement_provenance` (assessment assurance) | REUSE |
| Report verification | `verify_engagement_report_route` | **EXTEND** (logic extracted into `report_integrity`, now shared) |
| Export trust gate | `enforce_report_export` (`trust_enforcement_adapter`) | REUSE |
| Governed delivery | GOV-DELIVERY-001 `fa_governed_delivery_authorizations` / `_attempts` | REUSE (read only) |
| MSP relationship and read delegation | MSP-001 `resolve_actor_access`, `MSP_DELEGABLE_PERMISSIONS` | REUSE (ceiling unchanged) |
| MSP designation and membership | MSP-001 `msp_organization_active`, `resolve_msp_membership` | REUSE |
| MSP entitlement | `require_capability("msp.multi_tenant")` | REUSE |
| Customer administrator | TENANT-ADMIN-001 `check_tenant_admin_authority` | REUSE |
| MSP-initiated engagements | MSP-003 `msp_assessment_grants` | REUSE (a request may cite one; it grants nothing) |
| Billing | MSP-006 (delivery producer only) | REUSE (untouched) |
| Identity audit chains | `emit_msp_audit` → `emit_identity_audit_event` | **EXTEND** (9 event types, 9 detail keys) |
| Engagement audit trail | `emit_engagement_audit_event` | REUSE |
| Per-report MSP authorization | none existed | **NEW** table `msp_report_shares` (migration 0209) |
| Customer client portal (`apps/portal`) | portal identity and access grants | DEFER (unchanged; see below) |
| Presigned or bearer download URLs | none for reports | DEFER (not introduced) |
| PDF export for MSPs | `export_engagement_report_route` (PDF via reportlab) | DEFER |

## Detail

### Report store and versions

- **Existing:** every generated report is a row in `governance_reports`. The row carries:
  - its own `id`, a per-engagement `version`, `manifest_hash` (SHA-256 of the canonical `report_json`) and `section_hashes`;
  - a legacy Ed25519 `signature`;
  - TRUST-BINDING-001 `trust_*` columns.

  RLS uses the tenant.
- **API and permission:** `GET /field-assessment/engagements/{id}/reports[/{version}]` requires `report.read` and `governance:read`, and resolves the tenant from the caller.
- **Reuse:** MSP-007 never copies a report. A share stores only `report_id`, `report_version` and `manifest_hash`. Downloads read the row under the customer's RLS context.
- **Missing proof:** none for MSP-007.

### Release decision

- **Existing:** `_authoritative_report_state` is the single source of the DRAFT / REJECTED / FINAL decision. FINAL requires all of:
  - independent human QA (append-only QA log);
  - no QA rejection;
  - a `QUALIFIED` production-qualification decision;
  - a clean signed proof;
  - unchanged evidence;
  - a clean canonical provenance decision.

  No request parameter affects it.
- **Reuse:** a report is shareable, and readable through a share, only while this function returns `FINAL`. It is called on every share creation, verification and download, so nothing is cached.
- **Fail closed:** any state other than FINAL is blocker `REPORT_NOT_RELEASED`. That covers draft, synthetic, rejected, superseded, withdrawn and unknown. Report types with no release predicate never reach FINAL, so they cannot be shared.

### Lifecycle facts kept separate

The shareable-report view returns separate booleans, each read from its canonical owner:

| Fact | Source |
|---|---|
| `exists` | The record exists |
| `qa_approved` | `qa_approved_by` |
| `independent_qa` | The QA log |
| `production_qualified` | The release decision |
| `released` | `state == FINAL` |
| `delivery_authorized` | A GOV-DELIVERY-001 authorization with outcome `AUTHORIZED` for the same fingerprint |
| `delivered` | A transport attempt with outcome `SUCCEEDED` for the same fingerprint |

The view also returns `share_eligible`, an active share's existence, and its access state. None of these is collapsed into a single readiness flag, and there is no score.

### Verification

- **Existing:** `POST /field-assessment/engagements/{id}/reports/{version}/verify` checks the report in two ways:
  - It re-derives the manifest fingerprint (PROVENANCE-INTEGRITY-001).
  - It verifies the Vault Transit trust binding, or the legacy Ed25519 signature.
- **Extend:** that logic moved, unchanged, into `report_integrity(record, engagement_id=...)` in `api/field_assessment.py`. The verify route now calls it and returns the same responses, including the 503 when the legacy signing key is missing. MSP-007 calls the same function, so there is one verification engine.
  - **Regression:** the 30 test files that exercise verification, signing, trust binding and provenance integrity pass (1,149 passed, 7 skipped).
- **Vocabulary:** only outcomes the canonical checks produce:
  - `HASH_VERIFIED` (content matches its fingerprint);
  - `SIGNATURE_VERIFIED`;
  - `AUDIT_CHAIN_VERIFIED` (the provenance trust input `chain_valid`);
  - `VERIFICATION_UNAVAILABLE` (unsigned, key missing, or not checked);
  - `VERIFICATION_FAILED`.
- **Not used:** `SOURCE_UNVERIFIED` is not a separate outcome. Source authenticity is reported as the provenance summary's `source_authenticated` value, unchanged.
- **Not claimed:** no notarization, external certification or third-party attestation. A hash is never labelled a signature.

### Download

- **Existing:** `GET .../reports/{version}/export` serves JSON or PDF after the trust gate and the draft-access policy.
- **Reuse:** the MSP download serves the canonical `report_json`, plus its fingerprint, signature and integrity results, as one JSON document. The steps are:
  1. integrity verification (`report_integrity`);
  2. the same trust gate (`enforce_report_export`);
  3. a size bound (10 MiB);
  4. an engagement audit event (`report.content_accessed`, channel `msp_share:download`) and events on both identity chains.
- **No credential is issued.** There is no presigned URL, storage token or redirect. The bytes are returned by the authorized call, so nothing outlives it.
- **Defer:** PDF export for MSPs. The PDF renderer is bound to the customer export route's access policy and disclosure block, so reusing it needs a separate review.

### MSP authority

- **Existing:** MSP-001 `resolve_actor_access(required=...)` takes the intersection of:
  - a bound MSP membership in an active MSP;
  - the membership role's permissions;
  - the customer-approved capabilities;
  - the read-only ceiling `MSP_DELEGABLE_PERMISSIONS`.

  `report.read` is in the ceiling, but MSP-001 and MSP-002 expose no report route.
- **Decision:** no new permission. A share is read under the existing `report.read` delegation **and** an exact, customer-approved, per-report share, so neither alone is enough.
  - The customer cannot share with a relationship that does not delegate `report.read`.
  - Removing that delegation blocks every share at once.
- **Not sufficient alone:**
  - the relationship;
  - an MSP-003 assessment grant;
  - an MSP-006 payer assignment;
  - knowing a report id or hash.

  Tests t03, t04, t05 and t32 cover these.

### Customer administrator

TENANT-ADMIN-001 `check_tenant_admin_authority` checks a DB-canonical, bound, active `tenant_admin` of the caller's own tenant. Separation of duties is reused from MSP-001 and MSP-003:

- The approver holds no MSP membership (`principal_is_member_of`).
- The approver of an MSP request is not its requester.

### Audit

- **Extend:** 9 identity audit event types (`tenant.msp.report_*`) and 9 detail keys in the `safe_keys` allowlist. The keys are identifiers, fingerprints, decisions and blocker codes only.
- **Reuse:** `emit_engagement_audit_event` in the customer's engagement trail, for downloads and integrity failures.
- **Relationship history:** share events carry `relationship_id`, so they also appear in MSP-002's relationship history.

### Rejected duplications

The following were considered and rejected:

- A second report store or report copy for MSPs.
- A separate evidence index: the report's own evidence references are listed, as identifiers only.
- A second verification engine: verification was extracted and shared instead.
- A second Portal or Portal identity.
- A second audit ledger.
- A new billing record for sharing: MSP-006 delivery stays the only charge (t38).
- Widening `MSP_DELEGABLE_PERMISSIONS`.

### Deferred, with reasons

- **Client portal (`apps/portal`).** The approving authority is the customer's `tenant_admin`, which is a console identity. Portal users are engagement-scoped client roles and are not organization administrators. Sharing therefore lives on the console's `/partners` page. The client portal and its access grants are unchanged.
- **Presigned URLs.** None exist for reports, and none are introduced, so there is no bearer-URL revocation gap.
- **Report version comparison.** Partners see every version that was shared, with its version number and fingerprint. A content diff needs a canonical diff authority, and none exists.
- **Expiration events.** Expiry is enforced on every read and is recorded as a refused read (`SHARE_EXPIRED`). No scheduler writes an event at the moment of expiry.
