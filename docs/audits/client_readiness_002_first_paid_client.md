# CLIENT-READINESS-002 — First-Paid-Client Readiness Closure Audit

**Audit date:** 2026-09-29
**Audit branch:** `audit/client-readiness-002`
**Audited main SHA:** `dfccd3ff3f7d0ba3e216df1753680ea0e581d482`
**Audit type:** Read-only closure verification of #707 remediation + composition proof
**Auditor:** Claude Opus 4.7 (invoked by founder-operator)
**Scope:** post-#707 (through #726 governed delivery merge) — does FrostGate today accept and successfully complete a first paid Verified AI Governance Baseline engagement?

---

## 1. Executive Summary — Answer to the Direct Question

**What EXACTLY still prevents FrostGate from accepting and successfully completing its first paid Verified AI Governance Baseline customer?**

Three concrete blockers, in strict prerequisite order:

1. **No production trust anchor exists.** Migration 0191, service `governed_delivery_service.py`, and the qualification/QA authorities are all implemented in code, but every signature and every "trusted actor" the audit inventoried is either (a) local Vault dev mode, (b) a test-mode static token, or (c) unbound. `CUSTOMER-ZERO-TRUST-001` is `NEXT` and unclosed on `customer_one/roadmap_authority.yaml`. There is no HCP Vault Dedicated cluster, no populated `customer_zero_trust_evidence` manifest under `artifacts/`, and no ceremony evidence. Until this closes, all downstream signatures (qualification decisions, governed delivery authorizations, report signatures) are cryptographically inauthentic under the very trust model the roadmap requires.
2. **The Customer-Zero acceptance run has not been executed against the current SHA.** `CUSTOMER-ZERO-ACCEPT-001` is `BLOCKED` on the trust prerequisite. There is no on-current-SHA replayable proof of a complete evidence → deterministic truth → canonical QA → qualification → governed authorization chain. The `2026-08-06` restore drill was at migration 0172; current head is 0191. Nothing has been restored, replayed, or independently verified against the current schema, current authorities, or the newly-shipped `fa_governed_delivery_*` tables and `fa_qualification_*` tables. The FG_RESULT_TRUTH_GATE operational-acceptance parent objective remains OPEN.
3. **The "governed delivery" authority does not include transport.** PR #726 ships an authorization ledger, not a transport. `FaGovernedDeliveryAuthorization.outcome` is `AUTHORIZED`, never `DELIVERED`. The DB model's own docstring (line 1117) states: *"AUTHORIZED means the request was validated and authorized for transport. No transport has occurred."* There is no `fa_governed_delivery_attempts` table, no provider integration, no artifact-fingerprint receipt from an external transport, and no gate binding the existing PDF export route (`GET /engagements/{eid}/reports/{v}/export?format=pdf`) to a governed authorization. Any actor with `report.read` + `governance:read` scope in the correct tenant can pull the PDF today with no governed authorization required. That means the CR-707-004 root cause ("delivery is a state flag, not a customer receipt") is only *partially* remediated: a receipt object now exists, but the receipt still asserts authorization, not delivery.

**Bottom-line verdict:** `NOT_READY_BOUNDED_BLOCKERS`. FrostGate has cleared the code-authoring dimension of the CR-707-002 → CR-707-005 findings. It has not cleared the operational-proof dimension of any of them, and the transport dimension of CR-707-004 remains uncleared. There are no unbounded structural blockers.

---

## 2. Root Repository State

| Check | Value |
|---|---|
| Root repo path | `/home/jcosat/Projects/fg-core` |
| Root branch | `main` |
| Root HEAD | `dfccd3ff3f7d0ba3e216df1753680ea0e581d482` |
| Root `origin/main` | `dfccd3ff3f7d0ba3e216df1753680ea0e581d482` |
| Root working tree | clean |
| Audit branch (this worktree) | `audit/client-readiness-002` |
| Audit worktree path | `/home/jcosat/Projects/fg-core/.claude/worktrees/agent-a3e6080c1f486d338` |
| Audit worktree HEAD (pre-commit) | `dfccd3ff3f7d0ba3e216df1753680ea0e581d482` |

Preserved worktrees left untouched: `fg-core-customer-zero-accept-001`, `fg-core-customer-zero-trust-001`, `fg-core-customer-zero-trust-evidence`, `fg-core-customer-zero-vault-auth-repair`, plus historical branches.

### Roadmap authority checker results

| Work item / class | Checker output | Exit |
|---|---|---|
| `--work-item CUSTOMER-ZERO-TRUST-001` | AUTHORIZED (in next_sequence) | 0 |
| `--work-item CUSTOMER-ZERO-ACCEPT-001` | BLOCKED (blocked pending CUSTOMER-ZERO-TRUST-001) | 1 |
| `--work-item PROD-QUAL-001` | BLOCKED (not in next_sequence or deferred — fail-closed) | 1 |
| `--work-item GOV-DELIVERY-001` | BLOCKED (not in next_sequence or deferred — fail-closed) | 1 |
| `--work-class REPAIR` | AUTHORIZED | 0 |
| `--work-class NEXT` | invalid choice (only `REPAIR` is a valid `--work-class`) | 2 |

**Finding CR-002-A (governance drift, P2):** `PROD-QUAL-001` and `GOV-DELIVERY-001` are merged on `main` (PRs #724, #726) but the roadmap authority YAML at `customer_one/roadmap_authority.yaml` still returns BLOCKED for both work items. The `completed` list has not been updated with either. The roadmap document `docs/plans/customer_one_verified_governance_roadmap_20260910.md` (§4, §5) still describes both as blocked. This is a Level-2/Level-3 reconciliation defect: merged product truth (Level-3 ROADMAP.md) diverges from the sequencing authority (Level-2). The CODEX.md protocol mandates roadmap reconciliation on every PR that ships a feature.

---

## 3. #707 Findings Closure Matrix

Reconstructed from `docs/readiness/CLIENT_READINESS_001.md` (§25 findings inventory, §27 minimum safe revenue PR sequence).

| Finding | Title | #707 Severity | Claimed remediation | Current state | Evidence |
|---|---|---|---|---|---|
| CR-707-001 | Legacy public invitation acceptance trusts caller attribution | P1 | IDENTITY-ACCEPT-002 (PR #708) | **CLOSED** | Route retired; regression tests present; canonical `POST /identity/invitations/{token}/accept` retained. `docs/readiness/CLIENT_READINESS_001.md:106` records route as retired. |
| CR-707-002 | Native production qualification authority is absent | P1 | PROD-QUAL-001 (PR #724) | **PARTIAL** (code: CLOSED; ops-proof: OPEN) | Migration `0189_production_qualification_authority.sql` + `services/governance/report/qualification_authority.py` + `api/field_assessment.py` `/qualify/*` routes; 30 focused tests pass. But NO current-SHA replay proof; no qualified report has been produced on production data; three of the four required attestations (`PRODUCTION_DEPENDENCY_SECURITY`, `PRODUCTION_SCHEMA_AND_RLS`, `CANONICAL_ASSESSMENT_PROOF`, `DURABLE_EXECUTION_AND_RECOVERY`) have no independent operational proof produced against the current SHA. |
| CR-707-003 | Field Assessment Console loses named-human attribution | P1 | FA-ACTOR-001 (PRs #710, #711) | **CLOSED (code)** | 92 focused tests pass; PR #711 preserves delegated capabilities. Verified: `_actor_from_context`, `_actor_type_from_context` used across all material FA mutation routes in `api/field_assessment.py`. |
| CR-707-004 | Delivery is a state flag, not a customer receipt | P1 | GOV-DELIVERY-001 (PR #726) | **PARTIAL** — receipt object exists; transport does NOT | See §5. `FaGovernedDeliveryAuthorization` docstring `api/db_models_field_assessment.py:1117` explicitly states no transport occurs. No `fa_governed_delivery_attempts` table exists despite PR #726 body claiming it. |
| CR-707-005 | QA does not enforce separation of duties | P2 | REPORT-QA-001 (PR #713) | **PARTIAL** | `_enforce_report_qa_independence` at `api/field_assessment.py:13174` enforces `generated_by != reviewer_id` ONLY when `actor_ctx.auth_source != "api_key"`. Legacy API-key automation retains self-approval capability. No structural cross-actor role enforcement (compliance_reviewer ≠ qa_reviewer is enforced at the qualification layer, not at the report-QA layer). |
| CR-707-006 | Billable report lacks version-bound scope, methodology, limitations | P2 | Scoped into REPORT-QA-001 | **NOT_PROVEN** | No new report-schema audit was performed here; no evidence found that the tested report document now surfaces first-class approved scope + methodology + non-certification language. #707 explicitly said this belongs in REPORT-QA-001; nothing in the merged #713 diff summary suggests it was added. |
| CR-707-007 | Scan ingestion echoes raw evidence to browser | P2 | FA-EVIDENCE-RESPONSE-001 (proposed) | **OPEN** | No PR found addressing this in the range #708–#726. `raw_payload` echo remains in the scan-ingestion response model. |
| CR-707-008 | Uploaded evidence bytes default to local filesystem | P2 | EVIDENCE-STORAGE-001 (proposed) | **OPEN** | No durable object-storage provider integration merged. `FG_ARTIFACTS_DIR` remains the production knob; database backup does not include artifact bytes. First client must contractually exclude uploaded-file evidence or the CR-707-008 recovery gap is a delivery risk. |
| CR-707-009 | Provisioning recovery exposes direct SQL workaround | P2 | PROVISION-RECOVERY-001 (proposed) | **OPEN** | Not merged. `SLOT_STUCK` compensation still requires operator SQL. |
| CR-707-010 | Remediation authority is fragmented | P2 | FA-REMEDIATION-BRIDGE-001 (post-first-delivery) | **DEFERRED** | Acceptable per #707 §27; not a first-client blocker if scope excludes automated remediation lifecycle. |
| CR-707-011 | Cross-tenant export helper omits selected tenant context | P2 | Scoped into GOV-DELIVERY-001 | **NOT_PROVEN** | `apps/console/lib/fieldAssessmentApi.ts` `requestBlob()` was not audited here; PR #726 diff summary claims no console/BFF changes. Presumed OPEN — no counter-evidence found. |
| CR-707-012 | Some suites and fixtures do not compose hermetically | P3 | TEST-AUTHORITY-001 (post-launch) | **DEFERRED** | Not a first-client blocker. |

### Closure totals

- **CLOSED:** 2 (CR-707-001, CR-707-003)
- **PARTIAL:** 3 (CR-707-002, CR-707-004, CR-707-005)
- **OPEN:** 3 (CR-707-007, CR-707-008, CR-707-009)
- **NOT_PROVEN:** 2 (CR-707-006, CR-707-011)
- **DEFERRED:** 2 (CR-707-010, CR-707-012)
- **REGRESSED:** 0
- **SUPERSEDED:** 0

---

## 4. PR #708 through #726 Verification

| PR | Title | Purpose | Implementation location | Regression risk |
|---|---|---|---|---|
| #708 | fix(identity): retire legacy invitation acceptance authority | IDENTITY-ACCEPT-002 → closes CR-707-001 | Removed public route in `api/identity_administration/routes/invitations.py`; 6 regression tests | None observed |
| #710 | fix(field-assessment): enforce canonical human actor authority | FA-ACTOR-001 → closes CR-707-003 (round 1) | `apps/console/app/api/core/[...path]/route.ts` delegation-v3; Core `_actor_from_context` derives from `ActorContext.subject` | None observed |
| #711 | fix(auth): preserve delegated actor capabilities | FA-ACTOR-001 correction — delegated transport credentials retain capabilities | Auth layer; guards against unbound canonical membership | None observed |
| #712 | docs(roadmap): complete FA-ACTOR-001 and authorize REPORT-QA-001 | Governance ledger update | `customer_one/roadmap_authority.yaml`, `docs/plans/customer_one_verified_governance_roadmap_20260910.md` | None |
| #713 | fix(field-assessment): enforce canonical report QA authority | REPORT-QA-001 → partial CR-707-005 | Append-only `fa_report_qa_decisions`; SoD enforced only for non-API-key humans | Partial coverage of CR-707-005 |
| #714 | docs(roadmap): complete report QA and authorize production evidence | Governance ledger update | roadmap YAML | None |
| #715 | docs(roadmap): authorize Customer-Zero trust repair | Adds CUSTOMER-ZERO-TRUST-001 to `next_sequence` | roadmap YAML | None |
| #716 | feat(acceptance): add bounded Vault Transit trust adapter | Vault Transit adapter (application side) | `services/cgin/key_management/vault_transit.py` | None; adapter is prod-shaped but no HCP Vault yet |
| #717 | fix(acceptance): harden Customer-Zero Vault authentication | AppRole session hardening | `AppRoleAuthenticator` | None |
| #718 | Ops/customer zero trust evidence | Evidence validator tool | `tools/customer_zero_trust_evidence.py`, `services/cgin/key_management/trust_evidence.py` | None |
| #719 | Ops/customer zero trust evidence (extended) | Follow-up | same area | None |
| #720 | feat(trust-dev): local Vault development trust environment | Local dev lifecycle | `tools/trust/trust_dev_setup.sh`, `.env.trust-dev.example` | Explicitly labelled "DOES NOT produce CUSTOMER-ZERO-TRUST-001 completion evidence" |
| #721 | fix(tests): repair FA actor typing regression — strict mypy gate | Typing repair | test suite | None |
| #722 | fix(tests): align legacy suites with canonical authority semantics | Test alignment | legacy suites | None |
| #723 | feat(audit): AUDIT-AUTHORITY-001 — canonical portal identity audit authority | Portal identity audit ledger | `api/portal_identity_audit*.py` (deduced) | None observed |
| #724 | feat(qualification): PROD-QUAL-001 canonical production qualification authority | Closes CR-707-002 (code) | Migration 0189; ORM `FaProductionQualRequest`/`FaProductionAttestation`/`FaQualificationDecision`; permission `report.qualify` → compliance_reviewer only; `/qualify/*` routes; delivery gate binds `(tenant_id, report_id, report_version_id, report_fingerprint, decision=QUALIFIED)` | None observed |
| #725 | perf(tests): restore strict suite runtime 11h03m → 3h15m (PERF-GATES-001) | Strict test runtime repair | `gc.collect()` regression fix in test infra | None (perf-only) |
| #726 | feat(delivery): GOV-DELIVERY-001 canonical governed client delivery authority | Closes CR-707-004 (partial, code-only) | Migration 0191; ORM `FaGovernedDeliveryRequest`/`FaGovernedDeliveryAuthorization`; new POST `/engagements/{eid}/reports/{rid}/governed-delivery`; existing `deliver_report_version_route` emits governed records as side effect | See §5 for critical discrepancy: PR body claimed `fa_governed_delivery_attempts` table exists; it does not |

**Regression finding CR-002-B (P2):** PR #726 description says "**Migration 0191**: Two append-only, tenant-RLS-protected tables — `fa_governed_delivery_requests` and `fa_governed_delivery_attempts`" and describes "immutable outcome in fa_governed_delivery_attempts". Neither the migration nor the ORM has an `attempts` table. The actual second table is `fa_governed_delivery_authorizations`. This is a PR-description-to-implementation drift; the shipped implementation is authorization-only and cannot record transport attempts even structurally.

**Regression finding CR-002-C (P2):** PR #726 states "This item was previously blocked on PROD-QUAL-001 (#724); that gate is now cleared." The freeze law check still returns BLOCKED for both work items (§2). The Level-2 authority was never updated. The `roadmap_authority.yaml` `completed` list must include PROD-QUAL-001 (#724) and GOV-DELIVERY-001 (#726) or the Level-2 sequencing authority remains materially misleading.

**No PR in the #708–#726 range weakened an invariant.** Every append-only guard, RLS policy, and idempotency constraint remains in place.

---

## 5. Composition Audit — Commercial Execution Chain

Each boundary is classified as `PROVEN` (exact code and current-SHA evidence), `PARTIAL` (code exists, evidence gap), `NOT_PROVEN` (code exists, no operational proof), or `BLOCKED` (structural gap).

| # | Boundary | Classification | Exact evidence (file:line) |
|---|---|---|---|
| 1 | External customer boundary (contracting) | NOT_PROVEN | `docs/operators/FIRST_CLIENT_PLAYBOOK.md` §1–2 exists; no signed engagement executed |
| 2 | Tenant creation | PROVEN | `api/tenant_admin.py` provisioning route; 110 focused tests (#707 baseline) |
| 3 | Identity (canonical human) | PROVEN | Post-#708 legacy retirement + P1-01-PR2; only `POST /identity/invitations/{token}/accept` |
| 4 | Membership/capability | PROVEN | `services/tenant_users/*`; `require_permission`; PR #711 preserves delegated caps |
| 5 | Canonical actor authority (FA) | PROVEN | `api/field_assessment.py` `_actor_from_context`, `_actor_type_from_context` — post-FA-ACTOR-001 (#710/#711) |
| 6 | Engagement (create + tenant-bound) | PROVEN | `api/field_assessment.py:get_engagement`; tenant-bound; audit event emitted |
| 7 | Evidence ingestion | PARTIAL | Scan ingestion tenant-bound + evidence hash; CR-707-007 (raw echo) OPEN; CR-707-008 (durable storage) OPEN |
| 8 | Complete evidence state (FGA-027) | PROVEN | `services/governance/report/engine.py` complete evidence population; fingerprint; #693 merged |
| 9 | Deterministic findings | PROVEN | FGA-025/026/028; extensive component coverage |
| 10 | Epistemic determination | PROVEN | `services/governance/report/epistemic.py` |
| 11 | Result truth gate | PROVEN | `services/governance/report/result_truth_gate.py`; PASS achieved in #707 synthetic run |
| 12 | Report generation | PROVEN | `api/field_assessment.py` `generate_report_route`; signed manifest; version-bound |
| 13 | Report version/fingerprint | PROVEN | `FaReportVersion.result_truth_gate.result_fingerprint` embedded in stored `report_json` |
| 14 | QA authority (REPORT-QA-001) | PARTIAL | `api/field_assessment.py:13174` enforces different-person SoD for humans only; API-key path exempt (CR-707-005 partial); scope/methodology/limitations content NOT_PROVEN (CR-707-006) |
| 15 | Production qualification (PROD-QUAL-001) | PARTIAL (code CLOSED; ops NOT_PROVEN) | Migration 0189 + `services/governance/report/qualification_authority.py`; delivery gate binds full 5-tuple `(tenant_id, report_id, report_version_id, report_fingerprint, decision=QUALIFIED)` at `api/field_assessment.py:_require_production_qualified`. **No independent operational evidence exists that PRODUCTION_DEPENDENCY_SECURITY, PRODUCTION_SCHEMA_AND_RLS, CANONICAL_ASSESSMENT_PROOF, or DURABLE_EXECUTION_AND_RECOVERY have been produced against current SHA.** |
| 16 | Canonical recipient authority (GOV-DELIVERY-001) | PROVEN | `api/field_assessment.py:13677` `_resolve_delivery_recipient` — enforces `tenant_id + engagement_id` scoping for `portal_membership`, `portal_invitation`, `portal_grant` (dual path: legacy `PortalGrant` + canonical `credential_authority`), and `operator_direct` |
| 17 | Governed delivery authorization | PROVEN | `api/field_assessment.py:14058` `governed_delivery_route`; migration 0191; append-only guards; idempotency at DB level; fingerprint required (`api/field_assessment.py:14138` fails 422 on empty fingerprint) |
| 18 | Actual transport | **NOT_PROVEN** / **BLOCKED** | No transport tier exists. `services/governance/report/governed_delivery_service.py` is stateless validation only. No `fa_governed_delivery_attempts` table. The PDF export route `/engagements/{eid}/reports/{v}/export?format=pdf` at `api/field_assessment.py:9703` requires only `report.read` + `governance:read`; it does NOT check for a governed delivery authorization row. |
| 19 | Provider acceptance | NOT_REQUIRED_FOR_FIRST_CUSTOMER (if operator_direct chosen) — NOT_PROVEN otherwise | No provider integration for portal/email delivery of the report artifact |
| 20 | Delivery (customer received) | NOT_PROVEN | Delivered = state flag flip on `FaReportVersion.status`; no fingerprinted transfer acknowledgement |
| 21 | Receipt / customer access | PARTIAL | `GovernedDeliveryReceipt` at `api/field_assessment.py:14273` returns authorization record; NOT a transport acknowledgement |
| 22 | Audit / provenance | PROVEN | `emit_engagement_audit_event` with actor_type; append-only qualification + delivery ledgers; #723 AUDIT-AUTHORITY-001 |
| 23 | Backup / recovery | PARTIAL | `scripts/backup/fg_backup.sh` + Aug 6 2026 drill (`docs/governance/status/restore_drill_evidence_20260806.md`) — at migration 0172. **NO current-SHA restore drill against migration 0191 or the new authority tables.** Artifact bytes (CR-707-008) are not in the DB backup scope. |
| 24 | Remediation | PARTIAL / DEFERRED | Multiple parallel authorities; CR-707-010 acceptable for first client if manually operator-run |
| 25 | New evidence state | PARTIAL | FGA-027 complete evidence state can regenerate; no proven end-to-end reassessment cycle on current SHA |
| 26 | Independent verification | NOT_PROVEN | No customer-zero acceptance-branch run against current-SHA |
| 27 | Signed governance delta | NOT_PROVEN | Delta framework exists; no operational run |
| 28 | Reassessment | NOT_PROVEN | Depends on 25–27 |

**Composition summary:** Steps 1–17 exist as PROVEN or PARTIAL-with-code. Step 18 (actual transport) is the critical structural gap between "authorized to deliver" and "customer holds the report". Steps 15 and 23 are also structurally-implemented-but-operationally-unproven.

---

## 6. GOV-DELIVERY-001 Deep Audit

### A. Fingerprint Authority

**PROVEN.** `api/field_assessment.py:14137-14162` — `governed_delivery_route` requires a non-empty `report_fingerprint` extracted from `report_json['result_truth_gate']['result_fingerprint']`. Empty → 422 `MISSING_REPORT_FINGERPRINT`. Then `_load_qualification_decision` (line 13896) queries `FaQualificationDecision` with `report_fingerprint = <exact value>` and `decision = 'QUALIFIED'`. No fallback to version-only lookup. If any component of the 5-tuple mismatches, `qualification_decision_id` is empty and the route raises `PRODUCTION_QUALIFICATION_BLOCKED` (line 14158).

Both migrations (0189, 0190, 0191) enforce fingerprint columns as NOT NULL DEFAULT `''`, and the query requires exact match. **The version-only fallback the audit was asked to check for has been eliminated.**

### B. Recipient Authority

**PROVEN.** `_resolve_delivery_recipient` at line 13677 enforces:

- `operator_direct` — `recipient_id` MUST be null; authenticated operator with `report.generate` permission is the target
- `portal_grant` — dual-path lookup: legacy `PortalGrant` table (line 13729) + canonical `credential_authority.get_credential` (line 13741); status must be `active`; `metadata['engagement_id']` must match
- `portal_membership` — `portal_user_memberships` scoped by `tenant_id + engagement_id + active=true` (line 13765)
- `portal_invitation` — `portal_user_invitations` scoped by `tenant_id + engagement_id`, status not revoked/expired, `expires_at > NOW()` or null (line 13791)

All queries include `tenant_id AND engagement_id` — cross-tenant oracle attack fails closed with 403 `RECIPIENT_NOT_AUTHORIZED`.

### C. Lifecycle Truth

**Actual state machine in DB:**

```
REQUEST_CREATED     (FaGovernedDeliveryRequest row inserted)
    ↓
AUTHORIZATION_DECIDED   (FaGovernedDeliveryAuthorization row inserted; outcome = AUTHORIZED | REJECTED)
```

There is NO `TRANSPORT_ATTEMPTED`, `TRANSPORT_FAILED`, `TRANSPORT_ACCEPTED`, `DELIVERED`, or `RECEIPT_ACKNOWLEDGED` state. `FaGovernedDeliveryAuthorization.outcome` values are constrained to `{AUTHORIZED, REJECTED}` per `services/governance/report/governed_delivery_service.py:31-36` (`ALLOWED_OUTCOMES`). The docstring on `FaGovernedDeliveryAuthorization` at `api/db_models_field_assessment.py:1112-1120` states:

> outcome is AUTHORIZED or REJECTED; AUTHORIZED means the request was validated and authorized for transport. **No transport has occurred.**

**Question:** Can current FrostGate ever claim DELIVERED without evidence that an external delivery boundary was crossed?

**Answer:** Yes, at two levels:

1. `FaReportVersion.status` is set to `"delivered"` at `api/field_assessment.py:14007` (existing `deliver_report_version_route`) and at line 14228 (new `governed_delivery_route`) — this state transition is written before, and independently of, any actual transport.
2. `GovernedDeliveryReceipt` is returned to the client with `outcome=AUTHORIZED` and `schema_version=1.0` (line 14286) — the receipt confirms authorization but is semantically ambiguous to a naive reader who may equate a "receipt" with proof of delivery.

**Required answer per audit mission:** NO — FrostGate must not be able to claim DELIVERED without proof of external transport crossing. **Actual answer:** YES it currently can, at both the report-version status level and the receipt-object level.

### D. Idempotency

**Documented actual constraints:**

- Migration 0191:
  - `uq_fa_governed_delivery_requests_idempotency` — UNIQUE `(tenant_id, idempotency_key)` WHERE `idempotency_key != ''`
  - `uq_fa_governed_delivery_authorizations_request` — UNIQUE `(tenant_id, delivery_request_id)`
  - `uq_fa_governed_delivery_authorizations_active` — UNIQUE `(tenant_id, engagement_id, report_version_id, recipient_id, channel)` WHERE `outcome = 'AUTHORIZED'`
- Application-level guard: `api/field_assessment.py:14170-14225` — reuses existing request row for identical `(engagement_id, report_id, report_version_id, recipient_type, recipient_id, channel)`; returns existing receipt. Mismatch on any tuple element → 409 `IDEMPOTENCY_KEY_CONFLICT`.
- Idempotency key derivation: `services/governance/report/governed_delivery_service.py:51` — `SHA-256(tenant_id | engagement_id | report_version_id | recipient_id | channel)[:64]`. Caller may override.
- Append-only enforced by `append_only_guard()` PG trigger and SA event listeners (`api/db_models_field_assessment.py:1098-1181`).

Idempotency for the AUTHORIZATION operation is durable. Idempotency for TRANSPORT does not apply because there is no transport.

---

## 7. Real Transport Audit — TRANSPORT_PROVEN Question

**Verdict:** `TRANSPORT_NOT_PROVEN`.

Search results across `api/` and `services/`:

- No SMTP, SendGrid, SES, Twilio, S3 put_object, or blob upload code path invoked from any governed-delivery, report, or delivery-linked route.
- Portal invitation email uses `api/notifications/email.py` via Resend — but this delivers the *invitation*, not the report artifact.
- `download_url` references in `api/ui.py:875`, `api/ui_dashboards.py:127,894` are audit-packet download URLs for an audit UI, not report delivery.
- Report artifact bytes are served synchronously from two endpoints:
  - `api/field_assessment.py:9703` `GET /engagements/{eid}/reports/{version}/export?format=pdf` — requires `report.read` permission + `governance:read` scope. **Does NOT check for a governed delivery authorization row.**
  - `api/report_authority.py:332` `GET /reports/{report_id}/download/pdf` — separate report authority path.
- No presigned URL, no signed cookie, no fingerprinted external transfer receipt anywhere in the delivery chain.

**End-to-end transport question:** Can a governed authorization → exact artifact → exact recipient → transport invocation → provider evidence → durable receipt path be reconstructed on the current SHA?

- Governed authorization: YES (§6)
- Exact artifact: YES (report_version_id, report_fingerprint)
- Exact recipient: YES (recipient_type + recipient_id resolved with tenant+engagement)
- Transport invocation: **NO** — no code path invokes any transport
- Provider evidence: **NO** — no provider is called
- Durable receipt: PARTIAL — an authorization record is retained, but it does not evidence transport

### Smallest bounded first-customer transport requirement (design specification, not implementation)

For a first paid engagement using `operator_direct` recipient type:

1. Extend `FaGovernedDeliveryAuthorization` (or add `fa_governed_delivery_attempts` table matching PR #726's own description) with columns: `attempt_id`, `transport_type` (`operator_download`), `artifact_sha256`, `artifact_bytes_length`, `attempted_at`, `outcome` (`SUCCEEDED`/`FAILED`), `evidence_ref` (WORM audit chain reference).
2. Gate the artifact-serving endpoints on the existence of an AUTHORIZED row for the requesting subject.
3. On successful stream completion, insert an `attempts` row with SUCCEEDED + artifact SHA-256 tied to the exact bytes served.
4. `FaReportVersion.status = 'delivered'` transition happens ONLY after step 3.
5. Optional (recommended before first client): capture an operator-signed acknowledgement of receipt (Ed25519 over `(attempt_id, artifact_sha256, delivered_at)`).

This scope is bounded (~150-250 LOC + one migration + tests) and does not require any paid infrastructure for the `operator_direct` path.

---

## 8. Customer-Zero Trust Completion Audit

Reviewed: `services/cgin/key_management/vault_transit.py`, `services/cgin/key_management/trust_evidence.py`, `services/cgin/key_management/registry.py`, `tools/customer_zero_trust_evidence.py`, `tools/trust/trust_dev_setup.sh`, `.env.trust-dev.example`, `docs/deployment/customer_zero_trust_evidence.md`, `docs/deployment/customer_zero_vault_auth.md`.

The evidence contract at `docs/deployment/customer_zero_trust_evidence.md` explicitly lists what the manifest MUST contain. Mapping the 16 implied CUSTOMER-ZERO-TRUST-001 requirements to their current state:

| # | Requirement | Implementation | Operational proof | Classification |
|---|---|---|---|---|
| 1 | Three distinct managed trust roles | `services/cgin/key_management/vault_transit.py:205` `AppRoleAuthenticator` w/ role mapping | Local dev only (`trust_dev_setup.sh`) | LOCAL_ONLY |
| 2 | Stable key IDs (Ed25519) | Local dev creates `customer-zero-identity/acceptance/approval` Transit keys | No production keys | HCP_REQUIRED |
| 3 | Canonical identity assertion | `services/cgin/key_management/*` supports signing | No signed prod assertion | HCP_REQUIRED |
| 4 | Bounded acceptance entitlement issuance | Adapter shape exists | No prod entitlement issued | HCP_REQUIRED |
| 5 | Non-exportable approval signing | `deletion_allowed=false`, `type=ed25519` set in dev | No prod evidence | HCP_REQUIRED |
| 6 | Public-only verification | Evidence validator at `tools/customer_zero_trust_evidence.py` | No manifest produced | HCP_REQUIRED |
| 7 | Historical verification (rotation history) | `trust_evidence.py` schema requires rotation records | No rotation events on any prod key | HCP_REQUIRED |
| 8 | Durable provenance | `services/cgin/key_management/trust_evidence.py` fingerprints canonical manifest | Manifest not produced | HCP_REQUIRED |
| 9 | Operational fail-closed tests | `tests/test_vault_trust_dev_integration.py`, `tests/test_customer_zero_trust_evidence.py` | Green against dev Vault | LOCAL_ONLY |
| 10 | AppRole role_id distinctness | Enforced in `AppRoleAuthenticator.__init__` | No prod role IDs | HCP_REQUIRED |
| 11 | Bounded session (`token_ttl`, `token_max_ttl`) | Enforced at role config (`vault_approle.tf`) + adapter | No prod session | HCP_REQUIRED |
| 12 | HCP Vault cluster | Terraform in `frostgate-infra/hcp_cluster.tf` | Not applied | HCP_REQUIRED |
| 13 | CloudWatch audit stream | `frostgate-infra/aws_audit.tf` | Not applied | HCP_REQUIRED |
| 14 | Public anchor enrollment | `services/cgin/key_management/registry.py` supports anchor lookup | No anchors enrolled | HCP_REQUIRED |
| 15 | Failure/recovery evidence | Schema field required | No prod tests run | HCP_REQUIRED |
| 16 | Independent verification chain | `verify-complete` validator subcommand | Zero prod manifests | HCP_REQUIRED |

**Summary:** 0 PROVEN, 2 LOCAL_ONLY, 14 HCP_REQUIRED. No production trust evidence exists. This is the single largest unclosed blocker on the roadmap.

**External-repo verification:** `/home/jcosat/Projects/frostgate-infra` on `main` clean at `8121d24252dd1e7e3945424fcdacc5a320611fea`. Contains: `hcp_cluster.tf` (Vault Dedicated `standard_small`), `vault_transit.tf` (three keys, `prevent_destroy=true`), `vault_approle.tf` (three roles, distinct policies, `bind_secret_id=true`), `vault_policies.tf`, `aws_audit.tf` (CloudWatch), `terraform.tf` (HCP Terraform remote state, org `Frostgate`, workspace `frostgate-customer-zero`), `providers.tf` (no committed credentials). IaC is prod-shaped. NEVER APPLIED. No confirmation was performed here that HCP workspace binding is live; DO NOT run `terraform plan/apply` from this audit.

---

## 9. FrostGate-Infra Read-Only Review

- Path: `/home/jcosat/Projects/frostgate-infra`
- Branch: `main`
- HEAD: `8121d24252dd1e7e3945424fcdacc5a320611fea`
- Working tree: clean
- Provider locks: `hcp ~> 0.96`, `vault ~> 4.4`, `aws ~> 5.64`, `terraform ~> 1.16`
- HCP workspace binding: declared as `Frostgate/frostgate-customer-zero`; not verified live
- Secret-producing resources: none observed. `providers.tf` sources all credentials from env; `vault_approle.tf` explicitly notes SecretIDs are "SECRET — generated separately, transferred directly to Railway runtime secret storage, never passed through this Terraform configuration"
- Three-role separation: PROVEN in code (`vault_approle.tf` × 3, `vault_policies.tf` × 3, `vault_transit.tf` × 3 keys)
- Transit key definitions: Ed25519, `exportable=false`, `deletion_allowed=false`, `prevent_destroy` lifecycle
- AppRole separation: `token_no_default_policy=true`, `bind_secret_id=true`, distinct policy per role
- Remote state: HCP Terraform cloud block declared
- Cost-bearing resource comments: present ("COST-BEARING RESOURCES — DO NOT APPLY without operator approval")

No terraform apply performed. No HCP/AWS resources created. No credentials printed.

---

## 10. Security / Isolation / RLS

- 75 migrations reference `ENABLE ROW LEVEL SECURITY` or `CREATE POLICY` (grep count).
- Tenant isolation on the new authority tables:
  - `fa_qualification_decisions` — RLS enforced (migration 0189)
  - `fa_governed_delivery_requests` — RLS enforced (migration 0191, line 31)
  - `fa_governed_delivery_authorizations` — RLS enforced (migration 0191, line 76)
- Cross-tenant vectors in delivery routes: `_resolve_delivery_recipient` always filters by `tenant_id + engagement_id`; `_load_qualification_decision` filters by full 5-tuple; both fail closed on missing rows.
- Actor attribution: every governed-delivery ORM row includes `requested_by`/`authorized_by` and `actor_type`; these are derived from `ActorContext.subject` not caller input.
- Credential handling: SecretIDs never in Terraform state; runtime credentials via env only.
- Error oracle: 403 `RECIPIENT_NOT_AUTHORIZED` and 404 `ENGAGEMENT_NOT_FOUND` are indistinguishable-by-shape from absent-resource errors on the tested boundaries; cross-tenant probes cannot distinguish "does not exist" from "not authorized".
- `make fg-security`: **1239 passed, 1 skipped** in 592s. PASS.

---

## 11. Backup / Recovery Audit

- Backup tooling: `scripts/backup/fg_backup.sh` with `backup_config.sh` — supports encrypted pg_dump, offsite S3, drill mode against scratch container.
- Documented drill: `docs/governance/status/restore_drill_evidence_20260806.md` — 2026-08-06 at migration 0172. Row counts matched. Result PASS.
- Current migration head: **0191**. Delta since drill: 19 migrations added (including all Customer-Zero acceptance, PROD-QUAL, and GOV-DELIVERY authority tables).
- Artifact byte durability: local `FG_ARTIFACTS_DIR` default; not in pg_dump; no proven object-storage integration.
- Railway backup configuration: not audited here (Railway config out of scope for read-only audit).

**Verdict:** `PARTIAL`. Tooling exists and has been operationally proven ONCE at an outdated migration. Not proven against current SHA or against new authority tables. Artifact bytes are structurally NOT covered.

---

## 12. First-Customer Proof Coverage

| Category | Classification | Evidence |
|---|---|---|
| A. Truth demonstration (verified vs deficient AI governance) | IMPLEMENTED_NOT_PACKAGED | FGA-025 → FGA-028 result truth gate proven in test suites; no customer-facing "before/after" demonstration corpus |
| B. Tamper / authority demonstration (evidence substitution, spoofing, unauthorized approval, cross-tenant read) | IMPLEMENTED_NOT_PACKAGED | Extensive test coverage (`tests/security/`, `tests/test_cross_tenant_regression.py`); not packaged for customer consumption |
| C. Replay demonstration (deterministic identical outputs) | IMPLEMENTED_NOT_PACKAGED | FGA-027 complete evidence state + deterministic report engine; no customer-visible replay proof |
| D. Provenance demonstration (conclusion → finding → evidence → report version → qualification → authorization) | PARTIAL | Chain exists structurally; qualification and delivery-authorization layers are code-only (no live production run) |
| E. Governance delta (baseline → remediation → new evidence → verification → signed delta → reassessment) | NOT_PROVEN | Delta framework partially exists; no operational cycle completed on current SHA |

**Verdict:** No customer-visible proof pack has been produced. The FrostGate technical proof exists in test suites; a customer will not read pytest output. Packaging a Customer-Zero-Trust-authenticated demonstration corpus is a prerequisite for customer-consumable proof — and that packaging is itself blocked by Customer-Zero-Trust.

---

## 13. First-Client Operating Package

Documents found:

- Engagement scope definition: `docs/operators/FIRST_CLIENT_PLAYBOOK.md` §1 (customer profile), §3 (2-week assessment timeline). Adequate for design-partner engagement.
- Methodology: partial — six-domain scoring + Field Assessment components in `SYSTEM.md`; version-bound methodology statement in the report artifact: NOT_PROVEN (CR-707-006).
- Evidence request process: `docs/operators/first_client_prep.md` (referenced); `azure_ad_app_setup.md` (referenced).
- Customer data handling / retention / deletion: `docs/observability/retention_policy.md` (operational logs 90d, audit 7yr immutable, provenance 7yr immutable, security incident 3yr). `docs/operators/letters/3_data_handling_notice.md` present.
- Incident handling: `docs/operators/t8_incident_drill.md` present.
- Roles and responsibilities: playbook §2 checklist covers operator side; customer side implicit in `letters/`.
- Assessment limitations / non-certification language: CR-707-006 is `NOT_PROVEN` — no verified first-class scope/methodology/limitations section in the shipped report artifact.
- QA / release procedure: `docs/governance/audits/client_launch_readiness/LAUNCH_DEFINITION_OF_DONE.md` referenced by playbook §Preconditions.
- Remediation process: fragmented per CR-707-010; playbook does not depend on automated remediation lifecycle.
- Customer deliverables definition: playbook §3 timeline through Day 14 delivery; deliverable = "approved report + roadmap review"; but CR-707-006 leaves the artifact scope statement missing.

**Verdict:** Sufficient for a design-partner engagement with the operator managing the gaps by hand. Insufficient for a self-service or fully-productized engagement.

---

## 14. Test Execution

Executed on this audit branch at HEAD `dfccd3ff3f7d0ba3e216df1753680ea0e581d482`:

| Test suite | Result | Duration |
|---|---|---|
| `pytest tests/test_governed_delivery.py tests/test_production_qualification.py tests/test_report_delivery.py -q` | **75 passed** | 171s |
| `make fg-fast` | PASS (496 tests via existing runtime intelligence; runtime 387s vs 1140s warn budget) | 387s |
| `make fg-security` | **1239 passed, 1 skipped** | 592s |
| `make fg-contract` | PASS (contract lint + core OpenAPI + admin/core/artifacts diff clean) | (short) |

Strict `codex_gates.sh` was NOT run — this is a read-only audit and PERF-GATES-001 (#725) recently reduced strict runtime from 11h to 3h15m, but the audit mission explicitly instructs not to run strict without a specific reason. The most recent strict result on `main` (per merge commit history) is the #725 baseline: passing at 22,720 tests.

---

## 15. Blocker Classification

### P0 (cannot accept Client #1 safely)

**None.** FrostGate can safely accept a design-partner client under the operational constraints below. The remaining blockers are P1 (must close before delivering result to a paid client), not P0 (existential safety failure).

### P1 (must close before delivering result to first paid client)

1. **P1-CR002-TRUST — Customer-Zero-Trust-001 production ceremony**
   - Domain: cryptographic trust anchor
   - Exact problem: All application-layer signatures (qualification decisions, governed authorizations, report signatures) depend on trust roles whose production identities do not exist. Local Vault dev cannot serve as production evidence per `docs/deployment/customer_zero_trust_evidence.md`.
   - Evidence: `roadmap_authority.yaml` `active_objective.status = BLOCKED_PENDING_PREREQUISITE`; no manifest under `artifacts/customer_zero_trust_evidence*.json`; `frostgate-infra` HCP Terraform never applied.
   - Affected authority: All downstream signing; ability to make any cryptographic claim to a customer.
   - Customer consequence: Report signature verification against a public anchor fails because no public anchor exists.
   - Minimum closure: Provision HCP Vault Dedicated cluster; create three Transit keys; enroll three AppRoles; produce fully-populated evidence manifest passing `tools/customer_zero_trust_evidence.py verify-complete`; enroll public anchors; record rotation/failure tests; retain manifest under source control.
   - Requires paid infrastructure: **YES** (HCP Vault Dedicated Essentials/Small + AWS CloudWatch audit stream; ~$0.03/hr HCP + minimal CloudWatch = <$25/mo)
   - Estimated scope: 1–2 days of operator ceremony + evidence collection
   - Sequence: 1st

2. **P1-CR002-ACCEPT — Customer-Zero-Accept-001 current-SHA run**
   - Domain: operational acceptance
   - Exact problem: No replayable current-SHA end-to-end run producing the four required attestations tied to a specific report/version/fingerprint tuple.
   - Evidence: `roadmap_authority.yaml` `blocked` list contains CUSTOMER-ZERO-ACCEPT-001 pending trust prerequisite.
   - Affected authority: `PRODUCTION_DEPENDENCY_SECURITY`, `PRODUCTION_SCHEMA_AND_RLS`, `CANONICAL_ASSESSMENT_PROOF`, `DURABLE_EXECUTION_AND_RECOVERY` attestations
   - Customer consequence: `PROD-QUAL-001` cannot produce a QUALIFIED decision for any real customer report because no attestation-producing operator has valid trust credentials.
   - Minimum closure: Execute Customer-Zero acceptance corpus against current SHA post-trust; record all four attestations; produce QUALIFIED qualification decision; validate replay determinism.
   - Requires paid infrastructure: partial (needs trust closed first; then $0 operational work)
   - Estimated scope: 1 day of ceremony + validation
   - Sequence: 2nd

3. **P1-CR002-TRANSPORT — Governed delivery TRANSPORT completion**
   - Domain: artifact transport binding
   - Exact problem: `FaGovernedDeliveryAuthorization` is authorization-only. No `fa_governed_delivery_attempts` table exists despite PR #726's description. PDF export routes serve bytes without checking for an authorization record.
   - Evidence: `api/db_models_field_assessment.py:1117` docstring; missing table verified against `migrations/postgres/0191_governed_delivery_authority.sql`; `api/field_assessment.py:9703-9879` export route requires only `report.read` + `governance:read`.
   - Affected authority: GOV-DELIVERY-001 (partial)
   - Customer consequence: FrostGate cannot truthfully assert that "the customer received the report artifact" — only that "the operator was authorized to deliver".
   - Minimum closure: Add `fa_governed_delivery_attempts` table with `artifact_sha256`, `attempted_at`, `outcome`, `evidence_ref`; gate the artifact-bytes-serving endpoints on an AUTHORIZED delivery row for the requesting subject; write attempts row on successful stream with SHA-256 of served bytes; move `FaReportVersion.status = delivered` after attempt SUCCEEDED.
   - Requires paid infrastructure: NO — `operator_direct` transport type completes this without external services
   - Estimated scope: ~200 LOC + 1 migration + ~15 tests; 4–8 hours
   - Sequence: 3rd (unblocks CR-707-004 closure)

### P2 (controlled workaround acceptable for first client)

4. **P2-CR002-QA-SoD — Report QA API-key self-approval exemption**
   - `_enforce_report_qa_independence` at `api/field_assessment.py:13174` exempts `auth_source == "api_key"` from the different-person rule. For a first paid client, workaround: require the operator to review-approve as a distinct verified human, not via the API-key path. Document this in the playbook.

5. **P2-CR002-SCOPE — Report scope/methodology/limitations content**
   - CR-707-006 NOT_PROVEN. First-client workaround: the operator manually appends a scope/methodology/limitations page as a fixed cover addendum to the exported PDF, retained alongside the report artifact.

6. **P2-CR002-ROADMAP-DRIFT — Roadmap authority reconciliation**
   - PROD-QUAL-001 (#724) and GOV-DELIVERY-001 (#726) are merged but not reflected in `customer_one/roadmap_authority.yaml` `completed` list. Workaround: no immediate operational impact; correct in next roadmap-maintenance PR.

7. **P2-CR002-BACKUP — Current-SHA restore drill missing**
   - Drill evidence stale (2026-08-06, migration 0172). First-client workaround: run one restore drill against migration 0191 before first client's paper is signed; retain evidence file `docs/governance/status/restore_drill_evidence_YYYYMMDD.md`. No paid infrastructure required.

8. **P2-CR002-EVIDENCE-ECHO — Raw payload echo (CR-707-007)**
   - First-client workaround: scoped connectors only; do NOT enable console echo of raw scan payloads. Operator suppresses this in the delivered PDF.

9. **P2-CR002-ARTIFACT-STORAGE — CR-707-008 durable artifact storage**
   - First-client workaround: contractually exclude file-upload evidence; use only DB-persisted scan and questionnaire evidence. Explicitly reference in the engagement scope statement.

10. **P2-CR002-EXPORT-TENANT — CR-707-011 cross-tenant export helper**
    - First-client workaround: Platform Admin exports the report only from the customer's own tenant context, not from operator context. Document in playbook.

### P3 (post-first-client)

11. **P3-CR002-PROVISION-SQL — CR-707-009 SLOT_STUCK SQL workaround** (playbook acknowledges as engineering step)
12. **P3-CR002-REMEDIATION-BRIDGE — CR-707-010** (defer per #707 §27)
13. **P3-CR002-TEST-HERMETICITY — CR-707-012** (defer per #707 §27)

**Totals:** P0=0, P1=3, P2=7, P3=3.

---

## 16. Remaining Critical Path to First Paid Client

```
1. CUSTOMER-ZERO-TRUST-001 closure   ── HCP Vault ceremony + evidence manifest
        ↓
2. CUSTOMER-ZERO-ACCEPT-001 execution ── current-SHA run + 4 attestations + QUALIFIED decision
        ↓
3. GOV-DELIVERY-TRANSPORT closure     ── attempts table + artifact-bytes gate + SUCCEEDED transition
        ↓
4. P2 workarounds documented in playbook, or short-repair PRs merged
        ↓
5. Restore drill against migration 0191 (evidence file)
        ↓
6. L14 commercial execution (design partner scheduled → invoice → payment → portal access → roadmap review)
        ↓
   CUSTOMER-ONE VALIDATED → FIRST PAID CUSTOMER
```

### $0 remaining engineering work

- P1-CR002-TRANSPORT (3rd critical-path step): ~4–8h engineering; ~200 LOC + 1 migration + tests; zero infrastructure cost
- P2-CR002-QA-SoD tightening (optional): enforce different-person rule for API-key path too, if a compliance_reviewer role can be minted for the first client
- P2-CR002-SCOPE report addendum: manual PDF cover for first client; codified in playbook
- P2-CR002-ROADMAP-DRIFT: single YAML+MD PR to reconcile roadmap authority
- P2-CR002-BACKUP: run drill; retain evidence file
- P2-CR002-EVIDENCE-ECHO / EXPORT-TENANT: documented workaround in playbook

### Paid-infrastructure requirements

- **HCP Vault Dedicated Essentials/Small** — approximately $0.03/hr (~$22/mo) plus HVN + minimal CloudWatch charges
- **AWS CloudWatch audit stream** — <$5/mo at bounded log volume
- **Total incremental cost to close P1-CR002-TRUST:** <$30/mo recurring + one-time ceremony cost
- **Railway (production DB):** already provisioned (per audit references); not audited here
- **Stripe:** ready for L14 (documented as an L14 task, not a blocker)

### Operational ceremony (non-code)

- Vault ceremony: provision cluster, mint three AppRoles, create three keys, enroll public anchors, run rotation/failure tests, produce signed manifest
- Customer-Zero acceptance run: execute synthetic corpus, capture four attestations, validate replay determinism
- Restore drill: run `fg_backup.sh drill` post-migration-0191; retain artifact

### Customer-facing packaging

- Scope statement addendum (workaround for CR-707-006)
- Engagement scope contractual exclusion of file-upload evidence (workaround for CR-707-008)
- First-client playbook already contains most operational structure

### Post-launch work

- CR-707-006 permanent report schema fix
- CR-707-007 raw echo removal
- CR-707-008 durable artifact storage
- CR-707-009 provisioning recovery API
- CR-707-010 remediation bridge
- CR-707-011 export helper tenant context fix
- CR-707-012 test hermeticity

---

## 17. Readiness Verdict

**`NOT_READY_BOUNDED_BLOCKERS`**

FrostGate has no P0 blockers and no structural (architectural) blockers. The three P1 items are all bounded — trust ceremony (operational), acceptance run (operational), and transport completion (~1 day of engineering). Total time-to-ready is estimated 3–5 working days assuming HCP Vault provisioning completes without delay. No customer contract should be executed for delivery until the three P1 items close; contracting itself may proceed under the L14 commercial track if the founder-operator wishes.

**Explicit statement:** No production behavior was changed by this audit. No production secrets were read or written. No infrastructure was applied. No preserved worktree was touched. No existing test, invariant, authority, or gate was weakened. The only writes were this audit document at `docs/audits/client_readiness_002_first_paid_client.md` and (if required by policy) an entry in `docs/ai/PR_FIX_LOG.md`.

---

## Appendix A — Verification Commands Executed

```bash
# Repo state
git status                     # main clean at dfccd3ff
git rev-parse origin/main      # dfccd3ff3f7d0ba3e216df1753680ea0e581d482
git fetch origin --prune       # clean

# Roadmap authority (records for evidence)
python tools/ci/check_customer_one_roadmap.py --work-item CUSTOMER-ZERO-TRUST-001  # AUTHORIZED
python tools/ci/check_customer_one_roadmap.py --work-item CUSTOMER-ZERO-ACCEPT-001 # BLOCKED
python tools/ci/check_customer_one_roadmap.py --work-item PROD-QUAL-001            # BLOCKED (governance drift)
python tools/ci/check_customer_one_roadmap.py --work-item GOV-DELIVERY-001         # BLOCKED (governance drift)
python tools/ci/check_customer_one_roadmap.py --work-class REPAIR                  # AUTHORIZED

# Focused tests
.venv/bin/python -m pytest tests/test_governed_delivery.py \
                          tests/test_production_qualification.py \
                          tests/test_report_delivery.py -q
# → 75 passed in 171.82s

# Standard gates
make fg-fast     # PASS, 387s (well under 1140s warn budget)
make fg-security # 1239 passed, 1 skipped, 592s
make fg-contract # PASS all sub-checks
```

## Appendix B — Files Examined (partial list)

- Migrations: `0189`, `0190`, `0191`
- Services: `services/governance/report/governed_delivery_service.py`, `services/governance/report/qualification_authority.py`, `services/cgin/key_management/vault_transit.py`, `services/cgin/key_management/trust_evidence.py`
- API: `api/field_assessment.py:9620-14350` (report generation, export, QA, qualification, delivery routes), `api/db_models_field_assessment.py:1043-1181` (governed delivery ORM), `api/notifications/email.py`, `api/portal.py`, `api/report_authority.py`
- Docs: `SYSTEM.md`, `CLAUDE.md`, `CODEX.md`, `docs/plans/customer_one_verified_governance_roadmap_20260910.md`, `customer_one/roadmap_authority.yaml`, `docs/readiness/CLIENT_READINESS_001.md`, `docs/deployment/customer_zero_trust_evidence.md`, `docs/deployment/customer_zero_vault_auth.md`, `docs/operators/FIRST_CLIENT_PLAYBOOK.md`, `docs/observability/retention_policy.md`, `docs/governance/status/restore_drill_evidence_20260806.md`
- Tests: `tests/test_governed_delivery.py`, `tests/test_production_qualification.py`, `tests/test_report_delivery.py`, `tests/test_customer_zero_trust_evidence.py`
- Infra: `/home/jcosat/Projects/frostgate-infra/*.tf` (read-only)
