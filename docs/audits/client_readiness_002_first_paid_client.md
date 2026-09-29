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

Four concrete blockers, in strict prerequisite order (two are split from what a prior draft counted as one):

1. **No production trust anchor exists, AND the qualification/signing/delivery workflow is not wired to the Vault trust adapter even when it does.** Two distinct sub-blockers must be tracked separately, because closing one does not close the other:
   - **(1a) CUSTOMER-ZERO-TRUST-001 — Trust infrastructure not provisioned.** No HCP Vault Dedicated cluster exists; no populated `customer_zero_trust_evidence` manifest under `artifacts/` (searched — none present); `frostgate-infra` HCP Terraform never applied. The ceremony produces the manifest but nothing more.
   - **(1b) TRUST-BINDING-001 (NEW — extracted from CR-002-D) — Signing/qualification/delivery not bound to the Vault trust root.** Independent code audit at this SHA confirms: `services/governance/report/signing.py:30,88-98` signs reports directly with the environment variable `FG_REPORT_SIGNING_KEY` (Ed25519 seed loaded from `os.getenv`); the Vault Transit adapter at `services/cgin/key_management/vault_transit.py` is not referenced by `signing.py`, `qualification_authority.py`, or `governed_delivery_service.py`. `FaQualificationDecision` (`api/db_models_field_assessment.py:977-1026`), `FaProductionAttestation`, and `FaGovernedDeliveryAuthorization` (`api/db_models_field_assessment.py:1112-1166`) have NO signature, `signed_by`, or `signing_key_id` columns. `qualify_report_attest_route` (`api/field_assessment.py:8053-8121`) records `attested=body.attested` as a boolean from any actor holding the `report.qualify` permission — no Vault Transit sign/verify call is invoked. Therefore even after CUSTOMER-ZERO-TRUST-001 closes, report signatures will continue to use `FG_REPORT_SIGNING_KEY`, and qualification decisions will remain unsigned boolean records unless a separate binding work item cuts those signing paths over to the Vault Transit adapter.
   - **What the ceremony PROVES:** production Ed25519 signing capability exists at HCP Vault; three roles are enrolled; public anchors are enrolled for external verification; the manifest is durable under source control.
   - **What the ceremony does NOT AUTOMATICALLY BIND:** report signing (still `FG_REPORT_SIGNING_KEY`); qualification decisions (still unsigned booleans); governed delivery authorizations (still unsigned). Binding these downstream authorities to Vault Transit is separate engineering work not scoped into CUSTOMER-ZERO-TRUST-001.
   - Until BOTH (1a) provisioning AND (1b) binding close, no downstream signature can be produced against a production trust anchor. See §8 for the classification of "future signing capability" vs "verifiability of already-issued signatures" — these are separate concerns.
2. **The Customer-Zero acceptance run has not been executed against the current SHA.** `CUSTOMER-ZERO-ACCEPT-001` is `BLOCKED` on the trust prerequisite. There is no on-current-SHA replayable proof of a complete evidence → deterministic truth → canonical QA → qualification → governed authorization chain. The `2026-08-06` restore drill was at migration 0172; current head is 0191 (delta = 19 migrations). Nothing has been restored, replayed, or independently verified against the current schema, current authorities, or the newly-shipped `fa_governed_delivery_*` tables and `fa_qualification_*` tables. The `origin/test/customer-zero-accept-001` branch merge-base with current HEAD is `cb261717` (before PR #713), so the acceptance runner is stale by 13 commits including all REPORT-QA, PROD-QUAL, and GOV-DELIVERY code. The FG_RESULT_TRUTH_GATE operational-acceptance parent objective remains OPEN. Acceptance PREPARATION work (branch reconciliation, runner wiring, corpus review, current-schema restore drill) can proceed at $0 in parallel with trust; acceptance COMPLETION requires the trust anchor. See §8A/§8B for the split.
3. **The "governed delivery" authority does not include transport, and `operator_direct` cannot cross the customer boundary.** PR #726 ships an authorization ledger, not a transport. `FaGovernedDeliveryAuthorization.outcome` is `AUTHORIZED`, never `DELIVERED`. The DB model's own docstring (`api/db_models_field_assessment.py:1117`) states: *"AUTHORIZED means the request was validated and authorized for transport. No transport has occurred."* There is no `fa_governed_delivery_attempts` table (zero grep matches across `migrations/`, `api/`, `services/`), no provider integration, no artifact-fingerprint receipt from an external transport, and no gate binding the existing PDF export route (`GET /engagements/{eid}/reports/{version}/export?format=pdf` at `api/field_assessment.py:9700-9707`) to a governed authorization. That route requires only `report.read` permission plus `governance:read` scope, so any authorized tenant member can pull the PDF today without any governed delivery row ever existing. Additionally: `operator_direct` (`api/field_assessment.py:13701-13715`) requires `recipient_id is None` and declares the authenticated operator takes custody — it proves operator-side holding of the bytes, not customer receipt. Customer-boundary evidence requires a portal-family recipient type (`portal_membership`, `portal_invitation`, `portal_grant`) plus an actual customer-session download. That means the CR-707-004 root cause ("delivery is a state flag, not a customer receipt") is only *partially* remediated: an authorization receipt object now exists, but no transport receipt does, and even after the attempts-table lands, `operator_direct` will remain operator-custody-only. See §7 (`GOV-DELIVERY-TRANSPORT-001`) for the sharpened finding and recipient-type discipline.
4. **The application-layer signing paths are not bound to the Vault trust root.** Even after CUSTOMER-ZERO-TRUST-001 closes, `services/governance/report/signing.py:30,88-98` will continue to sign reports with the environment variable `FG_REPORT_SIGNING_KEY` (a locally-loaded Ed25519 seed); `FaQualificationDecision` and `FaGovernedDeliveryAuthorization` have no signature columns and record decisions as boolean rows. The Vault Transit adapter (`services/cgin/key_management/vault_transit.py`) exists but is not invoked from any signing / qualification / delivery code path — grep `-rn "vault_transit\|TrustAnchor" api/ services/governance/` returns zero matches. This is now called out as blocker P1-4 (`TRUST-BINDING-001`) — see §15.

**Bottom-line verdict:** `NOT_READY_BOUNDED_BLOCKERS`. FrostGate has cleared the code-authoring dimension of the CR-707-002 → CR-707-005 findings. It has not cleared the operational-proof dimension of any of them, the transport dimension of CR-707-004 remains uncleared, and the trust-binding dimension between the ceremony and the application-layer signing paths is not yet in scope of any merged PR. There are no unbounded structural blockers.

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
| 15 | Production qualification (PROD-QUAL-001) | PARTIAL (code CLOSED; ops NOT_PROVEN; TRUST-BINDING absent) | Migration 0189 + `services/governance/report/qualification_authority.py`; delivery gate binds full 5-tuple `(tenant_id, report_id, report_version_id, report_fingerprint, decision=QUALIFIED)` at `api/field_assessment.py:_require_production_qualified`. **No independent operational evidence exists that PRODUCTION_DEPENDENCY_SECURITY, PRODUCTION_SCHEMA_AND_RLS, CANONICAL_ASSESSMENT_PROOF, or DURABLE_EXECUTION_AND_RECOVERY have been produced against current SHA.** Additionally: `FaQualificationDecision` (`api/db_models_field_assessment.py:977-1026`) has NO signature/signing_key_id/signature_version columns; `qualify_report_attest_route` (`api/field_assessment.py:8053-8121`) records `attested=body.attested` as a boolean; no Vault Transit call is invoked — see P1-4 TRUST-BINDING-001. |
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

## 7. GOV-DELIVERY-TRANSPORT-001 — Sharpened Transport Blocker Findings

**Verdict:** `TRANSPORT_NOT_PROVEN`. Elevated to a first-order P1 blocker (see §15).

### 7.A — Direct evidence table

| # | Finding | Evidence (file:line) |
|---|---|---|
| 7.A.1 | `fa_governed_delivery_attempts` table does not exist | Zero grep matches across `migrations/`, `api/`, `services/`. The actual second table in migration 0191 is `fa_governed_delivery_authorizations`. |
| 7.A.2 | PR #726 body claimed `fa_governed_delivery_attempts` exists — description-to-implementation drift | PR #726 description text (source: PR merge commit `dfccd3ff`) named a non-existent table |
| 7.A.3 | PDF/JSON export route requires only `report.read` + `governance:read` — no governed delivery authorization check | `api/field_assessment.py:9700-9711` — decorator `dependencies=[Depends(authz_scope("governance:read"))]`; parameter `actor_ctx: ActorContext = Depends(require_permission("report.read"))`; no `_load_governed_delivery_authorization` call anywhere in function body 9703-9880 |
| 7.A.4 | `FaReportVersion.status = 'delivered'` written BEFORE any transport occurs | `api/field_assessment.py:14007` (`deliver_report_version_route` — legacy path) and `api/field_assessment.py:14228` (`governed_delivery_route` — new path). In both cases the state flip precedes the (non-existent) transport step. |
| 7.A.5 | `GovernedDeliveryReceipt` returns `delivery_authorization_id`, not a transport receipt | `api/field_assessment.py:12833-12851` — schema fields include `delivery_request_id`, `delivery_authorization_id`, `outcome`, `authorized_at`. No `attempted_at`, `artifact_sha256`, `bytes_transferred`, or `provider_reference` fields exist. |
| 7.A.6 | DB model docstring self-declares "No transport has occurred" | `api/db_models_field_assessment.py:1117` docstring on `FaGovernedDeliveryAuthorization` |
| 7.A.7 | `services/governance/report/governed_delivery_service.py` `ALLOWED_OUTCOMES` = `{"AUTHORIZED", "REJECTED"}` — no delivered/succeeded state | `services/governance/report/governed_delivery_service.py:31-36` |

### 7.B — Transport-capable machinery present in the codebase

| Component | Purpose | Used for report artifact delivery? |
|---|---|---|
| `api/notifications/email.py` (Resend, `https://api.resend.com/emails`) | Portal invitation delivery | **NO** — the only send call in this module is the portal invitation email (line 131); no attachment/report delivery |
| `operator_direct` recipient type | Enumerated in `ALLOWED_RECIPIENT_TYPES` (`services/governance/report/governed_delivery_service.py:15-22`) | Semantic-only — declares the operator takes direct responsibility; no code path streams bytes to the operator as a governed transport |
| `download_url` references in `api/ui.py:875`, `api/ui_dashboards.py:127,894` | Audit-packet UI links | **NO** — unrelated to FA report delivery |
| Presigned URL / S3 / SES / SendGrid / Twilio | — | **NONE** present in the delivery chain |

### 7.C — Customer consequence

Any authorized tenant member holding `report.read` + `governance:read` (roles including `platform_admin`, `governance_reviewer`, and effectively any workflow role with reader permission on the tenant) can pull the PDF today directly from `GET /engagements/{eid}/reports/{version}/export?format=pdf` with **no governed delivery authorization row required, no attempt logged, and no cryptographic receipt of the transferred bytes**. The `governed_delivery_route` at `api/field_assessment.py:14060` and the legacy `deliver_report_version_route` at `api/field_assessment.py:13934` create authorization/state records, but neither is a prerequisite for downloading the artifact. The governed delivery authorization trail therefore provides authorization evidence to the operator, not delivery assurance to the customer.

**Recipient-type discipline (correction from bot review of `operator_direct`):** the four recipient types differ in whether they cross the customer boundary:

| Recipient type | Authority proven | Customer boundary crossed? | Suitable for first-paid-client "customer received" evidence? |
|---|---|---|---|
| `operator_direct` | operator holds `report.generate`; `recipient_id` MUST be null (`api/field_assessment.py:13701-13715`) | **NO** — operator custody only; bytes remain with the authenticated operator | **NO** — this is operator-side custody, not customer receipt |
| `portal_membership` | customer identity has an active membership row scoped to `tenant_id + engagement_id` (`api/field_assessment.py:13762-13786`) | **YES** — via customer login to the portal | **YES**, if the customer actually authenticates and downloads |
| `portal_invitation` | valid non-revoked, non-expired invitation exists (`api/field_assessment.py:13788-13813`) | **YES** — via customer accepting the invitation and accessing the portal | **YES**, if the customer accepts and downloads |
| `portal_grant` | active credential/grant row for this engagement (`api/field_assessment.py:13726-13760`) | **YES** — via customer using the grant credential | **YES**, if the customer redeems the grant and downloads |

**For a first paid client where "the customer received the report artifact" must be evidenced:** `operator_direct` is INSUFFICIENT (it proves operator custody and completes the authorization-attempt evidence requirement only). The delivery must additionally use one of `portal_membership` / `portal_invitation` / `portal_grant`, AND the customer must actually authenticate against the portal and download the artifact. The `fa_governed_delivery_attempts` row (see §7.D closure) must be written by the customer's session, not the operator's session, for the transport row to constitute customer-side receipt evidence. `operator_direct` remains a legitimate recipient type for cases where the customer contractually delegates custody to the operator (e.g., a Big-4 auditor accepting the report on behalf of the customer), but that scenario should be explicit in the engagement letter.

### 7.D — Closure requirements (design specification only — NOT implemented in this audit)

A. **Migration** creating `fa_governed_delivery_attempts` (append-only, tenant-RLS-protected) with at minimum: `attempt_id PK`, `tenant_id`, `engagement_id`, `delivery_authorization_id FK`, `report_version_id`, `report_fingerprint`, `artifact_sha256`, `artifact_bytes_length`, `transport_type` (`operator_download` | `portal_grant_download` | `email_attachment` | `presigned_url`), `attempted_at`, `outcome` (`SUCCEEDED` | `FAILED` | `IN_PROGRESS`), `failure_reason_code`, `evidence_ref` (WORM/audit chain reference), plus append-only triggers matching the pattern in migration 0191.
B. **Route authority gate**: `GET /engagements/{eid}/reports/{v}/export` (and `GET /reports/{report_id}/download/pdf` at `api/report_authority.py:332`) must verify an AUTHORIZED `FaGovernedDeliveryAuthorization` row exists for the requesting subject with matching `(tenant_id, engagement_id, report_version_id, recipient_id)` before streaming bytes.
C. **Attempt-row insertion**: on successful stream completion, insert one `fa_governed_delivery_attempts` row with `outcome=SUCCEEDED`, `artifact_sha256` computed from the exact bytes served (or from the manifest hash if the artifact is deterministic), and `attempted_at`.
D. **Status transition correction**: move `FaReportVersion.status = 'delivered'` and `delivered_at` write to AFTER the attempt row insert with `SUCCEEDED`. Remove the pre-transport flip at lines 14007 and 14228.
E. **Lifecycle states** the DB must express: `AUTHORIZED_FOR_DELIVERY` → `TRANSPORT_ATTEMPTED` → `PROVIDER_ACCEPTED` (optional, per transport) → `DELIVERED` → `RECEIPT_ACKNOWLEDGED` (optional, if operator signs receipt). Extend `ALLOWED_OUTCOMES` in `services/governance/report/governed_delivery_service.py:31-36` accordingly OR use the new attempts-table state machine as the authoritative post-authorization ledger.
F. **Optional but recommended**: capture an operator-signed acknowledgement of receipt (Ed25519 over `(attempt_id, artifact_sha256, delivered_at)`) signed by the customer-zero-approval trust role once CUSTOMER-ZERO-TRUST-001 and TRUST-BINDING-001 both close.
G. **Recipient-type discipline for customer-boundary evidence:** for delivery rows that must prove "the customer received the artifact" (not merely "the operator was authorized to hold it"), the `fa_governed_delivery_attempts` row MUST be inserted by a session authenticated as the customer identity (portal_membership / portal_invitation / portal_grant recipient), not by the operator session. An `operator_direct` attempt row completes only the operator-custody attestation. Enforce at the route layer by binding `attempt_row.attempted_by` to `ActorContext.subject` and refusing `operator_direct` attempt insertion when the delivery contract specifies customer-boundary receipt.

This scope is bounded (~200 LOC + one migration + ~15 tests) and requires **no paid infrastructure** for the `operator_direct` / direct-download path. It does not depend on CUSTOMER-ZERO-TRUST-001 unless step F is included. Step G is a route-layer discipline addition and requires no infrastructure beyond a functioning portal login flow that the customer actually exercises.

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

### 8.z — Historical signature verifiability after cluster destruction (`HISTORICAL_VERIFICATION_AFTER_KEY_DESTRUCTION`)

**Classification: PARTIAL — verification is offline-capable BY DESIGN, but is currently NOT_PROVEN because no production manifest exists to persist the anchor material.**

The evidence schema at `schemas/artifacts/customer_zero_trust_evidence.schema.json` explicitly requires, per trust role: `public_key`, `public_key_fingerprint`, `algorithm=ed25519`, `key_id`, `key_version`, and a nested `public_anchor` object with `key_id + key_version + public_key_fingerprint`. This material, once persisted to `artifacts/customer_zero_trust_evidence*.json` under source control, is sufficient to verify already-issued signatures offline.

The trust adapter at `services/cgin/key_management/vault_transit.py:59-76` implements verification purely from the persisted `TrustAnchor` (`public_key`, `key_version`, `public_key_fingerprint`) — it decodes the Ed25519 public key locally, re-derives the fingerprint from the raw bytes (`services/cgin/key_management/vault_transit.py:89-91`), and invokes `key.verify(raw_signature, payload)` on the local `cryptography` primitive. **No live Vault call is required for verification.** The signature format `vault:v<N>:<base64-sig>` embeds the key version so the correct anchor can be resolved deterministically.

Therefore the three distinct concerns must be separated:

| Concern | State after Vault cluster destruction |
|---|---|
| Future signing capability (mint new signatures) | DESTROYED — private key is non-exportable in Vault Transit and is not held anywhere else |
| Provider-hosted key history / rotation metadata | DESTROYED — Vault Transit ledger and audit stream are cluster-scoped |
| Cryptographic verifiability of already-issued signatures | PRESERVED — provided the public anchor material (public_key + fingerprint + key_version) has been persisted to `artifacts/` under source control before destruction |
| Non-repudiation attributed to the Vault issuer identity | DEGRADED — verification against the public key still succeeds, but the chain-of-custody attestation that the key was issued by a specific Vault role cluster relies on the audit stream, which may be lost with the cluster |

**Sub-finding CR-002-D (P1 dependency, HCP_REQUIRED):** No manifest has been produced (§8 table, requirement 8). Therefore no anchor material has been persisted. FrostGate must ensure that the first production ceremony writes a fully-populated `customer_zero_trust_evidence*.json` (and any subsequent rotation manifests) under `artifacts/` and commits it to source control BEFORE any cluster-destroy action, or historical verifiability will collapse from PARTIAL to NOT_PROVEN.

**Correction of prior audit language:** Any statement that destroying the Vault cluster "invalidates all historical signatures" is overstated. Destroying the private signing key prevents FUTURE signatures. Existing signatures remain cryptographically verifiable against retained public anchor material. What the cluster-destroy would collapse is (a) the provider-side rotation history and (b) the Vault audit stream — not the mathematics of Ed25519 verification.

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

1. **CUSTOMER-ZERO-TRUST-001 — Production trust anchor ceremony (`HCP_REQUIRED`)**
   - Domain: cryptographic trust anchor infrastructure (future-signing capability at the KMS boundary)
   - Exact problem: No production Ed25519 signing keys exist at any managed KMS. The Vault Transit adapter (`services/cgin/key_management/vault_transit.py`) can only sign against a live Vault cluster; none exists.
   - Evidence: `roadmap_authority.yaml` `active_objective.status = BLOCKED_PENDING_PREREQUISITE`; zero files matching `artifacts/customer_zero_trust_evidence*.json`; `frostgate-infra` HCP Terraform never applied (state: NEVER APPLIED per §9).
   - **What this closure PROVES:** infrastructure exists (cluster + three Transit keys + three AppRoles); a fully-populated evidence manifest is signed and committed under source control; public anchors are enrolled for external verification; rotation/failure ceremonies are on record.
   - **What this closure does NOT AUTOMATICALLY BIND:** report signing, qualification decisions, or governed delivery authorizations. The application-layer signing path (§8.z code review confirms) uses `FG_REPORT_SIGNING_KEY` directly; no code path invokes `services/cgin/key_management/vault_transit.py` from `services/governance/report/*` or from `api/field_assessment.py`. **Binding those downstream authorities to the Vault trust root is separate scope — see P1-4 below.** Grep receipts: `grep -rn "vault_transit\|TrustAnchor" api/ services/governance/` returns zero matches.
   - Affected authority: **KMS-level future-signing capability only.** Downstream application-layer signing bindings depend on P1-4. Verification of already-issued signatures is a separate concern (see §8.z — verifiability is offline-capable given retained public anchor material).
   - Customer consequence: Cannot mint any production-authority signature at the KMS boundary. Cannot enroll a public anchor for external verification. Does NOT by itself change what the application signs or how qualification is recorded.
   - Minimum closure: Provision HCP Vault Dedicated cluster; create three Transit keys; enroll three AppRoles; produce fully-populated evidence manifest passing `tools/customer_zero_trust_evidence.py verify-complete`; enroll public anchors; record rotation/failure tests; **commit manifest under `artifacts/` in source control BEFORE any subsequent cluster-destroy would occur** (see §8.z, sub-finding CR-002-D).
   - Requires paid infrastructure: **YES** (HCP Vault Dedicated `standard_small` + AWS CloudWatch audit stream). See §16 for the pricing classification — the audit's prior "~$22/mo" figure was materially inaccurate; publicly-referenced third-party estimates put the standard tier well above $1000/mo, and exact live pricing is `EXACT_LIVE_PRICE=NOT_PROVEN` from this audit. Confirm against `https://portal.cloud.hashicorp.com/` before provisioning.
   - Estimated scope: 1–2 days of operator ceremony + evidence collection
   - Sequence: 1st (strict prerequisite for P1-4)

2. **CUSTOMER-ZERO-ACCEPT-001 — Customer-Zero acceptance current-SHA run** *(completion blocked on P1-1; PREPARATION unblocked)*
   - Domain: operational acceptance
   - Exact problem: No replayable current-SHA end-to-end run producing the four required attestations tied to a specific report/version/fingerprint tuple.
   - Evidence: `roadmap_authority.yaml` `blocked` list contains CUSTOMER-ZERO-ACCEPT-001 pending trust prerequisite; `origin/test/customer-zero-accept-001` merge-base with current HEAD is `cb261717` (before PR #713) — the runner is stale by 13 commits; current migration head is 0191 vs the branch's baseline.
   - Affected authority: `PRODUCTION_DEPENDENCY_SECURITY`, `PRODUCTION_SCHEMA_AND_RLS`, `CANONICAL_ASSESSMENT_PROOF`, `DURABLE_EXECUTION_AND_RECOVERY` attestations
   - Customer consequence: `PROD-QUAL-001` cannot produce a QUALIFIED decision under production trust for any real customer report until closure.
   - **PREPARATION (can be done at $0, before trust closes):** branch reconciliation of `test/customer-zero-accept-001` to current main; current-schema restore drill at migration 0191; runner wiring for production trust anchor injection (config-only, no live calls); corpus/expected-outcomes review.
   - **COMPLETION (blocked on CUSTOMER-ZERO-TRUST-001):** live production trust anchor signatures for the four gates; current-SHA attestations produced against real trust roles; independent public verification against the enrolled public anchors; signed provenance chain end-to-end.
   - Requires paid infrastructure: partial (needs trust closed first for COMPLETION; PREPARATION is $0)
   - Estimated scope: 1–2 days of PREPARATION + 1 day of COMPLETION ceremony (after trust closes)
   - Sequence: 2nd for COMPLETION; PREPARATION can start immediately

3. **GOV-DELIVERY-TRANSPORT-001 — Governed delivery TRANSPORT completion**
   - Domain: artifact transport binding
   - Exact problem: `FaGovernedDeliveryAuthorization` is authorization-only. No `fa_governed_delivery_attempts` table exists (despite PR #726's description drift claiming otherwise). PDF export routes serve bytes without checking for an authorization record. Additionally, `operator_direct` transport is operator custody only — it does NOT cross a customer boundary and therefore cannot by itself prove "the customer received the artifact"; it only proves "the authorised operator holds the bytes". Customer-boundary evidence for a first paid client requires a recipient type where the customer independently accesses the portal (see §7.C, §7.D revised).
   - Evidence: `api/db_models_field_assessment.py:1117` docstring; `api/field_assessment.py:9700-9711` export route decorator requires only `report.read` + `governance:read`; `api/field_assessment.py:14007` and `api/field_assessment.py:14228` set `rv.status = 'delivered'` before any transport; `services/governance/report/governed_delivery_service.py:31-36` `ALLOWED_OUTCOMES = {AUTHORIZED, REJECTED}`; `GovernedDeliveryReceipt` at `api/field_assessment.py:12833-12851` has no transport-attempt fields; `_resolve_delivery_recipient` at `api/field_assessment.py:13701-13715` requires `recipient_id is None` for `operator_direct` and explicitly documents "authenticated operator … takes direct custody".
   - Affected authority: GOV-DELIVERY-001 (currently PARTIAL — authorization only, not transport)
   - Customer consequence: FrostGate cannot truthfully assert that "the customer received the report artifact" via `operator_direct` — only that "the operator was authorized to deliver and took operator-side custody". Any tenant member with `report.read` + `governance:read` can pull the PDF today without a governed delivery row.
   - Minimum closure: See §7.D closure requirements A–E (attempts table + route gate + attempt row + status transition correction + lifecycle states) AND §7.D.G (recipient-type discipline for customer-boundary evidence).
   - Requires paid infrastructure: NO for the attempts-table + route-gate + `operator_direct` code path. Customer-boundary evidence via `portal_membership` / `portal_invitation` / `portal_grant` requires a functioning customer-facing portal login flow (which today exists in code but must be operationally exercised end-to-end by the customer for first paid engagement).
   - Estimated scope: ~200 LOC + 1 migration + ~15 tests; 4–8 hours engineering. Customer-boundary evidence (portal access + downloaded-by-customer attempt row) requires an additional customer-side operational step (one login + one download by the customer identity) — no additional infrastructure but requires the customer to actually access the portal.
   - Sequence: 3rd (unblocks CR-707-004 closure). Can be executed independently of P1-1 and P1-4.

4. **TRUST-BINDING-001 (NEW) — Bind report signing / qualification / delivery to the Vault Transit trust root**
   - Domain: application-layer signature binding (downstream of the KMS-level P1-1 ceremony)
   - Exact problem: Even after CUSTOMER-ZERO-TRUST-001 closes, the application still signs reports with `FG_REPORT_SIGNING_KEY` (an environment-loaded Ed25519 seed) and still records qualification decisions and governed-delivery authorizations as unsigned boolean rows. The Vault Transit adapter exists but is not called from any signing code path.
   - Evidence: `services/governance/report/signing.py:30` `_ENV_KEY = "FG_REPORT_SIGNING_KEY"`; `services/governance/report/signing.py:88-98` `sign_report()` loads the private key with `_load_private_key_bytes()` from that env var and signs locally with `cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`; `FaQualificationDecision` schema at `api/db_models_field_assessment.py:986-1006` has no `signature`, `signing_key_id`, or `signature_version` columns; `FaProductionAttestation` records `attested=body.attested` as a boolean at `api/field_assessment.py:8114` from any actor holding `report.qualify` — no signature production or verification against the Vault trust anchor is invoked; `FaGovernedDeliveryAuthorization` schema at `api/db_models_field_assessment.py:1124-1148` has no signature columns; grep `-rn "vault_transit\|TrustAnchor" api/ services/governance/` returns zero matches.
   - Affected authority: Downstream binding of PROD-QUAL-001 and GOV-DELIVERY-001 to the Vault trust root — a first paid client's report and qualification decision cannot be externally verified against the enrolled public anchors until these code paths sign via the Vault adapter (or emit Vault-signed manifests over the append-only rows).
   - Customer consequence: External verifiers CANNOT independently verify that a qualification decision or delivery authorization was issued by a specific Vault-issued role. Report Ed25519 signatures verify against `FG_REPORT_SIGNING_PUBLIC_KEY`, not against a Vault-issued anchor, so the trust chain does not terminate at the Vault ceremony's public anchors.
   - Minimum closure: cut `services/governance/report/signing.py` `sign_report()` over to invoke `services/cgin/key_management/vault_transit.py` (identity role) instead of a local `Ed25519PrivateKey`; add `signature`, `signing_key_id`, and `signature_version` columns to `fa_qualification_decisions` and `fa_governed_delivery_authorizations` (append-only migration); require `_finalize_qualification` and `_record_governed_delivery_authorization` to populate those columns via the Vault approval and acceptance roles respectively; add fail-closed tests covering signature production, verification against retained public anchor material, and refusal-to-write when Vault is unreachable.
   - Requires paid infrastructure: NO for the code work; YES for end-to-end proof (requires P1-1 to close first for live signing against production Vault).
   - Estimated scope: ~400–600 LOC + 1 migration + ~25 tests; 1–2 days engineering. Signing-path cutover is the highest-risk piece because every test that produces a signed report will need Vault Transit availability or an explicit test fake.
   - Sequence: 4th (blocked on P1-1 for live signing; code-level cutover + schema migration can begin as soon as P1-1 provisioning starts).

### P2 (controlled workaround acceptable for first client — MUST be documented in first-client operating conditions)

5. **P2-CR002-QA-SoD — Report QA API-key self-approval exemption (first-client operating condition)**
   - **Exact code location:** `api/field_assessment.py:13174` — function `_enforce_report_qa_independence(actor_ctx, *, generated_by, reviewer_id)`.
   - **Exact bypass condition:** the SoD check runs only when `actor_ctx.auth_source != "api_key"`. If the caller authenticated via API key, the different-person rule is skipped and the same subject that generated the report can approve it.
   - **Disposition:** P2 with **mandatory first-client operating requirement** (elevated from appendix). For any paid engagement, QA MUST be performed by a distinct verified human identity holding `compliance_reviewer` (or explicitly QA-authorized) role — NOT via the API-key path. This is not sufficient as a permanent structural control (a follow-up PR should extend the SoD enforcement to cover the API-key path or require an alternate cross-actor role check for machine authors), but it is sufficient as a controlled workaround for the first paid engagement provided the operator playbook makes this an explicit, verified precondition per report.
   - **Documentation requirement:** `docs/operators/FIRST_CLIENT_PLAYBOOK.md` must be updated (not tracked by this audit; recommended as a same-cycle P2 PR) to include a per-report checklist item: "QA reviewer authenticated as a distinct human identity via canonical session, not via API key. Confirm `_enforce_report_qa_independence` code path executed by inspecting the `fa_report_qa_decisions` row's actor_type."

6. **P2-CR002-SCOPE — Report scope/methodology/limitations content**
   - CR-707-006 NOT_PROVEN. **Corrected workaround (bot review):** the prior "manually appended cover addendum to the exported PDF" workaround is REJECTED because it produces customer-facing content that is absent from `report_json`, the section/manifest hash chain, the QA decision, and the qualification fingerprint. Appending post-export produces an artifact that is NOT the fingerprinted, QA'd, qualified version — so the delivered scope statement is neither version-bound nor approved, defeating the point of the CR-707-006 finding.
   - **First-client workaround:** deliver the scope/methodology/limitations content as a **clearly separate, explicitly-labeled non-report attachment** distinct from the signed report artifact. The attachment must NOT be integrated into the PDF (which would masquerade as report content); it must be a named companion document (e.g. `engagement_scope_and_limitations_<engagement_id>.pdf`) referenced in the engagement letter and delivered alongside the fingerprinted report. Retain both artifacts in the delivery record and note in the cover letter that only the signed report bytes are fingerprinted, QA'd, and qualified.
   - **Structural fix (post-first-client):** the scope/methodology/limitations content must be generated INTO `report_json` before fingerprinting, QA, and qualification. This is a code change to the report engine + serialization + PDF renderer; not scoped into this audit's P1 list because the separated-attachment workaround is sufficient for a first design-partner engagement provided the operator's cover letter is explicit.

7. **P2-CR002-ROADMAP-DRIFT — Roadmap authority reconciliation**
   - PROD-QUAL-001 (#724) and GOV-DELIVERY-001 (#726) are merged but not reflected in `customer_one/roadmap_authority.yaml` `completed` list. Workaround: no immediate operational impact; correct in next roadmap-maintenance PR.

8. **P2-CR002-BACKUP — Current-SHA restore drill missing**
   - Drill evidence stale (2026-08-06, migration 0172). First-client workaround: run one restore drill against migration 0191 before first client's paper is signed; retain evidence file `docs/governance/status/restore_drill_evidence_YYYYMMDD.md`. No paid infrastructure required.

9. **P2-CR002-EVIDENCE-ECHO — Raw payload echo (CR-707-007)**
   - **Corrected finding (bot review):** the prior workaround claimed the operator could "suppress this in the delivered PDF" and rely on scoped connectors alone. That is not sufficient: there is NO operator-accessible switch that disables the raw-payload echo in the API response. `ingest_scan_result_route` (`api/field_assessment.py:1610-1620`) unconditionally returns `ScanResultResponse`, and `_scan_result_to_response` (`api/field_assessment.py:1000-1014`) always populates `raw_payload=r.raw_payload or {}`. The Console fetch `ingestScan` at `apps/console/lib/fieldAssessmentApi.ts:884` receives the full JSON body from the API regardless of the TypeScript `Promise<ScanResultSummary>` return-type declaration — the type annotation narrows what the caller uses, not what the browser actually receives on the wire. Suppressing the payload from the delivered PDF does NOT change what the browser has already received.
   - **First-client workaround options (choose one, document explicitly):**
     - **(a) Avoid the Console scan-ingest UI entirely for first client.** Ingest scans only via API calls made from a controlled, non-browser client (server-side operator process or CLI). This eliminates the browser echo path without a code change. The Console MUST NOT be used to run `ingestScan` for first-client engagements until (b) is implemented.
     - **(b) Ship a code change (P2 with code closure required, not playbook-only).** Add a response-model split: `ScanResultResponseFull` for authorized inspection and `ScanResultResponseSummary` (excludes `raw_payload`) as the default `ingest_scan_result_route` response. Requires ~30 LOC + tests + Console type regeneration. This is the correct structural fix and should be the next post-first-client P2 to land.
   - **Recommended for first client:** option (a), because it requires zero code change and eliminates the browser exposure surface. Codify in `docs/operators/FIRST_CLIENT_PLAYBOOK.md`: "For first-client engagements, all scan ingestion must be executed via server-side API calls; the Console scan-ingest UI is disabled/unused. Any operator using the Console to ingest scans MUST first land the response-model split."

10. **P2-CR002-ARTIFACT-STORAGE — CR-707-008 durable artifact storage**
    - First-client workaround: contractually exclude file-upload evidence; use only DB-persisted scan and questionnaire evidence. Explicitly reference in the engagement scope statement.

11. **P2-CR002-EXPORT-TENANT — CR-707-011 cross-tenant export helper**
    - First-client workaround: Platform Admin exports the report only from the customer's own tenant context, not from operator context. Document in playbook.

### P3 (post-first-client)

12. **P3-CR002-PROVISION-SQL — CR-707-009 SLOT_STUCK SQL workaround** (playbook acknowledges as engineering step)
13. **P3-CR002-REMEDIATION-BRIDGE — CR-707-010** (defer per #707 §27)
14. **P3-CR002-TEST-HERMETICITY — CR-707-012** (defer per #707 §27)

**Totals:** P0=0, P1=4, P2=7, P3=3.

---

## 16. Remaining Critical Path to First Paid Client

```
Parallelizable now (require no dependency):
  A. GOV-DELIVERY-TRANSPORT-001 code closure (P1-3)
  B. CUSTOMER-ZERO-ACCEPT-001 PREPARATION ($0):
      - branch reconciliation, runner wiring, corpus review, migration-0191 restore drill
  C. TRUST-BINDING-001 code-level cutover (P1-4): schema migration + signing-path
      code changes can begin in a branch before P1-1 provisioning completes;
      live end-to-end signing requires P1-1 first
  D. P2 documentation + reconciliation PRs (playbook workarounds, roadmap YAML sync,
      response-model split for CR-707-007 if option (b) chosen)

Strict serial chain:
  1. CUSTOMER-ZERO-TRUST-001 closure   ── HCP Vault ceremony + evidence manifest (COST-BEARING)
        ↓
  2. TRUST-BINDING-001 completion       ── application-layer signing/qualification/
                                          delivery cut over to Vault Transit;
                                          signed qualification decision produced
        ↓
  3. CUSTOMER-ZERO-ACCEPT-001 COMPLETION ── current-SHA run + 4 attestations + QUALIFIED
                                          decision signed by production trust root
        ↓
  4. Restore drill re-run against migration 0191 with production trust (evidence file)
        ↓
  5. L14 commercial execution (design partner scheduled → invoice → payment → portal access → roadmap review)
        ↓
     CUSTOMER-ONE VALIDATED → FIRST PAID CUSTOMER
```

### $0 remaining engineering work (can proceed in parallel with the trust ceremony)

- GOV-DELIVERY-TRANSPORT-001 closure (§7.D): ~4–8h engineering; ~200 LOC + 1 migration + tests; zero infrastructure cost
- CUSTOMER-ZERO-ACCEPT-001 PREPARATION: branch reconciliation of `test/customer-zero-accept-001` (currently 13 commits behind); current-schema restore drill at migration 0191; runner wiring for trust-anchor injection
- P2-CR002-QA-SoD playbook mandate (§15, item 5): document distinct-human-QA requirement in `docs/operators/FIRST_CLIENT_PLAYBOOK.md`
- P2-CR002-SCOPE report addendum: manual PDF cover for first client; codified in playbook
- P2-CR002-ROADMAP-DRIFT: single YAML+MD PR to reconcile roadmap authority
- P2-CR002-BACKUP: run drill; retain evidence file
- P2-CR002-EVIDENCE-ECHO / EXPORT-TENANT: documented workaround in playbook

### Paid-infrastructure requirements (`EXACT_LIVE_PRICE=NOT_PROVEN`)

The prior audit revision stated "HCP Vault Dedicated Essentials/Small — approximately $0.03/hr (~$22/mo)". That figure could not be reproduced from any current HashiCorp source and is inconsistent with third-party pricing summaries observed during this audit. It is retracted and re-classified as `NOT_PROVEN`.

- **PRODUCT:** HCP Vault Dedicated
- **TIER (per `frostgate-infra/hcp_cluster.tf` + `variables.tf`):** `standard_small` (this is the smallest **production-grade** tier; `dev` and (formerly) `starter_small` are non-production. The IaC comment explicitly notes `starter_small` was disabled in hcp provider `v0.102.0`.)
- **CLUSTER HOURLY RATE:** `NOT_PROVEN` from this audit. Third-party summaries (envmanager.com, infisical.com, costbench.com) cite Standard tier ranges of approximately $1.15k–$5.5k/month for the cluster fee depending on size, with `standard_small` at the low end. These are historical / third-party figures and MUST be re-verified against `https://portal.cloud.hashicorp.com/` before provisioning.
- **CLIENT BILLING MODEL:** HCP Vault Standard tier applies a per-Vault-client monthly fee in addition to the cluster hourly rate. Third-party summaries cite figures around $70–$115/client/month. `NOT_PROVEN` from this audit; verify at portal.
- **ESTIMATED CLIENT COUNT for first paid engagement:** `0` for FrostGate operator use during the ceremony (three AppRoles authenticate but they are FrostGate-internal roles, not customer clients per HCP's billing definition — this requires operator confirmation at the HCP portal). First paid customer adds an operational workload against the Vault cluster whose client count depends on runtime behavior — `NOT_PROVEN` here.
- **CREDITS:** `NOT_PROVEN` (cannot verify without HCP account access)
- **8-HOUR COST:** `NOT_PROVEN`
- **12-HOUR COST:** `NOT_PROVEN`
- **24-HOUR COST:** `NOT_PROVEN`
- **30-DAY COST:** `NOT_PROVEN`
- **AWS CloudWatch audit stream:** small at bounded log volume; not separately priced here (`NOT_PROVEN`)
- **HVN:** no direct line-item charge per HashiCorp docs; billed through the Vault cluster
- **Source of historical estimate:** the prior audit's "$22/mo" figure — treated as a **historical estimate to be re-verified at HCP portal before provisioning**, not as a load-bearing budget figure. Do NOT budget from this audit; the founder-operator must retrieve a live quote from `https://portal.cloud.hashicorp.com/` and update the ceremony CHECKPOINT with the actual hourly + per-client rates before running `terraform apply`.
- **Railway (production DB):** already provisioned (per audit references); not audited here
- **Stripe:** ready for L14 (documented as an L14 task, not a blocker)

**Explicit cost checkpoint gate:** Before any `terraform apply` in `frostgate-infra`, the operator MUST record (a) the exact hourly cluster rate quoted by HCP portal for `standard_small` in AWS us-east-1, (b) the exact per-client monthly fee, and (c) the projected first-30-day burn, in a signed pre-provisioning artifact under `docs/governance/ceremony/`. This audit does not authorize any spend and does not assert a specific dollar figure.

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

FrostGate has no P0 blockers and no structural (architectural) blockers. The four P1 items are all bounded:

1. `CUSTOMER-ZERO-TRUST-001` — operator ceremony. `HCP_REQUIRED` (cost is `EXACT_LIVE_PRICE=NOT_PROVEN`; retrieve live quote before provisioning). Proves KMS-level signing capability at Vault; does NOT by itself bind the application-layer signing paths.
2. `CUSTOMER-ZERO-ACCEPT-001` — split into PREPARATION ($0, unblocked, can start immediately) and COMPLETION (blocked on P1-1 and P1-4).
3. `GOV-DELIVERY-TRANSPORT-001` — ~4–8h of engineering; unblocked; can proceed in parallel with the trust ceremony. First-paid-client customer-boundary evidence requires a portal recipient type + customer session download (see §7.C, §7.D.G).
4. `TRUST-BINDING-001` — cut report signing / qualification decisions / delivery authorizations over to the Vault Transit adapter; ~1–2 days engineering + schema migration; code-level work can begin before P1-1 completes but live end-to-end signing requires P1-1 first.

Total wall-clock time-to-ready depends on how quickly the operator can complete the HCP ceremony after provisioning; P1-2 PREPARATION, P1-3, and P1-4 code cutover can be sequenced in parallel to remove them from the critical path. No customer contract should be executed for delivery until all four P1 items close; contracting itself may proceed under the L14 commercial track if the founder-operator wishes.

**Explicit statement:** No production behavior was changed by this audit. No production secrets were read or written. No infrastructure was applied. No preserved worktree was touched. No existing test, invariant, authority, or gate was weakened. The only writes are (a) this audit document at `docs/audits/client_readiness_002_first_paid_client.md` and (b) if required by policy, an entry in `docs/ai/PR_FIX_LOG.md`.

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
