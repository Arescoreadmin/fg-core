# Customer-One Verified Governance Roadmap

**AUTHORITY NOTICE:** This document is the Level-2 sequencing authority for all FrostGate
engineering after 2026-09-09. It supersedes
`artifacts/audits/canonical_roadmap/FROSTGATE_CANONICAL_ROADMAP.md` for sequencing decisions.
`ROADMAP.md` is the Level-3 status ledger (merged PR tracker only).

- **Date:** 2026-09-13
- **Machine-readable mirror:** `customer_one/roadmap_authority.yaml`
- **Checker:** `tools/ci/check_customer_one_roadmap.py`

---

## 1. Customer-One Goal

**Definition:** Customer-One is the first paying client engagement, evidenced by all four of
the following conditions being simultaneously true:

1. Invoice issued to a named client.
2. Invoice paid (funds received or payment committed in writing).
3. Client portal accessed by a named user at the client organization.
4. Remediation roadmap opened and reviewed with the client.

No commercial milestone short of this complete set satisfies Customer-One. Design partner
scheduled does not equal L14 complete. All four conditions must be met before declaring
Customer-One closed.

---

## 2. Freeze Law

New capability enters the critical path only if it meets at least one of the following
criteria, supported by evidence:

1. **Closes a Customer-One blocker** — the capability is on the direct critical path to
   issuing, collecting, and delivering value to the first paying client.
2. **Required by a contracted customer requirement** — a signed or countersigned document
   from the client specifies the capability as a delivery condition.
3. **Measurably reduces delivery risk or cost** — a quantified argument with evidence shows
   that adding the capability reduces the probability or cost of a Customer-One failure mode.

**Insufficient justifications:** preference, curiosity, speculative future scale,
pre-emptive compliance preparation without a named client requirement, and internal tooling
improvements that do not map to a Customer-One blocker.

The Freeze Law applies to new capabilities only. Defect repair (work class `REPAIR`) is
always authorized and requires no Freeze Law justification.

---

## 3. Precedence Model

The following five levels form a strict hierarchy for sequencing and priority decisions.
Higher-level authorities override lower-level authorities when they conflict.

| Level | Name | Sources |
|-------|------|---------|
| 1 | Safety invariants | `SPINE_INVARIANTS.md`; security regression tests; RLS enforcement gates |
| 2 | Customer-One execution authority | `docs/plans/customer_one_verified_governance_roadmap_20260910.md`; `customer_one/roadmap_authority.yaml` |
| 3 | ROADMAP.md status ledger | `ROADMAP.md` — merged PR tracker only, not a sequencing authority |
| 4 | Scoped plans | `docs/plans/`; `docs/architecture/` |
| 5 | Historical evidence | `ENTERPRISE_PLAN.md`; `AUTHZ_COMPLIANCE_PLAN.md`; `artifacts/audits/canonical_roadmap/FROSTGATE_CANONICAL_ROADMAP.md` |

**Level 5 note:** `ENTERPRISE_PLAN.md` (Phase 3+ product strategy),
`AUTHZ_COMPLIANCE_PLAN.md` (RBAC tracking), and
`artifacts/audits/canonical_roadmap/FROSTGATE_CANONICAL_ROADMAP.md` (dated 2026-07-14) are
**SUBORDINATE** to this document for sequencing decisions. They remain valid historical
records but do not authorize new work or reprioritize the sequence below.

---

## 4. Current State

**As of 2026-09-11:**

| Metric | Value |
|--------|-------|
| Revenue Gate 1 | 12 / 12 items cleared |
| MRR | $0 |
| First invoice issued | Not yet |
| Identity platform | P-113.10 + P1-01-PR1 + P1-01-PR2 complete (#690 merged df1fc85f) |
| Open engineering work | CUSTOMER-ZERO-FINAL-READINESS-001 COMPLETE (#753) → CUSTOMER-ZERO-RUN3-PREAUTH-001 (offline pre-authorization gate) → (human cost authorization) → CUSTOMER-ZERO-TRUST-003 (paid ceremony Run 3) → CUSTOMER-ZERO-ACCEPT-001; TRUST-BINDING-001 closed #731; P0 repairs closed #750/#751 |
| Open commercial work | L14 — design partner, price, packet, Stripe, founder review |

Revenue Gate 1 is fully cleared. P1-01-PR2 merged and post-merge validated (2026-09-10).
The FG_RESULT_TRUTH_GATE implementation and truth invariants are complete, but its
operational acceptance remains open. FA-ACTOR-001 is complete through #710 and #711:
material Field Assessment mutations retain canonical human authority, current capability,
tenant/engagement binding, and shared persistence/audit attribution. REPORT-QA-001 is complete (#713); PROD-QUAL-001 is complete (#724); GOV-DELIVERY-001 is complete (#726); GOV-DELIVERY-TRANSPORT-001 is complete (#728 + #729). TRUST-BINDING-001 closed in PR #731 (2026-10-01). Two Customer-Zero trust ceremony runs were attempted; both failed to prove trust due to P0 defects: DEFECT-PROVENANCE-INTEGRITY (report content not bound to manifest hash) and DEFECT-VERIFIER-CONTRACT (verify_* raised instead of returning deterministic boolean). Both defects are now repaired: PROVENANCE-INTEGRITY-001 closed in #750 (2026-10-07), VAULT-VERIFY-CONTRACT-001 closed in #751 (2026-10-07). State reconciled in #749 (CZ-RECONCILE-001). CUSTOMER-ZERO-TRUST-001 is ATTEMPTED_NOT_PROVEN and blocked. CUSTOMER-ZERO-FINAL-READINESS-001 is COMPLETE (#753, c9717807). The current NEXT prerequisite is CUSTOMER-ZERO-RUN3-PREAUTH-001 (offline pre-authorization gate — no paid infrastructure); once complete, explicit human cost authorization is required before CUSTOMER-ZERO-TRUST-003 (Run 3, paid HCP ceremony) may proceed. Completion of CUSTOMER-ZERO-FINAL-READINESS-001 alone does NOT authorize CUSTOMER-ZERO-TRUST-003; CUSTOMER-ZERO-RUN3-PREAUTH-001 must close first, then a human cost authorization decision is required. CUSTOMER-ZERO-ACCEPT-001 remains the open acceptance parent and cannot execute until CUSTOMER-ZERO-TRUST-003 closes. Machine-readable authority: `customer_one/roadmap_authority.yaml`.

---

## 5. Authorized NEXT Sequence

The following items are the only authorized engineering and commercial work on the critical
path to Customer-One. Work not on this list requires a Freeze Law justification before it
can be added.

| ID | Title | Status | Blocker Closed |
|----|-------|--------|----------------|
| FA-ACTOR-001 | Bind Field Assessment actions to canonical human actors | COMPLETED — #710/#711 | Canonical human actor authority proven for material Field Assessment mutations |
| REPORT-QA-001 | Version-bound independent report QA authority | COMPLETED — #713 | QA decisions are canonically attributable to exact report versions |
| GOV-DELIVERY-TRANSPORT-001 | Governed delivery transport evidence | COMPLETED — #728 (31c35d68) + #729 (302173ed) | Governed authorization is now bound to durable append-only transport-attempt evidence; exact artifact bytes cross the HTTP boundary; 44 adversarial tests pass |
| TRUST-BINDING-001 | Bind governance artifacts to canonical trust authority | COMPLETED — #731 (2562e875) | All three governance artifact types cryptographically bound to Vault Transit; IDENTITY (report), APPROVAL (qualification), ACCEPTANCE (delivery authorization); domain separation + 42 adversarial tests |
| CZ-RECONCILE-001 | Reconcile Customer-Zero trust ceremony state | COMPLETED — #749 | Records CUSTOMER_ZERO_TRUST_NOT_PROVEN, DEFECT-PROVENANCE-INTEGRITY, DEFECT-VERIFIER-CONTRACT; introduces ceremony_state.yaml |
| PROVENANCE-INTEGRITY-001 | Repair report/provenance verification integrity | COMPLETED — #750 (7a707cfb) | DB-level mutation of report_json without changing manifest_hash now fails deterministically; 45 adversarial tests pass |
| VAULT-VERIFY-CONTRACT-001 | Repair deterministic fail-closed verification semantics | COMPLETED — #751 (8d3dd55a) | verify_*() returns deterministic boolean; VaultKeyVersionUnavailableError added; 51 adversarial tests pass |
| CUSTOMER-ZERO-TRUST-001 | Bounded operational trust infrastructure | BLOCKED — ATTEMPTED_NOT_PROVEN | Two ceremony runs executed; trust not proven due to P0 defects now repaired. Run 3 uses CUSTOMER-ZERO-TRUST-003 (requires fresh cost authorization after $321.81 accrued) |
| CUSTOMER-ZERO-FINAL-READINESS-001 | Customer-Zero final pre-ceremony readiness checklist | COMPLETED — #753 (c9717807) | All offline prerequisites verified; no paid infrastructure required; unblocked by PROVENANCE-INTEGRITY-001 + VAULT-VERIFY-CONTRACT-001 completion |
| CUSTOMER-ZERO-RUN3-PREAUTH-001 | Customer-Zero Run 3 pre-authorization gate | COMPLETED — #755 (8de43e22) | Freezes production candidate, resource inventory, proof matrix (A–K), abort matrix, teardown contract, cost-authorization REQUEST. preauth_result=READY_FOR_HUMAN_COST_AUTHORIZATION. authorization_status=NOT_AUTHORIZED. No paid infrastructure |
| CZ-RUN3-READINESS-INTEGRATION-REPAIR-001 | Post-merge readiness integration repair | COMPLETED — #756 (49a662f9) | Repairs A2 (lifecycle-aware completed check) and J_CE3 (machine-readable simulation evidence). 35 adversarial tests. Offline readiness: READY, 0 blockers |
| CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001 | Run-3 operator checklist, candidate rebinding, and cost-authorization preparation | COMPLETED — #758 (4b945df9) | Deterministic offline preflight manifest: 16 deferred live checks catalogued, source/candidate rebinding procedure, 21-resource inventory review, 4 preserved AWS audit resources, CloudWatch/Vault audit prerequisites, cost-authorization request structure, abort conditions, teardown plan. preflight_status=PREPARED_FOR_HUMAN_REVIEW. authorization_status=NOT_AUTHORIZED. 75 adversarial tests. CLI: tools/ci/customer_zero_run3_operator_preflight.py |
| CZ-RUN3-FAILURE-PREVENTION-001 | Run-3 adversarial failure prevention and cost containment audit | NEXT — offline preparation (adversarial audit) | Independent adversarial audit of Run-3 readiness: reconstructs Run-1/Run-2 failure modes, challenges readiness machinery for false-positive detection, audits CloudWatch integration, Terraform safety, cost model, offline rehearsal coverage, evidence completeness, teardown reliability, and governance authorization integrity. Produces machine-readable findings, failure-mode register, cost-containment plan, smoke-test contract, offline rehearsal spec, and go/no-go decision artifact. Zero new cloud spending. PR #760. |
| CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001 | Human cost-authorization review and decision preparation | NEXT — offline preparation | Prepare reviewable cost-authorization package: current HCP pricing evidence, proposed max cost (USD), proposed max runtime (hours), pricing validity window, operator identity, human approver identity, approval expiration, source/candidate binding. Result is a reviewable REQUEST — NOT automatic authorization. Actual spending requires a separate explicit human decision |
| CUSTOMER-ZERO-TRUST-003 | Customer-Zero trust ceremony Run 3 | BLOCKED — awaiting fresh explicit human cost authorization | Third paid HCP ceremony; offline preparation complete (PREAUTH + OPERATOR-PREFLIGHT closed); outstanding: explicit human cost authorization, confirmed HCP pricing, proposed max cost/runtime, authorization identity/expiration, actual terraform plan review, HCP Vault provisioning, live ceremony execution, CloudWatch audit delivery proof, independent verification, all 16 deferred live checks, teardown and preservation evidence |
| CUSTOMER-ZERO-ACCEPT-001 | Current-SHA production acceptance evidence | OPEN — blocked on CUSTOMER-ZERO-TRUST-003 | Current-SHA proof, durable recovery, dependency security, and schema/RLS evidence must exist before production qualification; TRUST-BINDING-001 prerequisite closed in #731 |
| L14 | Customer-One Commercial Execution | NEXT (non-engineering) | No paying client; L14 cannot close until FG_RESULT_TRUTH_GATE and all mandatory production gates pass |

`FG_RESULT_TRUTH_GATE` remains the open parent acceptance objective. Its implementation
is complete, but operational acceptance is `OPEN` pending the production acceptance
evidence and downstream authorities described below.

### FGA-028 — Grounded Determination & Executive Reporting Authority

- **Status:** COMPLETED — PR #695 merged and PR #696 repair merged; synchronized main SHA `9254df5eb323e8b631cc31c4e20aea369bbbb825`.
- **Completion evidence:** PR #695 introduced grounded material claims, deterministic lineage, canonical claim fingerprinting, and executive-report truth preservation. PR #696 repaired the strict-gate mypy regression. Post-merge strict validation: repository-wide mypy clean in 2,124 source files; full pytest `22,574 passed, 92 skipped`; pip, contract, authority integration, and dependency audits clean; `==> All gates passed.`; `codex_gates rc=0`.
- **Result:** Customer-facing report claims now project from FGA-025 semantic findings, FGA-026 epistemic determinations, and FGA-027 complete evidence state without allowing AI narrative to alter canonical truth.

### FGA-027 — Complete Evidence State Authority

- **Status:** COMPLETED — PR #693, merged SHA `c8c49d14aecf2838876d3d4a8f68a25e689ee9f3`.
- **Completion evidence:** Governance-report regressions and focused tests passed; mypy passed;
  `make fg-fast` passed; strict `codex_gates.sh` passed with `22562 passed, 92 skipped`,
  `==> All gates passed.`, and `codex_gates rc=0`.
- **Result:** Report evidence population is exhaustive, deterministic, replay-safe, and
  tenant/engagement scoped; partial retrieval, duplicate identities, and scope violations
  fail closed.

### FG_RESULT_TRUTH_GATE — Expert-Approved Result Truth Release Authority

- **Implementation status:** COMPLETE — FGA-025 through FGA-028 and the result-truth
  implementation are proven by focused semantic, epistemic, complete-evidence, lineage,
  replay, and release-boundary tests.
- **Operational acceptance:** OPEN — this is the parent acceptance objective, not an
  authorized implementation item. Its immediate prerequisite is `CUSTOMER-ZERO-ACCEPT-001`.
- **Current blocker:** Current-SHA production acceptance evidence, durable recovery evidence, and
  the four production gate attestations remain missing.
- **Mandatory acceptance gates:** Production dependency security, production schema
  authority/closed-world RLS, canonical assessment proof, durable execution, and
  recovery/retention. All must pass before customer data access, report issuance, or L14
  closure.
- **Required invariants:**
  - deterministic findings, epistemic states, grounded claims, and posture are grounded in
    complete evidence and replay identically;
  - incomplete, malformed, stale, contradictory, or unsupported evidence cannot improve truth;
  - every material executive claim resolves to canonical finding/evidence lineage;
  - LLM failure or disagreement cannot alter deterministic posture.

### Next-item determination

**Reconciled 2026-10-01 (HEAD 2562e875).** TRUST-BINDING-001 is complete via #731: all three governance artifact types are cryptographically bound to the canonical Vault Transit trust authority (IDENTITY role for reports, APPROVAL for qualification decisions, ACCEPTANCE for delivery authorizations). Migrations 0193 + 0194 add trust columns to all three artifact tables; 42 adversarial tests confirm role separation, domain separation, and fail-closed behavior.

**Reconciled 2026-10-07 (HEAD 8d3dd55a).** Two Customer-Zero trust ceremony runs are ATTEMPTED_NOT_PROVEN due to two P0 defects now repaired: DEFECT-PROVENANCE-INTEGRITY (PROVENANCE-INTEGRITY-001, #750) and DEFECT-VERIFIER-CONTRACT (VAULT-VERIFY-CONTRACT-001, #751). State reconciled in CZ-RECONCILE-001 (#749). Both repairs are in `completed` in `customer_one/roadmap_authority.yaml`. CUSTOMER-ZERO-FINAL-READINESS-001 is COMPLETE (#753, c9717807). The **immediate next item** is `CUSTOMER-ZERO-RUN3-PREAUTH-001` — an offline pre-authorization gate with no paid infrastructure requirement. **Completion of CUSTOMER-ZERO-FINAL-READINESS-001 alone does NOT authorize CUSTOMER-ZERO-TRUST-003.** The required sequence is: CUSTOMER-ZERO-RUN3-PREAUTH-001 must close first, then explicit human cost authorization must be granted (prior $321.81 authorization is consumed) before `CUSTOMER-ZERO-TRUST-003` (paid HCP ceremony Run 3) may proceed. `CUSTOMER-ZERO-ACCEPT-001` remains the open acceptance parent and cannot execute until CUSTOMER-ZERO-TRUST-003 closes. Machine-readable authority: `customer_one/roadmap_authority.yaml`.

**Reconciled 2026-10-07 (HEAD current).** CUSTOMER-ZERO-FINAL-READINESS-001 COMPLETE (#753, c9717807). CUSTOMER-ZERO-RUN3-PREAUTH-001 is now the authorized NEXT item. Correct sequence: FINAL-READINESS (done) → PREAUTH → human cost authorization → TRUST-003 (paid). TRUST-003 remains BLOCKED until both PREAUTH closes and explicit cost authorization is granted.

**Reconciled 2026-10-08 (HEAD 49a662f9 — CZ-RUN3-PREAUTH-CLOSEOUT-001).** CUSTOMER-ZERO-RUN3-PREAUTH-001 COMPLETE (#755, 8de43e22). CZ-RUN3-READINESS-INTEGRATION-REPAIR-001 COMPLETE (#756, 49a662f9). Offline readiness independently verified: `customer_zero_final_readiness.py` result=READY (0 offline blockers); `customer_zero_run3_preauth.py` preauth_result=READY_FOR_HUMAN_COST_AUTHORIZATION (0 blockers). The immediate next item is `CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001` — an offline preparation activity covering the 16 deferred live checks checklist, candidate fingerprint rebinding, Terraform resource-plan review, HCP pricing confirmation, explicit cost/runtime ceilings, and human authorization preparation. This item does NOT provision infrastructure, does NOT begin Run 3, and does NOT authorize spending. TRUST-003 remains BLOCKED pending fresh explicit human cost authorization (prior $321.81 authorization consumed), live Vault/HCP ceremony execution, live CloudWatch audit proof, and all 16 deferred live checks. CUSTOMER-ZERO-ACCEPT-001 remains BLOCKED. Cost authorization = NOT_AUTHORIZED. No cloud mutations.

**Reconciled 2026-10-09 (HEAD 4b945df9 — CZ-RUN3-OPERATOR-PREFLIGHT-CLOSEOUT-001).** CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001 COMPLETE (#758, 4b945df9). CZ-RUN3-OPERATOR-PREFLIGHT-CLOSEOUT-001 governance reconciliation in progress (#759). All three offline evaluators verified post-merge: `customer_zero_final_readiness.py` result=READY (0 blockers); `customer_zero_run3_preauth.py` preauth_result=READY_FOR_HUMAN_COST_AUTHORIZATION (0 blockers); `customer_zero_run3_operator_preflight.py` preflight_status=PREPARED_FOR_HUMAN_REVIEW (0 blockers). The **immediate next item** is `CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001` — prepare the human cost-authorization review package (current HCP pricing, proposed max cost/runtime, authorization identity and expiration, source/candidate binding). This item does NOT authorize spending. Actual spending requires a separate explicit human decision. TRUST-003 remains BLOCKED: offline preparation complete (#750–#758) but outstanding: explicit human cost authorization, confirmed HCP pricing, proposed max cost/runtime, authorization identity/expiration, actual terraform plan review, HCP Vault provisioning, live ceremony, CloudWatch audit delivery, independent verification, all 16 deferred live checks, teardown evidence. CUSTOMER-ZERO-ACCEPT-001 remains BLOCKED. Cost authorization = NOT_AUTHORIZED. No cloud mutations.

### Run-3 operator preflight identity (post-#758 closeout)

The following values were produced by `customer_zero_run3_operator_preflight.py` evaluated at source SHA `4b945df9d712d6007ab87e8aeaa48353fabdce39` (canonical main after PR #758 merge, evaluated 2026-10-09). They are historical validation values that document the preflight package at the time of this closeout.

| Field | Value |
|-------|-------|
| Source SHA | `4b945df9d712d6007ab87e8aeaa48353fabdce39` |
| Preflight fingerprint (historical) | `61241d900f7b31243e37d07db36069886b38c4a181aa2d946b712ea3deb5730a` |
| Candidate fingerprint (historical) | `6be4bd7fa266bb5d9de72a3ecabe94a1e44095aa49db1c87e9e96937c1cf719d` |
| Infrastructure fingerprint (historical) | `303aa7d0bd8b8a864ee4900aaf2fd2cf11fa9ac6055d0a3f599ec9c2012e37dd` |
| Preflight result | `PREPARED_FOR_HUMAN_REVIEW` |
| Cost authorization | `NOT_AUTHORIZED` |
| Deferred live checks | `16` |

**Important rebinding requirement:** These are historical validation values. This closeout PR itself changes the source SHA (by adding governance files). Any future human cost authorization MUST bind to the then-current validated candidate after re-running all three evaluators on canonical main at that time. Cost authorization remains NOT_AUTHORIZED; proposed_max_cost_usd remains null.

### Run-3 validated candidate identity (post-#756 closeout)

The following values were produced by `customer_zero_run3_preauth.py` evaluated at source SHA `49a662f9240ec1733fc2c91d65fcc7661e9a3291` (canonical main after PR #756 merge, evaluated 2026-10-08). They are historical validation values that document the candidate frozen at the time of this closeout PR.

| Field | Value |
|-------|-------|
| Source SHA | `49a662f9240ec1733fc2c91d65fcc7661e9a3291` |
| Candidate fingerprint (historical) | `f7d6e1b967dcb9eefd2daa3a68125becac84bc6c5c5ba972acdf07c830fba6c3` |
| Infrastructure fingerprint (historical) | `303aa7d0bd8b8a864ee4900aaf2fd2cf11fa9ac6055d0a3f599ec9c2012e37dd` |
| Preauth result | `READY_FOR_HUMAN_COST_AUTHORIZATION` |
| Cost authorization | `NOT_AUTHORIZED` |
| Proposed max cost | `null` |

**Important rebinding requirement:** These are historical validation values. This closeout PR itself changes the source SHA (by adding governance files). Any future human cost authorization MUST bind to the then-current validated candidate after re-running `tools/ci/customer_zero_run3_preauth.py` on canonical main at that time. The historical fingerprints above document the pre-closeout candidate and are NOT valid authorization targets going forward. Cost authorization remains NOT_AUTHORIZED; proposed_max_cost_usd remains null.

**Reconciled 2026-10-09 (HEAD ec8684df — CZ-RUN3-FAILURE-PREVENTION-001 added to next_sequence).** CZ-RUN3-OPERATOR-PREFLIGHT-CLOSEOUT-001 merged (PR #759, SHA ec8684df). The adversarial failure-prevention audit `CZ-RUN3-FAILURE-PREVENTION-001` has been added to `next_sequence` ahead of `CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001`. This PR self-authorizes via the same governance-amendment pattern used by PRs #757 and #759 (the governance amendment is its first change). The audit is `OFFLINE_PREPARATION` only: zero new cloud spending, no trust advancement, no cost authorization, no paid infrastructure. It produces machine-readable findings, a failure-mode register, cost-containment plan, smoke-test contract, offline rehearsal specification, and a go/no-go decision artifact. `CUSTOMER_ZERO_TRUST=NOT_PROVEN`, `TRUST-003=BLOCKED`, `ACCEPT-001=BLOCKED`, `THIRD_PAID_CEREMONY=NOT_AUTHORIZED`, `COST_AUTHORIZATION=NOT_AUTHORIZED`.

| Candidate | Repository evidence | Disposition |
|---|---|---|
| FGA-028 — Grounded Determination & Executive Reporting Authority | PR #695/#696 are merged and strict post-merge validated; grounded claims and executive-report truth boundary are implemented. | **COMPLETED** — reconciled after strict validation. |
| `FG_RESULT_TRUTH_GATE` operational acceptance | Truth implementation and invariants are complete; current-SHA production acceptance evidence and downstream authority chain remain open. | **OPEN PARENT OBJECTIVE** — not independently authorized implementation work. |
| `FA-ACTOR-001` | #710/#711 prove canonical, current, tenant-bound, engagement-scoped human attribution for material Field Assessment mutations. | **COMPLETED** — implementation and post-merge evidence reconciled. |
| Artifact ownership & evidence storage | Existing report/export manifests and storage-key validation provide foundations; no current evidence shows this is the immediate blocker ahead of result truth. | Deferred until result truth is release-gated. |
| Production dependency security closure | Forensic audit records critical/high dependency advisories as mandatory before external access. | **MANDATORY FG_RESULT_TRUTH_GATE ACCEPTANCE GATE** — must pass before customer data access, report issuance, or L14 closure; no independent feature authorization. |
| Production schema authority / closed-world RLS | Audit identifies `create_all()` and migration/RLS census gaps as mandatory production prerequisites. | **MANDATORY FG_RESULT_TRUTH_GATE ACCEPTANCE GATE** — migrations-only schema authority and tenant RLS proof required before L14 closure. |
| Canonical assessment proof, durable execution, recovery/retention | Audit requires a current-SHA end-to-end proof plus recoverable execution and restore/retention evidence before accepting customer data. | **MANDATORY FG_RESULT_TRUTH_GATE ACCEPTANCE GATES** — required for Customer-One closure; implementation remains separately scoped and is not performed in this documentation PR. |

### L14 — Customer-One Commercial Execution

- **Status:** NEXT — parallel to engineering work; non-engineering tasks only.
- **Required tasks (all must be complete before L14 closes):**
  1. Design partner scheduled (confirmed calendar date with named contact).
  2. Price locked at $5,000.
  3. Commercial packet complete (deck, one-pager, terms).
  4. Stripe payment flow proven (test transaction or live).
  5. Founder review complete.
  6. Invoice issued and paid (final evidence gate).

---

## 6. DEFERRED (Freeze Law — blocked until named gate)

The following items are explicitly deferred. They are not authorized for work until the
named gate condition is met. Any proposal to undefer an item requires a Freeze Law
justification filed as a PR against `customer_one/roadmap_authority.yaml`.

| ID | Title | Deferred Until |
|----|-------|----------------|
| RAG-RETRY | RAG ingestion retry endpoint (currently returns 503) | Live client requires it |
| SAML | SAML support | Client 5 or first client with SAML requirement |
| FEDRAMP | FedRAMP preparation | Signed govcon LOI |
| PCI-PLAYBOOK | PCI DSS playbook | PCI client identified |
| GOV-SERVICES | Governance orchestration / simulation / digital twin services (`services/governance_orchestration/`, `governance_simulation/`, `governance_digital_twin/`) | Live client use case with signed requirement |
| NEW-CI-LANES | New CI lanes | Engineering team exceeds 3 engineers |
| CROSS-FINDING | Cross-finding correlation | After Customer-One — portal enhancement, not a blocker |
| PORTAL-AI-GATE | Remove `portal_ai_enabled` manual gate | Cleared by P-2 (QA auto-enable); no remaining Customer-One blocker |

---

## 7. Completed (Historical Record)

All items below are fully merged and production-proven unless otherwise noted.

| ID | Title | PRs |
|----|-------|-----|
| P1-01-PR2 | Canonical Delegation — FIAP path integration + auth_scopes enforcement | #690 (df1fc85f) — focused 154/1, fg-fast 496/2/22149, strict 22555/92, rc=0 |
| P-113.1–P-113.5 | Identity administration phases 1–5 | #639, #650, #651, #652, #653, #654, #655, #656, #657 |
| P-113.6 | Platform Admin Credential Authority | #677, #678, #679 |
| P-113.7 | Console canonical platform-admin cutover (production proven) | #680 |
| P-113.8 | Canonical Invitation Acceptance (production proven) | #680 |
| P-113.9 | Seamless Identity Verification | #681 |
| P-113.10 | Invitation-Authorized Identity Enrollment | #682 |
| P1-01-PR1 | Canonical Identity Authority PR-1 (tenant lifecycle OIDC gate) | #683 |
| TENANT-LIFECYCLE-OIDC-002 | Tenant lifecycle enforcement for all OIDC providers | #684 |
| FGA-025 | Domain health scale inversion + worst-case aggregation | #686 |
| FGA-026 | Evidence Sufficiency & Epistemic Authority | #687 |
| P0-ID-CUTOVER | Runtime Identity Authority Cutover | HARD-001 #657, migration 0183 — production proven (artifacts/identity/hard-002-production-proof.json) |
| REVENUE-GATE-1 | Revenue Gate 1 — all 12 items cleared | #539, #540, #544, P-1, FA-1, FA-2, R-1, R-2, P-2 |

---

## 8. How to Propose a New Item

If you believe a new capability must enter the critical path, follow this process:

1. **Draft a Freeze Law justification.** State which of the three criteria applies:
   - Customer-One blocker (what specific gate does this close, and how?)
   - Contracted customer requirement (attach or cite the signed document)
   - Risk/cost reduction (quantify: what failure mode, what probability change, what
     cost change?)

2. **File a PR against `customer_one/roadmap_authority.yaml`.** The PR must:
   - Add the new item to `next_sequence` (if authorized) or explain why it is not deferred.
   - Include the Freeze Law trigger in the item's `blocker_closed` field.
   - Include evidence (link to customer communication, defect report, or quantified
     risk argument) in the PR description.
   - State the Customer-One impact: what happens if this item is not done before
     Customer-One closes?

3. **Do not begin work until the PR merges.** The authority file is the gate. Starting
   work before the PR merges bypasses the Freeze Law and is not authorized.

4. **Verify your work class.** Before beginning any work, run:
   ```
   python tools/ci/check_customer_one_roadmap.py --work-class <CLASS>
   ```
   Exit 0 means authorized. Exit 1 means blocked. Work classes are `NEXT`, `REPAIR`,
   `DEFERRED`, and `UNKNOWN`. Undeclared classes are fail-closed (exit 1).
