# Revenue-First Roadmap — REVENUE-FIRST-ROADMAP-001

**Date:** 2026-11-03
**Authority:** Supplements `customer_one_verified_governance_roadmap_20260910.md` (Level-2)
**Baseline SHA:** `76520b9c` (main after PR #797)
**Scope:** Documentation and sequencing only — no product code changes.

---

## 1. Purpose and Reconciliation Mandate

The existing Level-2 sequencing authority (`customer_one_verified_governance_roadmap_20260910.md`)
correctly defines Customer-One as: invoice issued + invoice paid + portal accessed by named client
user + remediation roadmap opened and reviewed. That definition stands.

This document resolves one structural ambiguity in the current sequencing: the Level-2 doc
states that "L14 cannot close until `FG_RESULT_TRUTH_GATE` and all mandatory production gates
pass." `FG_RESULT_TRUTH_GATE` operational acceptance is blocked on `CUSTOMER-ZERO-ACCEPT-001`,
which is blocked on `CUSTOMER-ZERO-TRUST-003` (the third paid Vault ceremony). This creates
an implicit chain:

> first paid client → Vault triple-signing ceremony → cost authorization → HCP infrastructure

That chain is not architecturally necessary for the first engagement. FrostGate has two
commercially distinct offers with separate dependency trees. This document makes that
separation explicit.

**This document does not:**
- Authorize new engineering work
- Change safety invariants or security controls
- Authorize infrastructure spending
- Mark production proof complete based on simulation
- Weaken any existing gate

---

## 2. Two Distinct Commercial Offers

### OFFER A — Paid Assessment (Conventional)

A complete, QA-governed, delivered field assessment engagement. Reports are signed with an
Ed25519 key (single-authority, operator-held). The signing provides integrity and provenance
but is not independently verifiable by a third party without FrostGate's public key.

**What is contractually promised:**
- Assessor-led field data collection using 9+ connectors
- NIST AI RMF control coverage analysis
- QA-reviewed and QA-approved report
- Client portal access with named-user invitation flow
- Remediation roadmap and tracking
- Governed delivery with append-only audit trail

**What is NOT promised:**
- Independent cryptographic verifiability without FrostGate
- Three-authority signing (assessor + reviewer + FrostGate seal)
- Vault-backed key protection and rotation
- Zero-trust key custody or hardware security module

**Vault ceremony required:** NO

---

### OFFER B — Cryptographically Verifiable Assurance

Everything in OFFER A, plus a report signed by three independent authorities (assessor
attestation, independent reviewer attestation, FrostGate cryptographic issuance seal)
with keys protected by HashiCorp Vault Transit. The signing is independently verifiable
using the published verification bundle — the report bytes, manifest hash, and
multi-authority signatures are all self-contained and auditor-reproducible.

**What is additionally promised:**
- Assessor Ed25519 attestation over their authority domain
- Independent reviewer Ed25519 attestation with SoD enforcement
- FrostGate issuance seal (Vault Transit, key version bound)
- Verification bundle: report bytes + manifest + triple signatures independently replayable
- Key rotation and revocation with chain-of-custody records
- Production-proven in a live ceremony (CUSTOMER-ZERO-ACCEPT-001)

**Vault ceremony required:** YES — `CUSTOMER-ZERO-TRUST-003` must close first

**Current state:** CUSTOMER-ZERO-TRUST-003 is BLOCKED. `CUSTOMER_ZERO_TRUST=NOT_PROVEN`.
Cost authorization = NOT_AUTHORIZED. OFFER B is unavailable until these conditions clear.

---

## 3. Coverage Analysis — Existing Roadmap vs Revenue-First Priorities

### 3.1 P0 — FIRST PAID CLIENT prerequisites

| Requirement | Canonical source | Current status |
|-------------|-----------------|----------------|
| Production interactive authentication (console OIDC) | PROD-AUTH-AUTOMATION-001 | INTERACTIVE_AUTH_VERIFICATION=NOT_PROVEN — Mode B operator runbook not yet executed in production |
| Tenant context resolved at sign-in | AUTH-TENANT-CONTEXT-001 (PR #792) | Code merged; production proof NOT_PROVEN |
| Portal invitation → enrollment → named user binding | MODE-B-E2E-ACCEPTANCE-001 (PR #795) | Simulation 27/27 PASS; PORTAL_LIVE_VERIFICATION=NOT_PROVEN |
| Tenant and engagement isolation | P-113 identity series (#639–#690); RLS gates | Code proven in simulation; production isolation proof pending live execution |
| Assessment execution (connectors, findings, QA) | Phase 1 FA (PRs 1–45); REPORT-QA-001 (#713) | COMPLETE — merged and production-deployed |
| Governed client invitation and portal enrollment | MODE-B-E2E-ACCEPTANCE-001; PORTAL-AUTH-E2E-001 spec | Simulation complete; live enrollment NOT_PROVEN |
| Independent report QA and release | REPORT-QA-001 (#713) | COMPLETE |
| Governed delivery with integrity | GOV-DELIVERY-TRANSPORT-001 (#728/#729) | COMPLETE |
| Report delivered to portal named user (DELIV-001) | PORTAL-AUTH-E2E-001 / MODE-B-E2E-ACCEPTANCE-001 | NOT_PROVEN — no approved report artifact delivered to live portal user in production |
| Client contract, scope, pricing | L14 | OPEN — $5,000 price proposed; packet incomplete; no design partner confirmed |
| Billing (Stripe payment flow proven) | L14 task 4 | OPEN — Stripe webhook endpoint exists; test/live transaction NOT_PROVEN |
| Founder review | L14 task 5 | OPEN |
| Invoice issued and paid | L14 task 6 | OPEN |

**Gap summary:** The engineering foundation for OFFER A is complete. The remaining blockers
are (a) production operator execution of authentication and portal verification runbooks, and
(b) L14 commercial execution. No new feature development is required.

### 3.2 Conflict with existing Level-2 sequencing

The Level-2 doc states L14 cannot close until `FG_RESULT_TRUTH_GATE` passes. This gate
requires `CUSTOMER-ZERO-ACCEPT-001`, which requires `CUSTOMER-ZERO-TRUST-003` (Vault
ceremony, cost NOT_AUTHORIZED). **This conflation is incorrect for OFFER A.**

`FG_RESULT_TRUTH_GATE` operational acceptance concerns the production provenance of
cryptographic signing authority — it is the prerequisite for OFFER B, not OFFER A. The
implementation of `FG_RESULT_TRUTH_GATE` (FGA-025–028, complete) confirms the report
truth invariants and evidence chain are deterministic. What remains unproven is the
*production Vault signing ceremony*, which is an OFFER B prerequisite.

**Reconciled stance:** L14 can close for OFFER A without `FG_RESULT_TRUTH_GATE` operational
acceptance, provided:
1. Production interactive auth proof is executed (Mode B operator runbook)
2. Portal live verification is executed (PORTAL-AUTH-E2E-001 operator runbook)
3. All L14 commercial items are closed

OFFER B requires `FG_RESULT_TRUTH_GATE` operational acceptance before it can be contracted.

### 3.3 P1 — PREMIUM TRUST prerequisites

| Requirement | Canonical source | Current status |
|-------------|-----------------|----------------|
| Assessor attestation capability | TRUST-BINDING-001 (#731); evidence.py signing domain | COMPLETE (IDENTITY role) |
| Independent reviewer attestation with SoD | TRUST-BINDING-001 (#731) | COMPLETE (APPROVAL role) |
| FrostGate cryptographic issuance seal | TRUST-BINDING-001 (#731); VAULT-VERIFY-CONTRACT-001 (#751) | COMPLETE (ACCEPTANCE role) |
| Vault Transit key custody in production | CUSTOMER-ZERO-TRUST-003 | BLOCKED — awaiting cost authorization |
| Key rotation, revocation, recovery | Vault key management | BLOCKED — no live Vault instance |
| Independent signature verification | verify_evidence.py; portable verification authority | Code complete; production proof NOT_PROVEN |
| Triple-signature production proof | CUSTOMER-ZERO-ACCEPT-001 | BLOCKED on TRUST-003 |
| FG_RESULT_TRUTH_GATE operational acceptance | CUSTOMER-ZERO-ACCEPT-001 | BLOCKED on TRUST-003 |

### 3.4 P2 — RECURRING ASSURANCE prerequisites

| Requirement | Current status |
|-------------|----------------|
| Continuous monitoring infrastructure | P0-7 TIM, P0-8 ETCC, P0-11 CGCT — COMPLETE (code) |
| Automated verification and supersession | Verification Bundle V1 (PR #52) — COMPLETE |
| Historical trust lineage | Trust Intelligence Authority (PR 1.8A) — COMPLETE (code) |
| Enterprise verification APIs | Auditor Proof Package (PR 1.9) — COMPLETE (code) |
| Subscription packaging | P1.2–P1.5 billing/capability series — COMPLETE (code) |
| Live client using these features | NOT_PROVEN — no paying client |

P2 infrastructure exists. Activation requires a live client on OFFER A or B.

---

## 4. Canonical Revenue-First Execution Order

### P0 — First Paid Client (OFFER A)

These are the only items on the critical path to first invoice. They are listed in
execution order. No new engineering is required — these are operator actions and
commercial tasks.

| ID | Item | Type | Owner | Status |
|----|------|------|-------|--------|
| PRODAUTH-RUN-001 | Execute Mode B production authentication runbook | Operator | Founder | NOT_PROVEN — requires live Auth0 session, `FG_PROD_AUTH_TEST_ENABLED=true`, console and portal active |
| PORTAL-RUN-001 | Execute PORTAL-AUTH-E2E-001 operator runbook in production | Operator | Founder | NOT_PROVEN — requires invitation sent to named user, pre-seeded approved report, live portal session |
| DELIV-001-PROOF | Confirm DELIV-001: approved report artifact downloadable by portal named user | Operator | Founder | NOT_PROVEN — clears the last REJECTED_INCOMPLETE in portal E2E evidence |
| L14-DESIGN-PARTNER | Design partner scheduled (confirmed calendar date, named contact) | Commercial | Founder | OPEN |
| L14-PRICE | Price locked at $5,000 | Commercial | Founder | OPEN — $5,000 proposed |
| L14-PACKET | Commercial packet complete (deck, one-pager, MSA/SOW terms) | Commercial | Founder | OPEN |
| L14-STRIPE | Stripe payment flow proven (test or live transaction) | Commercial | Founder | OPEN — webhook configured; transaction NOT_PROVEN |
| L14-FOUNDER | Founder review complete | Commercial | Founder | OPEN |
| L14-INVOICE | Invoice issued and paid | Commercial | Founder | OPEN — final evidence gate |

**Recommended immediate commercial milestone:** Execute PRODAUTH-RUN-001 and PORTAL-RUN-001
this sprint. These are zero-cost operator actions that convert NOT_PROVEN gates to PROVEN and
unblock L14. Once both runbooks produce ACCEPTED evidence records, L14 can proceed in parallel
with no further engineering dependencies.

### P1 — Premium Trust (OFFER B)

These items must complete before OFFER B can be contracted. They are blocked on
cost authorization and should not be unblocked without explicit founder decision.

| ID | Item | Type | Blocker | Status |
|----|------|------|---------|--------|
| CZ-PRICING-FP001 | Confirm current HCP Vault Dedicated pricing (FP-001 open) | Operator | Requires live HCP portal login | OPEN |
| CZ-COST-AUTH | Explicit human cost authorization for CUSTOMER-ZERO-TRUST-003 | Founder decision | FP-001 must close first | NOT_AUTHORIZED |
| CUSTOMER-ZERO-TRUST-003 | Third paid HCP Vault ceremony | Engineering+Ops | Cost authorization | BLOCKED |
| CUSTOMER-ZERO-ACCEPT-001 | Current-SHA production acceptance evidence | Engineering | TRUST-003 | BLOCKED |
| OFFER-B-LEGAL | Update MSA/SOW to promise triple-signature verifiability | Legal/Commercial | ACCEPT-001 | BLOCKED |

**Do not contract OFFER B until CUSTOMER-ZERO-ACCEPT-001 closes.**

### P2 — Recurring Assurance

| ID | Item | Activation trigger |
|----|------|--------------------|
| SUBSCRIPTION-001 | Activate subscription packaging for second client | First client on OFFER A |
| CONTINUOUS-001 | Enable TIM/ETCC for continuous posture monitoring | First client active |
| ENTERPRISE-VERIFY-001 | Publish enterprise verification API | First OFFER B client |
| BENCHMARK-001 | Enable CGIN cross-tenant benchmarks | Three or more OFFER A clients |

---

## 5. P0 / P1 / P2 Release Criteria

### P0 — OFFER A may launch when:

1. `PRODAUTH-RUN-001`: Mode B authentication evidence record has `acceptance_decision=ACCEPTED`
   (all 14 checks pass in production, no NOT_PROVEN in required manifest).
2. `PORTAL-RUN-001`: PORTAL-AUTH-E2E-001 operator runbook produces evidence with DELIV-001=PASS
   (approved report downloadable by named portal user in production).
3. `L14-STRIPE`: Live or test Stripe transaction confirmed.
4. `L14-INVOICE`: Invoice issued and paid by named client.

No Vault ceremony. No CUSTOMER-ZERO-TRUST-003. No `FG_RESULT_TRUTH_GATE` operational
acceptance. The cryptographic integrity of OFFER A is provided by the Ed25519
`FG_REPORT_SIGNING_KEY` (operator-held), report manifest hash binding, and
append-only audit trail — sufficient for the conventional assessment market.

### P1 — OFFER B may launch when:

1. `CUSTOMER-ZERO-ACCEPT-001` closes with current-SHA production acceptance evidence.
2. `FG_RESULT_TRUTH_GATE` operational acceptance is confirmed (depends on ACCEPT-001).
3. Triple-signature production proof exists (all three authority domains signing in production).
4. Independent verification tested end-to-end against a real report (not simulation).
5. OFFER B terms added to MSA/SOW (what is contractually guaranteed about key custody,
   rotation, revocation, independent verifiability).

### P2 — Recurring Assurance activates when:

1. At least one paying OFFER A client is active.
2. Continuous monitoring is configured for the client's engagement.
3. SLA governance and automated drift alerting are operational.

---

## 6. Launch Blockers

### Blockers for OFFER A (P0)

| Blocker | Type | Resolution |
|---------|------|------------|
| INTERACTIVE_AUTH_VERIFICATION=NOT_PROVEN | Operator action | Execute PRODAUTH-RUN-001 — no engineering required |
| PORTAL_LIVE_VERIFICATION=NOT_PROVEN | Operator action | Execute PORTAL-AUTH-E2E-001 operator runbook — no engineering required |
| DELIV-001 NOT_PROVEN | Operator action | Pre-seed approved report; run portal runbook — no engineering required |
| L14 commercial items open | Commercial | Design partner, price, packet, Stripe, founder review, invoice |

**Engineering blockers for OFFER A: NONE.** The codebase is production-ready for OFFER A.
The remaining blockers are operator execution and commercial activity.

### Blockers for OFFER B (P1)

| Blocker | Type | Resolution |
|---------|------|------------|
| CUSTOMER-ZERO-TRUST-003 BLOCKED | Requires cost authorization | Founder must confirm HCP pricing (FP-001) and authorize spend |
| CUSTOMER-ZERO-ACCEPT-001 BLOCKED | Depends on TRUST-003 | Cannot proceed until TRUST-003 closes |
| FG_RESULT_TRUTH_GATE OPEN | Depends on ACCEPT-001 | Cannot close until ACCEPT-001 closes |

**Cost authorization status: NOT_AUTHORIZED.** No paid infrastructure may be provisioned
until explicit founder authorization after FP-001 (HCP pricing) is confirmed.

---

## 7. Report Signing Dependency Map

```
OFFER A (Conventional Assessment)
├── Report signed with FG_REPORT_SIGNING_KEY (Ed25519 seed, operator-held)
│   └── Single-authority: FrostGate issuance signature
│       Status: ACTIVE — PR 38 (report signing key set in production)
├── Manifest hash binds report content
│   └── PROVENANCE-INTEGRITY-001 — COMPLETE (PR #750)
├── Governed delivery transport with append-only audit
│   └── GOV-DELIVERY-TRANSPORT-001 — COMPLETE (PR #728/#729)
└── QA separation of duties
    └── REPORT-QA-001 — COMPLETE (PR #713)

OFFER B (Cryptographically Verifiable Assurance) [BLOCKED]
├── OFFER A foundation (above) — required as substrate
├── Assessor attestation (IDENTITY domain, Ed25519)
│   └── TRUST-BINDING-001 — COMPLETE (PR #731) [code only]
├── Independent reviewer attestation (APPROVAL domain, Ed25519)
│   └── TRUST-BINDING-001 — COMPLETE (PR #731) [code only]
├── FrostGate issuance seal (ACCEPTANCE domain, Vault Transit)
│   └── TRUST-BINDING-001 — COMPLETE (PR #731) [code only]
│   └── Vault Transit key protection — REQUIRES CUSTOMER-ZERO-TRUST-003
├── Production key custody (Vault HCP, us-east-1)
│   └── CUSTOMER-ZERO-TRUST-003 — BLOCKED (cost NOT_AUTHORIZED)
├── Key rotation and revocation with chain-of-custody
│   └── BLOCKED — no live Vault instance
├── Independent verification bundle (offline-capable)
│   └── verify_evidence.py + PortableVerificationAuthority — code complete
│   └── Production proof — BLOCKED on TRUST-003
└── CUSTOMER-ZERO-ACCEPT-001 (current-SHA production acceptance)
    └── BLOCKED on TRUST-003
```

**Critical distinction:** `FG_REPORT_SIGNING_KEY` (OFFER A) is a conventional Ed25519
seed stored as an environment variable. It provides report integrity but not independent
verifiability or key custody guarantees. Vault Transit (OFFER B) provides HSM-backed key
storage, rotation, revocation, and third-party auditability.

Do not represent OFFER A signing as equivalent to OFFER B signing in any client-facing
communication.

---

## 8. Smallest Documentation-Only PR

This document is that PR. No product code, schema, or CI policy changes are required.

The Level-2 sequencing authority (`customer_one_verified_governance_roadmap_20260910.md`) is
amended with a single addendum (Section 10 below) clarifying the OFFER A / OFFER B boundary
and explicitly de-coupling OFFER A launch from `FG_RESULT_TRUTH_GATE` operational acceptance.

No `customer_one/roadmap_authority.yaml` machine-readable update is proposed at this time
because the OFFER A/B distinction is a commercial framing clarification, not a re-sequencing
of authorized engineering work. The existing next_sequence remains valid.

---

## 9. Recommended Immediate Commercial Milestone

**This week:**
1. Founder executes `docs/deployment/runbook-prod-auth-automation-001.md` with
   `FG_PROD_AUTH_TEST_ENABLED=true` to produce a Mode B ACCEPTED evidence record.
2. Founder executes PORTAL-AUTH-E2E-001 operator runbook
   (`docs/plans/portal-auth-e2e-001.md`) to produce a portal live verification
   evidence record with DELIV-001=PASS.

Both are zero-cost operator actions. Combined elapsed time: estimated 2–4 hours.

**Once both evidence records are ACCEPTED:**
- L14 engineering dependencies are cleared.
- Founder can proceed to design partner outreach, price lock, and commercial packet.
- OFFER A is ready to sell.

**OFFER B:** Hold. No paid infrastructure until FP-001 (HCP pricing) confirmed and
explicit cost authorization issued by founder. The engineering is complete; the
investment decision has not been made.

---

## 10. What Does NOT Need to Change for OFFER A

The following items are explicitly NOT required before OFFER A launches:

| Item | Reason deferred |
|------|----------------|
| CUSTOMER-ZERO-TRUST-003 | OFFER B prerequisite only; cost NOT_AUTHORIZED |
| Vault Transit production keys | OFFER B — required for HSM-backed triple-signing only |
| CUSTOMER-ZERO-ACCEPT-001 | OFFER B prerequisite only |
| FG_RESULT_TRUTH_GATE operational acceptance | OFFER B prerequisite — implementation is proven; production ceremony is not |
| RAG retry endpoint (503) | Deferred per Level-2 doc freeze: "Live client requires it" |
| SAML support | Deferred: "Client 5 or first client with SAML requirement" |
| Governance Digital Twin / Simulation / Execution engine (PRs 18.8.x) | Deferred per Level-2 freeze law |

---

## 11. Security and Truth Preservation

The following invariants are explicitly preserved by this document:

- MFA: required by Mode B harness; BLOCKED cascade on MFA challenge
- Tenant isolation: RLS enforced; console/portal boundary verified (56 boundary tests)
- Engagement grants: portal named-user path enforces engagement binding (BIND-001–003)
- QA separation of duties: `governance:qa_approve` scope; assessor ≠ self-approver (SoD)
- Report integrity: manifest hash binding (PROVENANCE-INTEGRITY-001); append-only transport
- Authorization: fail-closed on unknown actor; RBAC + capability enforcement active
- Audit evidence: append-only governance decision ledger; H13 audit atomicity
- Release controls: mode B harness verifies acceptance semantics before evidence is accepted

**Production proof status is not invented:**
- `INTERACTIVE_AUTH_VERIFICATION=NOT_PROVEN` — recorded honestly
- `PORTAL_LIVE_VERIFICATION=NOT_PROVEN` — recorded honestly
- `CUSTOMER_ZERO_TRUST=NOT_PROVEN` — recorded honestly
- `COST_AUTHORIZATION=NOT_AUTHORIZED` — recorded honestly

No gate is weakened, skipped, or declared complete by simulation.
