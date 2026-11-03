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

A complete, QA-governed, delivered field assessment engagement. Reports are signed via
Vault Transit (IDENTITY trust domain, single-authority FrostGate issuance key). The signing
provides integrity and provenance but does not carry assessor attestation, reviewer
attestation, or independent verifiability.

> **Signing note:** The legacy `FG_REPORT_SIGNING_KEY` env-key path is explicitly rejected
> in the canonical production path (`trust_binding.py:19`). After TRUST-BINDING-001 (#731),
> all three lifecycle steps (report generation, qualification, delivery authorization)
> require Vault Transit. Any compliant Vault instance satisfies this — HCP Vault Dedicated
> is not required. No Vault instance is currently running in production.

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
- HSM-backed key custody or hardware security module
- Zero-trust key rotation and revocation chain

**HCP Vault Dedicated ceremony (CUSTOMER-ZERO-TRUST-003): NOT REQUIRED**
**Vault Transit (any compliant instance): REQUIRED for report signing**

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

### 3.2 Conflict with existing Level-2 sequencing — Corrected

The Level-2 doc states L14 cannot close until `FG_RESULT_TRUTH_GATE` passes. The original
draft of this document incorrectly stated that this gate concerns only the production Vault
signing ceremony and therefore does not apply to OFFER A. **That claim was wrong.**

`FG_RESULT_TRUTH_GATE` has four mandatory acceptance gates defined in runtime code
(`result_truth_gate.py:_REQUIRED_PRODUCTION_GATES`):

| Gate | Vault-dependent | Status |
|------|----------------|--------|
| `PRODUCTION_DEPENDENCY_SECURITY` | No | COMPLETE (P0-DEP-REM-001 #786) |
| `PRODUCTION_SCHEMA_AND_RLS` | No | NOT_PROVEN |
| `CANONICAL_ASSESSMENT_PROOF` | No | NOT_PROVEN |
| `DURABLE_EXECUTION_AND_RECOVERY` | No | NOT_PROVEN |

Gates 2–4 are Vault-independent human operator attestations required "before customer data
access, report issuance, or L14 closure" (Level-2 doc §5). They apply to OFFER A and
OFFER B equally.

The component that is OFFER B-specific is the **operational acceptance ceremony**:
`CUSTOMER-ZERO-ACCEPT-001` (requires CUSTOMER-ZERO-TRUST-003 / HCP Vault Dedicated,
cost NOT_AUTHORIZED). This ceremony proves the full triple-signing chain in production.
OFFER A does NOT require this ceremony — but it does require the other three gate
attestations.

**Additionally:** report generation, production qualification, and governed delivery
authorization all require Vault Transit signing (TRUST-BINDING-001 #731). No Vault
instance is currently running in production. Any compliant Vault satisfies this for
OFFER A — HCP Vault Dedicated is not required.

**Reconciled stance:** L14 can close for OFFER A without CUSTOMER-ZERO-ACCEPT-001 and
without CUSTOMER-ZERO-TRUST-003, provided:
1. Vault Transit provisioned (any compliant instance) with three trust keys.
2. Gates 2–4 attested by operator at current SHA.
3. Mode B and portal runbooks executed (PRODAUTH-RUN-001, PORTAL-RUN-001).
4. All L14 commercial items closed.

OFFER B additionally requires CUSTOMER-ZERO-TRUST-003 and CUSTOMER-ZERO-ACCEPT-001.

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
| VAULT-PROVISION-001 | Provision Vault Transit with IDENTITY, APPROVAL, ACCEPTANCE keys | Ops | Founder | OPEN — no Vault instance running; HCP Vault Dedicated NOT required; self-hosted Vault OSS is sufficient; subject to founder approval before provisioning |
| GATE-ATTEST-DEPENDENCY | Attest `PRODUCTION_DEPENDENCY_SECURITY` | Operator attestation | Founder | ATTESTABLE NOW — P0-DEP-REM-001 (#786) closed all 108 advisories; CI gate is blocking |
| GATE-ATTEST-SCHEMA | Attest `PRODUCTION_SCHEMA_AND_RLS` | Operator attestation | Founder | OPEN — requires operator audit of current migrations + RLS policy state; no infra spending required |
| GATE-ATTEST-PROOF | Attest `CANONICAL_ASSESSMENT_PROOF` | Operator attestation | Founder | OPEN — requires current-SHA end-to-end proof; can run in pre-prod or staging |
| GATE-ATTEST-RECOVERY | Attest `DURABLE_EXECUTION_AND_RECOVERY` | Operator attestation | Founder | OPEN — requires restore drill at current schema (migration 0194); can run on Railway |
| PRODAUTH-RUN-001 | Execute Mode B production authentication runbook | Operator | Founder | NOT_PROVEN — requires live Auth0 session, `FG_PROD_AUTH_TEST_ENABLED=true` |
| PORTAL-RUN-001 | Execute PORTAL-AUTH-E2E-001 operator runbook in production | Operator | Founder | NOT_PROVEN — requires invitation sent to named user, pre-seeded approved report, live portal session |
| DELIV-001-PROOF | Confirm DELIV-001: approved report artifact downloadable by portal named user | Operator | Founder | NOT_PROVEN — clears the last REJECTED_INCOMPLETE in portal E2E evidence |
| L14-DESIGN-PARTNER | Design partner scheduled (confirmed calendar date, named contact) | Commercial | Founder | OPEN |
| L14-PRICE | Price locked at $5,000 | Commercial | Founder | OPEN — $5,000 proposed |
| L14-PACKET | Commercial packet complete (deck, one-pager, MSA/SOW terms) | Commercial | Founder | OPEN |
| L14-STRIPE | Stripe payment flow proven (test or live transaction) | Commercial | Founder | OPEN — webhook configured; transaction NOT_PROVEN |
| L14-FOUNDER | Founder review complete | Commercial | Founder | OPEN |
| L14-INVOICE | Invoice issued and paid | Commercial | Founder | OPEN — final evidence gate |

**Recommended immediate actions (zero infrastructure cost):**
- GATE-ATTEST-DEPENDENCY: attestable now from existing CI evidence.
- GATE-ATTEST-SCHEMA and GATE-ATTEST-PROOF: verification work only; no cloud provisioning.
- GATE-ATTEST-RECOVERY: restore drill on Railway.
- VAULT-PROVISION-001: requires founder decision on Vault hosting approach (see Section 12).

None of these require new feature code.

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

1. `VAULT-PROVISION-001`: Vault Transit provisioned with IDENTITY, APPROVAL, ACCEPTANCE
   keys and env vars set in production (any compliant instance — not HCP-required).
2. All four `FG_RESULT_TRUTH_GATE` production gates attested by operator:
   `PRODUCTION_DEPENDENCY_SECURITY` (now attestable), `PRODUCTION_SCHEMA_AND_RLS`,
   `CANONICAL_ASSESSMENT_PROOF`, `DURABLE_EXECUTION_AND_RECOVERY`.
3. `PRODAUTH-RUN-001`: Mode B authentication evidence record has `acceptance_decision=ACCEPTED`.
4. `PORTAL-RUN-001`: PORTAL-AUTH-E2E-001 operator runbook produces evidence with DELIV-001=PASS.
5. `L14-STRIPE`: Live or test Stripe transaction confirmed.
6. `L14-INVOICE`: Invoice issued and paid by named client.

No CUSTOMER-ZERO-TRUST-003 (HCP Vault Dedicated). No CUSTOMER-ZERO-ACCEPT-001 (ceremony
acceptance proof). No triple-signing. The four production quality gate attestations and
Vault Transit signing (single-authority IDENTITY domain) are sufficient for the conventional
assessment market.

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
| Vault Transit not provisioned | Ops prerequisite | Provision any compliant Vault instance with 3 transit keys; HCP Vault Dedicated NOT required; subject to founder approval (see Section 12) |
| `PRODUCTION_SCHEMA_AND_RLS` not attested | Operator attestation | Operator audit of current migration/RLS state; no infrastructure spending required |
| `CANONICAL_ASSESSMENT_PROOF` not attested | Operator attestation | Current-SHA end-to-end proof in pre-prod/staging; no production spending required |
| `DURABLE_EXECUTION_AND_RECOVERY` not attested | Operator attestation | Restore drill at current schema; can be executed on Railway |
| `PRODUCTION_DEPENDENCY_SECURITY` not attested | Operator attestation | Attestable now — P0-DEP-REM-001 (#786) evidence satisfies this gate |
| INTERACTIVE_AUTH_VERIFICATION=NOT_PROVEN | Operator action | Execute PRODAUTH-RUN-001 |
| PORTAL_LIVE_VERIFICATION=NOT_PROVEN | Operator action | Execute PORTAL-AUTH-E2E-001 operator runbook |
| DELIV-001 NOT_PROVEN | Operator action | Pre-seed approved report; run portal runbook |
| L14 commercial items open | Commercial | Design partner, price, packet, Stripe, founder review, invoice |

**No new feature code required.** All remaining OFFER A blockers are infrastructure
provisioning (Vault, founder-approved), operator attestations (verification work at current
SHA, no cloud spending), operator runbook execution, and commercial activity.

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
├── Report signed via Vault Transit (IDENTITY domain, trust_binding.py:DOMAIN_REPORT)
│   └── Single-authority: FrostGate issuance key — TRUST-BINDING-001 (#731)
│       Code: COMPLETE. Production: NOT_PROVEN (no Vault instance running).
│       Note: FG_REPORT_SIGNING_KEY explicitly rejected in canonical production path.
├── Production qualification (APPROVAL domain, trust_binding.py:DOMAIN_QUALIFICATION)
│   └── Requires all 4 FG_RESULT_TRUTH_GATE attestations + truth gate PASS
│       Code: COMPLETE. Production attestations: 1/4 proven (PROD_DEP_SEC via #786).
├── Governed delivery authorization (ACCEPTANCE domain, trust_binding.py:DOMAIN_DELIVERY_AUTHORIZATION)
│   └── GOV-DELIVERY-TRANSPORT-001 — COMPLETE (PR #728/#729). Requires QUALIFIED.
├── Manifest hash binds report content
│   └── PROVENANCE-INTEGRITY-001 — COMPLETE (PR #750)
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

| Item | Reason deferred / not required |
|------|--------------------------------|
| CUSTOMER-ZERO-TRUST-003 | OFFER B prerequisite only — HCP Vault Dedicated ceremony; cost NOT_AUTHORIZED |
| CUSTOMER-ZERO-ACCEPT-001 | OFFER B prerequisite only — HCP ceremony acceptance proof |
| Three-authority signing | OFFER B — assessor + reviewer + FrostGate seal; independent verifiability |
| HSM-backed key custody / HCP Vault | OFFER B — required for key custody and rotation guarantees contractually promised in OFFER B |
| RAG retry endpoint (503) | Deferred per Level-2 doc freeze: "Live client requires it" |
| SAML support | Deferred: "Client 5 or first client with SAML requirement" |
| Governance Digital Twin / Simulation / Execution engine (PRs 18.8.x) | Deferred per Level-2 freeze law |

> **Note:** `FG_RESULT_TRUTH_GATE` **production quality gate attestations** (PRODUCTION_SCHEMA_AND_RLS,
> CANONICAL_ASSESSMENT_PROOF, DURABLE_EXECUTION_AND_RECOVERY) are NOT deferred for OFFER A.
> They are mandatory for all report issuance. Vault Transit provisioning is also required for
> report signing. See Section 6 for the complete OFFER A blocker list.

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

---

## 12. Vault Transit Minimum Requirements for OFFER A

TRUST-BINDING-001 (#731) requires three Vault Transit keys for the full OFFER A lifecycle:

| Signing domain | Trust role | Required for |
|----------------|-----------|--------------|
| IDENTITY (`frostgate.report-proof.v1`) | Report generation | `generate_report_route` |
| APPROVAL (`frostgate.production-qualification.v1`) | Qualification decision | `qualify_report_finalize_route` |
| ACCEPTANCE (`frostgate.governed-delivery-authorization.v1`) | Delivery authorization | `governed_delivery_route` |

The three keys may reside on the **same** Vault instance. Domain separation is enforced by
payload prefix, not by key isolation across different servers. The three-key design prevents
cross-artifact forgery (an IDENTITY signature cannot be replayed as a QUALIFICATION
signature), not independent organizational custody — that is an OFFER B feature.

### Minimum viable Vault configurations for OFFER A

The following options are presented for founder review. None has been approved. No
provisioning may occur without explicit founder authorization.

| Option | Description | Approx. cost | HA | Key custody |
|--------|-------------|-------------|-----|-------------|
| **A — Vault OSS on Railway** | Add Vault service to existing Railway project; file-system storage backend; single node | +~$5–10/mo (Railway resource) | None | Operator-managed |
| **B — Vault OSS on a VPS** | Dedicated VPS (DigitalOcean, Linode, etc.); Vault with file or PostgreSQL backend | ~$5–12/mo | None | Operator-managed |
| **C — HCP Vault Dedicated (Standard Small)** | Fully managed, HSM-backed, us-east-1; the same infrastructure proposed for CUSTOMER-ZERO-TRUST-003 | ~$300–500/mo ongoing; ceremony ~$321/hr | Full HA | HCP-managed (HSM) |

**Option A** (Railway) is the lowest-cost path and reuses existing infrastructure. It
satisfies the technical Vault Transit requirement for OFFER A. It does NOT satisfy the HSM
key custody, rotation-with-revocation, or independent-auditability requirements that OFFER B
contractually promises.

**Option C** (HCP Vault Dedicated) would satisfy both OFFER A and OFFER B requirements,
but its cost is significantly higher and was previously NOT_AUTHORIZED. Using Option C for
OFFER A would also move closer to unblocking CUSTOMER-ZERO-TRUST-003 (OFFER B), but would
require explicit cost authorization.

### Required env vars (all options)

```
FG_CUSTOMER_ZERO_VAULT_ADDR=<vault_addr>
FG_CUSTOMER_ZERO_VAULT_AUTH_MODE=approle
FG_CUSTOMER_ZERO_IDENTITY_VAULT_ROLE_ID=<...>
FG_CUSTOMER_ZERO_IDENTITY_VAULT_SECRET_ID=<...>
FG_CUSTOMER_ZERO_APPROVAL_VAULT_ROLE_ID=<...>
FG_CUSTOMER_ZERO_APPROVAL_VAULT_SECRET_ID=<...>
FG_CUSTOMER_ZERO_ACCEPTANCE_VAULT_ROLE_ID=<...>
FG_CUSTOMER_ZERO_ACCEPTANCE_VAULT_SECRET_ID=<...>
FG_CUSTOMER_ZERO_IDENTITY_KEY_ID=<transit_key_name>
FG_CUSTOMER_ZERO_APPROVAL_KEY_ID=<transit_key_name>
FG_CUSTOMER_ZERO_ACCEPTANCE_KEY_ID=<transit_key_name>
FG_CUSTOMER_ZERO_VAULT_ISSUER=<issuer_label>
```

### Which requirements can be completed without infrastructure provisioning

| Requirement | Infrastructure needed? | Notes |
|-------------|----------------------|-------|
| `PRODUCTION_DEPENDENCY_SECURITY` attest | No | P0-DEP-REM-001 (#786) evidence is available now |
| `PRODUCTION_SCHEMA_AND_RLS` attest | No | Operator audit of migration state and RLS policies |
| `CANONICAL_ASSESSMENT_PROOF` attest | No (pre-prod) | Current-SHA E2E proof can run against Railway dev/staging |
| `DURABLE_EXECUTION_AND_RECOVERY` attest | No | Restore drill on Railway from existing backup |
| PRODAUTH-RUN-001 | No new infra | Uses existing production Auth0 + Railway deployment |
| PORTAL-RUN-001 | No new infra | Uses existing portal deployment |
| L14 commercial items | No | Sales, pricing, legal, billing |
| Vault Transit provisioning | YES — requires founder authorization | Option A or B; see table above |

**All four FG_RESULT_TRUTH_GATE gate attestations and all operator runbooks can be
completed without provisioning new infrastructure.** Only Vault Transit requires a new
provisioning decision.
