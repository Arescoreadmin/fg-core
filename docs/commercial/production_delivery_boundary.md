# Production Delivery Boundary

**Date:** 2026-11-03
**Authority:** `docs/plans/revenue_first_roadmap_20261103.md` Sections 5 and 6; `customer_one/roadmap_authority.yaml`
**Baseline SHA:** `33964b27` (this branch HEAD)

This document states the mandatory production controls that must be proven before FrostGate may issue any production report or collect live client data. It does not weaken, skip, or reorder any existing gate.

---

## Commercial Proposals and SOWs May Be Executed Before These Blockers Close

Commercial proposals, SOWs, DPAs, and payment collection may proceed before all production controls are proven. The delivery condition for the signed report must be disclosed honestly in every proposal and SOW.

Clients may be scheduled and onboarded. Data collection may not proceed until mandatory controls are met.

---

## Mandatory Controls Before ANY Production Report May Be Issued

The following eight controls must all be confirmed before FrostGate may issue a production report or collect live client assessment data. All eight are required for OFFER A and OFFER B.

| Control | Type | Status at SHA 33964b27 | Resolution path |
|---------|------|----------------------|-----------------|
| **Vault Transit provisioned** (IDENTITY, APPROVAL, ACCEPTANCE keys) | Ops prerequisite | NOT PROVISIONED — no Vault instance running in production | Provision any compliant Vault instance (Vault OSS on Railway is lowest cost); requires explicit founder authorization before provisioning |
| **PRODUCTION_DEPENDENCY_SECURITY attested** | Operator attestation | ATTESTABLE NOW — P0-DEP-REM-001 (#786) closed all 108 advisories; CI gate is blocking | Founder attestation against existing CI evidence; no infrastructure spending required |
| **PRODUCTION_SCHEMA_AND_RLS attested** | Operator attestation | NOT_PROVEN | Operator audit of current migration state (0001–0194) and RLS policy state; no infrastructure spending required |
| **CANONICAL_ASSESSMENT_PROOF attested** | Operator attestation | NOT_PROVEN | Current-SHA end-to-end proof in pre-prod or staging; no production spending required |
| **DURABLE_EXECUTION_AND_RECOVERY attested** | Operator attestation | NOT_PROVEN | Restore drill at current schema (migration 0194) on Railway; no cloud spending required |
| **Mode B production authentication (PRODAUTH-RUN-001)** | Operator action | INTERACTIVE_AUTH_VERIFICATION=NOT_PROVEN | Execute Mode B runbook with `FG_PROD_AUTH_TEST_ENABLED=true`; uses existing production Auth0 and Railway deployment; no new infrastructure |
| **Portal live verification (PORTAL-RUN-001)** | Operator action | PORTAL_LIVE_VERIFICATION=NOT_PROVEN | Execute PORTAL-AUTH-E2E-001 operator runbook; requires pre-seeded approved report and named user invitation; uses existing portal deployment |
| **DELIV-001 confirmed** | Operator action | NOT_PROVEN | Confirm that an approved report artifact is downloadable by a portal named user in production; clears the last REJECTED_INCOMPLETE in portal E2E evidence |

---

## FG_RESULT_TRUTH_GATE Production Gates

The `FG_RESULT_TRUTH_GATE` controls are defined in `result_truth_gate.py:_REQUIRED_PRODUCTION_GATES`. They apply to all report issuance paths — OFFER A and OFFER B equally. They are Vault-independent human operator attestations.

| Gate | Vault-dependent | Status |
|------|----------------|--------|
| PRODUCTION_DEPENDENCY_SECURITY | No | ATTESTABLE NOW (P0-DEP-REM-001 #786) |
| PRODUCTION_SCHEMA_AND_RLS | No | NOT_PROVEN |
| CANONICAL_ASSESSMENT_PROOF | No | NOT_PROVEN |
| DURABLE_EXECUTION_AND_RECOVERY | No | NOT_PROVEN |

**All four gates must be attested before the FG_RESULT_TRUTH_GATE produces a QUALIFIED report.** A QUALIFIED report is required before governed delivery authorization can be issued.

---

## What Proving Each Gate Requires

None of the four FG_RESULT_TRUTH_GATE attestations require new cloud infrastructure or paid spending. They require operator time and attention.

**PRODUCTION_DEPENDENCY_SECURITY:**
P0-DEP-REM-001 (PR #786) evidence satisfies this gate. Founder attestation against existing CI evidence is sufficient. This gate is attestable now.

**PRODUCTION_SCHEMA_AND_RLS:**
Operator audit of:
- All migrations from 0001 to 0194 applied cleanly in production database
- RLS policies enabled and correct on all tenant-owned tables
- No schema drift between migration files and live production schema
Estimated time: 2–4 hours. No cloud spending.

**CANONICAL_ASSESSMENT_PROOF:**
Run a complete end-to-end assessment engagement at the current SHA (33964b27) in pre-production or staging:
- Create engagement, run all 13 connectors, complete questionnaire
- Generate and QA-approve a report
- Provision portal access and confirm named-user login
Estimated time: 1 day. Can run on Railway dev environment. No production spending.

**DURABLE_EXECUTION_AND_RECOVERY:**
Execute a restore drill from the most recent backup:
- Restore pre-engagement database backup to a test environment
- Confirm all assessment data, findings, reports, and portal access records are recoverable
- Confirm restore procedure is documented and tested
Estimated time: 2–4 hours. Can run on Railway. No cloud spending.

---

## Client Data Collection Requires Vault Transit Provisioning

After the four FG_RESULT_TRUTH_GATE gates are attested, client data collection requires Vault Transit to be provisioned. The report generation, qualification, and governed delivery routes all require Vault Transit (see `trust_binding.py` and TRUST-BINDING-001 PR #731).

**OFFER A minimum:** Any compliant Vault instance with three Transit keys (IDENTITY, APPROVAL, ACCEPTANCE). Vault OSS on Railway (~$5–10/month) satisfies this requirement. HCP Vault Dedicated is NOT required for OFFER A.

**OFFER B:** Requires HCP Vault Dedicated (CUSTOMER-ZERO-TRUST-003). This is BLOCKED on cost authorization (NOT_AUTHORIZED). Do not contract OFFER B until CUSTOMER-ZERO-TRUST-003 closes.

**Vault provisioning requires explicit founder authorization before any provisioning action.**

---

## What OFFER A Does NOT Require

The following items are explicitly NOT required before OFFER A launches. Do not block OFFER A on these.

| Item | Reason deferred |
|------|----------------|
| CUSTOMER-ZERO-TRUST-003 | OFFER B prerequisite only — HCP Vault Dedicated ceremony; cost NOT_AUTHORIZED |
| CUSTOMER-ZERO-ACCEPT-001 | OFFER B prerequisite only — production acceptance ceremony |
| Three-authority signing | OFFER B — assessor + reviewer + FrostGate seal; independent verifiability |
| HSM-backed key custody | OFFER B — HCP Vault requirement |
| FG_RESULT_TRUTH_GATE operational acceptance | OFFER B — this is CUSTOMER-ZERO-ACCEPT-001 (ceremony proof); NOT the same as the four gate attestations above |

---

## What OFFER B Requires (BLOCKED)

OFFER B requires everything in OFFER A, plus:
- CUSTOMER-ZERO-TRUST-003 (third paid HCP Vault ceremony) — BLOCKED on cost NOT_AUTHORIZED
- CUSTOMER-ZERO-ACCEPT-001 (current-SHA production acceptance evidence) — BLOCKED on TRUST-003
- Triple-signature production proof (assessor + reviewer + FrostGate seal in production)
- Independent verification bundle tested end-to-end against a real report
- OFFER B terms added to MSA/SOW

**Do not contract OFFER B until CUSTOMER-ZERO-ACCEPT-001 closes.**

---

## Authoritative References

- Level-2 sequencing: `docs/plans/customer_one_verified_governance_roadmap_20260910.md`
- Revenue-first framing: `docs/plans/revenue_first_roadmap_20261103.md`
- Roadmap authority: `customer_one/roadmap_authority.yaml`
- OFFER A/B boundary: `docs/plans/revenue_first_roadmap_20261103.md` Section 2
- FG_RESULT_TRUTH_GATE gates: `result_truth_gate.py:_REQUIRED_PRODUCTION_GATES`
- Trust binding: `services/governance/trust_binding.py`; TRUST-BINDING-001 PR #731
- Production gate attestation procedure: `docs/plans/revenue_first_roadmap_20261103.md` Section 4

---

*This document does not change any safety invariants, security controls, or production gates. It documents them accurately to support commercial planning. No gate is weakened, skipped, or declared complete by documentation.*
