# Customer-Zero Run-3 Failure Mode Register

**Document ID:** FAILURE-MODES-RUN3-001
**Audit:** CZ-RUN3-FAILURE-PREVENTION-001
**Canonical Source SHA:** ec8684df4699be43b40d1edc9a79b58fd23e3637
**Date:** 2026-10-09
**Classification:** OFFLINE_PREPARATION — no cloud spending, no trust advancement

---

## Purpose

This register reconstructs the failure modes from Customer-Zero trust ceremony Runs 1 and 2,
identifies residual risks for Run 3, and maps preventive controls and recovery actions for
each failure mode. It is a companion to the audit document
`docs/audits/customer_zero_run3_failure_prevention_001.md`.

---

## Historical Failure Modes (Runs 1 and 2)

### FM-001: DEFECT-PROVENANCE-INTEGRITY

| Field | Value |
|-------|-------|
| Failure ID | DEFECT-PROVENANCE-INTEGRITY |
| Historical occurrence | Both Runs 1 and 2 |
| Root cause | `verify_*` read stored `manifest_hash` without re-deriving from current `report_json`. DB-level mutation of `report_json` produced invalid proof that passed verification. |
| Financial impact | $321.81 total (shared with FM-002 — ceremonies ran but trust was not proven) |
| Trust impact | Customer-Zero trust NOT PROVEN; post-run acceptance blocked |
| Existing remediation | PROVENANCE-INTEGRITY-001 (PR #750, SHA 7a707cfb) |
| Preventive control | `_derive_manifest_hash_from_report_json()` helper added; content-binding pre-check at all three Vault verification sites |
| Detection point | Offline adversarial test suite (45 tests A–K); any future verify call |
| Recovery action | N/A — defect is repaired and tested |
| Residual risk | LOW — code-level repair with adversarial test coverage |
| Status | REPAIRED |

### FM-002: DEFECT-VERIFIER-CONTRACT

| Field | Value |
|-------|-------|
| Failure ID | DEFECT-VERIFIER-CONTRACT |
| Historical occurrence | Both Runs 1 and 2 |
| Root cause | Post-rotation cross-domain verification with differing key versions raised `VaultTransitError` instead of returning deterministic `False`. Non-deterministic error propagation violated the fail-closed boolean contract. |
| Financial impact | $321.81 total (shared with FM-001) |
| Trust impact | Customer-Zero trust NOT PROVEN |
| Existing remediation | VAULT-VERIFY-CONTRACT-001 (PR #751, SHA 8d3dd55a) |
| Preventive control | `VaultKeyVersionUnavailableError(VaultTransitError)` added; `VaultBackend.verify()` returns `False` for absent key versions; `TrustBindingAuthority.verify_*()` catches `VaultTransitError` → `False` (deterministic boolean at authority boundary) |
| Detection point | Offline adversarial test suite (51 tests A–N including root-cause regression); any verify path |
| Recovery action | N/A — defect is repaired and tested |
| Residual risk | LOW — all verify paths covered by adversarial tests |
| Status | REPAIRED |

### FM-003: CloudWatch Audit Proof Partial

| Field | Value |
|-------|-------|
| Failure ID | AUDIT-PROOF-PARTIAL |
| Historical occurrence | Both Runs 1 and 2 (partially) |
| Root cause | CloudWatch log group confirmed to receive Vault audit events, but ceremony failed before full proof capture and independent verification. Audit proof was present but not independently verified at ceremony closure. |
| Financial impact | Sunk cost within $321.81 |
| Trust impact | Audit proof incomplete for TRUST determination (CloudWatch confirmation alone is necessary but not sufficient) |
| Existing remediation | G-family live checks (G-VAULT-AUDIT-CLOUDWATCH, G-AUDIT-DELIVERY-CHECKPOINT) added to the 16 deferred live checks matrix; Checkpoint Q procedure documented in operator preflight runbook |
| Preventive control | Audit smoke test must pass before ceremony proceeds to signing proofs (see smoke test contract) |
| Detection point | Checkpoint Q audit smoke test — must execute before G-family checks |
| Recovery action | If Checkpoint Q fails: execute ABORT-POST-003 (controlled teardown) — do not proceed to trust ceremony |
| Residual risk | MEDIUM — live check deferred to ceremony; no offline substitute exists |
| Status | DEFERRED_TO_LIVE |

---

## Run-3 Pre-ceremony Risk Register

### RM-001: Stale Source SHA at Ceremony Time

| Field | Value |
|-------|-------|
| Risk ID | RM-001 |
| Category | Governance / Source Binding |
| Description | Each governance PR changes the source SHA. The frozen candidate fingerprint and simulation evidence bind to a prior SHA. If not regenerated before ceremony, evaluators fail. |
| Probability | HIGH — governance PRs have been frequent; the current simulation evidence is already stale (FP-002) |
| Financial impact | No direct cost; waste of operator preparation time if discovered late |
| Trust impact | Readiness evaluators return degraded results; ceremony cannot proceed |
| Preventive control | Regenerate simulation evidence on canonical main before cost review; re-run all three evaluators |
| Detection point | J_CE3 dimension in `customer_zero_final_readiness.py` |
| Recovery action | Regenerate evidence file and re-run evaluators (zero cost, offline) |
| Residual risk | LOW — detection is immediate and recovery is free |
| Status | ACTIVE (FP-002) |

### RM-002: HCP Pricing Change Since Runs 1 and 2

| Field | Value |
|-------|-------|
| Risk ID | RM-002 |
| Category | Cost / Authorization |
| Description | HCP Vault Dedicated pricing may have changed since Runs 1 and 2. The $321.81 historical figure cannot serve as a reliable ceiling for Run 3. |
| Probability | MEDIUM — HCP pricing is subject to change; cannot be confirmed offline |
| Financial impact | Authorized amount may be insufficient or based on stale pricing |
| Trust impact | None directly; authorization integrity at risk |
| Preventive control | Confirm pricing in HCP portal before cost authorization (FP-001) |
| Detection point | CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001 |
| Recovery action | Delay cost authorization until pricing is confirmed |
| Residual risk | LOW if confirmed before authorization |
| Status | ACTIVE (FP-001) |

### RM-003: Terraform Plan Drift

| Field | Value |
|-------|-------|
| Risk ID | RM-003 |
| Category | Infrastructure |
| Description | The Terraform plan reviewed offline may differ from the plan produced against a real HCP environment (new provider versions, changed defaults, drift from preserved AWS resources). |
| Probability | LOW-MEDIUM — preserved AWS resources have been stable since last teardown |
| Financial impact | Unexpected resource creation or modification during ceremony |
| Trust impact | Resource inventory fingerprint may not match what was reviewed |
| Preventive control | Run `terraform plan` (no apply) immediately before ceremony; compare to expected inventory |
| Detection point | Pre-ceremony terraform plan review (deferred live check PRE_PROVISIONING) |
| Recovery action | If plan shows unexpected changes: stop, investigate, do not apply |
| Residual risk | LOW if plan is reviewed before apply |
| Status | DEFERRED_TO_LIVE |

### RM-004: HCP Provisioning Timeout

| Field | Value |
|-------|-------|
| Risk ID | RM-004 |
| Category | Infrastructure / Cost |
| Description | HCP Vault Dedicated cluster provisioning may take longer than expected, consuming billable time before trust proofs begin. |
| Probability | LOW — provisioning was successful in Runs 1 and 2 |
| Financial impact | Additional hourly charges during extended provisioning |
| Trust impact | None if ceremony completes; ceremoney fails if hard abort deadline passes |
| Preventive control | Set hard abort deadline that accounts for expected provisioning time; monitor HCP status page before ceremony |
| Detection point | Wall-clock monitoring during provisioning |
| Recovery action | If provisioning exceeds expected time: stop and tear down (ABORT-CER-001); do not proceed to trust ceremony |
| Residual risk | LOW — proven successful in prior runs |
| Status | DEFERRED_TO_LIVE |

### RM-005: SecretID Compromise

| Field | Value |
|-------|-------|
| Risk ID | RM-005 |
| Category | Security |
| Description | AppRole SecretIDs for the three trust roles are created out-of-band and transferred directly to Railway secret storage. If compromised, an attacker could authenticate as a trust role. |
| Probability | LOW — secrets are not committed to Terraform state or any file |
| Financial impact | Potentially high if trust ceremony evidence is used maliciously |
| Trust impact | Trust proof integrity at risk if SecretIDs are compromised |
| Preventive control | SecretIDs are generated after provisioning; transferred directly via Railway UI; never stored in files or Terraform state; rotated immediately after ceremony |
| Detection point | Audit log review (Vault audit events to CloudWatch) |
| Recovery action | Revoke AppRole SecretIDs; rotate keys if compromise suspected; restart ceremony or treat trust as NOT PROVEN |
| Residual risk | LOW — standard AppRole security practices followed |
| Status | MITIGATED_BY_DESIGN |

### RM-006: Teardown Incomplete (Billable Resources Left Running)

| Field | Value |
|-------|-------|
| Risk ID | RM-006 |
| Category | Cost / Teardown |
| Description | The HCP Vault Dedicated cluster and HVN continue to accrue charges until destroyed. A partial teardown (stages 1-2 complete, stage 3 fails) leaves billable infrastructure running. |
| Probability | LOW — teardown was successful in Runs 1 and 2 |
| Financial impact | Ongoing hourly HCP charges until teardown completes |
| Trust impact | None (but financial risk is real) |
| Preventive control | Use four-stage teardown procedure; verify HCP portal shows cluster DELETED (not just Terraform state); capture billing evidence after teardown |
| Detection point | HCP portal cluster status; AWS cost explorer |
| Recovery action | Complete teardown; if stage fails, retry; if retry fails, destroy via HCP console directly |
| Residual risk | LOW — proven in prior runs |
| Status | DEFERRED_TO_LIVE |

---

## Summary

| Status | Count | Risk IDs |
|--------|-------|---------|
| REPAIRED | 2 | FM-001, FM-002 |
| DEFERRED_TO_LIVE | 2 | FM-003, RM-003 + RM-004 + RM-006 |
| ACTIVE (require action before ceremony) | 2 | RM-001 (FP-002), RM-002 (FP-001) |
| MITIGATED_BY_DESIGN | 1 | RM-005 |

The two ACTIVE risks (RM-001, RM-002) map to P1 findings FP-002 and FP-001 respectively. Both are resolvable without paid infrastructure. No failure mode independently prevents Run 3 from proceeding once cost authorization is obtained.
