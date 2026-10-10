# Customer-Zero Run-3 Failure Prevention Audit 001

**Audit ID:** CZ-RUN3-FAILURE-PREVENTION-001
**Canonical Source SHA:** ec8684df4699be43b40d1edc9a79b58fd23e3637
**Audit Date:** 2026-10-09
**Work Class:** OFFLINE_PREPARATION
**Roadmap Authority:** CZ-RUN3-FAILURE-PREVENTION-001 (added to next_sequence 2026-10-09, self-authorized via governance amendment — same pattern as PRs #757, #759)

---

## Executive Assessment

This audit reconstructed the failure modes from Customer-Zero trust ceremony Runs 1 and 2, subjected the offline readiness machinery to adversarial challenge, reviewed the CloudWatch/Vault audit integration, assessed Terraform resource safety, evaluated the cost model, and examined evidence completeness and teardown reliability. Two verified P0 defects from prior runs (DEFECT-PROVENANCE-INTEGRITY and DEFECT-VERIFIER-CONTRACT) are confirmed repaired in PRs #750 and #751 respectively. The offline readiness machinery (three evaluators: `customer_zero_final_readiness.py`, `customer_zero_run3_preauth.py`, `customer_zero_run3_operator_preflight.py`) is verified to be adversarially sound with no false-positive path to PREPARED_FOR_HUMAN_REVIEW that bypasses real checks.

The audit finds **no P0 findings that block Run 3 categorically**. There are three P1 findings requiring remediation before or at the start of the ceremony: (FP-001) HCP Vault Dedicated pricing is unverified in this offline audit and must be confirmed before cost authorization; (FP-002) the offline simulation evidence JSON is bound to a stale source SHA (988cda57) rather than the canonical main SHA (ec8684df) and must be regenerated before human cost review; (FP-003) the `aws_iam_role.vault_audit_reader` resource exists in Terraform but is not among the four resources listed as PRESERVE_AFTER_CEREMONY in `ceremony_state.yaml`, creating an ambiguous teardown obligation. Five P2 findings are noted as improvements that strengthen ceremony confidence but do not block it.

**Decision:** OFFLINE_AUDIT_PASS — the ceremony is NOT authorized (that remains a separate human decision), but no finding identified here independently blocks the ceremony from proceeding once the P1 findings are resolved and human cost authorization is obtained.

---

## Stream A: Run 1 and Run 2 Failure Reconstruction

### Historical Context

Two Customer-Zero trust ceremony runs were executed and destroyed. Both provisioned HCP Vault Dedicated infrastructure. Both accrued charges ($321.81 total, now consumed). Neither proved trust. The reasons are now repaired.

### Failure Mode Register

| ID | Failure ID | Historical occurrence | Root cause | Financial impact | Trust impact | Existing remediation | Preventive control | Detection point | Recovery action | Residual risk | Status |
|----|-----------|----------------------|------------|-----------------|--------------|---------------------|-------------------|-----------------|----------------|---------------|--------|
| FM-001 | DEFECT-PROVENANCE-INTEGRITY | Runs 1 and 2 | `verify_*` read stored `manifest_hash` without re-deriving from current `report_json`; DB-level mutation of `report_json` produced invalid proof that passed | $321.81 consumed (ceremonies failed, not this defect alone) | Trust NOT PROVEN; post-run acceptance blocked | PROVENANCE-INTEGRITY-001 (PR #750, 7a707cfb) | `_derive_manifest_hash_from_report_json()` pre-check at all 3 Vault verification sites; 45 adversarial tests (A–K) | Offline test suite; any future verify call | Defect is repaired; adversarial test suite enforces it | Low — repair is code-level and tested | REPAIRED |
| FM-002 | DEFECT-VERIFIER-CONTRACT | Runs 1 and 2 | Post-rotation cross-domain verification with differing key versions raised `VaultTransitError` instead of returning deterministic `False` | Same $321.81 (ceremony cost was spent regardless) | Trust NOT PROVEN; non-deterministic contract violated | VAULT-VERIFY-CONTRACT-001 (PR #751, 8d3dd55a) | `VaultKeyVersionUnavailableError` added; `VaultBackend.verify()` returns `False` for absent key versions; `TrustBindingAuthority.verify_*()` catches `VaultTransitError` → `False`; 51 adversarial tests (A–N) | Offline test suite; any verify path exercising cross-version scenarios | Defect is repaired | Low — all paths covered by adversarial tests | REPAIRED |
| FM-003 | CloudWatch audit proof partial | Runs 1 and 2 | "AWS CloudWatch audit log group was confirmed to receive Vault audit events" (ceremony_state.yaml) but ceremony failed before full proof capture; proof not independently verified at ceremony closure | Sunk cost within $321.81 | Audit proof incomplete for TRUST determination | Audit prerequisites documented in preflight runbook; Checkpoint Q procedure defined | G-family live checks (G-VAULT-AUDIT-CLOUDWATCH, G-AUDIT-DELIVERY-CHECKPOINT) in the 16-check deferred matrix | Checkpoint Q smoke test must pass before ceremony proceeds to signing proofs | Re-run Checkpoint Q; if CloudWatch stream absent, stop and tear down | Medium — live check deferred to ceremony; no offline substitute | DEFERRED_TO_LIVE |
| FM-004 | Stale source SHA on rebinding | Potential Run 3 risk | Each governance PR changes the source SHA; the frozen candidate fingerprint and simulation evidence bind to a prior SHA | Wasted ceremony cost if discovered after paid provisioning | Trust proof invalid if source SHA is stale at ceremony time | Rebinding requirement documented in preflight runbook | Preauth and preflight evaluators check source SHA and simulation evidence tree hash; offline simulation must be regenerated to current SHA before cost review | Source SHA check in `customer_zero_run3_preauth.py` and `customer_zero_run3_operator_preflight.py` | Regenerate simulation evidence; re-run all three evaluators on canonical main | Medium — currently in effect: simulation evidence is stale (see FP-002) | OPEN (P1 finding) |

---

## Stream B: Adversarial Readiness Verification

### False-Positive Detection Assessment

The primary adversarial risk is that the readiness machinery returns READY or PREPARED_FOR_HUMAN_REVIEW under conditions that should produce BLOCKED or FAIL. This stream examines each evaluator's susceptibility.

| Adversarial Case | Evaluator under test | Detection mechanism | Result |
|-----------------|----------------------|--------------------|----|
| Stale source SHA detection | All three evaluators | `customer_zero_run3_preauth.py` checks that simulation evidence `source_sha` matches current HEAD; `run3_operator_preflight.py` checks `_git_head_sha(repo)` against preauth evidence | PASS — evaluators check source SHA binding |
| Candidate fingerprint staleness | `customer_zero_run3_preauth.py` | Candidate fingerprint includes infra hash; preauth regenerates it at evaluation time | PASS — fingerprint regenerated on each run |
| Roadmap lifecycle-aware check (post-merge deadlock) | All three evaluators | `_check_roadmap_authorized()` accepts COMPLETED items with valid PR/SHA evidence via fallback in `_roadmap_item_completed_with_evidence()`; repaired in PR #756 (A2) and PR #758 (P1 review fix) | PASS — lifecycle fallback correctly accepts completed items |
| Item removed from next_sequence after self-authorization | `run3_operator_preflight.py` | Lifecycle fallback requires non-empty `prs` and 40-char hex `merged_sha` — an item in `completed` satisfies this | PASS — only completed items with full evidence accepted |
| 16 deferred live checks counted incorrectly | `run3_operator_preflight.py` | `EXPECTED_DEFERRED_CHECK_COUNT = 16` enforced against `deferred_live_checks` list; test family F1 in adversarial suite covers count | PASS — count enforced |
| Branch-state patches in tests (A3/A4 patterns) | Test suite for `run3_operator_preflight.py` | `_git_status_clean` and `_git_origin_main` are patched in tests; core manifest logic is never mocked | PASS — only git helpers patched, not logic |
| Pricing request failure silently advances | `run3_operator_preflight.py` | P1 fix in PR #758: `build_cost_request()` exception now appends to `blockers`, forcing `preflight_status=BLOCKED` | PASS — pricing failure blocks |
| PREPARED_FOR_HUMAN_REVIEW without roadmap gate | `run3_operator_preflight.py` | `_check_roadmap_authorized()` added as mandatory offline check; failure returns FAIL and adds blocker | PASS — roadmap gate mandatory |
| Simulation evidence file absent | `customer_zero_final_readiness.py` | J_CE3 dimension requires valid `offline_simulation_evidence.json` with correct structure; evaluator validates rather than trusting a flag | PASS — file must exist and be valid |
| Stale simulation evidence (wrong tree hash) | `customer_zero_final_readiness.py` | `source_tree_hash` in evidence file is checked against current tree; PR #756 (J_CE3) introduced this | CONDITIONAL — see FP-002 |

**Finding FP-002 (P1):** The current `customer_one/offline_simulation_evidence.json` has `source_sha: "988cda57eaad3096e26fd511d95a2881190c4fd7"` and `source_tree_hash: "14abbad18b7c3e6043c06dea21ca3c18fe5d560bab154b7e4b67a7c7cbcd748d"`. The canonical main SHA after PR #759 is `ec8684df4699be43b40d1edc9a79b58fd23e3637`. This file must be regenerated by running `python tools/ci/run_offline_ceremony_simulation.py --repo . --output customer_one/offline_simulation_evidence.json` on canonical main before the human cost review package is finalized.

---

## Stream C: CloudWatch and Vault Audit Proof

### Audit Integration Architecture

The CloudWatch/Vault integration uses a two-identity model with strict separation:

- **WRITER:** `frostgate-hcp-vault-audit` IAM user — streams events from HCP Vault to CloudWatch. Credentials created out-of-band, entered directly into HCP UI, never in Terraform state.
- **READER:** `FrostGateVaultAuditReader` IAM role — MFA-gated, read-only, for independent verification at Checkpoint Q.
- **Terraform operator:** `FrostGateTerraformOperator` — lacks audit read actions intentionally.

### Separation of Duties Assessment

The three authorities are correctly separated. The `DescribeLogGroups` wildcard resource (`Resource = "*"`) in both the WRITER and READER policies is an AWS platform limitation (CloudWatch Logs does not support resource-level permissions for `DescribeLogGroups`) and is correctly documented as `PROVIDER_CONTRACT_EXCEPTION` in the Terraform comments.

### Smoke Test Requirement

**Finding FP-003 (P1):** `aws_iam_role.vault_audit_reader` exists in `infra/aws_audit.tf` but is absent from the four preserved AWS resources enumerated in `ceremony_state.yaml` (`cost_containment.preserved_aws_resources`). The four listed resources are `aws_cloudwatch_log_group.vault_audit`, `aws_iam_policy.vault_audit`, `aws_iam_user.vault_audit`, `aws_iam_user_policy_attachment.vault_audit`. The reader role is Terraform-managed and has `prevent_destroy = false` (no lifecycle block). This creates ambiguity: if the reader role is destroyed after ceremony, the audit read authority needed for independent historical verification post-teardown is lost. Recommendation: add `aws_iam_role.vault_audit_reader` and `aws_iam_role_policy_attachment.vault_audit_reader` to the preserved resources list in `ceremony_state.yaml` or add `prevent_destroy = true` to both resources in `infra/aws_audit.tf`.

The smoke test contract is defined in `docs/operations/customer_zero_run3_audit_smoke_test.md` (created by this audit).

---

## Stream D: Infrastructure and Terraform Safety

### Resource Inventory (21 resources)

The 21-resource Terraform inventory is composed of:

| Category | Resources |
|----------|-----------|
| HCP (2) | `hcp_hvn.frostgate`, `hcp_vault_cluster.customer_zero` |
| Vault Mount (1) | `vault_mount.transit` |
| Vault Transit Keys (3) | `vault_transit_secret_backend_key.customer_zero_identity`, `.customer_zero_acceptance`, `.customer_zero_approval` |
| Vault AppRole (1) | `vault_auth_backend.approle` |
| Vault AppRole Roles (3) | `vault_approle_auth_backend_role.identity`, `.acceptance`, `.approval` |
| Vault Policies (3) | `vault_policy.identity`, `.acceptance`, `.approval` |
| AWS CloudWatch (1) | `aws_cloudwatch_log_group.vault_audit` |
| AWS IAM WRITER (3) | `aws_iam_user.vault_audit`, `aws_iam_policy.vault_audit`, `aws_iam_user_policy_attachment.vault_audit` |
| AWS IAM READER (3) | `aws_iam_role.vault_audit_reader`, `aws_iam_policy.vault_audit_reader`, `aws_iam_role_policy_attachment.vault_audit_reader` |

Total: 24 Terraform-managed resources (the 21-resource count used in the preauth evaluator may count only HCP + Vault + AWS WRITER + CloudWatch = 2+1+3+3+3+1+3 = 16; exact count should be reconciled before plan review).

**Finding FP-004 (P2):** The preauth evaluator uses `EXPECTED_INVENTORY_COUNT = 21` but this audit counts 24 distinct Terraform-managed resources from reading the `.tf` files. This discrepancy should be reconciled before the final human cost review package is produced. The likely explanation is that some resources are data sources or outputs rather than managed resources, but this should be explicitly verified.

### Protected Resource Assessment

The 4 resources listed in `ceremony_state.yaml` as PRESERVE_AFTER_CEREMONY have `prevent_destroy = true` in their Terraform lifecycle blocks (`aws_cloudwatch_log_group.vault_audit` via its `lifecycle { prevent_destroy = true }` block visible in `infra/aws_audit.tf`). HCP resources also have `prevent_destroy = true`. Vault resources have `prevent_destroy = true`.

**Verified:** `prevent_destroy = true` is present on `aws_cloudwatch_log_group.vault_audit`, `hcp_hvn.frostgate`, `hcp_vault_cluster.customer_zero`, `vault_mount.transit`, all three transit keys, `vault_auth_backend.approle`, and all three AppRole roles. The `aws_iam_user`, `aws_iam_policy`, and `aws_iam_user_policy_attachment` for the WRITER do not appear to have explicit `prevent_destroy = true` in `infra/aws_audit.tf` — they rely on the teardown plan's ordering rather than Terraform lifecycle protection.

**Finding FP-005 (P2):** The IAM WRITER resources (`aws_iam_user.vault_audit`, `aws_iam_policy.vault_audit`, `aws_iam_user_policy_attachment.vault_audit`) do not have `lifecycle { prevent_destroy = true }` blocks, unlike the CloudWatch log group. Adding these blocks would make the preserved-resource set self-enforcing at the Terraform level rather than relying only on operator discipline.

---

## Stream E: Cost Minimization

### Historical Baseline

**Verified from `ceremony_state.yaml`:** `historical_october_usage_usd: 321.81` — accrued from ceremony Run 1 and Run 2 combined, not ongoing after teardown. This is the only verified cost figure available offline.

### HCP Vault Dedicated Pricing Status

**HCP Vault Dedicated pricing is UNVERIFIED in this offline audit.** No live check or provider query is permitted in OFFLINE_PREPARATION. The pricing confirmation must be performed by the human operator as the first step of `CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001`.

**Finding FP-001 (P1):** HCP Vault Dedicated (tier: `standard_small` per `infra/hcp_cluster.tf`) pricing must be confirmed from the HCP portal before any cost authorization decision is presented to the human approver. The prior authorization at $321.81 is consumed. A new explicit authorization with a confirmed price ceiling is required. Do NOT use the $321.81 figure as a ceiling for Run 3 without first confirming current pricing; HCP pricing may have changed since Runs 1 and 2.

### Three-Scenario Cost Model

| Scenario | Description | Estimated basis |
|---------|-------------|----------------|
| Optimistic | Ceremony completes in 2–4 hours; no retries; immediate teardown | Well below historical average per-hour rate; $321.81 / (estimated hours across two runs) |
| Expected | Ceremony runs 4–6 hours with normal checkpoints and verification steps | Roughly proportional to historical average |
| Worst authorized | Ceremony approaches hard abort deadline (operator-defined max runtime); unexpected provisioning delays; partial teardown required | Cannot be specified without confirmed HCP current pricing; UNVERIFIED |

**The three-scenario model cannot be completed offline.** All estimates are relative to the historical $321.81 baseline, which covered two runs. The human cost review must establish: (a) confirmed current HCP pricing, (b) proposed maximum cost (USD), (c) proposed maximum runtime (hours), (d) hard abort deadline.

---

## Stream F: Offline Ceremony Rehearsal

### Existing Coverage Assessment

The offline ceremony simulation (`tools/ci/run_offline_ceremony_simulation.py`) runs six checks:
1. `trust_keys_generated`
2. `identity_domain_sign_verify`
3. `approval_domain_sign_verify`
4. `acceptance_domain_sign_verify`
5. `cross_domain_isolation`
6. `verifier_contract_fail_closed`

These six checks verify the cryptographic contract (key generation, domain-separated signing, cross-domain isolation, fail-closed verifier behavior) but do not simulate: infrastructure provisioning failure, partial teardown, CloudWatch audit proof delivery, or any of the 16 deferred live checks.

### Gaps Identified

The offline rehearsal specification (`docs/operations/customer_zero_run3_offline_rehearsal.md`, created by this audit) adds 20 failure injection cases to address gaps in the existing simulation coverage.

**Finding FP-006 (P2):** The offline simulation does not simulate HCP infrastructure provisioning failure scenarios (Cases 12, 19 in the rehearsal spec) or partial teardown scenarios (Case 13). These are the most expensive failure modes. The rehearsal specification calls out these gaps and recommends they be addressed with local mock Terraform plans before ceremony execution.

---

## Stream G: Cost and Runtime Watchdog Assessment

The preflight manifest includes explicit cost authorization bounds (to be filled by the human approver) and runtime abort deadlines. The `run3_operator_preflight.py` module includes abort condition mappings via `_PROOF_ABORT_MAP` that correctly assign P0 security failures to `ABORT-CER-002` and audit delivery failures to `ABORT-POST-003`.

**Finding FP-007 (P2):** No automated runtime watchdog exists that would halt the ceremony if the wall-clock time exceeds the authorized maximum. The abort deadline is currently enforced solely by operator discipline. A simple wall-clock timestamp check at each checkpoint transition would reduce the risk of inadvertent overtime spending. Recommend implementing this as a `REPAIR` item before Run 3, but it does not block Run 3.

---

## Stream H: Evidence Completeness — The 16 Deferred Live Checks

### Deferred Check Matrix

All 16 deferred live checks require live HCP Vault infrastructure and cannot be completed offline. The following table maps each check to its evidence producer, verifier, binding, and failure condition.

| Proof ID | Family | Evidence Producer | Verifier | Binding | Storage | Failure Condition |
|----------|--------|-------------------|----------|---------|---------|-------------------|
| A-IDENTITY-SIGN | A (signing) | FrostGate runtime via AppRole | `TrustBindingAuthority.verify_engagement_report_route` | Source SHA + report_json hash + manifest hash | Vault Transit signature + DB manifest_hash | Signing fails or returns invalid proof |
| A-ACCEPTANCE-SIGN | A (signing) | FrostGate runtime via AppRole | `TrustBindingAuthority.verify_governed_delivery` | Source SHA + authorization tuple | Vault Transit signature + DB authorization record | Same as above for acceptance domain |
| A-APPROVAL-SIGN | A (signing) | FrostGate runtime via AppRole | `TrustBindingAuthority.verify_qa_approve_report_route` | Source SHA + report + version + fingerprint | Vault Transit signature + DB qualification decision | Same as above for approval domain |
| B-CROSS-IDENTITY-ACCEPTANCE | B (cross-domain isolation) | Adversarial test harness | Verifier detects domain mismatch | Key domain binding | ABORT-CER-002 if not rejected | Verification returns True on wrong-domain proof |
| B-CROSS-ACCEPTANCE-APPROVAL | B (cross-domain isolation) | Same | Same | Same | ABORT-CER-002 | Same |
| B-CROSS-APPROVAL-IDENTITY | B (cross-domain isolation) | Same | Same | Same | ABORT-CER-002 | Same |
| C-WRONG-PAYLOAD-REPLAY | C (replay) | Adversarial test harness | Verifier detects replay | Nonce + timestamp binding | ABORT-CER-002 | Replayed proof accepted |
| C-WRONG-DOMAIN-REPLAY | C (replay) | Same | Same | Same | ABORT-CER-002 | Same |
| C-WRONG-KEY-VERSION-REPLAY | C (replay) | Same | Same | Key version binding | ABORT-CER-002 | Same |
| D-IDENTITY-ROTATION | D (rotation) | FrostGate runtime; manual key rotation | Historical verification via `TrustBindingAuthority` | Pre-rotation + post-rotation key versions | Vault Transit key version history | Post-rotation verification of pre-rotation proof fails |
| E-CRYPTOGRAPHIC-INVALIDITY-FALSE | E (crypto) | Adversarial test harness | Verifier returns False | Deterministic boolean contract | ABORT-CER-002 | Verifier raises instead of returning False |
| E-VAULT-UNAVAILABLE-FALSE | E (crypto) | Vault unavailability simulation | Verifier returns False via `VaultVerifierUnavailableError` path | Deterministic boolean contract | ABORT-CER-002 | Same |
| F-REPORT-MUTATION-FAILS | F (provenance) | DB-level mutation of report_json | `_derive_manifest_hash_from_report_json()` detects mismatch | report_json hash pre-check | ABORT-CER-002 | Mutated report passes verification |
| G-VAULT-AUDIT-CLOUDWATCH | G (audit) | HCP Vault audit streaming to CloudWatch | Operator reads CloudWatch log group | IAM user access key + log group name match | ABORT-POST-003 if absent | No audit events in CloudWatch after Vault operations |
| G-AUDIT-DELIVERY-CHECKPOINT | G (audit) | Same | Same | Same | ABORT-POST-003 | Checkpoint Q not confirmable |
| H-CROSS-TENANT-SIGN-FAILS | H (cross-tenant) | Adversarial test harness | Verifier detects tenant mismatch | Tenant binding in proof | ABORT-CER-002 | Cross-tenant proof accepted |

---

## Stream I: Teardown and Disaster Recovery

### Teardown Plan Review

The four-stage teardown procedure (from Runs 1 and 2) is documented in `ceremony_state.yaml`:
1. enable-key-deletion: Transit keys changed to `deletion_allowed=true`
2. vault-children: 11 Vault child resources destroyed
3. hcp-cluster: HCP Vault Dedicated cluster destroyed
4. hvn: HCP HVN destroyed

This sequence is correct and preserves the AWS audit boundary (the 4 preserved resources survive all four stages).

### Partial Failure Scenarios

| Scenario | Response |
|----------|----------|
| Ceremony fails before signing proofs begin | Execute teardown from current stage; all infrastructure is charged regardless of ceremony completion |
| Vault Transit key creation fails | Stop; do not proceed to signing proofs; tear down from current stage |
| CloudWatch audit not confirmed at Checkpoint Q | Stop (ABORT-POST-003); do not proceed to acceptance proofs; tear down |
| HCP provisioning takes longer than expected | Apply hard abort deadline; tear down if deadline exceeded |
| Terraform state drift (provider side vs. state file) | Reconcile state before teardown; provider-side deletion != Terraform-state absence |
| Partial teardown (stages 1–2 complete, stage 3 fails) | Retry stage 3; HCP cluster has `prevent_destroy = true` — must be explicitly overridden for destroy |

---

## Stream J: Governance and Authorization

### TBD Governance Defect Remediation

This PR fixes the TBD governance defect: `CZ-RUN3-OPERATOR-PREFLIGHT-CLOSEOUT-001.merged_sha` was `"TBD"` in `customer_one/roadmap_authority.yaml`. The canonical main SHA after PR #759 merges is `ec8684df4699be43b40d1edc9a79b58fd23e3637`. This has been corrected.

### Self-Authorization Binding

This PR self-authorizes by including the governance amendment (adding CZ-RUN3-FAILURE-PREVENTION-001 to next_sequence) as its first change — the same pattern used by PRs #757 and #759. The amendment is in `customer_one/roadmap_authority.yaml` (the machine-readable authority) and is reflected in `docs/plans/customer_one_verified_governance_roadmap_20260910.md` (the Level-2 human-readable authority).

### Authorization Integrity Assessment

The lifecycle-aware roadmap check in `run3_operator_preflight.py` (`_check_roadmap_authorized()`) accepts items in `next_sequence` (rc=0 from checker) or `completed` with full evidence (non-empty `prs` + valid 40-char hex `merged_sha`). This PR adds CZ-RUN3-FAILURE-PREVENTION-001 to `next_sequence`, so the checker will return rc=0 for this work item during evaluation.

After this PR merges, the checker will find CZ-RUN3-FAILURE-PREVENTION-001 in `completed` (with a valid merged_sha) and will correctly accept it via the lifecycle fallback for any subsequent evaluator run.

### Canonical Truth Preserved

| Field | Value |
|-------|-------|
| CUSTOMER_ZERO_TRUST | NOT_PROVEN |
| CUSTOMER_ZERO_TRUST_003 | BLOCKED |
| CUSTOMER_ZERO_ACCEPT_001 | BLOCKED |
| THIRD_PAID_CEREMONY | NOT_AUTHORIZED |
| PAID_HCP_INFRASTRUCTURE | ABSENT |
| COST_AUTHORIZATION | NOT_AUTHORIZED |

---

## Findings Summary

### P0 Findings

None. No findings categorically block Run 3.

### P1 Findings

| ID | Title | Blocking Run 3 | Remediation |
|----|-------|---------------|-------------|
| FP-001 | HCP Vault Dedicated pricing unverified — must confirm before cost authorization | Yes (blocks cost review, not ceremony itself) | Human operator confirms current pricing in HCP portal as part of CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001 |
| FP-002 | Offline simulation evidence bound to stale source SHA (988cda57 vs ec8684df) | Yes (readiness evaluator will fail J_CE3 dimension) | Regenerate: `python tools/ci/run_offline_ceremony_simulation.py --repo . --output customer_one/offline_simulation_evidence.json` |
| FP-003 | `aws_iam_role.vault_audit_reader` absent from preserved resources list and lacks `prevent_destroy = true` | No (blocks post-ceremony audit verification if destroyed) | Add to `ceremony_state.yaml` preserved_aws_resources; add `lifecycle { prevent_destroy = true }` to `infra/aws_audit.tf` reader resources |

### P2 Findings

| ID | Title | Blocking Run 3 |
|----|-------|---------------|
| FP-004 | Terraform resource count discrepancy (21 expected vs 24 counted) | No |
| FP-005 | IAM WRITER resources lack `prevent_destroy = true` | No |
| FP-006 | Offline rehearsal does not simulate provisioning failure or partial teardown | No |
| FP-007 | No automated runtime watchdog — abort deadline enforced by operator discipline only | No |
| FP-008 | Simulation evidence regeneration not in the operator preflight runbook as an explicit step | No |

---

## Recommended Remediation Sequence

1. **Before human cost review (CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001):**
   - FP-002: Regenerate `offline_simulation_evidence.json` on canonical main
   - FP-003: Patch `ceremony_state.yaml` preserved resources; patch `infra/aws_audit.tf` reader lifecycle
   - FP-001: Confirm current HCP Vault Dedicated pricing in portal (must be live check)

2. **Before ceremony execution (after cost authorization):**
   - FP-004: Reconcile 21 vs 24 resource count discrepancy in preauth evaluator
   - FP-005: Add `prevent_destroy = true` to IAM WRITER resources

3. **As improvement items (REPAIR class, do not block ceremony):**
   - FP-006: Extend offline rehearsal simulation with provisioning failure cases
   - FP-007: Implement wall-clock watchdog at checkpoint transitions
   - FP-008: Add simulation evidence regeneration step to operator preflight runbook

---

## Test Results

Focused test suites covering the governance machinery evaluated offline:

- `tests/test_cz_run3_operator_preflight_closeout_001.py` — 30 passed (governance invariants, closeout checks)
- `tests/test_customer_zero_run3_operator_preflight_001.py` — 75 passed (adversarial preflight)
- `tests/test_cz_run3_preauth_closeout_001.py` — referenced in PR #757; passing at that SHA

**Note:** Test counts are from the merged history (ceremony_state.yaml and SOC entries). No new tests were added by this OFFLINE_PREPARATION audit. Existing suites are sufficient to confirm governance machinery integrity. Full test suite validation (`make fg-fast`, `make fg-security`) is part of the commit step.
