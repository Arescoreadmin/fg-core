# Customer-Zero Run-3 Offline Rehearsal Specification

**Document ID:** REHEARSAL-SPEC-RUN3-001
**Audit:** CZ-RUN3-FAILURE-PREVENTION-001
**Canonical Source SHA:** ec8684df4699be43b40d1edc9a79b58fd23e3637
**Date:** 2026-10-09
**Classification:** OFFLINE_PREPARATION — specification only; all rehearsal cases are offline

---

## Purpose

This specification defines 20 failure injection cases that must be rehearsed offline before
the third Customer-Zero trust ceremony (CUSTOMER-ZERO-TRUST-003). The existing offline
simulation (`tools/ci/run_offline_ceremony_simulation.py`) covers the cryptographic contract
(6 checks) but does not simulate infrastructure failure, partial teardown, or operational
interruption scenarios.

**Scope:** These are offline rehearsal cases only. Cases that require live HCP infrastructure
are simulated using local mocks, Terraform dry-runs, or synthetic state manipulation. No paid
infrastructure is used.

---

## Existing Coverage (Baseline)

The `run_offline_ceremony_simulation.py` script already covers:

| Check | Description |
|-------|-------------|
| trust_keys_generated | Ed25519 keys generated for all three domains |
| identity_domain_sign_verify | Sign + verify in the IDENTITY domain |
| approval_domain_sign_verify | Sign + verify in the APPROVAL domain |
| acceptance_domain_sign_verify | Sign + verify in the ACCEPTANCE domain |
| cross_domain_isolation | Cross-domain proofs rejected |
| verifier_contract_fail_closed | Verifier returns False (not raises) on all error paths |

These six cases provide the cryptographic baseline. The 20 cases below extend the rehearsal
to operational, infrastructure, and governance failure modes.

---

## Section 10: 20 Failure Injection Cases

### Case 1: Missing Approval

**Scenario:** Human cost authorization has not been obtained. An operator attempts to begin
the ceremony.

**Injection:** Set `authorization_status = NOT_AUTHORIZED` in the preflight manifest (already
the default). Attempt to proceed past the authorization gate check.

**Expected outcome:** Ceremony blocked by `CUSTOMER-ZERO-TRUST-003 = BLOCKED (not authorized)`.
The evaluator does not advance. No infrastructure provisioned.

**Verification:** Run `customer_zero_run3_operator_preflight.py --repo .`; confirm
`authorization_status = NOT_AUTHORIZED` and no ceremony steps are listed as ready.

**Rehearsal method:** Offline — read YAML file.

---

### Case 2: Expired Approval

**Scenario:** A human cost authorization was granted but has since expired (past the
expiration timestamp set by the approver).

**Injection:** Set `approval_expiration = <past timestamp>` in a test authorization record.

**Expected outcome:** Cost review package rejected at validation. Ceremony blocked.

**Verification:** Confirm the human review procedure checks expiration and does not accept
an expired authorization.

**Rehearsal method:** Offline — document check.

---

### Case 3: Changed Source SHA

**Scenario:** A new PR merges after the offline preparation is complete, changing the
source SHA. The candidate fingerprint and simulation evidence are now stale.

**Injection:** This scenario is currently ACTIVE (FP-002): `offline_simulation_evidence.json`
has `source_sha = 988cda57`, canonical main is `ec8684df`. Run the readiness evaluator without
regenerating the evidence file.

**Expected outcome:** J_CE3 dimension FAILS in `customer_zero_final_readiness.py`. Result
is NOT READY.

**Verification:** Run `python tools/ci/customer_zero_final_readiness.py --repo . --json` and
confirm J_CE3 returns FAIL with `source_sha mismatch` or equivalent message.

**Rehearsal method:** Offline — run evaluator without regenerating evidence.

---

### Case 4: Changed Candidate Fingerprint

**Scenario:** An infra change (e.g., variable change in `infra/variables.tf`) changes the
infrastructure fingerprint, invalidating the frozen candidate.

**Injection:** Temporarily modify `infra/variables.tf` to change a variable default, then
re-run `customer_zero_run3_preauth.py`.

**Expected outcome:** Candidate fingerprint changes; preauth evaluator detects the change.

**Verification:** Confirm the new fingerprint differs from the historical value in
`docs/plans/customer_one_verified_governance_roadmap_20260910.md`.

**Rehearsal method:** Offline — local file modification (revert after rehearsal).

---

### Case 5: Missing Audit Event

**Scenario:** Vault audit logging is not configured. CloudWatch receives no events after
a Vault operation.

**Injection:** Simulate by assuming no events in the CloudWatch log group (the group exists
but is empty, as it is during pre-ceremony state).

**Expected outcome:** Smoke test (Step 3) FAILS. ABORT-POST-003 is triggered. Ceremony does
not proceed.

**Verification:** Walk through the smoke test contract with an empty CloudWatch group.
Confirm the 2-minute timeout leads to ABORT-POST-003.

**Rehearsal method:** Offline — walk through procedure mentally; the log group is empty now.

---

### Case 6: Audit Reader Denied

**Scenario:** The MFA token is expired or incorrect. `sts:AssumeRole` for
`FrostGateVaultAuditReader` fails.

**Injection:** Simulate by attempting the assume-role with an expired MFA code (offline
dry-run only — do not actually call AWS).

**Expected outcome:** Reader role assumption fails. Checkpoint Q cannot be completed.
Smoke test cannot confirm audit events. ABORT-POST-003.

**Verification:** Confirm the smoke test procedure requires reader role assumption to succeed.

**Rehearsal method:** Offline — trace through the procedure.

---

### Case 7: Incorrect Audit Event Correlation

**Scenario:** Audit events appear in CloudWatch but are from a different Vault cluster or
from a previous ceremony run. The log group name matches but the cluster ID does not.

**Injection:** Review the event body format. Confirm events include a cluster identifier
or timestamp that would distinguish them.

**Expected outcome:** Operator must verify that event timestamps post-date ceremony start
and that event bodies reference the correct cluster.

**Verification:** Confirm the smoke test evidence template records the timestamp comparison.

**Rehearsal method:** Offline — review evidence template.

---

### Case 8: Missing Signing Evidence

**Scenario:** A signing proof (e.g., A-IDENTITY-SIGN) is claimed to have been executed,
but no evidence record (Vault Transit signature, DB manifest_hash column) is captured.

**Injection:** Simulate by removing a signing evidence field from a mock evidence record.

**Expected outcome:** Proof family A is incomplete; trust determination cannot proceed.

**Verification:** Confirm the evidence manifest in the preflight defines what evidence is
required for each signing proof.

**Rehearsal method:** Offline — review evidence manifest requirements.

---

### Case 9: Negative Authorization Test Failure

**Scenario:** A cross-domain substitution attempt (B-family) is expected to return False.
Instead, the test is misconfigured and no negative test is run.

**Injection:** Skip the B-family negative tests and proceed to trust determination.

**Expected outcome:** B-CROSS-* proofs are unchecked; trust determination cannot claim
cross-domain isolation is proven.

**Verification:** Confirm the 16 deferred check list requires all B-family checks to be
executed and recorded.

**Rehearsal method:** Offline — review the deferred check matrix.

---

### Case 10: Evidence Export Failure

**Scenario:** After the ceremony completes, the evidence export step fails (e.g., file
write permission denied, insufficient storage).

**Injection:** Simulate by writing to a read-only path (offline dry-run).

**Expected outcome:** Export step fails; operator retries to a writable path. Evidence must
be exportable before teardown.

**Verification:** Confirm the evidence capture procedure has a fallback export path.

**Rehearsal method:** Offline — review evidence capture procedure.

---

### Case 11: Provisioning Timeout

**Scenario:** HCP Vault Dedicated cluster provisioning takes longer than expected, consuming
billable time.

**Injection:** Simulate by adding a 30-minute "wait" to the provisioning step in a local
mock Terraform plan.

**Expected outcome:** Operator applies hard abort deadline. If provisioning does not
complete within the allowed window, ABORT-CER-001 is triggered.

**Verification:** Confirm the abort procedure is understood before ceremony.

**Rehearsal method:** Offline mock — walk through the abort decision with a hypothetical
30-minute overrun.

---

### Case 12: Partial Resource Creation

**Scenario:** Terraform apply starts but fails mid-way (e.g., HVN created, cluster
creation fails due to HCP quota error).

**Injection:** Simulate by writing a mock Terraform state with partial resources (HVN
present, cluster absent).

**Expected outcome:** Operator must assess whether any billable resources are running.
If HVN was created without cluster, determine whether HVN alone is billable. Execute
targeted teardown.

**Verification:** Confirm the teardown procedure handles partial states.

**Rehearsal method:** Offline mock — write a synthetic partial state file and trace the
teardown procedure.

---

### Case 13: Teardown Timeout

**Scenario:** Terraform destroy for the HCP cluster hangs (e.g., cluster is in a
transitional state, destroy API call times out).

**Injection:** Simulate by assuming the destroy command returns a timeout error.

**Expected outcome:** Operator waits for state to stabilize, retries, or destroys via
HCP console directly. Does not abandon without confirmation of deletion.

**Verification:** Confirm the operator knows how to verify cluster deletion in HCP console
independent of Terraform state.

**Rehearsal method:** Offline — trace through the escalation procedure.

---

### Case 14: Protected-Resource Deletion Attempt

**Scenario:** Operator accidentally runs `terraform destroy` without the staged teardown
procedure. Terraform's `prevent_destroy = true` blocks deletion of protected resources.

**Injection:** Simulate by running `terraform plan -destroy` (no apply) locally with the
infra directory.

**Expected outcome:** Terraform plan fails with "Error: Instance cannot be destroyed" for
resources with `prevent_destroy = true`. The four preserved AWS resources and HCP resources
are protected.

**Verification:** Run `terraform plan -destroy` on infra/ and confirm the correct resources
are protected. (This is a safe offline check — plan does not destroy anything.)

**Rehearsal method:** Offline dry-run — `terraform plan -destroy` only.

---

### Case 15: Runtime Limit Exceeded

**Scenario:** The ceremony reaches the hard abort deadline (maximum authorized runtime) without
completing all proofs.

**Injection:** Simulate by setting the hard abort deadline to 5 minutes from now in a
hypothetical ceremony.

**Expected outcome:** Operator triggers ABORT-CER-001 (if proofs incomplete) or
ABORT-CER-002 (if a proof failed). Teardown begins immediately.

**Verification:** Confirm the abort-to-teardown sequence is understood.

**Rehearsal method:** Offline — trace through the abort decision tree.

---

### Case 16: Cost Threshold Reached

**Scenario:** Estimated accrued cost approaches the authorized maximum cost (USD).

**Injection:** Simulate by computing elapsed time × confirmed hourly rate and comparing
to the authorized maximum.

**Expected outcome:** At 75% of maximum cost, operator emits a warning. At 100% of
maximum cost, operator executes ABORT-CER-001 regardless of ceremony state.

**Verification:** Confirm the operator knows how to compute running cost from elapsed time.

**Rehearsal method:** Offline — arithmetic exercise with hypothetical pricing.

---

### Case 17: Operator Interruption

**Scenario:** The operator is unexpectedly interrupted (phone call, emergency) during the
ceremony.

**Injection:** Walk through the ceremony with an assumed 15-minute interruption at each
major checkpoint.

**Expected outcome:** Ceremony is paused, not abandoned. Paid infrastructure is running
during the pause (accruing cost). If interruption exceeds a defined threshold, operator
triggers ABORT-CER-001 and teardown.

**Verification:** Confirm a pause/abort decision threshold is defined in the authorization
package.

**Rehearsal method:** Offline — decision table review.

---

### Case 18: Stale Terraform Inventory

**Scenario:** The Terraform state file is stale or references resources from a previous
ceremony. The `terraform plan` shows unexpected drift.

**Injection:** Compare the current infra/ state file (if any) against the expected
21/24-resource inventory. Identify any unexpected resources.

**Expected outcome:** Operator reviews the plan before applying. Unexpected resources are
investigated before proceeding.

**Verification:** Confirm the pre-ceremony plan review step is in the operator checklist.

**Rehearsal method:** Offline — run `terraform plan` (no apply) on infra/.

---

### Case 19: Missing HCP Prerequisite

**Scenario:** The HCP project (`frostgate-production`) is not accessible or the HCP token
is expired when Terraform apply is run.

**Injection:** Simulate by assuming the HCP authentication token is expired.

**Expected outcome:** Terraform plan fails with an HCP authentication error. Ceremony does
not proceed.

**Verification:** Confirm the operator knows how to refresh the HCP token before ceremony.

**Rehearsal method:** Offline — review HCP authentication procedure.

---

### Case 20: Incomplete Final Evidence Manifest

**Scenario:** The ceremony completes but the final evidence manifest is missing one or more
required proof records (e.g., F-REPORT-MUTATION-FAILS was not run).

**Injection:** Review the evidence manifest template from the preflight runbook. Mark one
proof family as "not run."

**Expected outcome:** Trust determination cannot claim full proof. The incomplete proof
is documented. Trust is NOT PROVEN for the missing element.

**Verification:** Confirm the trust determination procedure checks that all 16 deferred
live checks are completed before declaring trust proven.

**Rehearsal method:** Offline — review evidence completeness checklist.

---

## Rehearsal Completion Checklist

Before Run 3, an operator must walk through all 20 cases and confirm each outcome:

| Case | Description | Outcome confirmed | Notes |
|------|-------------|------------------|-------|
| 1 | Missing approval | [ ] | |
| 2 | Expired approval | [ ] | |
| 3 | Changed source SHA | [ ] | Currently ACTIVE (FP-002) |
| 4 | Changed candidate fingerprint | [ ] | |
| 5 | Missing audit event | [ ] | |
| 6 | Audit reader denied | [ ] | |
| 7 | Incorrect audit event correlation | [ ] | |
| 8 | Missing signing evidence | [ ] | |
| 9 | Negative authorization test failure | [ ] | |
| 10 | Evidence export failure | [ ] | |
| 11 | Provisioning timeout | [ ] | |
| 12 | Partial resource creation | [ ] | |
| 13 | Teardown timeout | [ ] | |
| 14 | Protected-resource deletion attempt | [ ] | Safe: `terraform plan -destroy` only |
| 15 | Runtime limit exceeded | [ ] | |
| 16 | Cost threshold reached | [ ] | |
| 17 | Operator interruption | [ ] | |
| 18 | Stale Terraform inventory | [ ] | Safe: `terraform plan` only |
| 19 | Missing HCP prerequisite | [ ] | |
| 20 | Incomplete final evidence manifest | [ ] | |

**Completion standard:** All 20 cases reviewed; any case with an unexpected outcome
documented and triaged before ceremony.
