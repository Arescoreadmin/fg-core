# Customer-Zero Run-3 Operator Preflight Runbook

**Work item:** CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001  
**Status:** COMPLETE — offline preparation only  
**Authority level:** OFFLINE_PREPARATION (does NOT authorize spending)

---

## Purpose

This runbook describes how to run the offline operator preflight authority gate for
the third Customer-Zero trust ceremony (CUSTOMER-ZERO-TRUST-003). The preflight gate
produces a deterministic, independently reviewable manifest covering:

- All 16 deferred live checks (catalogued for human review)
- Source/candidate rebinding procedure
- Terraform resource plan review
- Preserved AWS audit resource verification
- HCP Vault audit-to-CloudWatch prerequisites
- Pricing request structure (NOT an approval)
- Explicit cost/runtime abort thresholds (human must fill)
- Teardown deadline (human must fill)
- Evidence capture procedures
- Stop/rollback authority

**SAFETY INVARIANT:** Running this runbook does NOT:
- Provision paid HCP infrastructure
- Begin Run 3
- Authorize spending
- Prove trust
- Unblock CUSTOMER-ZERO-TRUST-003 or CUSTOMER-ZERO-ACCEPT-001

---

## Prerequisites

Before running the preflight gate, verify:

1. All offline prerequisites are complete:
   - PROVENANCE-INTEGRITY-001 (PR #750) — merged
   - VAULT-VERIFY-CONTRACT-001 (PR #751) — merged
   - CUSTOMER-ZERO-FINAL-READINESS-001 (PR #753) — merged
   - CUSTOMER-ZERO-RUN3-PREAUTH-001 (PR #755) — merged
   - CZ-RUN3-READINESS-INTEGRATION-REPAIR-001 (PR #756) — merged
   - CZ-RUN3-PREAUTH-CLOSEOUT-001 — merged
   - CUSTOMER-ZERO-RUN3-OPERATOR-PREFLIGHT-001 — this PR (must be merged)

2. AWS audit infrastructure present:
   - `aws_cloudwatch_log_group.vault_audit` — ACTIVE
   - `aws_iam_user.vault_audit` — ACTIVE
   - `aws_iam_policy.vault_audit` — ACTIVE
   - `aws_iam_user_policy_attachment.vault_audit` — ACTIVE
   - `aws_iam_role.vault_audit_reader` — ACTIVE

3. Python environment:
   ```bash
   cd ~/Projects/fg-core
   source .venv/bin/activate
   ```

---

## Running the Preflight Gate

### Basic usage

```bash
cd ~/Projects/fg-core
python tools/ci/customer_zero_run3_operator_preflight.py --repo .
```

### Machine-readable JSON output

```bash
python tools/ci/customer_zero_run3_operator_preflight.py --repo . --json
```

### Save manifest to file

```bash
python tools/ci/customer_zero_run3_operator_preflight.py --repo . --json --output /tmp/preflight_manifest.json
```

### Exit codes

| Exit code | Meaning |
|-----------|---------|
| 0 | PREPARED_FOR_HUMAN_REVIEW — all offline checks pass |
| 1 | BLOCKED — one or more offline checks failed |
| 2 | Internal error |

---

## Interpreting the Output

### PREPARED_FOR_HUMAN_REVIEW

All 10 mandatory offline checks pass. The 16 deferred live checks are correctly
catalogued. The manifest is ready for human operator review.

**This does NOT authorize spending.** A human operator must review the manifest
and create a separate explicit cost authorization before any paid HCP infrastructure
is provisioned.

### BLOCKED

One or more offline checks failed. The manifest cannot be submitted for human review
until blockers are resolved. Resolve each blocker in the BLOCKERS section and re-run.

---

## The 10 Mandatory Offline Checks

| Check ID | Description | Evidence Strength |
|----------|-------------|-------------------|
| SOURCE-BINDING | Current HEAD is a valid 40-char hex SHA | STATIC_VERIFIED |
| CANDIDATE-FINGERPRINT | Candidate fingerprint deterministic | TEST_PROVEN |
| INFRA-FINGERPRINT | Infrastructure fingerprint deterministic | STATIC_VERIFIED |
| INVENTORY-COUNT | Exactly 21 resource inventory entries | STATIC_VERIFIED |
| PROOF-MATRIX-COMPLETENESS | All 16 deferred live checks, no duplicates | STATIC_VERIFIED |
| FINAL-READINESS-READY | evaluate() returns READY, 0 blockers | STATIC_VERIFIED |
| PREAUTH-READY | Preauth CLI exits 0 | TEST_PROVEN |
| SIMULATION-GREEN | offline_simulation_evidence.json valid | TEST_PROVEN |
| TEARDOWN-CONTRACT | Abort matrix and teardown contract valid | STATIC_VERIFIED |
| PRESERVED-AUDIT-RESOURCES | 4 AWS audit resources PRESERVE_AFTER_CEREMONY | STATIC_VERIFIED |

---

## The 16 Deferred Live Checks

These checks CANNOT be satisfied offline. They require live HCP Vault infrastructure.
Each must be executed and verified during the ceremony itself.

| Proof ID | Family | Description |
|----------|--------|-------------|
| A-IDENTITY-SIGN | A | IDENTITY trust role positive signing |
| A-ACCEPTANCE-SIGN | A | ACCEPTANCE trust role positive signing |
| A-APPROVAL-SIGN | A | APPROVAL trust role positive signing |
| B-CROSS-IDENTITY-ACCEPTANCE | B | IDENTITY cannot verify as ACCEPTANCE |
| B-CROSS-ACCEPTANCE-APPROVAL | B | ACCEPTANCE cannot verify as APPROVAL |
| B-CROSS-APPROVAL-IDENTITY | B | APPROVAL cannot verify as IDENTITY |
| C-WRONG-PAYLOAD-REPLAY | C | Payload tamper returns False |
| C-WRONG-DOMAIN-REPLAY | C | Wrong-domain replay returns False |
| C-WRONG-KEY-VERSION-REPLAY | C | Wrong-version replay returns False |
| D-IDENTITY-ROTATION | D | IDENTITY key rotation + historical verification |
| E-CRYPTOGRAPHIC-INVALIDITY-FALSE | E | Invalid signature returns False, not raises |
| E-VAULT-UNAVAILABLE-FALSE | E | Vault unavailable returns False, not raises |
| F-REPORT-MUTATION-FAILS | F | Mutated report_json fails verify_report() |
| G-VAULT-AUDIT-CLOUDWATCH | G | Vault audit events visible in CloudWatch |
| G-AUDIT-DELIVERY-CHECKPOINT | G | Audit verified EARLY (checkpoint Q) |
| H-CROSS-TENANT-SIGN-FAILS | H | Cross-tenant signing denied at policy level |

**Note:** evidence_strength for all 16 is NOT_PROVEN until the ceremony executes.

---

## Resource Plan

### Ephemeral (destroyed after ceremony)

| Address | Purpose |
|---------|---------|
| hcp_hvn.frostgate | HCP Virtual Network |
| hcp_vault_cluster.customer_zero | HCP Vault Dedicated cluster (COST_BEARING) |
| vault_mount.transit | Vault Transit engine mount |
| vault_transit_secret_backend_key.customer_zero_identity | IDENTITY signing key |
| vault_transit_secret_backend_key.customer_zero_acceptance | ACCEPTANCE signing key |
| vault_transit_secret_backend_key.customer_zero_approval | APPROVAL signing key |
| vault_auth_backend.approle | AppRole authentication backend |
| vault_approle_auth_backend_role.identity | IDENTITY AppRole |
| vault_approle_auth_backend_role.acceptance | ACCEPTANCE AppRole |
| vault_approle_auth_backend_role.approval | APPROVAL AppRole |
| vault_policy.identity | IDENTITY policy |
| vault_policy.acceptance | ACCEPTANCE policy |
| vault_policy.approval | APPROVAL policy |

### PRESERVED FOREVER (never destroyed)

| Address | Purpose |
|---------|---------|
| aws_cloudwatch_log_group.vault_audit | Vault audit log group |
| aws_iam_user.vault_audit | Audit writer IAM user |
| aws_iam_policy.vault_audit | Audit writer IAM policy |
| aws_iam_user_policy_attachment.vault_audit | Policy attachment |

### Reused from prior ceremonies

| Address | Purpose |
|---------|---------|
| aws_iam_role.vault_audit_reader | MFA-gated read-only verification role |
| aws_iam_policy.vault_audit_reader | Read-only CloudWatch policy |
| aws_iam_role_policy_attachment.vault_audit_reader | Role policy attachment |

---

## Audit Prerequisites

Before HCP cluster creation:
1. Verify `aws_cloudwatch_log_group.vault_audit` is present and accessible
2. Verify `aws_iam_user.vault_audit` writer credential is available
3. Abort if CloudWatch group absent (ABORT-PRE-009)

Checkpoint Q (immediately after cluster provisioning):
1. Perform any Vault operation (e.g., test auth)
2. Verify at least one audit event appears in CloudWatch
3. Abort if no events visible (ABORT-POST-003)
4. Only proceed to proof matrix execution after audit delivery confirmed

---

## Cost Authority

The preflight manifest contains a pricing REQUEST, NOT an approval.

| Field | Value |
|-------|-------|
| authorization_status | NOT_AUTHORIZED |
| proposed_max_cost_usd | None (human must set) |
| proposed_max_runtime_hours | None (human must set) |
| historical_cost_usd | $321.81 (prior runs consumed) |
| pricing_confidence | HISTORICAL_ONLY |

A human operator must:
1. Confirm current HCP pricing in the HCP portal
2. Set an explicit maximum cost ceiling (not based on historical $321.81)
3. Set an explicit maximum runtime limit
4. Set cost and runtime abort thresholds
5. Set a teardown deadline
6. Record their name/identity and authorization expiration

---

## Staged Teardown Contract

Teardown is always staged and narrow. Never use `terraform destroy` (destroys ALL).

| Stage | Action | Targets |
|-------|--------|---------|
| STAGE_1 | Enable key deletion | 3 Transit keys (deletion_allowed=true) |
| STAGE_2 | Destroy Vault children | Transit mount, AppRoles, policies |
| STAGE_3 | Destroy HCP cluster | hcp_vault_cluster.customer_zero |
| STAGE_4 | Destroy HVN | hcp_hvn.frostgate |

**PROHIBITION:** AWS audit resources must NEVER be targeted for destruction in any stage.

---

## Abort Conditions Summary

| Trigger | Stage | Response |
|---------|-------|----------|
| Candidate mismatch | PRE | STOP, no provisioning |
| Source mismatch | PRE | STOP, no provisioning |
| Readiness regression | PRE | STOP, no provisioning |
| Missing human authorization | PRE | STOP, no provisioning |
| Cost envelope missing | PRE | STOP, no provisioning |
| Runtime limit missing | PRE | STOP, no provisioning |
| Unexpected resources in plan | PRE | STOP, no provisioning |
| Operator MFA not confirmed | PRE | STOP, no provisioning |
| Missing audit prerequisites | PRE | STOP, no provisioning |
| Live plan mismatch | PRE | STOP, no provisioning |
| Unexpected resources post-apply | POST | STOP + teardown |
| Vault health failure | POST | STOP + teardown |
| Audit destination failure | POST | STOP + teardown |
| Cost threshold breach | POST | STOP + teardown |
| Runtime threshold breach | POST | STOP + teardown |
| Secret exposure | POST | STOP + teardown |
| Source SHA mismatch | POST | STOP + teardown |
| Signing failure | CEREMONY | STOP + teardown |
| Cross-domain isolation failure | CEREMONY | STOP + teardown (P0) |
| Replay failure | CEREMONY | STOP + teardown (P0) |
| Historical verification failure | CEREMONY | STOP + teardown |
| Audit proof failure | CEREMONY | STOP + teardown |
| Tenant isolation failure | CEREMONY | STOP + teardown (P0) |
| Report provenance failure | CEREMONY | STOP + teardown (P0) |
| Portable verification failure | CEREMONY | STOP + teardown |
| Evidence not captured | TEARDOWN | STOP teardown |
| Unexpected paid resources retained | TEARDOWN | STOP + investigate |
| Audit resources targeted | TEARDOWN | STOP immediately (P0) |
| Historical proof broken post-teardown | TEARDOWN | STOP, no acceptance |

---

## Evidence Capture (Required Before Teardown)

- CloudWatch audit events captured to local file
- Portable verification bundles enrolled with all 3 trust key public materials
- Ceremony evidence manifest signed and captured
- All proof family results (A-K) documented

**Abort if any evidence is missing before teardown begins (ABORT-TEAR-001).**

---

## Post-Ceremony Requirements

After teardown:
1. `PortableVerificationAuthority.verify_offline()` must pass on all captured artifacts
2. Billing evidence captured after teardown completes
3. Provider-side deletion confirmed (not just Terraform state)

If portable verification fails post-teardown: do NOT declare CUSTOMER-ZERO-TRUST proven.

---

## Validation Commands

```bash
# Run preflight gate
python tools/ci/customer_zero_run3_operator_preflight.py --repo .

# Verify final readiness still READY
python tools/ci/customer_zero_final_readiness.py --repo .

# Verify preauth still READY_FOR_HUMAN_COST_AUTHORIZATION
python tools/ci/customer_zero_run3_preauth.py --repo . --json

# Run preflight test suite
.venv/bin/pytest tests/test_customer_zero_run3_operator_preflight_001.py -q

# Run full fast gate
make fg-fast
```

---

## Canonical Truth Record

This runbook does NOT change any of the following:

| Item | Status |
|------|--------|
| CUSTOMER_ZERO_TRUST | NOT_PROVEN |
| CUSTOMER_ZERO_TRUST_003 | BLOCKED |
| CUSTOMER_ZERO_ACCEPT_001 | BLOCKED |
| THIRD_PAID_CEREMONY | NOT_AUTHORIZED |
| PAID_HCP_INFRASTRUCTURE | ABSENT |
| COST_AUTHORIZATION | NOT_AUTHORIZED |
| CLOUD_MUTATIONS | 0 |
