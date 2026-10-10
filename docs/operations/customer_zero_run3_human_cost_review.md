# Customer-Zero Run-3 Human Cost Review Procedure

**Document ID:** HUMAN-COST-REVIEW-RUN3-001
**Work item:** CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001
**Canonical Source SHA:** 873148e84b9d9163bb13c8e3e185f5c47d43225e
**Date:** 2026-10-10
**Classification:** OFFLINE_PREPARATION — no cloud spending, no trust advancement

---

## CRITICAL SAFETY NOTICE

This document prepares a cost-authorization REVIEW PACKAGE. It does NOT authorize spending.

**This PR does NOT:**
- Provision HCP Vault infrastructure
- Run `terraform apply` or `terraform destroy`
- Create AWS resources
- Authorize spending
- Grant cost authorization
- Prove Customer-Zero trust
- Authorize the third paid ceremony

**Actual spending requires a separate explicit human decision.**

---

## Purpose

This procedure prepares the complete human cost-authorization review package for the
third Customer-Zero trust ceremony (CUSTOMER-ZERO-TRUST-003). It covers:

1. Pricing evidence capture procedure (FP-001 — currently OPEN)
2. Three-scenario cost model (all PENDING until pricing is verified)
3. Execution window optimization (classifying steps as Offline/Pre-provisioning/Paid/Post-teardown)
4. Authorization request contents
5. Independent verification procedure
6. Runtime and cost controls
7. Audit-first smoke test binding
8. Teardown and preservation contract

---

## FP-001 Status: OPEN

Finding FP-001 from CZ-RUN3-FAILURE-PREVENTION-001:

> **HCP Vault Dedicated pricing unverified — must confirm before cost authorization.**

The human operator MUST confirm current HCP Vault Dedicated pricing from the HCP portal
before the cost authorization package can advance from `BLOCKED_PRICING_UNVERIFIED` to
`PENDING_HUMAN_REVIEW`.

**The $321.81 historical figure is CONSUMED.** It covers Runs 1 and 2 only.
It MUST NOT be used as a pricing reference or cost ceiling for Run 3.

---

## Phase 1: Pricing Evidence Capture

### What the operator must do (live check — cannot be completed offline)

1. Log into HCP portal: https://portal.cloud.hashicorp.com
2. Navigate to: Billing > Pricing (or equivalent current portal path)
3. Find: HCP Vault Dedicated > `standard_small` tier > `aws us-east-1` region
4. Confirm current hourly rate (USD)
5. Record all required evidence fields in `customer_one/run3_pricing_evidence_schema.json`

### Required evidence fields

| Field | What to record |
|-------|---------------|
| `source` | "HCP Portal — https://portal.cloud.hashicorp.com/billing/pricing" (or actual URL) |
| `product_tier_confirmed` | "HCP Vault Dedicated standard_small" |
| `region_confirmed` | "aws/us-east-1" |
| `currency` | "USD" |
| `hourly_rate_usd` | Current confirmed rate (e.g., "X.XX") |
| `billing_unit` | "per hour" or confirmed billing granularity |
| `minimum_charge_hours` | Minimum billable period (if any) |
| `minimum_charge_usd` | Minimum charge in USD (if any) |
| `rate_confirmed_at` | ISO-8601 UTC timestamp of confirmation |
| `rate_valid_until` | Expiry window for this pricing evidence |
| `verifier_identity` | Full name of operator who confirmed the price |
| `verifier_role` | "Ceremony operator" or specific role |
| `fingerprint` | SHA-256 of deterministic JSON: `{"rate": X.XX, "currency": "USD", "tier": "standard_small", "region": "us-east-1", "confirmed_at": "..."}` |

### After recording evidence

1. Update `customer_one/run3_pricing_evidence_schema.json` with all fields
2. Compute and set `pricing_evidence_fingerprint` in `customer_one/run3_cost_authorization_request.json`
3. Update `fp_001_status` in both files from `"OPEN"` to `"CONFIRMED"`
4. Update `request_status` in authorization request from `BLOCKED_PRICING_UNVERIFIED` to `PENDING_HUMAN_REVIEW`

---

## Phase 2: Cost Model (Three Scenarios)

The cost model module (`services/governance/run3_cost_model.py`) is ready. All scenarios
currently output `PENDING` because pricing is unverified.

### Scenario A: Successful first attempt

**Paid path:**
1. Provision HCP HVN + Vault cluster (est. 10–20 min)
2. Configure Vault Transit engine + AppRole (est. 15–30 min)
3. Audit smoke test PASS (est. 10–15 min)
4. Signing proof families A–F, H (est. 60–90 min)
5. Checkpoint Q (audit verification) (est. 15–20 min)
6. Trust determination (est. 5–10 min)
7. Teardown (est. 15–20 min)

**Total estimated paid runtime:** 120–240 minutes  
**HCP cost:** `PENDING` (confirmed_rate × elapsed_hours)  
**AWS cost:** Negligible (< $0.01 for KB-scale audit volume)

### Scenario B: Early failure (abort on smoke test)

**Paid path:**
1. Provision HCP HVN + Vault cluster (est. 10–20 min)
2. Configure Vault Transit + AppRole (est. 15–30 min)
3. Audit smoke test FAIL → ABORT-SMOKE-001 (est. 5–10 min)
4. Teardown (est. 15–20 min)

**Total estimated paid runtime:** 30–60 minutes  
**HCP cost:** `PENDING`  
**AWS cost:** Negligible

### Scenario C: Worst authorized runtime

**Paid path:** Cluster runs until operator-set maximum runtime regardless of state.

**Total paid runtime:** `requested_max_runtime_minutes` (human-set)  
**HCP cost:** `PENDING` = `confirmed_rate × (requested_max_runtime_minutes / 60)`  
**AWS cost:** Negligible

**This is the cost ceiling that bounds the spending authorization.**

---

## Phase 3: Execution Window Optimization

### Step classification

Every Run-3 ceremony step is classified by billing impact:

| Phase | Steps | Billing impact |
|-------|-------|---------------|
| **Offline** | All offline preparation, CI verification, readiness checks, preflight gate | **$0** |
| **Pre-provisioning** | Final source SHA verification, Terraform plan review, authorization confirmation, IAM access key creation (out-of-band) | **$0** — cluster not yet running |
| **Paid** | HCP HVN provisioning → Vault cluster provisioning → all ceremony steps → Checkpoint Q → teardown begins | **HCP rate × elapsed hours** |
| **Post-teardown** | Billing evidence capture, evidence archival, teardown verification | **$0** — cluster destroyed |

### Offline steps (before paying)

The following MUST be completed before provisioning to minimize the paid window:

- All offline evaluation gates pass (`customer_zero_final_readiness.py`, `customer_zero_run3_preauth.py`, `customer_zero_run3_operator_preflight.py`)
- Pricing evidence confirmed and recorded
- Authorization request filled and reviewed
- Human approver provides explicit authorization
- Operator identity and approver identity recorded
- Terraform plan reviewed and approved (`terraform plan -out run3.tfplan`)
- HCP credentials loaded into environment (not in Terraform state)
- AppRole SecretID paths prepared (delivery mechanism ready)
- Terminal 1 (ceremony operations) and Terminal 2 (watchdog monitoring) ready
- Watchdog configured with confirmed hourly rate and authorized max runtime

### Pre-provisioning steps (immediately before starting clock)

1. Confirm AWS audit resources are ACTIVE:
   - `aws_cloudwatch_log_group.vault_audit`
   - `aws_iam_user.vault_audit`
   - `aws_iam_policy.vault_audit`
   - `aws_iam_user_policy_attachment.vault_audit`
   - `aws_iam_role.vault_audit_reader`
   - `aws_iam_role_policy_attachment.vault_audit_reader`
2. Record ceremony start timestamp (UTC)
3. Start operator watchdog: `watchdog.start()`
4. Record the exact moment provisioning begins

### Paid steps (minimize duration here)

1. `terraform apply run3.tfplan` (provision HVN + cluster + children)
2. Configure Vault Transit engine
3. Configure AppRole authentication
4. Configure FrostGate runtime connectivity
5. Configure HCP audit logging (HCP UI: Cluster → Observability → Audit Logging)
6. Create IAM access key for `frostgate-hcp-vault-audit` user (out-of-band)
7. **AUDIT SMOKE TEST** (SMOKE-TEST-RUN3-001) — MUST PASS before any signing
8. Signing proof families (A–F, H) as specified in proof matrix
9. Checkpoint Q (audit event verification)
10. Trust determination
11. **Begin teardown immediately** — no delays after trust determination

### Post-teardown steps

1. Verify HCP cluster destroyed (HCP portal + Terraform state)
2. Verify provider-side deletion (HCP console — do not rely on Terraform state alone)
3. Capture billing evidence (HCP billing dashboard)
4. Confirm zero ongoing cost accrual
5. Archive all ceremony evidence

---

## Phase 4: Authorization Request Fields

The authorization request (`customer_one/run3_cost_authorization_request.json`) requires
the following human-filled fields before it can advance to `PENDING_HUMAN_REVIEW`:

| Field | Required action |
|-------|----------------|
| `pricing_evidence_fingerprint` | Computed after pricing confirmed (Phase 1) |
| `pricing_valid_until` | From pricing evidence confirmation |
| `aws_account` | FrostGate AWS account ID (from `aws sts get-caller-identity`) |
| `operator_identity` | Human operator: full name, confirmed manually |
| `approver_identity` | Human approver: full name, confirmed manually |
| `requested_max_cost_usd` | Human decision after pricing confirmed |
| `requested_max_runtime_minutes` | Human decision |
| `teardown_reserve_minutes` | Human decision (recommend 30 min minimum) |
| `authorization_expires_at` | Human decision (expiry of this authorization) |
| `candidate_fingerprint` | From running `customer_zero_run3_preauth.py --repo . --json` |

---

## Phase 5: Independent Verification

### Verifier CLI

```bash
cd ~/Projects/fg-core
source .venv/bin/activate
python services/governance/customer_zero_cost_review.py --repo . --json
```

### Expected output when package is BLOCKED (current state)

```json
{
  "overall_state": "BLOCKED",
  "blocker_count": <N>,
  "blockers": [
    "C06_PRICING_FP001_NOT_OPEN: FP-001 is OPEN ...",
    ...
  ]
}
```

### Expected output when package is READY

All 22 conditions must pass (`PASS`) and `overall_state` must be `READY_FOR_HUMAN_DECISION`.

The verifier NEVER returns `APPROVED`. Approval requires a separate, explicit human decision.

---

## Phase 6: Runtime and Cost Controls

### Operator watchdog

The runtime watchdog (`services/governance/run3_operator_watchdog.py`) provides:

- **Start record:** Records ceremony start time (UTC)
- **75% warning:** Emits `WARN_75` when elapsed time reaches 75% of effective max runtime
- **100% stop signal:** Emits `STOP_EFFECTIVE_MAX` at effective max (max_runtime - teardown_reserve)
- **Hard deadline:** Emits `HARD_STOP` when elapsed time exceeds max_runtime_minutes

### Watchdog limitation (critical)

The watchdog estimates cost from elapsed time and confirmed hourly rate. This is a
**LOWER BOUND ESTIMATE only**. Cloud billing is delayed — the actual provider-billed
amount may not appear in the HCP account until after teardown.

**The watchdog does NOT provide a guaranteed dollar cap.**

The time-based control (max_runtime_minutes) is the binding constraint. The dollar figure
is derived from `confirmed_hourly_rate × (max_runtime_minutes / 60)`.

### Usage during ceremony

```python
from services.governance.run3_operator_watchdog import OperatorWatchdog
from decimal import Decimal

# Initialize with confirmed values (after pricing confirmation)
watchdog = OperatorWatchdog(
    max_runtime_minutes=<authorized_value>,
    teardown_reserve_minutes=<authorized_value>,
    hourly_rate_usd_estimate=<confirmed_hcp_rate>,
)
ceremony_start = watchdog.start()
print(f"Ceremony started: {ceremony_start}")

# At each checkpoint:
status = watchdog.check("audit_smoke_test")
if status.should_stop:
    print("HARD STOP — INITIATE TEARDOWN NOW")
elif status.should_warn:
    print(f"WARNING: {status.runtime_percent:.0f}% of authorized runtime consumed")
```

---

## Phase 7: Audit-First Smoke Test Binding

The authorization request binds to `SMOKE-TEST-RUN3-001` (defined in
`docs/operations/customer_zero_run3_audit_smoke_test.md`).

**Invariant:** No signing proof may begin until the audit smoke test passes.

### Smoke test binding verification

The `audit_smoke_test_contract` field in `run3_cost_authorization_request.json` must:
- `document_id`: `"SMOKE-TEST-RUN3-001"`
- `reference_file`: `"docs/operations/customer_zero_run3_audit_smoke_test.md"`
- `invariant`: explicitly states no signing proof may begin before smoke test passes
- `abort_on_failure`: `"ABORT-SMOKE-001 — immediate controlled teardown"`

### Abort path on smoke test failure

If the smoke test fails (no CloudWatch events within 2 minutes, or events do not contain
the expected cluster identifier):

1. Record failure condition and timestamp
2. DO NOT attempt to diagnose with paid infrastructure running
3. Execute `ABORT-SMOKE-001`: immediate controlled teardown
4. Record teardown start and completion timestamps
5. Verify billing stops (provider-side deletion confirmed)
6. Archive failure evidence

---

## Phase 8: Teardown and Preservation

### Six preserved AWS resources (canonical per ceremony_state.yaml post-PR #761)

| Resource | Lifecycle | protect_destroy |
|----------|-----------|----------------|
| `aws_cloudwatch_log_group.vault_audit` | PERSISTENT_AUDIT_AUTHORITY | Yes |
| `aws_iam_policy.vault_audit` | PERSISTENT_AUDIT_AUTHORITY | No (FP-005) |
| `aws_iam_user.vault_audit` | PERSISTENT_AUDIT_AUTHORITY | No (FP-005) |
| `aws_iam_user_policy_attachment.vault_audit` | PERSISTENT_AUDIT_AUTHORITY | No (FP-005) |
| `aws_iam_role.vault_audit_reader` | PERSISTENT_AUDIT_AUTHORITY | Yes (PR #761) |
| `aws_iam_role_policy_attachment.vault_audit_reader` | PERSISTENT_AUDIT_AUTHORITY | Yes (PR #761) |

**Preservation invariant:** No teardown action authorizes deletion of any of these 6 resources.
They are NOT ceremony-scoped. They are the durable audit boundary for all future ceremonies.

### Staged teardown sequence

1. Enable HCP Vault key deletion (`deletion_allowed = true` for all Transit keys)
2. Destroy Vault children (Transit mount, 3 keys, AppRole, 3 roles, 3 policies)
3. Destroy HCP Vault cluster
4. Destroy HCP HVN
5. **Verify 6 preserved AWS resources are still ACTIVE**
6. Capture billing evidence (HCP portal)
7. Confirm zero ongoing cost accrual

---

## Acceptance Criteria for this PR

This PR (`governance/customer-zero-run3-human-cost-review-001`) achieves:

1. Complete offline cost review package structure
2. Pricing evidence schema with capture procedure (operator-actionable)
3. Independent verifier with 22 fail-closed conditions
4. Cost model with three scenarios (all PENDING until pricing confirmed)
5. Execution window optimization documentation
6. Authorization request with all fields (financial fields null — FP-001 OPEN)
7. Runtime watchdog design with explicit billing disclaimer
8. Audit-first smoke test binding
9. Teardown and preservation contract
10. 28+ adversarial tests

**This PR does NOT produce spending authorization.** The authorization request
status is `BLOCKED_PRICING_UNVERIFIED` and will remain so until the human operator
confirms current HCP pricing from the HCP portal.
