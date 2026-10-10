# Customer-Zero Run-3 Cost Containment Plan

**Document ID:** COST-CONTAINMENT-RUN3-001
**Audit:** CZ-RUN3-FAILURE-PREVENTION-001
**Canonical Source SHA:** ec8684df4699be43b40d1edc9a79b58fd23e3637
**Date:** 2026-10-09
**Classification:** OFFLINE_PREPARATION — no cloud spending, no trust advancement

---

## Important Pricing Notice

**HCP Vault Dedicated pricing is UNVERIFIED in this offline document.**

The only verified cost figure available offline is the historical accrual from Runs 1 and 2:

> **$321.81 USD** — verified from `customer_one/ceremony_state.yaml`
> (`cost_containment.historical_october_usage_usd: 321.81`)

This amount is **consumed**. It is NOT a cost ceiling for Run 3. It is a historical reference
only. A new cost authorization with confirmed current pricing is required.

**Pre-ceremony required action:** The human operator must log into the HCP portal and
confirm current HCP Vault Dedicated (`standard_small`, `us-east-1`) pricing before any
cost authorization decision is presented for human approval. This is Finding FP-001 (P1)
from the failure prevention audit.

---

## What Accrues Costs

### HCP (primary cost driver — UNVERIFIED current rate)

| Resource | Cost model | Current rate |
|----------|-----------|-------------|
| `hcp_hvn.frostgate` | Included with cluster | Included |
| `hcp_vault_cluster.customer_zero` (standard_small) | Hourly, while provisioned | **UNVERIFIED — confirm in HCP portal** |

The HVN itself does not incur a separate line-item charge. Cost is billed through the
cluster. The cluster is only provisioned during the ceremony and destroyed immediately after.

### AWS (negligible)

| Resource | Cost model | Estimate |
|----------|-----------|---------|
| `aws_cloudwatch_log_group.vault_audit` | $0.50/GB ingestion (us-east-1, 2026) | < $0.01/ceremony (KB-scale audit volume) |
| IAM user, policy, role | No direct cost | $0.00 |

AWS costs are negligible for ceremony-scale Vault audit traffic. Confirmed in `infra/aws_audit.tf`
inline comments.

---

## Three-Scenario Cost Model

All scenarios are relative to the historical $321.81 baseline. Absolute dollar amounts are
**not specified** because HCP current pricing is unverified. The human reviewer must complete
this table with confirmed pricing before authorizing spending.

### Scenario 1: Optimistic

**Description:** Ceremony completes in 2–4 hours. No retries. All checkpoints pass on first
attempt. Immediate teardown after trust determination.

**Cost basis:** Historical rate × 2–4 hours.

**Absolute estimate:** UNVERIFIED — requires confirmed current HCP hourly rate.

**Prerequisites for this scenario:** All offline preparation complete; audit smoke test
passes immediately; CloudWatch streaming configured correctly on first attempt; AppRole
SecretIDs transferred without issue.

### Scenario 2: Expected

**Description:** Ceremony runs 4–6 hours. Normal checkpoint cadence including Checkpoint Q
(audit verification). One or two minor delays (configuration, verification). Immediate
teardown.

**Cost basis:** Historical rate × 4–6 hours.

**Absolute estimate:** UNVERIFIED — requires confirmed current HCP hourly rate.

**Note:** The $321.81 covered two complete ceremony runs including multiple checkpoints and
provisioning. A single Run 3 ceremony should cost less than $321.81 if it completes in one
session with no major delays.

### Scenario 3: Worst Authorized

**Description:** Ceremony approaches the hard abort deadline (human-defined maximum runtime).
Unexpected provisioning delays, configuration issues, or verification retries. Teardown
initiated at deadline whether or not trust is proven.

**Cost basis:** Historical rate × (operator-defined maximum runtime hours).

**Absolute estimate:** UNVERIFIED. The human approver must define the maximum authorized
runtime and compute the worst-case cost at confirmed current pricing before authorizing.

**Do not authorize without:** Confirmed HCP current pricing AND explicit maximum runtime
hours AND explicit maximum cost (USD).

---

## Cost Control Requirements

These requirements are inherited from `ceremony_state.yaml` third_ceremony_operational_model:

1. No paid HCP infrastructure before all offline gates pass.
2. Explicit human authorization required before paid provisioning.
3. Explicit cost ceiling (USD) with confirmed current HCP portal pricing.
4. Explicit maximum runtime (hours) set before ceremony begins.
5. Explicit start timestamp recorded.
6. Review deadline and hard-abort deadline set before ceremony begins.
7. No unattended overnight execution.
8. No exploratory debugging against paid infrastructure.
9. Failed checkpoint means STOP and controlled teardown — not retry.
10. Known staged teardown path verified before ceremony begins.
11. Billing evidence captured after teardown completes.
12. Provider-side deletion is not the same as Terraform-state absence — both required.
13. Fresh cost authorization required for Run 3 — previous $321.81 usage means old
    authorization is consumed.

---

## Human Cost Authorization Package Requirements

The following information must be assembled for `CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001`
before any spending decision is presented to the human approver:

| Item | Source | Status |
|------|--------|--------|
| Confirmed current HCP Vault Dedicated (standard_small) hourly rate | HCP portal (live check) | PENDING |
| Pricing validity window (when rate was confirmed) | HCP portal | PENDING |
| Proposed maximum cost (USD) | Human approver decision | PENDING |
| Proposed maximum runtime (hours) | Human approver decision | PENDING |
| Hard abort deadline (wall-clock time) | Human approver decision | PENDING |
| Operator identity (who will run the ceremony) | Known: Jason Cosat | READY |
| Human approver identity | Human decision | PENDING |
| Approval expiration | Human decision | PENDING |
| Source SHA binding (must be current canonical main) | Re-run evaluators post-PR-#760 | PENDING (FP-002) |
| Candidate fingerprint (from `customer_zero_run3_preauth.py`) | Re-run after simulation regen | PENDING (FP-002) |
| Audit prerequisites confirmed (4 AWS resources ACTIVE) | AWS console check | DEFERRED_TO_LIVE |

---

## Historical Cost Reference

Verified from `customer_one/ceremony_state.yaml`:

```
historical_october_usage_usd: 321.81
usage_note: "Accrued from ceremony run 1 and run 2; not ongoing after teardown"
```

Teardown stages completed (all four):
1. enable-key-deletion — COMPLETE
2. vault-children (11 Vault child resources) — COMPLETE
3. hcp-cluster — COMPLETE
4. hvn — COMPLETE

Cost is not ongoing. AWS audit resources preserved (no cost accrual beyond negligible
CloudWatch storage).

---

## Pricing Verification Procedure

Before CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001:

1. Log into HCP portal (https://portal.cloud.hashicorp.com) with authorized identity.
2. Navigate to Billing or Pricing for HCP Vault Dedicated.
3. Confirm the current hourly rate for `standard_small` tier in `aws us-east-1`.
4. Record: rate (USD/hour), date confirmed, validity window.
5. Add confirmed pricing to the cost authorization package.
6. Compute worst-case cost at authorized maximum runtime.
7. Present the complete package to the human approver.

**Do not proceed to Step 2 of CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001 without
completing this verification.**
