# CUSTOMER-ZERO-TRUST-001 Cost Authorization Package

**Ceremony:** `customer-zero-trust-2026-10-02-001`
**Status:** AWAITING OPERATOR PRICING VERIFICATION

This document must be completed by the operator before `terraform apply` may be authorized.
Do not substitute public pricing estimates for account-applicable portal pricing.

---

## HCP Vault Dedicated — Standard Small / AWS us-east-1

| Field | Value | Status |
|---|---|---|
| Tier | `standard_small` | PROVEN — from `variables.tf` |
| Cloud | AWS | PROVEN — from `variables.tf` |
| Region | `us-east-1` | PROVEN — from `variables.tf` |
| Hourly price | _operator to fill_ | NOT_PROVEN |
| Provider monthly estimate | _operator to fill_ | NOT_PROVEN |
| Regional differential | _operator to fill_ | NOT_PROVEN |
| Pricing evidence timestamp | _operator to fill_ | NOT_PROVEN |
| Pricing source | HCP portal cluster-creation estimator | NOT_PROVEN |
| Account-applicable | YES / NO | NOT_PROVEN |

**HUMAN OPERATOR ACTION REQUIRED:**

Log in to HCP portal → Vault → Create cluster (do not submit) → select Standard Small / AWS us-east-1.
Record the displayed hourly rate and monthly estimate. These are the account-applicable prices.

---

## Vault Client Pricing

| Field | Value | Status |
|---|---|---|
| Price per unique client | _operator to fill_ | NOT_PROVEN |
| Billing period | monthly | ASSUMED |
| Partial-month prorated | _operator to confirm_ | NOT_PROVEN |
| Minimum ceremony client count estimate | 3–5 AppRole principals | ESTIMATED |
| Maximum ceremony client count estimate | 10 | ESTIMATED |
| Pricing evidence timestamp | _operator to fill_ | NOT_PROVEN |
| Account-applicable | YES / NO | NOT_PROVEN |

**HUMAN OPERATOR ACTION REQUIRED:**

In HCP portal → Billing → Pricing FAQ or support chat: confirm the per-client monthly rate
and whether clients are prorated for partial months or charged the full monthly rate.

**Why this matters:** If the per-client charge is NOT prorated, even an 8-hour ceremony
creates a full month's client charge per unique Vault principal (~$72/client from public
pricing — account pricing may differ).

---

## Credits

| Field | Value | Status |
|---|---|---|
| Available balance | _operator to fill_ | NOT_PROVEN |
| Expiration date | _operator to fill_ | NOT_PROVEN |
| Vault Dedicated eligible | YES / NO | NOT_PROVEN |
| Restrictions | _operator to fill_ | NOT_PROVEN |
| Evidence timestamp | _operator to fill_ | NOT_PROVEN |

**HUMAN OPERATOR ACTION REQUIRED:**

Log in to HCP portal → Billing → Credits. Record balance, expiration, and eligibility.

---

## AWS Infrastructure Charges

| Resource | Charge | Status |
|---|---|---|
| IAM user | $0.00 | PROVEN |
| IAM policy | $0.00 | PROVEN |
| IAM policy attachment | $0.00 | PROVEN |
| CloudWatch log group | $0.00 (creation) | PROVEN |
| CloudWatch log ingestion | $0.50/GB (us-east-1) | PUBLIC_PROVIDER_PRICE |
| CloudWatch log storage (365d) | $0.03/GB/month | PUBLIC_PROVIDER_PRICE |
| Vault audit log volume (ceremony) | ~KB/day | ESTIMATED |
| **Expected AWS total (ceremony)** | **~$0.01** | DERIVED |

AWS charges are negligible for ceremony-scale Vault audit traffic. The dominant cost is the HCP cluster.

---

## Derived Ceremony Exposure

These figures will be populated once account-applicable pricing is confirmed.
Until then, all 8h/12h/24h figures are NOT_PROVEN.

```
8-hour ceremony exposure:
  Cluster: [hourly] × 8 = NOT_PROVEN
  Clients: [per-client] × [count] × [proration] = NOT_PROVEN
  AWS: ~$0.01 (DERIVED)
  Credits: NOT_PROVEN
  NET: NOT_PROVEN

12-hour ceremony exposure:
  Cluster: [hourly] × 12 = NOT_PROVEN
  Clients: same as 8h (prorated) or same as 8h (unprorated) = NOT_PROVEN
  AWS: ~$0.01 (DERIVED)
  Credits: NOT_PROVEN
  NET: NOT_PROVEN

24-hour ceremony exposure:
  Cluster: [hourly] × 24 = NOT_PROVEN
  Clients: NOT_PROVEN
  AWS: ~$0.01 (DERIVED)
  Credits: NOT_PROVEN
  NET: NOT_PROVEN
```

---

## Authorization Record Template

Complete this section before Checkpoint E (authorization to apply):

```
COST AUTHORIZATION RECORD
=========================
Ceremony: customer-zero-trust-2026-10-02-001
Date: ___________________
Operator name: ___________________
Operator ref: ___________________

HCP Cluster (Standard Small, us-east-1):
  Hourly rate (account-applicable):  $___________  [SOURCE: HCP portal]
  Monthly estimate (account):        $___________  [SOURCE: HCP portal]

Vault client pricing:
  Per-client rate (account):         $___________  [SOURCE: HCP portal]
  Billing period:                    monthly
  Partial-month prorated:            YES / NO      [SOURCE: HCP support/FAQ]

Credits:
  Available balance:                 $___________  [SOURCE: HCP portal billing]
  Expiration:                        ___________
  Vault Dedicated eligible:          YES / NO

Ceremony exposure estimates:
  8h gross (cluster + clients):      $___________
  8h net (after credits):            $___________
  12h gross:                         $___________
  12h net:                           $___________
  Maximum authorized exposure:       $___________

AUTHORIZATION:
  [ ] I have verified the above pricing from the HCP portal.
  [ ] I accept the maximum exposure of $__________.
  [ ] I authorize terraform apply for ceremony customer-zero-trust-2026-10-02-001.

Signature: ___________________  Date: ___________________
```
