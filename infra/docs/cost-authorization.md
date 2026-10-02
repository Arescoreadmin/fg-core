# CUSTOMER-ZERO-TRUST-001 Cost Authorization Package

**Ceremony:** `customer-zero-trust-2026-10-02-001`
**Status:** COST_READY_FOR_OPERATOR_AUTHORIZATION

**COST_AUTHORIZATION = NOT_GRANTED**

Pricing evidence has been proven and the cost model is complete. The operator
must explicitly authorize spending before `terraform apply` may proceed.
See §Authorization Record below.

---

## Evidence Classification Key

| Label | Meaning |
|---|---|
| LIVE_PROVEN | Verified from authenticated HCP portal or live system |
| PROVIDER_DOCUMENTED | Stated in canonical HashiCorp documentation |
| DERIVED | Calculated from LIVE_PROVEN or PROVIDER_DOCUMENTED inputs |
| ESTIMATED | Planning assumption not backed by provider evidence |
| NOT_PROVEN | Still unknown; blocks authorization if load-bearing |

---

## HCP Account State

| Field | Value | Status |
|---|---|---|
| Organization | Frostgate-org | LIVE_PROVEN |
| Project | frostgate-production | LIVE_PROVEN |
| Billing model | Trial | LIVE_PROVEN |
| Trial credits remaining | $500.00 | LIVE_PROVEN — 2026-10-02 |
| Month-to-date HCP spend | $0.00 | LIVE_PROVEN — 2026-10-02 |
| Trial credit expiry | Six months from org creation | PROVIDER_DOCUMENTED |
| Credit expiry date (exact) | _operator to fill_ | NOT_PROVEN |
| Vault Dedicated cluster limit (Trial) | 1 cluster | PROVIDER_DOCUMENTED |
| Credits consumed before card charge | YES | PROVIDER_DOCUMENTED |
| Services stop if credits exhausted (no card) | YES | PROVIDER_DOCUMENTED |

**Source:** `developer.hashicorp.com/hcp/docs/hcp/admin/billing` — 2026-10-02

---

## HCP Vault Dedicated — Standard Small / AWS us-east-1

| Field | Value | Status |
|---|---|---|
| Tier | `standard_small` | LIVE_PROVEN — from Terraform `variables.tf` + portal |
| Cloud | AWS | LIVE_PROVEN — from Terraform `variables.tf` |
| Region | `us-east-1` | LIVE_PROVEN — from Terraform `variables.tf` |
| Cluster hourly rate | $1.84299/hour | LIVE_PROVEN — HCP portal Billing → Pricing, 2026-10-02 |
| Client monthly rate | $72.92/month/client | LIVE_PROVEN — HCP portal Billing → Pricing, 2026-10-02 |
| Billing start | Cluster creation | PROVIDER_DOCUMENTED |
| Billing stop | Cluster deletion | PROVIDER_DOCUMENTED |
| Partial-hour billing | Charged by the minute | PROVIDER_DOCUMENTED |
| Regional differential | Included in displayed rate | LIVE_PROVEN — rate is region-specific (us-east-1) |
| Pricing evidence timestamp | 2026-10-02 | LIVE_PROVEN |

**Source:** `developer.hashicorp.com/hcp/docs/hcp/admin/billing/pricing-definitions` — 2026-10-02

---

## HCP Vault Dedicated — Essentials Small / AWS us-east-1 (reference)

| Field | Value | Status |
|---|---|---|
| Cluster hourly rate | $1.57799/hour | LIVE_PROVEN — HCP portal Billing → Pricing, 2026-10-02 |
| Client monthly rate | $72.92/month/client | LIVE_PROVEN — identical to Standard |
| Saving vs Standard Small | $0.265/hour | DERIVED |
| 8h saving vs Standard | $2.12 | DERIVED |

Architecture assessment: Essentials Small does not provide sufficient cost
savings ($2.12 over 8 hours) to justify changing the approved architecture.
Standard Small is retained. No Terraform change required.

---

## Vault Client Billing Model

| Field | Value | Status |
|---|---|---|
| Billing unit | Per unique client per monthly billing period | PROVIDER_DOCUMENTED |
| Client counting window | Monthly (resets at end of billing cycle) | PROVIDER_DOCUMENTED |
| Same client, multiple authentications | Counted once per month | PROVIDER_DOCUMENTED |
| Billing rate | $72.92/month/client (flat, not prorated) | LIVE_PROVEN |
| Client count reductions before month end | Not possible | PROVIDER_DOCUMENTED |
| Expected ceremony client count | 3 AppRole principals | ESTIMATED |
| Client cost (3 clients) | $218.76 | DERIVED |

**Critical billing fact:** Client charges are flat-rate monthly, not prorated.
A client that authenticates once in a billing period incurs the full
$72.92/month charge regardless of when the cluster is destroyed.

**Implication:** Destroying the cluster after 8 hours does not reduce the
per-client charge. The $218.76 client cost is effectively locked in from the
first AppRole authentication during the ceremony.

**Mitigation:** $218.76 falls well within the $500.00 trial credit balance
at $0 net cash exposure, assuming credits apply as documented.

---

## AWS Infrastructure Charges

| Resource | Charge | Status |
|---|---|---|
| IAM user | $0.00 | LIVE_PROVEN |
| IAM policy | $0.00 | LIVE_PROVEN |
| IAM policy attachment | $0.00 | LIVE_PROVEN |
| CloudWatch log group (creation) | $0.00 | LIVE_PROVEN |
| CloudWatch log ingestion | $0.50/GB (us-east-1) | PROVIDER_DOCUMENTED |
| CloudWatch log storage (365d) | $0.03/GB/month | PROVIDER_DOCUMENTED |
| Vault audit log volume (ceremony) | ~KB/day | ESTIMATED |
| **Expected AWS total (ceremony)** | **< $0.01** | DERIVED |

AWS charges are negligible relative to HCP cost at ceremony scale.

---

## Derived Ceremony Exposure — Standard Small, 3 clients

All calculations use: cluster $1.84299/hour, clients 3 × $72.92 = $218.76 flat.

### Hourly cluster cost only (before client component)

| Duration | Cluster cost |
|---|---|
| 3h | $5.52897 |
| 5h | $9.21495 |
| 8h | $14.74392 |
| 10h | $18.42990 |
| 12h | $22.11588 |
| 24h | $44.23176 |
| 7 days | $309.62328 |
| 30 days | $1,327.75 |

### Total gross (cluster + 3 clients flat + AWS negligible)

| Duration | Cluster | Clients | Total gross | After $500 credits |
|---|---|---|---|---|
| 3h | $5.53 | $218.76 | ~$224.29 | **$0** (credits cover) |
| 5h | $9.21 | $218.76 | ~$227.97 | **$0** (credits cover) |
| 8h | $14.74 | $218.76 | ~$233.50 | **$0** (credits cover) |
| 10h | $18.43 | $218.76 | ~$237.19 | **$0** (credits cover) |
| 12h | $22.12 | $218.76 | ~$240.88 | **$0** (credits cover) |
| 24h | $44.23 | $218.76 | ~$262.99 | **$0** (credits cover) |
| 7 days | $309.62 | $218.76 | ~$528.38 | **$28.38** (credits exhausted) |
| 30 days | $1,327.75 | $218.76 | ~$1,546.51 | **$1,046.51** (credits exhausted) |

**Accidental-leave-running threshold:**
Credits ($500) are exhausted at approximately **~$281 cluster runtime**
beyond the $218.76 client floor. At $1.84299/hour that is approximately
**152 cluster-hours** before credits run out (from first client auth).
**At current pace with 3 clients authenticated: ~6.4 days before cash charges begin.**

**For a standard 8-hour ceremony:** estimated gross $233.50, net $0 cash
after credits, with $266.50 in credits remaining.

All figures DERIVED from LIVE_PROVEN pricing and ESTIMATED client count.

---

## Remaining Uncertainty

| Item | Impact | Resolution |
|---|---|---|
| Credit expiration date | If credits expired, $233.50 becomes real cash | Operator reads from HCP portal Billing → Credits |
| Exact client count | Could be >3 if admin token itself is billed as a client | Verify in HCP portal post-ceremony; unlikely to affect outcome |
| Credit applicability to Vault Dedicated Standard specifically | If excluded, $233.50 becomes real cash | Confirmed via PROVIDER_DOCUMENTED Trial terms; Vault Dedicated is an HCP service eligible for trial credits |

**Only the credit expiration date remains unconfirmed.** All other uncertainties are resolved or immaterial given the $500 balance.

---

## Authorization Record Template

Complete this section before Checkpoint E (authorization to apply):

```
COST AUTHORIZATION RECORD
=========================
Ceremony:     customer-zero-trust-2026-10-02-001
Date:         ___________________
Operator:     ___________________

HCP Cluster (Standard Small, us-east-1):
  Hourly rate (LIVE_PROVEN):    $1.84299/hour
  Billing granularity:          per-minute

Vault Client pricing:
  Per-client rate (LIVE_PROVEN): $72.92/month/client
  Billing period:                monthly (flat, not prorated)
  Expected clients:              3 AppRole principals (ESTIMATED)
  Expected client charge:        $218.76

Trial credits:
  Available balance (LIVE_PROVEN): $500.00
  Expiration date:                 ___________ [OPERATOR TO FILL]
  Vault Dedicated eligible:        YES (PROVIDER_DOCUMENTED — Trial covers all HCP services)

Ceremony exposure estimates:
  Expected runtime:              3–5 hours
  Operational ceiling:           8 hours
  Freeze/review threshold:       12 hours
  8h gross (cluster + clients):  ~$233.50
  8h net (after credits):        ~$0.00 (assuming credits valid)
  12h gross:                     ~$240.88
  12h net:                       ~$0.00 (assuming credits valid)
  Maximum authorized exposure:   $___________

AUTHORIZATION:
  [ ] I have verified the above pricing from the HCP portal Billing → Pricing page.
  [ ] I confirm trial credits of $500.00 are available and have not expired.
  [ ] I accept the maximum gross exposure of $__________ (suggest $275 for 8h + margin).
  [ ] I authorize terraform apply for ceremony customer-zero-trust-2026-10-02-001.
  [ ] I understand that once AppRole clients authenticate, $218.76 in client
      charges is locked for the monthly billing period regardless of cluster lifetime.
  [ ] I will destroy the cluster promptly after the ceremony is complete
      or after the 12-hour freeze threshold is reached.

Signature: ___________________  Date: ___________________
```

---

## Proposed Authorization Statement

*(Prepared for operator review. DO NOT treat as authorization — the operator
must read, fill, and sign the record above.)*

> I authorize creation of the CUSTOMER-ZERO-TRUST-001 production trust
> infrastructure for ceremony `customer-zero-trust-2026-10-02-001`, using
> HCP Vault Dedicated Standard Small in AWS us-east-1, at the verified
> account-applicable rate of **$1.84299/hour** for the cluster plus
> **$72.92/month/client** flat (not prorated), with 3 expected AppRole
> clients. Expected gross exposure: **~$233.50** for an 8-hour ceremony.
> Expected net cash cost: **$0**, covered by the $500.00 trial credit balance,
> subject to credits being valid and not expired. Authorized maximum runtime:
> **8 hours**. If the 12-hour freeze threshold is reached before all
> checkpoints are complete, stop provisioning and do not proceed to
> Checkpoint E without renewed explicit authorization. Destroy the cluster
> promptly upon ceremony completion.
>
> Ceremony ID: `customer-zero-trust-2026-10-02-001`
> Operator: ___________________
> Date: ___________________
