# Customer-Zero Run-3 Pricing Evidence Capture

**Work item:** CUSTOMER-ZERO-RUN3-PRICING-EVIDENCE-001
**Status:** OFFLINE_PREPARATION — FP-001 OPEN
**Canonical truth:** CUSTOMER_ZERO_TRUST=NOT_PROVEN, THIRD_PAID_CEREMONY=NOT_AUTHORIZED

---

## 1. Purpose

This runbook documents how a human operator captures verified pricing evidence for
HCP Vault Dedicated (standard_small, us-east-1) and populates
`customer_one/run3_pricing_evidence_instance.json` to close FP-001 from
CZ-RUN3-FAILURE-PREVENTION-001.

**Why this matters:** Two previous ceremony runs cost $321.81 combined. That figure
is CONSUMED and cannot serve as a ceiling for Run 3. The actual current HCP hourly
rate is unknown offline. An incorrectly estimated rate will produce a cost model
that understates real exposure, potentially leading to unauthorized overspend.

**What this evidence enables:** Once the evidence instance is fully populated,
independently reviewed, and fingerprinted, the verifier tool can advance the
authorization request status from `BLOCKED_PRICING_UNVERIFIED` toward
`READY_FOR_HUMAN_DECISION`.

**What this evidence does NOT do:** It does not authorize Run 3. It does not set
a cost ceiling. It does not approve spending. All of those require explicit human
decisions recorded separately.

---

## 2. Prerequisites

Before starting evidence capture:

- [ ] Authorized HCP identity (jcosat0211@gmail.com or authorized FrostGate operator)
- [ ] Access to HCP portal: https://portal.cloud.hashicorp.com
- [ ] Local checkout of fg-core at the current main SHA
- [ ] Python environment: `cd /home/jcosat/Projects/fg-core && source .venv/bin/activate`
- [ ] A designated independent reviewer (a different person from the collector)
- [ ] The file `customer_one/run3_pricing_evidence_instance.json` open for editing

Do NOT use `cosatjason@gmail.com` — that identity is unauthorized per
`user_auth0_identities.md`. Use `jcosat0211@gmail.com`.

---

## 3. Step 1: Access HCP Portal Pricing

1. Navigate to: https://portal.cloud.hashicorp.com
2. Sign in with `jcosat0211@gmail.com`
3. Navigate to: **Billing** → **Pricing** (or **Plans** depending on portal version)
4. Select **HCP Vault** → **Dedicated**
5. Find the pricing for:
   - Tier: `standard_small`
   - Cloud provider: `AWS`
   - Region: `us-east-1`

Look for:
- Hourly rate (USD/hour)
- Billing unit (hourly, per-minute, etc.)
- Billing granularity (is it billed per full hour, or can partial hours be charged?)
- Any minimum charge (minimum billable unit)
- Any additional per-operation charges (seal/unseal, API calls, etc.)

**If pricing is not visible in the portal:** Check:
- https://www.hashicorp.com/products/vault/pricing
- https://developer.hashicorp.com/hcp/docs/vault/pricing

Record the URL where you found the pricing in `source.reference_url`.

---

## 4. Step 2: Record Evidence Fields

Open `customer_one/run3_pricing_evidence_instance.json` and populate all null fields:

### Required fields and what valid vs. invalid values look like:

| Field | Valid example | Invalid example | Why |
|-------|--------------|-----------------|-----|
| `evidence_id` | `"CZ-RUN3-PRICING-2026-10-15"` | `null` | Must uniquely identify this capture event |
| `collection_timestamp_utc` | `"2026-10-15T14:30:00+00:00"` | `"2026-10-15T14:30:00"` (no tz) | Must be timezone-aware ISO-8601 |
| `expiry_policy.expires_at_utc` | `"2026-11-14T14:30:00+00:00"` | `null` | 30 days from collection |
| `provider.tier` | `"standard_small"` | `"standard"` or `"plus_small"` | Must exactly match HCP tier |
| `provider.region` | `"us-east-1"` | `"us-east1"` or `"us_east_1"` | Must exactly match HCP region string |
| `pricing.currency` | `"USD"` | `"usd"` (lowercase is OK — normalized) | |
| `pricing.hourly_rate_usd` | `"1.58"` | `"~$1.60"` or `1.58` (float) | Use a quoted Decimal string |
| `pricing.billing_unit` | `"hourly"` | `null` | Human description |
| `pricing.billing_unit_minutes` | `60` | `0` or `-1` | Must be a positive integer |
| `pricing.minimum_billable_unit` | `"1 hour"` | `null` | Text description |
| `pricing.minimum_charge_usd` | `"1.58"` | `"-1.00"` | Must be >= 0 |
| `pricing.unknown_charges_acknowledged` | `true` | `null` | Must be a boolean; set true only if you have checked for additional charges |
| `source.classification` | `"hcp_portal_screenshot"` | `"estimate"` | Must be one of the valid values |
| `source.reference_url` | `"https://portal.cloud.hashicorp.com/..."` | `"http://..."` (non-HTTPS) | Must start with `https://` |
| `provenance.collector_identity` | `"jcosat0211@gmail.com"` | `null` | Full email or name |
| `provenance.independent_reviewer_identity` | `"reviewer@example.com"` | Same as collector | MUST be different person |

Valid `source.classification` values:
- `"hcp_portal_screenshot"` — screenshot taken from the HCP portal
- `"hcp_api_response"` — programmatically retrieved from HCP API
- `"hcp_sales_quote"` — written quote from HashiCorp sales
- `"hcp_pricing_page"` — observed from the public pricing page

### What unknown_charges_acknowledged means:

Set `unknown_charges_acknowledged` to `true` only if you have **actively checked**
for any charges beyond the base hourly rate (API call charges, seal/unseal fees,
support tier surcharges, network egress, etc.) and are satisfied that the hourly
rate captures the material cost for a ~2-4 hour ceremony.

Setting this to `false` will cause `is_defensible_upper_bound=False` in the bounded
exposure report, meaning the cost ceiling cannot be certified.

---

## 5. Step 3: Compute Evidence Fingerprint

After populating all fields, compute the SHA-256 fingerprint of the `pricing` sub-object:

```bash
cd /home/jcosat/Projects/fg-core
python3 -c "
import json, hashlib
with open('customer_one/run3_pricing_evidence_instance.json') as f:
    instance = json.load(f)
pricing = instance['pricing']
canonical = json.dumps(pricing, sort_keys=True, separators=(',', ':'))
fp = hashlib.sha256(canonical.encode()).hexdigest()
print('Fingerprint:', fp)
print('Canonical JSON:', canonical)
"
```

Copy the output fingerprint into:
```json
"integrity": {
    "evidence_fingerprint_sha256": "<paste fingerprint here>",
    "fingerprint_covers_fields": ["pricing"],
    "fingerprint_algorithm": "sha256"
}
```

**Important:** The fingerprint is computed over the `pricing` sub-object ONLY. If you
modify any `pricing` field after computing the fingerprint, you must recompute it.
A stale fingerprint will cause `REJECTED_TAMPERED`.

---

## 6. Step 4: Independent Review

A **different person** from the collector must independently verify the evidence:

1. They must have independent access to HCP portal or pricing documentation
2. They must confirm:
   - The hourly rate is current (not estimated, not from memory)
   - The tier is `standard_small`
   - The region is `us-east-1`
   - The source URL is live and accurate
   - The fingerprint matches the actual pricing fields
3. They must set `provenance.independent_reviewer_identity` to their own identity

**Separation of duties is enforced:** The verifier will reject evidence where
`collector_identity == reviewer_identity`. Self-certification is not permitted.

---

## 7. Step 5: Run the Verifier

```bash
cd /home/jcosat/Projects/fg-core
.venv/bin/python services/governance/run3_pricing_evidence_verifier.py \
    customer_one/run3_pricing_evidence_instance.json
```

Or use the full pipeline verifier:

```bash
.venv/bin/python tools/ci/verify_pricing_evidence.py --repo . 2>&1
```

A successful run produces output ending with:

```json
{
  "overall_status": "BLOCKED_HUMAN_INPUTS",
  "approved": false
}
```

(or `READY_FOR_HUMAN_DECISION` when all non-human inputs are complete)

---

## 8. Step 6: Interpret Results

| Status | Meaning | Action |
|--------|---------|--------|
| `BLOCKED_PRICING_UNVERIFIED` | Evidence file has null fields or fingerprint not set | Populate all null fields and set fingerprint |
| `BLOCKED_PRICING_EVIDENCE_INVALID` | Evidence file has structural or content errors | Fix the specific error in the finding messages |
| `REJECTED_SCHEMA` | Required fields missing or file not parseable | Add the missing fields |
| `REJECTED_CONTENT` | tier/region/currency/rate wrong | Check the HCP portal values match expected |
| `REJECTED_PROVENANCE` | Identity fields null or same person | Set distinct collector and reviewer identities |
| `REJECTED_FRESHNESS` | Timestamp issues (future, naive, expired) | Fix timestamp format or recollect fresh evidence |
| `REJECTED_SOURCE` | Invalid classification or non-HTTPS URL | Use a valid classification and HTTPS URL |
| `REJECTED_TAMPERED` | Fingerprint present but wrong | Recompute fingerprint from current pricing fields |
| `UNVALIDATED` | Fingerprint null — structural checks pass | Compute and set the fingerprint |
| `VALIDATED` | Evidence passes all checks | Proceed to cost authorization request |
| `BLOCKED_FINANCIAL_EXPOSURE` | Pricing valid but max cost/runtime not set | Human operator sets financial limits |
| `BLOCKED_HUMAN_INPUTS` | Pricing valid but operator/approver identity not set | Human fills identities |
| `READY_FOR_HUMAN_DECISION` | All automated checks pass | Human approver makes explicit authorization decision |

---

## 9. Step 7: Decision Preparation

Once evidence is `VALIDATED` and the overall status reaches `BLOCKED_HUMAN_INPUTS`
or better, prepare the bounded exposure report:

```bash
cd /home/jcosat/Projects/fg-core
.venv/bin/python3 -c "
from decimal import Decimal
from services.governance.run3_cost_model import PricingInputs, compute_bounded_exposure

inputs = PricingInputs(
    hourly_rate_usd=Decimal('<actual confirmed rate>'),
    billing_unit_minutes=60,  # or confirmed value
    minimum_charge_usd=Decimal('<confirmed minimum>'),
    aws_cloudwatch_per_gb_usd=Decimal('0.50'),
    estimated_audit_volume_gb=Decimal('0.001'),
)
inputs._unknown_charges_acknowledged = True  # only if confirmed

# Use your proposed max runtime (e.g., 240 minutes = 4 hours)
report = compute_bounded_exposure(inputs, max_runtime_minutes=240)
import json
print(json.dumps(report.to_dict(), indent=2))
"
```

The human approver must review:
- `total_bounded_ceiling_usd` — this is the maximum authorized spend
- `is_defensible_upper_bound` — must be `true` for the ceiling to be certifiable
- `unknown_charges_warning` — if present, address before authorization

---

## 10. Checklist

Pre-authorization checklist for the human operator:

- [ ] Logged into HCP portal with authorized identity (`jcosat0211@gmail.com`)
- [ ] Verified current hourly rate for `standard_small` in `us-east-1` from live portal
- [ ] All `null` fields in `run3_pricing_evidence_instance.json` populated
- [ ] `collection_timestamp_utc` is timezone-aware and not in the future
- [ ] `expiry_policy.expires_at_utc` set to 30 days from collection (not past)
- [ ] `source.classification` set to a valid value
- [ ] `source.reference_url` is a live HTTPS URL pointing to pricing evidence
- [ ] `provenance.collector_identity` set to your own identity
- [ ] `provenance.independent_reviewer_identity` set to a DIFFERENT person's identity
- [ ] Independent reviewer has confirmed the values independently
- [ ] Evidence fingerprint computed and set in `integrity.evidence_fingerprint_sha256`
- [ ] `unknown_charges_acknowledged` set to `true` (after checking for additional charges)
- [ ] Verifier returns `VALIDATED` for the evidence instance
- [ ] Bounded exposure report reviewed by human approver
- [ ] Human approver has explicitly authorized the proposed maximum spend

---

## 11. What NOT to Do

**Do NOT:**

- **Fabricate or estimate pricing values** — use only values observed directly from
  the HCP portal or official HashiCorp documentation. Fabricated values produce a
  cost model that does not reflect real exposure.

- **Reuse expired evidence** — evidence expires after 30 days. The verifier rejects
  expired evidence (`REJECTED_FRESHNESS`). Collect fresh evidence before each ceremony.

- **Self-certify** — the collector and independent reviewer must be different people.
  The verifier enforces separation of duties (`REJECTED_PROVENANCE`).

- **Set the fingerprint before finalizing pricing fields** — compute the fingerprint
  last, after all `pricing` sub-object fields are final. Modifying pricing after
  fingerprinting produces a tamper detection failure.

- **Use `$321.81` as a cost ceiling** — that figure is CONSUMED (Runs 1+2 only).
  It cannot serve as any reference for Run 3 authorization.

- **Skip the independent reviewer** — self-signed evidence cannot be used for
  cost authorization. A second person with independent portal access must verify.

- **Set `approved: true` anywhere in the pipeline** — APPROVED state is unreachable
  through automation. Any code that produces APPROVED is a critical defect.

---

*This runbook is part of CUSTOMER-ZERO-RUN3-PRICING-EVIDENCE-001.
Canonical truth: CUSTOMER_ZERO_TRUST=NOT_PROVEN, THIRD_PAID_CEREMONY=NOT_AUTHORIZED.*
