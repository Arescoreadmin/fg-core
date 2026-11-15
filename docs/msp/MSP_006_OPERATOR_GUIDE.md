# MSP-006 operator guide

This guide is for FrostGate platform operators setting up and checking MSP partner billing. Every step below uses existing authorities. None of it moves money: live settlement is NOT PROVEN, and no step contacts a payment processor.

## Before first use

1. **Apply migration 0207.** It adds `msp_payer_assignments` and enables forced RLS on `usage_events`. It must be applied in the target environment.
2. **Check billing_v2 callers.** After 0207, `usage_events` is readable only within a bound tenant context. The billing_v2 record, list and explain routes now bind it. Any out-of-band job that reads `usage_events` without a tenant context will see no rows.
3. **Create the meter** (once), through the existing meter route:

   ```
   POST /admin/billing/meters
   {"meter_code": "msp.assessment_delivered", "display_name": "Assessment delivered (MSP)",
    "unit": "assessment", "aggregation_mode": "sum", "billing_category": "msp"}
   ```

   Usage for `msp.*` meters can only come from MSP-006's trusted producer. The public usage route refuses them.
4. **Confirm MSP-001 setup.** The MSP must be designated (`PUT /admin/msp/organizations/{id}`), and the customer must have approved the relationship.

## Set up an MSP-paid (Mode A) customer

1. **Commercial agreement.** Create an `active` contract for the MSP (the payer) in the subscription authority: `POST /admin/subscriptions/contracts`.
2. **Price.** The MSP must have a `tenant_contracts` row in force, pointing at a `pricing_versions` row whose `rates_json` contains:

   ```json
   {"assessment.delivered": {"unit_amount_minor": 125000, "currency": "USD"}}
   ```

   The rules for this row:
   - `sha256_hash` must equal `canonical_hash({"pricing_version_id": …, "rates_json": …})` (`api/msp_billing.pricing_version_hash`).
   - `contract_hash` must equal the existing canonical contract hash.
   - Amounts are integer minor units; a float rate is rejected.
   - Price lists are append-only. To change a price, add a new version and a new contract with a later `start_at`. Charges already made keep their price.
3. **Payer assignment.** Through the internal admin gateway, as `platform.admin`:

   ```
   POST /admin/msp/billing/payer-assignments
   {"customer_tenant_id": "<customer>", "relationship_id": "<relationship>",
    "billing_mode": "msp_paid", "product_code": "assessment.delivered",
    "subscription_contract_id": "<MSP's contract>", "currency": "USD",
    "expires_at": "<ISO time, at most 400 days ahead>"}
   ```

   The payer is derived from the mode; you cannot name it. Creation fails, writing nothing, if the relationship is not active, the MSP is not active, or the agreement is not the payer's active agreement. A customer has at most one active payer per product.

## Set up a customer-paid (Mode B) customer

Follow the same steps, with the customer as payer:

- the agreement and price belong to the customer;
- the assignment uses `"billing_mode": "customer_paid"`.

The MSP cannot see a customer-paid assignment or its charges.

## What happens on delivery

When QA approval advances an engagement to `delivered` (all gates passed), the producer records one charge for the resolved payer, at the price in force at that moment.

| Outcome | Meaning |
|---|---|
| `recorded` | One `usage_events` row under the payer, `billing_status = pending` |
| `duplicate` | Already recorded; nothing added |
| `not_applicable` | The customer has no payer assignment, so this is not MSP-billed |
| `not_billable` | An assignment exists but something failed closed. The reason is on the customer's audit chain (`tenant.msp.billing_usage_not_billable`). |

Reasons for `not_billable`:

| Reason | Cause |
|---|---|
| `PAYER_ASSIGNMENT_NOT_IN_EFFECT` | Outside the assignment's window |
| `MSP_RELATIONSHIP_INACTIVE` | The relationship is proposed, suspended, revoked or expired |
| `MSP_ORGANIZATION_NOT_ACTIVE` | The MSP designation is suspended |
| `CUSTOMER_TENANT_INACTIVE` | The customer tenant is not active |
| `PAYER_AGREEMENT_INVALID` | The agreement is not active or not in force |
| `PRICING_NOT_FOUND`, `PRICING_CONTRACT_HASH_MISMATCH`, `PRICING_HASH_MISMATCH` | Price setup is missing or does not verify |
| `PRICING_RATE_INVALID` | The rate is not an integer in minor units |
| `PRICING_CURRENCY_MISMATCH` | The rate's currency differs from the assignment's |
| `METER_NOT_CONFIGURED` | The meter is missing or inactive |

Billing never blocks a delivery. If recording fails, reconciliation lists the delivery.

## End or change billing

- **Terminate:**

  ```
  POST /admin/msp/billing/payer-assignments/{id}/terminate
  {"customer_tenant_id": "<customer>", "expected_version": <n>}
  ```

  Future deliveries stop resolving to that payer. Charges already recorded remain.
- **Change payer or mode:** terminate, then create a new assignment.
- **A customer revoking or suspending the MSP** stops new charges at once. It does not cancel any subscription, and it removes no recorded charge.

## Check and reconcile

**Payers** (`billing.read`, `tenant_admin`) see their own charges:

```
GET /admin/msp/billing/usage?period=2026-11
```

This returns integer totals per currency and `"settlement": "NOT_PROVEN"`.

**Platform** reconciliation:

```
GET /admin/msp/billing/reconciliation?payer_tenant_id=<payer>&period=2026-11
```

`ok: true` means every charge recomputed exactly, with no duplicates and no unexplained delivery. If not, check these fields:

| Field | Meaning |
|---|---|
| `charges[].problems` | Per-charge failures, for example `MISSING_PROCESSOR_REFERENCE`, `PAYER_CHANGED`, `AMOUNT_MISMATCH` |
| `duplicate_source_references` | More than one charge for the same delivery |
| `deliveries_without_usage` | A delivery covered by an assignment with neither a charge nor a not-billable decision. Investigate and re-run the producer. It is idempotent. |
| `report_sha256` | The same inputs always give the same hash; keep it with the period's records |

## Rollback

Revert the PR. Migration 0207 is additive. Leave `msp_payer_assignments` in place, empty or not. No existing financial row is modified.

## Not yet supported

Do not promise these:

- live processor settlement or invoicing;
- split or multi-party billing;
- credits and adjustments;
- per-managed-tenant or monitoring billing;
- a billing dashboard;
- white-label invoices.
