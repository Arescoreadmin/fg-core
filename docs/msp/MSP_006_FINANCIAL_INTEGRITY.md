# MSP-006 financial integrity

This document states the controls that keep MSP-006 charges exact, single, attributable and verifiable, and how each one is tested. Tests are in `tests/security/test_msp_006_billing.py` (numbered by the MSP-006 acceptance matrix) and the Postgres probe `test_0207_msp_006_billing_rows_are_isolated_by_forced_rls`.

## Idempotency

| Requirement | Control | Test |
|---|---|---|
| One source operation, at most one usage record per dimension | Key `msp006:{product}:{customer}:{engagement}`; database unique `(tenant_id, idempotency_key)` on `usage_events` | 11 |
| Same key and same payload returns the existing record | The producer looks up first; it returns `duplicate` with the existing id | 11 |
| Same key with a different payload is rejected | `payload_sha256` compared on every replay; `UsageIdempotencyConflict` | 13 |
| Concurrent retries cannot double charge | The INSERT runs in a savepoint. Losing the unique race rolls back, re-reads and compares. | 12 |
| At-least-once delivery, effectively-once effect | The producer is safe to re-run; the record is in the source transaction | 11, 12 |
| Stable processor idempotency | `BillingReconciler` reports with the usage record's idempotency key | 30 |
| Partial failure is recoverable | Savepoint rollback; reconciliation lists the delivery under `deliveries_without_usage` | 30b |
| Failed processor sync never erases usage | Status moves `pending` → `reported`; rows are never deleted (ORM append-only guard) | 28, 30 |
| Statuses are distinguished | `pending` (`pending_processor_ack`), `reported`, `rejected`, `ignored`, `failed`. Settlement is `NOT_PROVEN`. | 28, 30 |
| No duplicate payer | Partial unique index: one active assignment per customer and product | 9, 37 |

Distributed exactly-once delivery is not claimed. The guarantee is one database record per source operation.

## Money

- **Integer minor units only.** Rates must be `int ≥ 0`. Floats, booleans, negatives and strings fail closed with `PRICING_RATE_INVALID` (tests 20, 20b).
- **Explicit currency.** Every rate, assignment and charge carries ISO 4217 currency. A rate in a currency other than the assignment's fails closed with `PRICING_CURRENCY_MISMATCH` (test 21).
- **Deterministic amounts.** amount = quantity × unit amount. There is no rounding, because there are no fractions.
- **No caller totals.** Totals are summed from stored integer amounts. No route accepts an amount, a quantity or an invoice total.
- **No retroactive repricing:**
  - `pricing_versions` rows are append-only in Postgres.
  - A charge stores the pin (`pricing_version_id`, `pricing_hash`, `tenant_contract_id`, `contract_hash`) in force at the delivery time.
  - A new price list affects only later deliveries (test 18/19).
  - A tampered price list fails closed with `PRICING_HASH_MISMATCH` (test 21b).
- **No negative quantities.** The producer always emits 1. Credits and adjustments are not implemented. When added, they must be explicit compensating records, never edits.

## Authority separation

| Rule | Test |
|---|---|
| An MSP relationship alone creates no payer assignment and no charge | 3/4 |
| Customer approval alone creates no liability | 3/4 |
| Neither the customer nor the MSP can create a payer assignment | 38/39 |
| A failed assignment leaves no row and no audit event | 40 |
| An unknown, foreign, draft or canceled agreement fails closed | 8, 40 |
| An ambiguous payer resolution fails closed with no charge | 9b |
| An expired assignment fails closed, and its not-billable decision is audited | 10 |
| A payer assignment grants no data access and no entitlement | 22 |
| Revoking a relationship never cancels a subscription | 22 |

## Trusted producers and canonical completion

| Rule | Test |
|---|---|
| Only `field_assessment.delivery` produces MSP usage; the public metering route refuses `msp.*` meters | 14 |
| The public metering route refuses the producer's `msp006:` idempotency namespace, so no other writer can occupy a delivery's slot | 14b |
| The producer reads the customer, the completion and its time from the database; a foreign or incomplete engagement is never billed | 15, 16 |
| Usage binds the delivery audit event id (`source_event_ref`) | 17 |
| The producer is wired once, between `eng.status = "delivered"` and the portal grant in `qa_approve_report_route` | 17b |

## Isolation (forced RLS)

**`msp_payer_assignments`.** Visible only to the customer or the payer. In customer-paid mode the MSP sees nothing. A third tenant, or a session with no context, sees nothing.

**`usage_events`.** Visible only to its own payer tenant. A write naming another tenant is refused by `WITH CHECK`.

**API.** Billing reads need `billing.read`, and return only the caller's own records. Foreign customers and foreign MSPs see nothing (tests 5/6, 7/32).

The customer of an MSP-paid delivery does not see the MSP's wholesale charge. That is the MSP's financial record.

The pre-existing billing_v2 reads (`/admin/tenants/{id}/billing/usage`, `/admin/billing/explain`) require only `admin:read`, so they exclude MSP charges. `billing.read` cannot be bypassed through them (test 32b).

## Reconciliation

`reconcile_period(payer, YYYY-MM)` and the platform route `GET /admin/msp/billing/reconciliation` produce a deterministic report with a `report_sha256` (test 30c).

For each charge, the report recomputes:

- the payload hash;
- payer, product and quantity;
- the price-list hash and rate, and the amount;
- the payer assignment, plus any payer, mode or currency change;
- the processor reference.

Across the period it reports:

- duplicate source references (test 29);
- missing processor references (test 30);
- webhook replays recorded in the ledger;
- deliveries with no usage and no recorded not-billable decision, counted only while an assignment was in force (before any termination) (tests 30b, 30d, 30e);
- totals per currency.

A charge is reconstructed entirely from its own record and from immutable pins, so the report never depends on current prices.

## Webhooks

| Rule | Test |
|---|---|
| Signatures are verified with the real SDK (no mocking in these tests) | 25–27 |
| A forged signature is rejected and writes nothing | 26 |
| A replayed event is recorded once | 25 |
| A late or duplicate lifecycle event cannot move a `disabled` (canceled) link back to active | 27 |

## Audit

These events are added to the existing per-tenant identity hash chain:

- `tenant.msp.payer_assigned` (customer and payer)
- `tenant.msp.payer_assignment_terminated` (customer and payer)
- `tenant.msp.billing_usage_recorded` (customer and payer)
- `tenant.msp.billing_usage_not_billable` (customer, with reason)

Each event binds the actor, the MSP, the customer, the relationship, the operation, the correlation id and the timestamp. The chains verify after the full flow (test 35).

The billing ledger records `usage_recorded` and `usage_reported` per payer.

No payment secret, processor key, webhook secret or customer personnel identity appears in a billing response, report or log (test 36).

## Financial data classification

| Data | Class | Who sees it |
|---|---|---|
| Unit amounts, charge amounts, totals | Confidential, financial | The payer only (`billing.read`) and the platform |
| Payer assignment (mode, product, window, currency) | Confidential, commercial | The customer and the payer |
| Usage attribution (customer id, relationship id, engagement id) | Confidential | The payer and the platform |
| Processor keys and webhook secrets | Secret | Server environment only; never stored, logged or returned |
| Assessor and reviewer identities | Customer personnel | The customer's own chain only; never in payer-visible records |

## Remaining risks

- **Production settlement blocker (F10).**
  - `StripeProvider.report_usage` calls `stripe.SubscriptionItem.create_usage_record`, which the installed stripe-python 15.3.1 does not provide. Every attempt to report usage to Stripe fails.
  - No processor has acknowledged an MSP-006 charge, and settlement is NOT PROVEN.
  - Real collection is blocked until the integration is repaired (for example, Stripe Billing Meters) under a separate founder authorization and independently validated in Stripe test mode.
- **Six other billing tables lack database RLS.** `billing_event_ledger`, `billing_accounts`, `billing_subscription_links` and the three subscription tables are still isolated only by application filters (F1).
- **CodeQL #91–#94 and #3.** Path injection in the device-coverage invoice export. Not reachable from MSP-006; it needs a separate fix (F9).
- **Single product.** Only `assessment.delivered` is billable. Per-managed-tenant and monitoring dimensions are not implemented.
- **No credits or adjustments.** Corrections need a future governed compensating-record flow.
