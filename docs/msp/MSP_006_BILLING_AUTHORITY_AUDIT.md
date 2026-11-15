# MSP-006 billing authority audit

This audit is the mandatory first phase of MSP-006 (partner billing, usage attribution and subscription integration). It was taken on `main` at `fc31ce17d7c63648087c75755aedb0e60f32549d` (2026-11-15), before any MSP-006 code was written.

It answers one question: which existing billing, subscription, entitlement and payment components MSP-006 should reuse, so that it creates no competing commercial authority. Every finding was checked against the code. Nothing is inferred from documents alone.

## Answers to the audit questions

**Is Stripe the canonical payment processor?**

Yes, and it is the only processor integrated. It has two independent integrations:

- `api/stripe_webhooks.py` (L14). One-off assessment checkout. It verifies signatures, deduplicates events and confirms payment atomically. Its event handling was proven in Stripe test mode (L14 #801–#804).
- `services/billing/stripe_provider.py` with `api/billing_v2.py` (P1.5). Customers, subscriptions and usage reporting. No evidence shows it was ever exercised against Stripe, in test mode or live.

**Which authority controls subscription status, payment state and entitlements?**

| Concern | Sole authority |
|---|---|
| Subscription status | `api/subscriptions.py`: `SubscriptionContract` (the commercial deal) and `SubscriptionItem` (the line item, with lifecycle) |
| Entitlements | `SubscriptionItem` activation syncs a `TenantBundleAssignment`, which `api/entitlements.py` resolves. Billing never grants entitlements (the `billing_v2` docstring says so, and the code agrees). |
| Provider payment and sync state | `billing_subscription_links.sync_status` and `usage_events.billing_status` (`billing_v2`) |
| One-off assessment payment | `AssessmentRecord.payment_status` (`api/stripe_webhooks.py`) |
| MSP consent | `api/msp_authority.py` and `msp_service_relationships` (MSP-001) |

MSP-006 duplicates none of these.

**What do the authority-integration warnings mean?**

```
[billing] SKIPPED(db_registration)   [subscriptions] SKIPPED(db_registration)
[billing] SKIPPED(tests)             [subscriptions] SKIPPED(tests)
```

| Warning | Finding | Classification |
|---|---|---|
| `db_registration` | Not a missing registration. `api/db_models_billing.py` and `api/db_models_subscriptions.py` are imported at the bottom of `api/db_models.py` (lines 3977–3978), so their tables are registered for `create_all`. The check looks only at `api/db.py`, and `tools/ci/check_authority_integration.py` excludes both modules by name. | Benign; registration is indirect |
| `tests` | Not missing tests. `tests/test_billing_engine.py` (36 tests) and `tests/test_subscription_engine.py` (20 tests) exist. `authority_manifest.yaml` declares `tests: []` for both. | A manifest declaration gap |
| Manifest accuracy | The `billing` entry names `api_file: api/billing.py` (the device-coverage engine) but lists the `billing_v2` tables. The two are separate code paths. | A manifest accuracy gap |
| **Real production risk** | **F1 below**: these tables exist in Postgres only through `create_all`, without RLS. | **REPAIR**, scoped (see F1) |

Following the mission, MSP-006 does not add these imports to `api/db.py`.

## Capability matrix

| Capability | Existing authority | Production maturity | Reuse decision | Security concern | Required change |
|---|---|---|---|---|---|
| Commercial agreement (who contracted) | `subscription_contracts` (`api/subscriptions.py`) | Mounted and tested; tables only via `create_all` | **REUSE** | No database RLS (F1) | A payer assignment must reference an `active` contract of the payer tenant, valid at the time of the event |
| Line items and entitlements | `subscription_items` → `TenantBundleAssignment` → `api/entitlements.py` | Mounted and tested | **REUSE** (unchanged) | — | None. Payment never grants entitlement or customer-data access. |
| Price list | `pricing_versions` (`rates_json`, `sha256_hash`) | Migration 0012; append-only triggers | **EXTEND** | `sha256_hash` is never verified today | MSP rate keys use integer minor units and an explicit currency. MSP-006 recomputes the pricing hash and fails closed on a mismatch. |
| Per-tenant price binding | `tenant_contracts` (`pricing_version_id`, `contract_hash`) | Migration 0012; forced RLS (0110) | **REUSE** | Float `commitment_minimum` (hash input only) | The charge is priced from the payer's contract active at the event time. `contract_hash` is re-verified with `api/billing.py:_canonical_contract_hash`. |
| Usage metering | `usage_meters` and `usage_events` (`services/billing/metering.record_usage_event`) | Mounted and tested; tables only via `create_all` | **EXTEND** and **REPAIR** | No RLS (F1). The public `POST /billing/usage/events` lets any bound tenant record any meter (F7). | Forced RLS on `usage_events`. Producer-restricted meters. Idempotency payload comparison. |
| Billing ledger | `billing_event_ledger` (hash-chained per tenant) | Mounted; tables only via `create_all` | **REUSE** | No RLS. Stripe webhooks write a pseudo-tenant `"stripe"`. Rows hold ids and states, not amounts. | None in MSP-006; RLS **DEFER**red (F1) |
| Reconciliation | `services/billing/reconciliation.BillingReconciler` | No callers | **REUSE** for provider retries | Cross-tenant when it is given no tenant | MSP-006 adds deterministic charge reconstruction alongside it, with no second ledger |
| Processor adapter | `BillingProvider`, `NullBillingProvider`, `StripeProvider` | No processor proof for usage | **REUSE** (test mode only) | No live-key guard (F3) | Refuse live keys on MSP-006 paths. Settlement is **NOT PROVEN**. |
| Subscription webhooks | `POST /billing/webhooks/stripe` (`billing_v2`) | Mounted; tests mock verification | **REPAIR** (scoped) | An out-of-order event can resurrect a canceled link (F6). `dict(evt)` conversion has not been proven against the real SDK object (F8). | A terminal state guard and tests with a real signature |
| Device-coverage invoicing | `api/billing.py` `/billing/*` | Mounted; migration 0012 | **DEFER** (not used by MSP-006) | Float money (F4). CodeQL #91–#94 and #3 (F9). | None in MSP-006 |
| Assessment checkout | `api/stripe_webhooks.py` | Test-mode proven (L14) | **DEFER** (not MSP billing) | — | None |
| MSP consent and parties | `api/msp_authority.py`, `msp_service_relationships` | Merged, with CI Postgres proof | **REUSE** | — | Billing reads the relationship. It never extends it. |
| MSP multi-client right | `msp.multi_tenant` capability | Merged | **REUSE** | — | None. It is the right to operate, never a payment agreement. |
| Payer assignment | **none exists** | — | **NEW** (justified: no existing concept) | Must be isolated per party | A new table with forced RLS (`msp_payer_assignments`), written only by the platform |
| In-memory prototypes | `api/usage_attribution.py`, `api/billing_integration.py` | Unmounted, `dict` stores | **DEFER** (never an authority) | Must not be mistaken for an authority | None |

There is no event queue or outbox in the billing path. MSP-006 records usage in the same database transaction as the source event, so none is needed.

## Findings

### F1 (P1, pre-existing): billing_v2 and subscription tables have no database tenant isolation

Seven tenant-keyed tables have no Postgres migration:

- `billing_accounts`, `billing_subscription_links`, `usage_events`, `billing_event_ledger`;
- `subscription_contracts`, `subscription_items`, `subscription_event_ledger`.

`init_db` creates them through `Base.metadata.create_all` before running migrations (`api/db.py`, postgres branch), so no RLS is ever applied. `tools/ci/check_core_rls.py` scans only `CREATE TABLE` statements in migration files and never sees them.

**MSP-006 decision:** repair `usage_events` only, because it is where MSP-006 stores financial amounts. Migration 0207 declares the table, enables and forces RLS, and adds a tenant policy. The three billing_v2 routes that touch `usage_events` (record, list, explain) now bind the tenant context first. The other six tables remain a documented risk for a follow-up:

- `billing_event_ledger` holds no amounts, and its webhook pseudo-tenant needs its own design.
- MSP-006 reads `subscription_contracts` only with an explicit payer filter.

### F2: billing_v2 and subscriptions open sessions with no tenant context

They use `Session(get_engine())` directly. Any table given RLS must have its callers bind the context, or they silently see nothing. This is why F1 is repaired table by table.

### F3: the Stripe provider has no test-mode guard

`StripeProvider` uses whatever `STRIPE_API_KEY` is set. MSP-006 is authorized for test mode only, so its processor path refuses any key that is not a test key and fails closed.

### F4: legacy invoice money uses floating point

`api/billing.py` computes amounts with `float` and `round(..., 6)`. MSP-006 uses integer minor units throughout and reuses only the hash pin.

### F5: two in-memory prototypes

`api/usage_attribution.py` and `api/billing_integration.py` are not authorities.

### F6: an out-of-order subscription webhook can resurrect a canceled link

`_handle_stripe_subscription_event` sets `sync_status` from the event type alone. A delayed `customer.subscription.updated` arriving after `customer.subscription.deleted` turns a `disabled` link back to `synced`. MSP-006 makes `disabled` terminal for subscription lifecycle events.

### F7: any tenant can record any meter

`POST /billing/usage/events` accepts any active `meter_code` from the bound tenant. A tenant could therefore record billable MSP usage itself. MSP-006 reserves its meters for its trusted producer.

### F8: webhook event conversion is unproven against the SDK

`StripeProvider.parse_webhook` returns `dict(evt)`. The L14 handler had to move to `event.to_dict()` (#803). MSP-006 tests the billing_v2 webhook with a real signed payload, with no mocked verification.

### F9: CodeQL #91–#94 (path injection) and #3 (clear-text storage) in `api/billing.py`

Re-queried on 2026-11-15: all five are open and high severity.

- **#91–#94:** `_atomic_write` (lines 80–86) receives paths built from the tenant and an invoice id or credit-note id. Those ids are chosen by the caller when it creates the invoice or credit note (`req.invoice_id`, `req.credit_note_id`). A credential holding `admin:write` and `admin:read` for a tenant could therefore make evidence export write outside `artifacts/billing/`.
- **#3:** flags the same write path.

**Reachability from MSP-006:**

- The console BFF proxies nothing under `/billing`.
- MSP credentials gain nothing on `/billing/*`.
- MSP-006 adds no route to `api/billing.py` and no billing export or attachment.

**Decision:** this is not a direct MSP-006 blocker. It needs its own CODEQL-REMEDIATE PR: validate the ids as path-safe tokens, or derive the path from a hash. Nothing is dismissed and no scanner rule changes.

## Competitive gap widened

Compliance-automation partner programs typically bill partners per seat or by flat tier, with no tie to client consent. MSP-006 bills a partner only for a delivered assessment made while the customer's own approval was in force. Each charge is pinned to a hashed price version and contract, and can be reconstructed independently.

A regulated buyer (CFO, General Counsel) can therefore tie every partner charge to an approval they granted and to a price they agreed. Every billed delivery adds a verifiable commercial record to the customer's governance history, and that record cannot be rebuilt elsewhere.
