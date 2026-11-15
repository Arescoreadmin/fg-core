# MSP-006 architecture: partner billing and usage attribution

MSP-006 turns a delivered, MSP-managed assessment into exactly one attributable, priced and reconcilable charge against exactly one payer. It reuses the existing billing, subscription, pricing and consent authorities; the reuse audit is `MSP_006_BILLING_AUTHORITY_AUDIT.md`.

**Not standalone.** `api/msp_billing.py` is a component of the MSP-001 partner authority and the billing_v2 metering authority. It owns one table, `msp_payer_assignments`, and nothing else.

## The four parties

| Party | Meaning | Source of truth |
|---|---|---|
| Platform | FrostGate | The platform operator (`platform.admin`, internal admin gateway) |
| Service provider | The MSP organization | `msp_organizations` and `msp_service_relationships` (MSP-001) |
| Service recipient | The customer tenant | `tenants`; the tenant in which the assessment was delivered |
| Payer | The party contractually responsible for the bill | `msp_payer_assignments.payer_tenant_id`, bound to that party's `subscription_contracts` row |

The service provider is not automatically the payer, and the recipient is not automatically the payer. An MSP relationship is consent to access, not a payment agreement.

## Five questions, answered by every charge

| Question | Field (in `usage_events.metadata_json`) |
|---|---|
| Who consumed the service? | `customer_tenant_id`: the delivering tenant, read from the database |
| Who provided it? | `msp_tenant_id`, `relationship_id` |
| Who pays? | `payer_tenant_id`, `payer_assignment_id`, `billing_mode` |
| What occurred? | `product_code`, `quantity`, `unit`, `source_event_id` (the engagement), `source_event_ref` (its delivery audit event) |
| How is it verified? | `pricing_version_id` + `pricing_hash`, `tenant_contract_id` + `contract_hash`, `payload_sha256`; `reconcile_period()` recomputes each |

## Commercial modes

| Mode | Payer | Use |
|---|---|---|
| `msp_paid` (Mode A) | The MSP | Wholesale and reseller. FrostGate bills the MSP for deliveries to its managed customers. |
| `customer_paid` (Mode B) | The customer | Direct subscription with managed delivery. FrostGate bills the customer; the MSP operates. |

The schema enforces that the payer is the MSP in Mode A and the customer in Mode B (`msp_payer_mode_matches_payer`). At most one active assignment exists per customer and product (`uq_msp_payer_one_active_per_product`), so a delivery can never resolve to two payers.

Split billing, multi-party invoices, revenue sharing and marketplace settlement are not supported. They are future extensions.

## Payer assignment (the only new state)

Only a platform operator creates or terminates an assignment, through the internal admin gateway with `platform.admin`. The customer and the MSP cannot. The request names the customer, the relationship, the mode, the product, the currency, the validity window (at most 400 days) and the payer's commercial agreement. The payer is derived from the mode and the relationship; it is never accepted from the caller.

Creation requires all of these, in the same transaction:

1. The relationship belongs to the named customer and is `active` now (MSP-001 derived status).
2. The MSP organization is designated and active.
3. The commercial agreement (`subscription_contracts`) belongs to the derived payer, has status `active` and is in force.

Any failure leaves no row and no audit event. Success writes `tenant.msp.payer_assigned` to the customer's and the payer's audit chains. Termination uses compare-and-set on `version` and writes `tenant.msp.payer_assignment_terminated`.

## Usage attribution

**Billable completion.** For `assessment.delivered`, the only product, billable completion is the canonical QA-approval auto-advance in `api/field_assessment.py` (`qa_approve_report_route`). That advance requires the production-qualification and readiness gates to pass. It sets the engagement to `delivered`, emits `engagement.status_transitioned`, and promotes the engagement to governance.

**The trusted producer.** Immediately after promotion, in the same transaction, `record_delivery_usage_safely` calls `record_assessment_delivery_usage`. The producer:

1. Re-reads the engagement and its delivery audit event from the customer's tenant. The caller supplies no tenant, time or quantity.
2. Resolves the payer at the delivery time. The order is:
   - assignment;
   - window;
   - customer lifecycle;
   - relationship `active`;
   - MSP organization active;
   - agreement in force;
   - the payer's contract → price list, with both hashes verified;
   - integer rate;
   - currency.

   Each failure has its own reason code.
3. Records one `usage_events` row under the payer's tenant through `services/billing/metering.record_usage_event`. The meter is `msp.assessment_delivered`, the quantity 1, and the source `field_assessment.delivery`. The idempotency key is `msp006:assessment.delivered:{customer}:{engagement}`.
4. Writes `tenant.msp.billing_usage_recorded` to the customer's and the payer's chains, or `tenant.msp.billing_usage_not_billable`, with its reason, to the customer's chain.

**Billing never blocks delivery.** A failure rolls back to a savepoint. The delivery then appears in reconciliation as "delivered without usage".

**No client-reported usage.** The public `POST /billing/usage/events` refuses every meter under the `msp.` prefix (`BILLING_METER_RESTRICTED`), so only the trusted producer can create billable MSP usage.

## Pricing

Prices reuse `pricing_versions` (append-only in Postgres) and `tenant_contracts` (forced RLS):

- **Rate format.** An MSP rate key is `{"unit_amount_minor": <int ≥ 0>, "currency": "<ISO 4217>"}`. Floats, booleans, negatives and strings are rejected.
- **Price-list hash.** `pricing_versions.sha256_hash` must equal `canonical_hash({pricing_version_id, rates_json})`.
- **Contract hash.** `tenant_contracts.contract_hash` must equal the existing `_canonical_contract_hash`.
- **Price in force.** The charge uses the payer's contract in force at the delivery time, and stores the resulting pin. A later price list never changes an earlier charge.

The amount is quantity × unit amount, in integer minor units. There is no rounding because nothing is fractional.

## Subscription and entitlement boundaries

| Concept | Authority | MSP-006 effect |
|---|---|---|
| MSP authorized to operate | `msp.multi_tenant` + MSP-001 relationship | Read only |
| Customer subscribed or entitled | `subscription_items` → `TenantBundleAssignment` → entitlements | None |
| Payer responsible | `msp_payer_assignments` + `subscription_contracts` | New (assignment); agreement read only |
| Subscription active or canceled | `subscription_contracts.status` | Read; a non-active agreement stops new charges |

Further rules:

- A payer assignment grants no data access and no entitlement.
- Payment never grants access.
- Revoking an MSP relationship never cancels a subscription.
- Canceling an agreement never deletes usage.

## Relationship lifecycle

| Change | New deliveries | Accrued charges |
|---|---|---|
| Proposed, or approved but not yet effective | Not billable (`MSP_RELATIONSHIP_INACTIVE`) | n/a |
| Approved and active | Billable | Kept |
| Suspended | Not billable until resumed | Kept |
| Resumed | Billable again | Kept |
| Revoked or expired | Not billable | Kept |
| MSP designation suspended | Not billable (`MSP_ORGANIZATION_NOT_ACTIVE`) | Kept |
| MSP membership removed | No effect on billing; billing is organization-level, and access is governed by MSP-001 | Kept |
| Customer tenant disabled | Not billable (`CUSTOMER_TENANT_INACTIVE`) | Kept |
| Agreement canceled or suspended | Not billable (`PAYER_AGREEMENT_INVALID`) | Kept |
| Payer assignment terminated | Not MSP-billed (`NO_PAYER_ASSIGNMENT`) | Kept |

Authorization revocation is not billing cancellation. Nothing in MSP-006 cancels a subscription or deletes a financial record.

## Persistence and isolation

**`msp_payer_assignments`** (migration 0207) has forced RLS. A row is visible only to the customer or the payer. In customer-paid mode the MSP does not see it, and there is no empty-context bypass.

**`usage_events`** (repaired by 0207, audit finding F1) now has forced RLS: a row is visible only to its own payer tenant. The three billing_v2 routes that read or write it now bind the tenant context first.

**Cross-context work.** Producer, resolver and reconciliation switch to each party's context only for that party's rows, then restore the customer's context. This is the same pattern as the MSP-002 portfolio.

**No new infrastructure.** There is no queue, cache or new service. Usage is recorded in the source transaction, which is durable and needs no outbox.

## Routes

| Route | Authorization | Purpose |
|---|---|---|
| `GET /admin/msp/billing/payer-assignments` | `billing.read`, own tenant | Assignments where the caller is the customer or the payer |
| `GET /admin/msp/billing/usage?period=YYYY-MM` | `billing.read`, own tenant | The caller's own charges as payer, with monthly totals per currency; paginated |
| `POST /admin/msp/billing/payer-assignments` | Internal gateway + `platform.admin` | Create an assignment |
| `POST /admin/msp/billing/payer-assignments/{id}/terminate` | Internal gateway + `platform.admin` | Terminate an assignment (compare-and-set) |
| `GET /admin/msp/billing/reconciliation?payer_tenant_id&period` | Internal gateway + `platform.admin` | Deterministic reconciliation report |

`billing.read` is a new permission in the existing RBAC authority, granted to `tenant_admin` only. An MSP's relationship never implies it.

The console does not proxy these routes. A billing dashboard is out of scope.

## Processor integration

**Live settlement: NOT PROVEN.** `StripeProvider.report_usage` calls `stripe.SubscriptionItem.create_usage_record`, which the installed stripe-python 15.3.1 no longer provides (audit finding F10). Usage therefore stays `pending` until a processor acknowledges it.

**Test-mode reporting.** `report_pending_usage` reuses `BillingReconciler` with a stable idempotency key (the usage record's key). It refuses any provider that is not an explicit test-mode adapter, including `StripeProvider`.

**Webhooks.** The billing_v2 subscription webhook keeps its signature verification. MSP-006 fixes two defects in it:

- event conversion with the real SDK (F8);
- resurrection of a canceled link by a late event (F6).

No live charge, live subscription or processor dashboard change was made.

## Competitive gap widened [MOAT-WIDENING]

| Competitor class | Gap |
|---|---|
| Compliance automation (Vanta, Drata, Secureframe) | Partner billing is seat or tier based, with no tie to client consent. FrostGate bills a partner only for a delivered, QA-approved assessment made while the customer's own approval was in force, and every charge is recomputable from hashed prices. |
| Security assessment firms (Big 4, boutiques) | Engagements are invoiced by hand from statements of work. FrostGate's charge is generated by the delivery itself and reconciles to the customer's audit chain. |
| Traditional GRC (ServiceNow, OneTrust) | No partner commercial model is bound to evidence. A FrostGate charge carries its delivery evidence reference. |

**Compounding.** Each billed delivery joins the customer's governance record (consent, delivery and charge) in one verifiable chain. The longer a partner operates on FrostGate, the more of its customers' commercial and governance history lives there, and none of it can be reconstructed elsewhere.

## Rollback

Revert the PR. Migration 0207 is additive:

- `msp_payer_assignments` can remain empty.
- Removing the `usage_events` RLS would require a new migration, which is not recommended: the policy only enforces the tenant filter that billing_v2 already applies.
- No existing row is changed.
