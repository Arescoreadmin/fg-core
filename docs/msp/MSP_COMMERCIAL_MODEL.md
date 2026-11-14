# MSP commercial model (design; no billing code in MSP-001)

MSP-001 adds no payment processing, invoicing, pricing or metering. It establishes what billing will attribute against, and gates MSP operations on the existing `msp.multi_tenant` entitlement.

## Existing authorities to reuse (no second billing engine)

| Need | Existing authority | State |
|---|---|---|
| Partner can operate multi-client | `msp.multi_tenant` capability (`api/entitlements.py`, bundles, tier map) | **Used by MSP-001**: it gates propose, discovery and context. |
| Portfolio reporting, tenant switching, white label | `msp.cross_tenant_reporting`, `msp.tenant_switching`, `msp.white_label` | Keys exist; unused until MSP-002 and MSP-008. |
| Contracts and line items | `subscription_contracts`, `subscription_items` (`sku_code`, `meter_code`, `parent_item_id` "MSP parent subscription") | Present; no MSP logic. |
| Billing eligibility | `tenant_kind` policy (`billing_eligible`) | MSPs are `customer`-kind tenants, so they are billable. |
| Payment | Stripe (L14 hardening, #801–#804) | Present for direct customers. |

## Attribution contract (for MSP-006)

Every billable usage event must carry:

| Field | Source of truth |
|---|---|
| `provider_tenant_id` | The MSP tenant, from the bound credential, never the request body |
| `beneficiary_tenant_id` | The customer tenant, from `DelegatedAccess.customer_tenant_id` |
| `relationship_id` | `DelegatedAccess.relationship_id`; proves consent at the time of use |
| `capability` / `sku_code` | The product capability used (an assessment, a monitoring subscription, a premium framework) |
| `actor_subject` | The real actor, for dispute resolution |
| `occurred_at`, `correlation_id` | Request time and request id, joinable to the audit chain |

Rules:

1. **One payer per event.** The relationship's commercial terms decide whether the MSP is billed (wholesale) or the customer is billed (direct). The terms field is MSP-006 work; the default is the MSP. A usage event is never billed to both, so there is no double charging.
2. **No event without consent.** Usage is attributable only when a `DelegatedAccess` was granted for that request. A denied request is never billed.
3. **Billing visibility follows the payer.** MSP personnel see only the MSP's own wholesale invoices and usage, grouped by customer *id*. Customer billing data (the customer's direct contracts, payment methods, invoices) is never visible to the MSP. That data lives under the customer tenant's RLS, and no MSP capability covers it.
4. **Managed-customer count** means the number of relationships with derived status `active`. It is computed from `msp_service_relationships`, never stored separately.

## Monetization dimensions

These are future work, ordered by expected time to revenue:

1. Per managed customer, per month (active relationships).
2. Per assessment delivered under delegation (field assessment SKU).
3. Continuous governance monitoring subscription per customer.
4. Premium frameworks and evidence storage tiers.
5. White label and partner branding (`msp.white_label`).

## Competitive gap widened

Partner programs in compliance-automation and GRC tools typically give a partner account standing access to every client workspace. FrostGate's model differs in three ways, each enforced in code and tested:

- **Customer-approved access.** Access is approved by the customer, scoped to named capabilities and time-boxed.
- **Revocable in one request.** The customer can revoke access, and revocation takes effect on the next request.
- **Customer-visible record.** Every delegated action is recorded in the customer's own audit chain.

For regulated buyers (CISO, GC), this means a managed-service arrangement does not dilute the evidence chain's provenance.

**Compounding effect.** Each relationship's consent and activity history is part of the customer's governance record. It accumulates across partners and cannot be reconstructed elsewhere.

This is a foundation, not yet a revenue feature: see `MSP_FIRST_CLIENT_READINESS.md`.
