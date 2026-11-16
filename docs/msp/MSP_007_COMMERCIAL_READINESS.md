# MSP-007 commercial readiness

**Status:** implemented and locally tested. CI and Postgres verification are pending on the PR. Nothing here is deployed, customer-verified or production ready.

This document has no prices, revenue, demand or market figures, because none has been established.

## What becomes sellable once deployed

| Capability | What makes it defensible |
|---|---|
| **A. Customer-controlled cross-organization evidence exchange** | Ownership is enforced by the database (forced RLS, partial unique index) and by the customer's canonical administrator, not by UI convention |
| **B. Verifiable report integrity and provenance** | Recipients can recompute the fingerprint themselves. Signatures are checked by the same engine as FrostGate's own verify route. Release is the canonical QA → qualification → provenance decision |
| **C. Reusable managed-reporting workflow** | One partner index per customer, grouped by real availability, with next actions owned by the right party |
| **D. Audit-ready access history** | Every share decision, read and refused read is on two hash chains and in the engagement trail, and survives revocation |
| **E. Version-bound sharing** | A share never silently widens to a new version or changed content |
| **F. Multi-customer reporting without cross-tenant disclosure** | Per-party RLS, identical 404s, and customer-keyed Console state |
| **G. Lower partner overhead** | No emailed PDFs or manual integrity attestations: the partner verifies in place |
| **H. Integration with assessments** | Requests are tied to MSP-003 engagements; billing stays with MSP-006 delivery |

## Packaging options (not priced)

These are options to evaluate, not commitments:

- **Direct customer reporting:** unchanged.
- **Partner-managed reporting:** MSP-007 sharing for MSP-served customers.
- **Verified evidence delivery:** shared reports plus recipient-side fingerprint verification.
- **Continuous governance reporting and premium managed assurance:** future packages that would need the deferred items below.

## Before anything can be charged

- **Cost boundary:** every MSP read re-runs the canonical release decision and the integrity checks. Per-read cost is not measured.
- **Delivery boundary:** sharing is not delivery and records no usage. A sharing charge would need a separately authorized MSP-006 meter and pricing. It must not be inferred from this capability.
- **Settlement:** MSP-006 settlement is NOT PROVEN (audit F10), so no MSP revenue can be collected yet.

## Remaining blockers

- Migration 0209 and MSP-001/002/003/006 are not deployed.
- No live partner and no customer acceptance of evidence sharing exists.
- Stripe production settlement is NOT PROVEN.
- RLS debt on the billing and subscription tables remains.
- The CodeQL backlog and the security-suite runtime regression remain.

## Deferred capabilities

- Partner PDF export (needs a review of the PDF access policy).
- Offline signature verification kit for recipients.
- Report version comparison (no canonical diff authority).
- Notifications for requests, shares and expiry.
- Expiry events written by a scheduler.
- Bulk portfolio export.
- Client portal (`apps/portal`) visibility of shares.
