# MSP-003 operator guide

This guide is for FrostGate platform operators supporting partner-guided onboarding and MSP-initiated assessments. Nothing here creates access on anyone's behalf: customers approve relationships and assessments themselves.

## Before first use

1. **Apply migration 0208** after 0206 (MSP-001) and 0207 (MSP-006). It adds `msp_assessment_grants` and `msp_onboarding_requests` with forced RLS.
2. **Set up the MSP** (MSP-001): designate it (`PUT /admin/msp/organizations/{id}`) and assign the `msp.multi_tenant` entitlement. Its administrators must be bound `tenant_admin` members.
3. **Set up commercial authority** (MSP-006) for each customer an MSP will initiate assessments for: an active agreement, a hash-pinned price and a payer assignment for `assessment.delivered`. Without these, initiation is refused with `MSP_ASSESSMENT_NOT_ENTITLED` and the Console shows the next action "FrostGate: set up billing for this customer".

## Review onboarding referrals

An MSP's referral of a new organization arrives in a per-MSP queue:

```
GET /admin/msp/platform/onboarding?msp_tenant_id=<msp>
```

This route and the two below require the internal admin gateway and `platform.admin`. The Console never proxies them.

**To accept a referral:**

1. Decide whether the organization already exists on FrostGate. The MSP was never told. If it exists, link to that tenant instead of creating a duplicate.
2. Otherwise, provision the tenant through the canonical routes: `POST /admin/tenants`, then `POST /admin/tenants/{id}/invite-initial-admin` using the contact email from the referral. Verify the contact's identity as usual.
3. Link the referral to the tenant:

   ```
   POST /admin/msp/platform/onboarding/{request_id}/link
   {"msp_tenant_id": "<msp>", "customer_tenant_id": "<tenant>"}
   ```

   Linking grants nothing. The MSP now sees the derived stage, which moves through `provisioning`, `invited`, `customer_accepted`, `awaiting_customer_approval` and `active` as the customer accepts the invitation and approves the MSP's relationship request.

**To decline:**

```
POST /admin/msp/platform/onboarding/{request_id}/reject
{"msp_tenant_id": "<msp>"}
```

Unreviewed referrals expire after 30 days. Linked, rejected, canceled and expired referrals never change again.

## Assessment requests

Operators do not approve or start assessments. For support, these are the states and fixes:

| What the MSP sees | Cause | Fix |
|---|---|---|
| Awaiting customer approval | The customer has not decided | The customer reviews it on `/partners` |
| No billing arrangement covers this assessment | No payer assignment or price resolves | Platform: MSP-006 payer assignment and price |
| Relationship not active | Suspended, revoked or expired | The customer resumes it, or the MSP re-requests |
| Customer account not active | The tenant is suspended | Platform tenant lifecycle |
| Approval period ended | The grant expired | The MSP sends a new request |

A started assessment is an ordinary customer engagement. Assessors, scans, evidence, readiness gates, QA approval and governed delivery work exactly as for a direct customer. On delivery, MSP-006 records one charge for the resolved payer. Settlement is NOT PROVEN.

## Revocation

- **Customer revokes a grant:** the MSP can no longer start that assessment or see its progress. An engagement already started continues and remains the customer's.
- **Customer revokes the relationship:** every new MSP request and initiation for that customer fails. History is kept.
- **Platform suspends an MSP designation:** every MSP-003 action by that MSP fails immediately.

## Audit

Every request, decision, initiation and onboarding step is on the identity audit chain of each party (`tenant.msp.assessment_*` and `tenant.msp.onboarding_*`). It also appears in the relationship history on `/msp` and `/partners`. MSP-initiated engagements carry an `msp` block on their canonical `engagement.created` event.

## Rollback

Revert the PR and leave the tables in place. Migration 0208 is additive, and initiated engagements stay valid.
