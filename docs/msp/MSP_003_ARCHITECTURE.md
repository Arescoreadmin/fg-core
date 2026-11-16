# MSP-003 architecture: partner-guided onboarding and assessment orchestration

MSP-003 lets an approved MSP guide a customer onto FrostGate and start an assessment, but only one the customer has approved. It is not a new platform. It coordinates existing authorities and adds two small records.

**Authorization:** `customer_one/roadmap_authority.yaml`, entry `MSP-003` (FOUNDER_AUTHORIZED; Freeze Law criteria 1 and 2 not claimed). The authority map is in `MSP_003_AUTHORITY_AUDIT.md`, and the security model in `MSP_003_SECURITY_MODEL.md`.

## What MSP-003 adds

| Piece | Where | What it is |
|---|---|---|
| `msp_assessment_grants` | Migration 0208, `api/db_models_msp.py` | One customer-approved, expiring, single-use grant to initiate one engagement |
| `msp_onboarding_requests` | Migration 0208, `api/db_models_msp.py` | An MSP's referral of an organization that is not yet a tenant (a platform review queue) |
| Orchestration API | `api/msp_orchestration.py` | Grant request, decision and initiation routes; onboarding referral and platform review routes |
| Canonical creation for MSP | `api/field_assessment.py` `create_engagement_with_audit` | Same store function and the same `engagement.created` audit and timeline events as the create route. The route is unchanged; parity is test-enforced. |
| Audit fields | `emit_msp_audit(extra=…)`; the identity audit allowlist | Grant, engagement, previous and new state on each MSP event |
| Console | `/msp` and `/partners`, `components/msp/AssessmentGrants.tsx` and `OnboardingRequests.tsx` | MSP request, start and progress views; customer approve, decline and revoke |

## Flow

```
MSP admin                       FrostGate platform              Customer admin
---------                       ------------------              --------------
(new organization)
POST onboarding/requests  ───▶  review queue
                                provision tenant (canonical
                                POST /admin/tenants, invite-
                                initial-admin)
                                POST platform/onboarding/{id}/link
                                                                accept invitation (canonical)
POST relationships (MSP-001) ─────────────────────────────────▶ approve relationship (MSP-001)
POST assessments/grants      ─────────────────────────────────▶ approve | reject grant
                                POST billing/payer-assignments
                                (MSP-006, commercial authority)
POST grants/{id}/initiate
  └─ create_engagement_with_audit in the CUSTOMER's tenant
     (status in_progress, canonical engagement.created event)
                                                                assessors, scans, evidence,
                                                                readiness, QA approval,
                                                                governed delivery (unchanged)
                                MSP-006 producer: one usage event on canonical delivery
GET assessments/grants (progress = canonical engagement status)
                                                                revoke grant | revoke relationship
```

An existing customer skips the first block: onboarding is the MSP-001 relationship proposal and approval.

## Grant lifecycle

```
requested ──approve──▶ approved ──initiate──▶ initiated
    │                      │                      │
    ├─reject──▶ rejected   └─revoke──▶ revoked ◀──┘ (revoke)
    └─withdraw─▶ withdrawn
```

- Only the customer approves, rejects or revokes. Only the MSP requests, withdraws or initiates.
- Every transition is a compare-and-set on `(id, status, version)`. Decisions carry `expected_version`, so a decision applies only to the version that was reviewed.
- `expired` is derived from `expires_at` and never stored.
- Revoking an initiated grant does not cancel the engagement. Rule 24 forbids silent cancellation. The engagement stays the customer's, under Field Assessment's lifecycle.

## Orchestration status: derived, not duplicated

The engagement status is never copied. A grant view's `progress.engagement_status` is read from `fa_engagements` on each request.

- `blockers` are the reasons initiation is unavailable now: `CUSTOMER_APPROVAL_PENDING`, `GRANT_EXPIRED`, `RELATIONSHIP_INACTIVE`, `CUSTOMER_TENANT_INACTIVE`, `NOT_ENTITLED`, and so on.
- `next_actions` say who acts next: customer, MSP, platform or assessor.

The initiate route raises the first blocker from that same function (`initiation_blockers`), so the Console's explanation and Core's decision cannot diverge.

The mission's suggested stages map as follows:

| Suggested stage | MSP-003 source |
|---|---|
| REQUESTED, AWAITING_CUSTOMER_APPROVAL | Grant `requested` |
| AUTHORIZED, READY | Grant `approved` with no blockers |
| IN_PROGRESS, AWAITING_CUSTOMER_ACTION, IN_REVIEW, QA_APPROVED | Canonical `fa_engagements.status` and Field Assessment readiness; not duplicated |
| DELIVERED | Canonical `delivered` (QA auto-advance) |
| CANCELED | Grant `rejected`, `withdrawn` or `revoked`; or the canonical engagement `cancelled` |

## Onboarding stages (derived after linking)

| Stored | Derived stage | From |
|---|---|---|
| `requested` | `requested`, or `expired` after 30 days | Row |
| `rejected`, `canceled` | Same | Row |
| `linked` | `provisioning` (no admin yet), `invited` (admin unbound), `customer_accepted`, `awaiting_customer_approval`, `active`, `relationship_inactive`, `customer_inactive` | `evaluate_client_lifecycle` and the MSP-001 relationship |

## Billing linkage (MSP-006)

- Initiation creates no usage and no ledger entry (test t37).
- The only billable trigger is still the canonical delivery: the QA auto-advance calls the MSP-006 producer. It records at most one charge per engagement (t38/t39).
- Initiation requires that `resolve_payer(...)` resolves now. MSP-initiated work is therefore never unbillable by accident, and an MSP without a commercial arrangement cannot start work. The payer, price and charge are still decided at delivery time by MSP-006.
- A cancelled or undelivered engagement is never billed (t32).

## Automation

Expiry is computed at read time, so no job is needed and none was added. Onboarding stages are re-derived on every read from canonical state, so there is nothing to synchronize. Reminders and notifications are not implemented: `next_actions` is the coordination signal, and delivery channels are deferred. Nothing here approves, accepts liability, QA-approves or delivers on anyone's behalf.

## Deployment prerequisites

1. Apply migration 0208 (additive) after 0206 and 0207.
2. MSP-001 and MSP-006 prerequisites:
   - an MSP designation;
   - the `msp.multi_tenant` entitlement on the MSP;
   - `FG_INTERNAL_GATEWAY_SECRET`;
   - migration 0207;
   - a payer assignment with a price, for each customer that MSPs will initiate for.
3. The console BFF deploys with the two new proxied prefixes. Platform review routes are reachable only through the internal admin gateway.

## Rollback

Revert the PR. Migration 0208 is additive; leave both tables in place. Engagements already initiated are ordinary customer engagements and stay valid. No existing row is modified.

## Deferred

- MSP staff acting as assessors inside customer tenants (scans, evidence).
- Evidence sharing and managed reporting (MSP-007).
- Notifications.
- MSP-led tenant creation.
- An MSP-side audit of progress reads. The progress view shows only the status of an engagement the MSP itself initiated, under the existing `assessment.read` delegation.
