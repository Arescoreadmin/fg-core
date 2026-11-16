# MSP-003 security model

Tests are in `tests/security/test_msp_003_orchestration.py` (named `tNN` after the acceptance matrix) and `tests/test_migrations_postgres_replay.py::test_0208_msp_003_orchestration_rows_are_isolated_by_forced_rls` (CI Postgres).

## Principles

- **An MSP relationship is not assessment authority.** The MSP-001 ceiling `MSP_DELEGABLE_PERMISSIONS` is unchanged and read-only (t07). Write authority exists only in a grant, whose own ceiling is `GRANT_CAPABILITIES = {"assessment.create"}`. Each ceiling decodes only its own capabilities, so neither can widen the other.
- **An organization ID is not a credential.** Requesting a grant for an unknown, inactive, unrelated or pending customer returns the same `404 MSP_CUSTOMER_NOT_FOUND` (t07, t17, t43). There is no discovery endpoint. Onboarding referrals never search tenants; the platform does the matching.
- **Customer approval is not permission to bypass QA.** A grant authorizes creating one engagement, nothing more. MSP-003 has no engagement status mutation (t25). MSP credentials cannot reach the Field Assessment status, QA-approve or patch routes, with or without a forged tenant header (t33–t36).
- **Initiation is not billable delivery** (t37–t39).

## Effective authority for initiation

All of these are checked at the moment of the call, with nothing cached:

| Constraint | Check | Test |
|---|---|---|
| A. MSP relationship | `effective_status(relationship) == "active"` | t16b, t29–t31 |
| B. Customer-approved delegation | Grant `approved`, `now < expires_at`, `engagement_id` empty | t09, t11, t12 |
| C. MSP actor | `check_tenant_admin_authority` on the MSP tenant (DB-canonical, bound, active) | t13 |
| C'. MSP designation | `msp_organization_active` | t14 |
| D. Customer tenant | `tenants.lifecycle_state == "active"` and kind `customer` | t15 |
| E. Scope | `assessment_type` and `assessor_id` come from the grant; the initiate body accepts no fields | t08, t21 |
| F. Lifecycle eligibility | Compare-and-set `approved` → `initiated`; the canonical creation path | t22–t24 |
| G. Product entitlement | MSP-006 `resolve_payer(customer, "assessment.delivered", now)` resolves | t16 |

## Separation of duties

- Only the customer's canonical `tenant_admin` approves, rejects or revokes. An MSP actor gets `403 MSP_APPROVAL_REQUIRES_CUSTOMER` (t10).
- The approver may not be the requester, and may not hold any active membership in the MSP (`principal_is_member_of`): `403 MSP_SELF_APPROVAL_DENIED` (t10).
- A platform operator has no approval route. Through the console, delegation accepts only the session tenant's own named `tenant_admin`. A forged `X-Tenant-ID` is rejected (t19, t20).
- Approval may shorten but never extend the requested expiry. It is capped by the relationship's expiry and needs an active relationship (t24).
- Read-only credentials (`admin:read`) and governance or portal credentials cannot decide grants (t45/t46).

## Tenant isolation

- **API.** Grants load only for one of their two parties. Unknown and foreign ids return identical 404s (t43). Listings filter to the caller's own rows (t17, t44).
- **Postgres RLS** (forced, with no empty-context bypass):
  - `msp_assessment_grants`: `tenant_id = ctx OR msp_tenant_id = ctx`, in both `USING` and `WITH CHECK`;
  - `msp_onboarding_requests`: `tenant_id = ctx` (the MSP only).

  The CI probe proves that:
  - each party sees its rows, and a third tenant or an empty context sees none;
  - spoofed inserts are refused;
  - a third tenant's update matches nothing;
  - a compare-and-set lets exactly one concurrent writer win;
  - one engagement id cannot back two grants.
- **Engagements.** The engagement is created in the customer's tenant under the customer's RLS context. The MSP holds no copy of customer data.

## Idempotency and concurrency

| Operation | Identity | Behavior |
|---|---|---|
| Grant request | `(msp, customer, request_key)`, unique | Same scope: returns the grant, `created: false`. Different scope: 409 (t22). |
| Onboarding request | `(msp, request_key)`, unique | Same payload: `created: false`. Different payload: 409 (t06). |
| Initiation | The grant (single use), with `engagement_id` unique | Repeat: same engagement, `created: false` (t22). A concurrent loser rolls back its engagement inside the savepoint and returns the winner's (t23; Postgres probe). |
| Decisions | `expected_version` | A stale version or a replay gets 409 (t24). |

## Audit

Events are written to the existing identity hash chain of both parties (no new ledger):

- `tenant.msp.assessment_grant_{requested, approved, rejected, withdrawn, revoked}`
- `tenant.msp.assessment_initiated`
- `tenant.msp.onboarding_{requested, canceled, rejected, linked}`

The last group goes to the MSP's chain, plus the customer's once linked.

Each event records:

- the acting subject and membership;
- the MSP and the customer;
- the relationship;
- `grant_id`, `engagement_id` and `onboarding_request_id`;
- the operation;
- `previous_state` and `new_state`;
- the correlation id;
- the timestamp.

The new detail keys are added to the identity audit allowlist. They are identifiers and states only; contact emails are never written to audit.

The canonical `engagement.created` event carries an `msp` block (MSP, relationship, grant), so MSP-initiated engagements are distinguishable from direct ones (t41). Grant events appear in the relationship's existing history route, attributed to the right party (t28). Unrelated tenants' chains receive nothing, and both chains verify (t41/t42).

## Customer data exposure

| To the MSP | Not to the MSP |
|---|---|
| Its own grants and their canonical engagement status, only while the grant is not revoked and the relationship delegates `assessment.read` (t26, t29) | Evidence, findings and reports (still only through MSP-001 delegated reads, unchanged); the customer's approving subject; the customer's staff |
| Onboarding stage after linking: derived labels only, such as invited or accepted | The customer's users, configuration or lifecycle details |

The customer sees every request made to it, including scope, expiry and requesting MSP. It does not see the MSP's requesting subject (t28).

## Remaining risks

- **Progress reads are not audited per read.** MSP-002 portfolio reads are audited; MSP-003 progress reads are not (a deferred item).
- **The assessor is a free identifier, approved by the customer.** It is not bound to a tenant membership. Field Assessment QA separation of duties still applies to it.
- **No notifications.** Requests rely on the customer opening `/partners`.
- **Production is not evidenced.** Migration 0208 is not applied anywhere, and the MSP-001/002/006 prerequisites are not evidenced in production.
