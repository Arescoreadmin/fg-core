# PORTAL-AUTH-E2E-001 — Portal Production Authentication End-to-End Specification

**Work item:** PORTAL-AUTH-E2E-001  
**Status:** SPECIFICATION — production verification NOT_PROVEN  
**Parent:** MODE-B-PROOF-HARDENING-001 / PORTAL-COMPATIBILITY-001  
**Created:** 2026-11-02  

---

## Purpose

Define the governed live verification that must occur before FrostGate claims production
Portal authentication readiness. This specification defines required actors, prerequisites,
assertions, production-safe operations, and evidence requirements.

Portal live verification is `NOT_PROVEN` until a full run against the production Portal
satisfies all assertions listed here. Simulated or unit-test evidence does NOT satisfy
this gate.

---

## Architecture Context

The Portal (`apps/portal`) is a separate Next.js application from the Console.

| Aspect | Portal | Console |
|--------|--------|---------|
| Session token | `pnu1.` (named-user) or opaque (grant-based demo) | Auth.js JWT |
| Cookie | `fg_portal_session` | `__Secure-authjs.session-token` |
| Authentication | Auth0 OIDC → `/portal/named-users/enroll` | Auth0 OIDC → Auth.js |
| User table | `portal_users` (external clients) | `tenant_users` (workforce) |
| Role model | portal-membership-based | Auth0 role claims |
| BFF host | `apps/portal` | `apps/console` |
| Invitation token | `pni1.*` | `fgwi1.*` (Console workforce) |

Sessions are completely separate. A valid Console session cannot authorize Portal access
and vice versa.

---

## Required Actors

| Actor | Type | Role | Description |
|-------|------|------|-------------|
| `portal_operator` | FrostGate internal | Platform Admin (Support/Administrator) | Issues invitations, manages Portal users |
| `portal_client_user` | External client | `viewer` Portal membership | Receives and accepts invitation |
| `synthetic_portal_identity` | Test account | Portal enrollment test | `frostgatetest@gmail.com` or dedicated Portal test account |

---

## Prerequisites

Before running this verification:

1. A synthetic test tenant exists (`synthetic-portal-test-tenant`) in Core production
2. A test engagement exists under that tenant
3. The `portal_operator` identity has Console access with platform-admin role
4. The Portal BFF is deployed and reachable at the Portal origin
5. Core API is healthy and connected to the Portal BFF
6. Email delivery is available (or invitation token is known for operator-assisted flow)
7. The Portal OIDC application is registered in Auth0 (separate from Console OIDC app)

---

## Step-by-Step Verification Sequence

### Stage 1 — Governed Client Invitation

**Actor:** `portal_operator`

1. Log in to the Console as a platform-admin (`portal_operator`)
2. Navigate to the test engagement
3. Issue a Portal invitation for `synthetic_portal_identity` via Core API:
   ```
   POST /portal/invitations
   Body: { tenant_id, engagement_id, email, portal_role: "viewer" }
   ```
4. Record: invitation ID, `pni1.*` token (do NOT include in evidence)
5. Verify: invitation record created in `portal_user_invitations`

**Assertion:** INV-001 — invitation issued with `pni1.*` token format

---

### Stage 2 — Named-User Enrollment

**Actor:** `synthetic_portal_identity`

1. Receive invitation email (or obtain `pni1.*` token via operator)
2. Navigate to Portal URL: `/accept-invite?token=pni1.{token}`
3. Portal BFF redirects to: `/api/auth/oidc?mode=accept&inviteToken=pni1.{token}`
4. Complete Auth0 OIDC authentication (MFA if configured)
5. Return to `/api/auth/oidc/callback`
6. Portal BFF calls `POST /portal/invitations/{token}/accept`
7. Core creates `portal_users` record and `portal_user_memberships` record
8. Core returns `pnu1.*` token; BFF sets `fg_portal_session` cookie
9. User lands on Portal dashboard

**Assertions:**
- ENROLL-001: Invitation token is consumed (single-use: replay attempt → 409/410)
- ENROLL-002: `pnu1.*` session token set in `fg_portal_session` cookie (HttpOnly, SameSite=Lax)
- ENROLL-003: `portal_users` record created with correct `oidc_subject`
- ENROLL-004: `portal_user_memberships` record created with `engagement_id` bound
- ENROLL-005: Replayed `pni1.*` token rejected (409 INVITATION_ALREADY_ACCEPTED)

---

### Stage 3 — Tenant Binding and Engagement Assignment

**Actor:** `synthetic_portal_identity` (authenticated Portal session)

1. Navigate to Portal session info: `GET /portal/named-users/me`
2. Verify response includes `tenant_id`, `engagement_id`, `portal_role`
3. Verify `auth_version` matches the membership record

**Assertions:**
- BIND-001: Session is bound to exactly one `tenant_id`
- BIND-002: Session is bound to the specific `engagement_id`
- BIND-003: `auth_version` in session matches `auth_version` in membership

---

### Stage 4 — Authorized Assessment Participation

**Actor:** `synthetic_portal_identity`

Using safe GET/read-only probes only:

1. `GET /field-assessment/engagements/{engagement_id}` — expect HTTP 200
2. `GET /field-assessment/engagements/{engagement_id}/findings` — expect HTTP 200
3. `GET /governance/assets` — expect HTTP 200 (if tenant has assets)

**Assertions:**
- ACCESS-001: Engagement data accessible (HTTP 200)
- ACCESS-002: Findings accessible (HTTP 200)
- ACCESS-003: Response data is scoped to the bound engagement only

---

### Stage 5 — Approved Report Visibility

**Actor:** `synthetic_portal_identity`

1. `GET /field-assessment/engagements/{engagement_id}/reports` — expect HTTP 200
2. Verify only approved reports are returned (not draft/in-review)

**Assertion:** REPORT-001 — only approved reports visible to Portal viewer

---

### Stage 6 — Governed Deliverable Retrieval

**Actor:** `synthetic_portal_identity`

1. Attempt to download an approved report:
   `GET /field-assessment/engagements/{engagement_id}/reports/{version}/download`
2. Verify download is scoped to the engagement

**Assertion:** DELIV-001 — report download succeeds for approved engagement report

---

### Stage 7 — Grant Revocation

**Actor:** `portal_operator`

1. Revoke the Portal membership via Core API:
   ```
   DELETE /portal/named-sessions/{session_id}
   ```
   or by updating membership `active=false`
2. After revocation, attempt to use the existing `pnu1.*` session:
   `GET /portal/named-users/me`

**Assertions:**
- REVOKE-001: HTTP 403 or 401 on next request after revocation
- REVOKE-002: `auth_version` mismatch causes session invalidation

---

### Stage 8 — Session Termination

**Actor:** `synthetic_portal_identity`

1. `POST /portal/named-sessions/self` (logout) or Portal logout UI
2. Verify `fg_portal_session` cookie is cleared
3. Attempt to access protected Portal route — expect redirect to /login

**Assertions:**
- LOGOUT-001: `fg_portal_session` cookie cleared after logout
- LOGOUT-002: Protected Portal route redirects to /login after session cleared

---

### Stage 9 — Cross-Tenant Denial

**Actor:** `synthetic_portal_identity`

Using safe probes only:

1. Attempt to access a different tenant's engagement:
   `GET /field-assessment/engagements/{other_engagement_id}` (where other_engagement belongs to a different tenant)
2. Expect: HTTP 403 (tenant boundary)

**Assertion:** XTENANT-001 — cross-tenant engagement access denied (403)

---

### Stage 10 — Cross-Engagement Denial

**Actor:** `synthetic_portal_identity`

1. Attempt to access an engagement NOT bound to the membership:
   `GET /field-assessment/engagements/{unbound_engagement_id}`
2. Expect: HTTP 403 (engagement boundary)

**Assertion:** XENGAG-001 — cross-engagement access denied (403)

---

### Stage 11 — Expired or Replayed Invitation Rejection

**Actor:** Any (unauthenticated)

1. Attempt to use the original `pni1.*` token again after it was accepted:
   `POST /portal/invitations/{token}/accept`
2. Expect: HTTP 409 INVITATION_ALREADY_ACCEPTED or HTTP 410 GONE

**Assertion:** REPLAY-001 — replayed invitation token rejected with 409/410

---

## Evidence Requirements

Evidence must include:

| Field | Required |
|-------|---------|
| Schema version | ✓ |
| Verification profile | `portal_named_user` |
| Environment | `production` |
| Portal origin | ✓ |
| Core service identifier | ✓ |
| Deployment/commit SHA | ✓ |
| Workflow run ID | ✓ if CI-triggered |
| UTC execution timestamp | ✓ |
| Required check manifest | all assertions above |
| Check status (PASS/FAIL/NOT_PROVEN/BLOCKED) | ✓ per assertion |
| Overall acceptance decision | ✓ |
| Test execution mode | `automated` or `operator_assisted` |
| Evidence provenance | ✓ |
| Deterministic fingerprint | SHA-256 |

**Prohibited from evidence:**
- Raw `pni1.*` or `pnu1.*` tokens
- Raw `fg_portal_session` cookie values
- Auth0 OIDC access tokens or ID tokens
- Email addresses in public artifacts
- HMAC session secrets or Core API keys

---

## Production-Safe Operations

All probes MUST be:
- Read-only (GET requests) except where the operation IS the assertion (invitation, enrollment, revocation)
- Using the synthetic test identity, NOT a real client identity
- Scoped to the synthetic test tenant and synthetic test engagement
- Non-destructive (no deleting or overwriting real engagement data)
- Idempotent where possible (enrollment token is single-use; plan for this)

Mutation operations allowed:
- Issuing a synthetic invitation (creates test data only)
- Accepting the invitation (enrollment — idempotent via INVITATION_ALREADY_ACCEPTED)
- Revoking the synthetic session (cleanup)

---

## Acceptance Criteria

The production Portal verification is ACCEPTED when:
- All assertions INV-001 through REPLAY-001 are PASS
- Evidence fingerprint is valid
- `test_execution_mode` is `automated` or `operator_assisted`
- `environment` is `production` (not `simulation`)
- No raw credentials appear in the evidence
- Independent verifier exits 0

Until this gate is satisfied:
- `PORTAL_LIVE_VERIFICATION=NOT_PROVEN`
- Portal client onboarding is NOT cleared by this specification alone

---

## Deferred Items

The following require dedicated implementation work before they can be verified:

1. **Automated MFA for synthetic Portal identity** — if the test account requires MFA,
   Strategy B (operator-assisted) is required
2. **Email delivery confirmation** — invitation email receipt requires a test inbox or
   operator interception of the `pni1.*` token via API
3. **Attestation submission** — POST to `/governance/assets/{id}/attestations` is a write
   operation; requires controlled test asset
4. **Finding status update** — PATCH `/field-assessment/engagements/{id}/findings/{id}`
   requires a real finding in the test engagement

---

## Relationship to Console Mode B

Console Mode B (MODE-B-PROOF-HARDENING-001) and Portal E2E (PORTAL-AUTH-E2E-001) are
**independent verifications** with no shared session state. Passing one does not imply
the other.

The Console harness uses the `frostgatetest@gmail.com` account to test Console access.  
The Portal harness will use a separate Portal-enrolled identity (or the same email
enrolled via the Portal OIDC flow, which creates a distinct `portal_users` record).

They share the Auth0 tenant but use different Auth0 applications and produce different
session types (`Auth.js JWT` vs `pnu1.*` token).
