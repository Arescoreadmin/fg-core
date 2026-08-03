# T4 Operational Evidence — Portal Named-User Proof

Status: PENDING — gates not yet executed

Gate sequence: G1 → G2 → G3 → G4 → G5 → G6

T4 closes when a brand-new customer receives an email, accepts the invitation,
logs in, uses the portal, and logs out — without engineering assistance.

---

## G1 — Invitation

**Status: PENDING**

| Field | Value |
|---|---|
| Environment | prod |
| Date/time (UTC) | |
| Operator | |
| Invitee email | |
| Invitation ID | |
| Request ID | |
| `delivery_state` | |
| `email_message_id` (Resend) | |
| Idempotency key | |
| Invitation expires at | |
| Audit event: `portal_invitation_issued` | |

**G1 result: PENDING**

---

## G2 — Email Delivery

**Status: PENDING**

| Field | Value |
|---|---|
| Resend message ID | |
| Resend dashboard: accepted | |
| Resend dashboard: delivered | |
| SPF check | |
| DKIM check | |
| DMARC check | |
| Sending domain | |
| Link in email points to | |
| Token present in URL (query param `token=`) | |
| No Auth0 secret or internal credential in URL | |
| Invitation TTL shown in email | |

**G2 result: PENDING**

---

## G3 — Acceptance

**Status: PENDING**

| Field | Value |
|---|---|
| Date/time (UTC) | |
| Auth0 account created (new user) or linked (existing) | |
| Auth0 user ID (`sub`) | |
| Auth0 organization membership verified | |
| FrostGate portal_user_id | |
| FrostGate membership_id | |
| `portal_role` on membership | |
| `active` on membership | |
| Audit event: `portal_invitation_accepted` | |
| Audit event: `portal_user_created` | |
| Audit event: `portal_membership_created` | |
| Session token issued (pnu1.) | |
| Invitation status = accepted | |

**G3 result: PENDING**

---

## G4 — Login

**Status: PENDING**

| Field | Value |
|---|---|
| OIDC login endpoint | |
| Auth0 token validated | |
| Tenant correctly resolved | |
| RBAC: portal_role matches expected | |
| Session created (pnu1.) | |
| Session expires at | |
| `GET /portal/named-users/me` returns correct identity | |
| Cross-tenant access attempt: blocked | |

**G4 result: PENDING**

---

## G5 — Portal Pages

**Status: PENDING**

All tests performed as the invited user with no engineering intervention.

| Page | URL / Endpoint | HTTP Status | Notes |
|---|---|---|---|
| Dashboard | `/portal/engagement/{id}/dashboard` | | |
| Profile (`/portal/named-users/me`) | `GET /portal/named-users/me` | | |
| Engagement list | `/portal/engagement/{id}/timeline` | | |
| Report list | `/portal/engagement/{id}/reports` | | |
| Evidence | `/portal/engagement/{id}/evidence` | | |
| Logout | `DELETE /portal/named-sessions/self` | 204 | |

No 401s. No 403s. No redirect loops.

**G5 result: PENDING**

---

## G6 — Session

**Status: PENDING**

Logout sequence:

| Check | Result |
|---|---|
| `DELETE /portal/named-sessions/self` → 204 | |
| Session status in DB = revoked | |
| Audit event: `portal_session_revoked` | |
| Replay of same token → 401 | |
| Second logout (same token) → 204 (idempotent) | |
| Login required again to access portal | |

**G6 result: PENDING**

---

## Evidence Summary

| Field | Value |
|---|---|
| Invitee email | |
| Invitation ID | |
| Invite request ID | |
| Resend message ID | |
| Acceptance timestamp (UTC) | |
| Auth0 user ID | |
| Auth0 organization membership | |
| FrostGate portal_user_id | |
| FrostGate membership_id | |
| RBAC assignment | |
| Session ID | |
| Session created at (UTC) | |
| Session revoked at (UTC) | |
| Logout audit event ID | |

---

## Failure Policy

No manual intervention is permitted:

- No Auth0 user creation via dashboard
- No DB updates to portal_users, portal_user_memberships, or portal_user_sessions
- No RBAC edits via admin endpoints
- No portal grants manually issued

Any manual intervention = failed gate. Revoke and restart.
