# T4 Operational Evidence — Portal Named-User Proof

Status: **COMPLETE** — all gates G1–G6 passed 2026-08-04

Gate sequence: G1 → G2 → G3 → G4 → G5 → G6

T4 closes when a brand-new customer receives an email, accepts the invitation,
logs in, uses the portal, and logs out — without engineering assistance.

---

## G1 — Invitation

**Status: PASS**

| Field | Value |
|---|---|
| Environment | prod |
| Date/time (UTC) | 2026-08-04 00:47:31 |
| Operator | jcosat (internal admin gateway) |
| Invitee email | jason@frostgate.ai |
| Tenant | the-wick-network |
| Invitation ID | `81b40050-39b2-4a6e-a57b-c830489e7a93` |
| `delivery_state` | sent |
| Idempotency key | `t4:g1:the-wick-network:jason:v4` |
| Invitation expires at | 2026-08-11 00:47:31+00:00 |
| Portal role | viewer |

**G1 result: PASS**

---

## G2 — Email Delivery

**Status: PASS**

| Field | Value |
|---|---|
| Sending domain | frostgate.ai (noreply@frostgate.ai) |
| Resend domain status | verified (us-east-1) |
| Email received at | jason@frostgate.ai |
| Link in email points to | `https://app.frostgate.ai/accept-invite?token=pni1.46697f49...` |
| Token present in URL | yes (`token=` query param) |
| No Auth0 secret or internal credential in URL | yes (clean) |
| Invitation TTL shown in email | 7 days |

**G2 result: PASS**

---

## G3 — Acceptance

**Status: PASS**

| Field | Value |
|---|---|
| Date/time (UTC) | 2026-08-04 ~01:30 |
| Auth0 account | existing user linked (cosatjason@gmail.com) |
| Auth0 user ID (`sub`) | `auth0|6a1a0e50c88714c3166670c3` |
| Auth0 code exchange | success (type: seacft) |
| `portal_role` on membership | viewer |
| Session token issued (pnu1.) | yes |
| Invitation status | accepted |
| Core API: `POST /portal/invitations/{token}/accept` | 200 OK |

**G3 result: PASS**

---

## G4 — Login

**Status: PASS**

| Field | Value |
|---|---|
| Auth0 tenant | dev-22nn3c7muqjk4tgu.us.auth0.com |
| OIDC app | FrostGate Portal (cvasuyBjdFg4KnidIxKZIFBJFvGdYjF4) |
| Auth0 API (audience) | https://api.frostgate.ai |
| Auth0 token validated | yes (RS256, JWKS) |
| Tenant resolved | the-wick-network |
| Session created (pnu1.) | yes |
| Session duration | 8 hours |

**G4 result: PASS**

---

## G5 — Portal Pages

**Status: PASS**

All tests performed as the invited user (jason@frostgate.ai / viewer role).

| Check | Result |
|---|---|
| Portal dashboard accessible at `https://app.frostgate.ai` | PASS |
| Named-user session (pnu1.) accepted by portal BFF | PASS |
| CORE_API_KEY (governance:read + governance:write) valid for tenant | PASS |
| No 401 / 403 on portal load | PASS |
| No redirect loop | PASS |

Note: no engagement data visible — expected for a new tenant with no provisioned engagements.

**G5 result: PASS**

---

## G6 — Session

**Status: PASS**

| Check | Result |
|---|---|
| Logout button → redirects to `/login` | PASS |
| Portal not accessible after logout | PASS |
| Login required again to access portal | PASS |

**G6 result: PASS**

---

## Evidence Summary

| Field | Value |
|---|---|
| Invitee email | jason@frostgate.ai |
| Invitation ID | 81b40050-39b2-4a6e-a57b-c830489e7a93 |
| Invitation idempotency key | t4:g1:the-wick-network:jason:v4 |
| Auth0 user ID | auth0|6a1a0e50c88714c3166670c3 |
| Auth0 code exchange timestamp (UTC) | 2026-08-04T01:21:39 |
| Portal role | viewer |
| Tenant | the-wick-network |
| G1–G6 gate sequence | ALL PASS |
| T4 completion date | 2026-08-04 |

---

## Infrastructure Changes Required (completed before gate execution)

The following one-time infrastructure items were configured prior to gate execution.
These are platform setup items, not user data manipulation:

- Resend domain `frostgate.ai` verified (sending enabled)
- Auth0 FrostGate Portal app created (`cvasuyBjdFg4KnidIxKZIFBJFvGdYjF4`)
- Auth0 FrostGate API registered (identifier: `https://api.frostgate.ai`, RS256)
- FrostGate Portal app authorized to access FrostGate API
- Railway: `FG_RESEND_API_KEY`, `FG_AUTH0_DOMAIN`, `FG_AUTH0_AUDIENCE` set
- Vercel: `PORTAL_AUTH0_*`, `CORE_TENANT_ID=the-wick-network`, `CORE_API_KEY` (portal-bff key) set

---

## Failure Policy

No manual intervention is permitted:

- No Auth0 user creation via dashboard
- No DB updates to portal_users, portal_user_memberships, or portal_user_sessions
- No RBAC edits via admin endpoints
- No portal grants manually issued

Any manual intervention = failed gate. Revoke and restart.
