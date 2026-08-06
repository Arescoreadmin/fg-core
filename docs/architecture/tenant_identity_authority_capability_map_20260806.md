# Tenant Identity Authority — Capability Map

**Date:** 2026-08-06  
**Branch:** plan/tenant-identity-administration-platform-20260806  
**Status:** PLANNING ARTIFACT — launch freeze active; no runtime changes  
**Authority:** jcosat

This document defines the authority graph, surface ownership, source-of-truth decisions, data ownership, trust boundaries, legacy paths, target paths, and migration boundaries for the Tenant Identity & Administration Platform.

---

## Authority Graph

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FROSTGATE IDENTITY AUTHORITY                        │
│                                                                             │
│  ┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐  │
│  │  Platform Console │      │  Tenant Admin    │      │  End-User Portal  │  │
│  │                  │      │  Surface         │      │                  │  │
│  │  platform_admin  │      │  tenant_admin    │      │  portal_user     │  │
│  │  platform_support│      │  tenant_operator │      │                  │  │
│  └────────┬─────────┘      └────────┬─────────┘      └────────┬─────────┘  │
│           │                         │                          │            │
│           ▼                         ▼                          ▼            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      BFF / Admin Gateway                            │   │
│  │  apps/console/app/api/core/[...path]/route.ts                      │   │
│  │  Credential selection: operator-class | tenant-class | portal-class │   │
│  └─────────────────────────────┬───────────────────────────────────────┘   │
│                                 │                                           │
│           ┌─────────────────────┴──────────────────────┐                   │
│           ▼                                              ▼                  │
│  ┌─────────────────────┐                    ┌─────────────────────────┐   │
│  │   CORE API          │                    │  AUTH0 PROVIDER         │   │
│  │  (FrostGate source  │◄──────────────────►│  (IdP operations only)  │   │
│  │   of truth for      │                    │  org membership         │   │
│  │   governance state) │                    │  credential enrollment  │   │
│  └─────────────────────┘                    │  MFA                    │   │
│           │                                 │  password reset         │   │
│           │                                 │  session tokens         │   │
│           ▼                                 └─────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     POSTGRESQL (RLS-gated)                          │   │
│  │  tenant_users            tenant_invitations   tenant_identity_*     │   │
│  │  portal_users            portal_user_*        tenant_users (RLS)   │   │
│  │  portal_grants           tenant_identity_audit_events               │   │
│  │  tenant_identity_bindings tenant_identity_configs                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Surface Ownership

| Surface | Owner | Authority class | Auth mechanism |
|---|---|---|---|
| Platform Console | FrostGate operators | `platform_admin`, `platform_support` | Auth0 OIDC + Admin Gateway governed session |
| Tenant Administration Surface | Tenant administrators | `tenant_admin`, `tenant_operator` | Auth0 org OIDC + Admin Gateway governed session (H1) |
| End-User Portal | Portal users | `portal_user` | OIDC (named-user) or shared grant secret |

---

## Source-of-Truth Decisions

| Concern | Source of truth | Rationale |
|---|---|---|
| Tenant membership status | Core (`tenant_users.status`) | Core is governance authority; Auth0 is provider |
| Tenant membership roles | Core (`tenant_users` + `tenant_rbac.py`) | Core enforces SoD invariants |
| Invitation state machine | Core (`tenant_invitations`) | Auth0 org invitation is IdP transport; state lives in Core |
| Session revocation | Core (`identity_authority/authority.py` — `auth_version`) | Immediate invalidation without blocklist scan |
| Portal user identity | Core (`portal_users`) | Separate identity population from workforce users (PR #577) |
| Portal access grants | Core (`portal_grants` + `portal_user_memberships`) | Engagement ownership validated by Core |
| Auth0 org membership | Auth0 (provider) | Used for IdP operations only; Core membership is canonical |
| Auth0 user identity (subject) | Auth0 (provider) | `(provider, issuer, subject)` tuple is identity authority; email is invitation verification only |
| Password credential | Auth0 only | FrostGate operators and tenant admins have no access |
| MFA enrollment | Auth0 only | FrostGate has no visibility |
| Engagement ownership | Core (`fa_engagements.tenant_id`) | Field Assessment authority |
| Audit chain | Core (`tenant_identity_audit_events` — append-only, hash-linked) | Tamper-evident evidence |

**Conflict resolution rule:** Core governance state wins over Auth0 IdP state. A disabled Core membership (`tenant_users.status = disabled`) rejects all sessions regardless of Auth0 org status.

---

## Data Ownership

| Table | Owner service | Access pattern | Tenant isolation |
|---|---|---|---|
| `tenant_users` | Core identity | `admin_identity.py`, `workforce.py` | RLS on `tenant_id` |
| `tenant_invitations` | Core identity | `admin_identity.py` | RLS on `tenant_id` |
| `tenant_identity_configs` | Core identity | `tenant_identity_policy.md` | RLS on `tenant_id` |
| `tenant_identity_providers` | Core identity | Auth0 adapter | RLS on `tenant_id` |
| `tenant_identity_bindings` | Core identity | `tenant_identity_authority.py` (IA-1) | RLS on `tenant_id` |
| `tenant_identity_audit_events` | Core identity | Append-only; hash-linked | RLS on `tenant_id` |
| `portal_users` | Core portal identity | `portal_user_authority.py` | RLS via `portal_user_memberships.tenant_id` |
| `portal_user_invitations` | Core portal identity | `portal_user_authority.py` | RLS via `tenant_id` |
| `portal_user_memberships` | Core portal identity | `portal_user_authority.py` | RLS on `tenant_id` |
| `portal_user_sessions` | Core portal identity | `portal_user_authority.py` | RLS via `tenant_id` |
| `portal_user_audit_events` | Core portal identity | Append-only | RLS on `tenant_id` |
| `portal_grants` | Core portal access | `portal_grant_service.py` | `tenant_id` column |
| `fa_engagements` | Field Assessment | `services/field_assessment/store.py` | `tenant_id` column |

---

## API Ownership

| Route pattern | Owner | Authority required |
|---|---|---|
| `POST /workforce/users` | Core identity (`workforce.py`) | `admin:write` + `identity.scim` |
| `GET /workforce/users` | Core identity (`workforce.py`) | `admin:read` |
| `POST /admin/tenants/{id}/identity-bindings` | Core tenant authority (`tenant_identity_authority.py`) | `platform_admin` |
| `GET /portal/grants`, `POST /portal/grants` | Core portal (`portal.py`) | Mixed — see API-001/API-002 findings |
| `POST /portal/invitations` | Core portal identity (`portal_user_authority.py`) | `admin:write` |
| `GET /portal/named-users/me` | Core portal identity | Named-user session |
| H1 routes: `GET/POST /admin/tenants/{id}/users` | Core tenant admin (H1-PR5) | `tenant_admin` session |
| H2 routes: `POST /invitations` (unified) | `InvitationAuthority` (H2-PR1) | Context-dependent |

---

## Audit Ownership

| Event category | Audit table | Ownership | Append-only |
|---|---|---|---|
| Tenant identity lifecycle | `tenant_identity_audit_events` | Core identity | Yes (trigger) |
| Portal user lifecycle | `portal_user_audit_events` | Core portal identity | Yes (trigger) |
| Governance decisions | `fa_governance_events` | Field Assessment | Yes (trigger) |
| Platform admin actions | (future unified audit — H2) | Platform | Planned for H2 |

**H2 target:** Single unified audit pipeline with shared event schema, hash linkage, and tenant-scoped filtering. Current state: two separate audit tables for tenant identity and portal identity; no cross-stream correlation.

---

## Notification Ownership

| Notification type | Current owner | Current path | H2 target |
|---|---|---|---|
| Console user invitation | `api/notifications/email.py` | Resend via stdlib urllib | Unified notification pipeline |
| Portal named-user invitation | `api/notifications/email.py` | Resend via stdlib urllib | Unified notification pipeline |
| Portal grant delivery | Email route (`apps/console/app/api/email/route.ts`) | Console BFF | Unified notification pipeline |
| Password reset | Auth0 (IdP-managed) | Auth0 email templates | Remains Auth0-managed |
| MFA enrollment | Auth0 (IdP-managed) | Auth0 email templates | Remains Auth0-managed |

**H2 target (H2-PR6):** Shared notification pipeline with retry, idempotency, delivery tracking, and tenant-scoped audit events for all FrostGate-originated notifications.

---

## External Provider Ownership

| Provider | Owns | Does not own |
|---|---|---|
| Auth0 | OIDC token issuance; credential enrollment; MFA; password reset; org membership (IdP); session tokens | Core membership status; role assignments; audit chain; engagement ownership |
| Resend | Email delivery | Invitation lifecycle state; delivery audit |
| PostgreSQL | Governance state persistence; RLS isolation; append-only audit | Session token validation (Core validates in-process) |

---

## Legacy Paths

| Path | Problem | H0 fix | H2 retirement |
|---|---|---|---|
| Console invitation via tenant API key (`/workforce/users` with portal key) | AUTH-001: Core correctly rejects; BFF uses wrong credential class | H0-PR1: BFF uses operator-class credential | H2-PR5: unified invitation authority |
| Portal grant with browser-supplied `client_id` and `engagement_id` | API-001: No server-side ownership validation | H0-PR3/H0-PR4: server-side revalidation | H2-PR5: unified portal access authority |
| BFF classifies `/portal/grants` as admin-gateway; Core does not recognize it | API-002: Authority routing drift | H0-PR4: align classification | H2-PR4: session authority consolidation |
| Shared credential portal login (`pcu1.` prefix) | Not a security issue; weaker than named-user | No H0 change | H2: access authority consolidation; named-user preferred |

---

## Target Authority Architecture (post-H2)

```
INVITATION AUTHORITY (H2-PR1)
  ┌────────────────────────────────────────────────────────────────────┐
  │  InvitationAuthority                                               │
  │  - create_invitation(type, recipient, tenant, role, expiration)    │
  │  - resend_invitation(invitation_id)                                │
  │  - revoke_invitation(invitation_id)                                │
  │  - accept_invitation(token) → triggers Auth0 enrollment            │
  │  - get_invitation_lifecycle(invitation_id)                         │
  │  Emits: canonical InvitationEvent → unified audit pipeline         │
  │  Handles: console_user | portal_named_user | portal_shared         │
  └────────────────────────────────────────────────────────────────────┘

MEMBERSHIP AUTHORITY (H2-PR2)
  ┌────────────────────────────────────────────────────────────────────┐
  │  MembershipAuthority                                               │
  │  - get_membership(tenant_id, user_id)                              │
  │  - activate_membership(...)                                        │
  │  - disable_membership(...)                                         │
  │  - update_role(...)                                                │
  │  - revoke_all_sessions(membership_id)                              │
  │  Auth0: provider adapter (block/unblock; invitation acceptance)    │
  │  Core: governance authority (membership status, role, audit)       │
  └────────────────────────────────────────────────────────────────────┘

ROLE AUTHORITY (H2-PR3)
  ┌────────────────────────────────────────────────────────────────────┐
  │  RoleAuthority                                                     │
  │  - assign_role(membership_id, role, reason, approver)              │
  │  - revoke_role(membership_id, role)                                │
  │  - enforce_sod(membership_id, proposed_role)                       │
  │  SoD invariants: tenant_admin ≠ compliance_reviewer (hardcoded)    │
  └────────────────────────────────────────────────────────────────────┘

CREDENTIAL AUTHORITY (existing, formalized in H2-PR4)
  ┌────────────────────────────────────────────────────────────────────┐
  │  CredentialAuthority                                               │
  │  - issue_session(principal, tenant, version)                       │
  │  - revoke_session(session_id)                                      │
  │  - revoke_all_for_subject(subject_id)                              │
  │  - is_session_revoked(session_id, auth_version)                    │
  │  Current: api/identity_authority/authority.py                      │
  └────────────────────────────────────────────────────────────────────┘

SESSION AUTHORITY (existing, formalized in H2-PR4)
  ┌────────────────────────────────────────────────────────────────────┐
  │  SessionAuthority                                                  │
  │  - validate_session(token) → auth_version check → membership check │
  │  - revoke_session(session_id)                                      │
  │  Current: admin_gateway oidc.py + require_governed_session()       │
  └────────────────────────────────────────────────────────────────────┘

PORTAL ACCESS AUTHORITY (H2-PR5)
  ┌────────────────────────────────────────────────────────────────────┐
  │  PortalAccessAuthority                                             │
  │  - create_grant(tenant_id, engagement_id, recipient, type)         │
  │  - validate_engagement_ownership(tenant_id, engagement_id)         │
  │  - revoke_grant(grant_id)                                          │
  │  - get_access_lifecycle(tenant_id)                                 │
  │  Current: portal_grant_service.py + portal_user_authority.py       │
  └────────────────────────────────────────────────────────────────────┘

AUDIT AUTHORITY (H2-PR6 notification + existing audit tables)
  ┌────────────────────────────────────────────────────────────────────┐
  │  AuditAuthority                                                    │
  │  - emit(event_type, tenant_id, actor, target, metadata)            │
  │  - verify_chain(tenant_id, from_event, to_event)                   │
  │  Current: per-table append-only triggers; hash linkage in identity │
  │  Target: unified pipeline; shared notification; idempotency        │
  └────────────────────────────────────────────────────────────────────┘
```

---

## Dependency Map

```
Auth0 Organizations (IA-1, done)
    └─► Tenant identity binding
            └─► Console user invitation (H0-PR1)
                    └─► Tenant admin session (H1-PR4)
                            └─► Tenant user admin APIs (H1-PR5)
                                    └─► Unified Invitation Authority (H2-PR1)

Field Assessment engagements (existing)
    └─► Engagement ownership validation (H0-PR3)
            └─► Portal grant server-side check (H0-PR4)
                    └─► Engagement selector UI (H1-PR7)
                            └─► Portal Access Authority (H2-PR5)

Session revocation (existing: identity_authority/authority.py)
    └─► Tenant admin session revocation API (H1-PR9)
            └─► Credential/Session Authority consolidation (H2-PR4)

Audit tables (existing: tenant_identity_audit_events)
    └─► Tenant audit surface (H1-PR10)
            └─► Unified audit pipeline (H2-PR6)
```

---

## Trust Boundaries

| Boundary | Trust level | Rule |
|---|---|---|
| Browser → BFF | Untrusted | BFF validates session; strips payload tenant overrides |
| BFF → Core | Internal-trusted | Core re-validates authority class and tenant binding |
| Core → PostgreSQL | Internal-trusted via RLS | `app.tenant_id` session variable set before every query |
| Core → Auth0 | External-trusted | M2M credentials; scoped to 12 least-privilege scopes (per IA-0 audit) |
| Auth0 → Core | External-trusted callback | JWT RS256 JWKS-verified; no base64 decode |
| Tenant admin session | Tenant-scoped | route tenant = session tenant; `auth_version` validated live |
| Portal user session | Engagement/grant scoped | `pnu1.` or `pcu1.` prefix; engagement binding enforced |
| Auth0 org membership | IdP assertion only | Core membership is authoritative; Auth0 org is provider |

---

## Migration Boundaries

| Component | H0 action | H1 action | H2 action |
|---|---|---|---|
| Console invitation (BFF credential) | Fix authority routing | No change | Migrate to InvitationAuthority |
| Portal grant creation | Add server-side ownership validation | No change | Migrate to PortalAccessAuthority |
| `admin_identity.py` console invitation | No change to API | Extend for tenant_admin scope | Consolidate to InvitationAuthority |
| `portal_user_authority.py` named-user invitation | No change | Expose via H1 portal access | Consolidate to InvitationAuthority |
| `portal_grant_service.py` | Add ownership check | No change | Consolidate to PortalAccessAuthority |
| Audit tables | No change | Add tenant audit surface | Unified audit pipeline |

**Compatibility rule:** Legacy paths are wrapped, not removed, until H2-PR5. No breaking API changes until all consumers are confirmed migrated.
