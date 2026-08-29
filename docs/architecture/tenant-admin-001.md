# TENANT-ADMIN-001 — Delegated Tenant Administration Authority

**Status:** Implemented
**Delivered:** feat/tenant-admin-001-delegated-administration
**Predecessors:** AUTH-ROLE-001A, AUTH-ROLE-001B
**Successor:** TENANT-ACCESS-001 → CLIENT-E2E-001

---

## Purpose

Provide a DB-canonical, per-tenant delegated administration surface so a
tenant administrator can manage the console users and portal access that
belong to **their tenant only**, subject to a hard delegation ceiling and
uniform cross-tenant denial.

Business objective:

> A tenant administrator can manage permitted Console users, Portal access,
> and permitted Identity governance for THEIR TENANT ONLY, subject to
> delegation ceilings and hard cross-tenant enforcement.

Non-negotiable properties:

1. **JWT role claims are advisory, not canonical.** Every authority
   decision performs a fresh SELECT against `tenant_users` inside the
   request's DB session.
2. **Authority is per-tenant.** The route tenant is the only source of
   truth for the target tenant; the actor's session must agree.
3. **Delegation ceilings are static allowlists.** Adding a new client role
   is a code change, not a data change.
4. **Cross-tenant denial is uniform.** Both wrong-tenant and not-admin
   surface a single `TENANT_ADMIN_DENIED` — no oracle differentiation.
5. **Bootstrap is platform-only.** The first-admin endpoint requires
   `platform.admin`, is idempotent, and does not create a durable backdoor.
6. **Console and portal remain distinct.** A console tenant_admin is not
   automatically a portal grantee.

---

## Canonical authority chain

```
HTTP request
  → AuthGateMiddleware      (authenticate: API key or JWT)
  → require_scopes(...)     (coarse scope gate; e.g. admin:read/write)
  → require_permission(...) (permission gate resolved from JWT/API-key roles)
  → resolve_authoritative_tenant(request, actor_ctx, tenant_id)
      (verify path-tenant == key-bound-tenant == actor-session-tenant)
  → check_tenant_admin_authority(db, actor_ctx, tenant_id)
      (DB-authoritative check on tenant_users row)
  → route body                (mutation runs)
      → assert_role_delegatable(new_role)   (delegation ceiling)
      → membership_version_svc.bump_version (AUTH-ROLE-001B revision)
      → enqueue_projection                  (AUTH-ROLE-001B outbox)
      → emit_identity_audit_event           (append-only audit chain)
      → db.commit()                         (single atomic transaction)
```

Every layer above is fail-closed. The tenant-admin authority check is the
one that adds delegated-administration semantics on top of the existing
identity chain; it does not replace any prior layer.

---

## Platform vs tenant authority separation

| Authority              | Held by                                            | Grants                                                     |
| ---------------------- | -------------------------------------------------- | ---------------------------------------------------------- |
| `platform.admin`       | FrostGate platform operators (Auth0 role or PSP)   | Cross-tenant operations, bootstrap, credential rotation.   |
| `tenant_admin` (DB)    | A user whose canonical `tenant_users` row for tenant T has `role='tenant_admin'`, `active=TRUE`, `identity_binding_status='bound'`, `principal_id IS NOT NULL` | Delegated administration of users and portal-access for **tenant T only**. |
| `client_*` roles       | Non-admin members invited by a tenant_admin        | Client-side surfaces (evidence portal, remediation, etc.). |

`tenant_admin` grants **no platform authority**. A tenant_admin cannot
call the bootstrap endpoint, cannot rotate platform credentials, and
cannot list other tenants' users.

---

## First-admin bootstrap design

Endpoint: `POST /admin/tenants/{tenant_id}/bootstrap-admin`

Authorization: `require_permission("platform.admin")` + `admin:write`
scope.

Behavior:

- If no `tenant_users` row exists for `(tenant_id, email)`: create one
  with `role='tenant_admin'`, `active=TRUE`, `identity_binding_status='unbound'`,
  `principal_id=<body.principal_id or NULL>`.
- If one exists but `role != 'tenant_admin'` or `active=FALSE`: promote it
  and bump `membership_version`. Enqueue Auth0 projection when the
  membership is already bound to an Auth0 provider.
- If one exists and is already a tenant_admin: no-op (idempotent).
- Emit `tenant.admin.bootstrap` identity audit event with actor
  attribution and `reason_code ∈ {TENANT_ADMIN_BOOTSTRAPPED, ALREADY_TENANT_ADMIN}`.
- Response includes `bootstrapped: bool` so the caller can distinguish
  first-issue from re-issue.

Non-backdoor invariant: bootstrap does not persist any platform-level
authority on the tenant row. The tenant_admin row it creates is
subject to the same authority checks as any other tenant_admin.

---

## Delegation ceilings

Two disjoint allowlists in `api/tenant_admin_authority.py`:

- `DELEGATABLE_ROLES` — the sole set of role strings a tenant_admin may
  assign via invite or update. Currently:
  `user`, `auditor`, `client_executive`, `client_compliance`,
  `client_auditor`, `client_remediation_owner`, `client_security_owner`,
  `client_read_only`.
- `FORBIDDEN_DELEGATION_ROLES` — explicitly rejected even if listed
  elsewhere. Includes `tenant_admin` (no self-replication),
  `platform_admin`, all FrostGate internal roles (`Administrator`,
  `Operator`, `CISO`, `Executive`, `Auditor`, `Developer`, `Support`,
  `Compliance`, `AssessmentEngineer`, `FieldAssessor`, `Consultant`), and
  the legacy governance roles (`compliance_reviewer`, `qa_reviewer`,
  `assessor`).

Enforcement:

- `assert_role_delegatable(role)` — the single authority. Called by
  both `POST /users/invite` and `PATCH /users/{id}` when the payload
  includes a role.
- Failure returns 403 `ROLE_NOT_DELEGATABLE`.

Adding a new delegatable role requires:

1. Add to `DELEGATABLE_ROLES` in `api/tenant_admin_authority.py`.
2. Add corresponding entry to `ROLE_PERMISSIONS` in
   `api/actor_context.py` so the role actually resolves to a
   permission set.
3. Add a parametrized test to `TestDelegationCeiling.test_e3` (already
   auto-covers via `pytest.mark.parametrize` on `sorted(DELEGATABLE_ROLES)`).

---

## Self-escalation denial

A tenant_admin cannot modify their own `role` or `active` flag. Attempted
`PATCH /admin/tenants/{tid}/users/{their_own_id}` with `role` or `active`
returns 403 `SELF_ESCALATION_DENIED`. Cosmetic edits (`display_name`)
remain permitted.

This means a tenant_admin cannot deactivate themselves and cannot
demote themselves to `client_read_only`. Only another tenant_admin or a
platform admin (via bootstrap or direct DB path) can perform those
mutations.

---

## Console vs portal separation

Console users are managed via `POST /admin/tenants/{tid}/users/invite`
against `tenant_users`. Portal access is managed via `POST
/admin/tenants/{tid}/portal-access/invite`, which delegates to the
canonical `services/portal_grant_service.py` (credential authority
R4.9). The two surfaces:

- Use different tables (`tenant_users` vs `tenant_credentials`
  with `credential_type='portal_access'`).
- Use different role vocabularies (`DELEGATABLE_ROLES` above vs
  portal-only roles `general|executive|remediation|technical|compliance`).
- Require distinct explicit invocations. Being a console tenant_admin
  does NOT create any portal grant for the admin.

Portal roles are explicitly rejected by `assert_role_delegatable`.

---

## Identity-governance boundary

TENANT-ADMIN-001 routes intentionally do NOT require
`TenantIdentityConfig` to be provisioned. This is a considered choice:

- Bootstrap must work before Auth0/OIDC is configured for the tenant
  (chicken-and-egg for new tenants).
- Tenant admins can list, invite, and update users using the
  invitation-only status — the actual identity binding happens later
  via the AUTH-ROLE-001B / invitation-flow chain.
- Routes that DO require identity_config remain unchanged
  (`POST /workforce/users` still gates on
  `require_capability("identity.scim")` and
  `require_identity_configured()`).

---

## Auth0 boundary

Auth0 remains read-only for TENANT-ADMIN-001. Every mutation that
changes `role` or `active`:

1. Bumps `tenant_users.membership_version` via `membership_version_svc.bump_version()`.
2. Enqueues an `identity_projection_outbox` row via `enqueue_projection()`
   (AUTH-ROLE-001B) — but only when the target user has:
   - A bound canonical `principal_id`.
   - `identity_provider = 'auth0'`.
   - A non-null `identity_subject`.

The projection worker (existing AUTH-ROLE-001B component) picks up the
outbox row and updates Auth0 `app_metadata` asynchronously. Failures
retry with exponential backoff and never roll back the authoritative
mutation.

---

## Invitation authority

TENANT-ADMIN-001 does NOT introduce a second invitation authority.
`POST /admin/tenants/{tid}/users/invite`:

- Creates the `tenant_users` row directly (same shape as workforce),
  with `identity_binding_status='unbound'`.
- Does NOT create a `tenant_invitations` row — that path (used by
  `TenantIdentityStore.create_invitation()`) requires an identity
  configuration to exist, which we deliberately do not require.
- Is idempotent by `(tenant_id, email)` — a duplicate invite returns
  the existing row with `invited=false`.

For post-bootstrap identity binding, tenants use the existing
`POST /admin/identity/tenants/{tid}/invitations` flow, which continues
to require identity_config and drives Auth0 binding via the invitation
flow.

The unified-invitation-authority consolidation is scheduled for P1-01
H2 (post-RC1), not TENANT-ADMIN-001.

---

## Tenant isolation

All queries are scoped by `WHERE tenant_id = :t` and use the same
`resolve_authoritative_tenant` + `check_tenant_admin_authority` pair,
so cross-tenant enumeration is blocked at three layers:

1. `bind_tenant_id` — key-bound tenant must equal route tenant.
2. `resolve_authoritative_tenant` — actor session tenant must equal
   route tenant.
3. `check_tenant_admin_authority` — DB `tenant_users` row must exist
   for the actor in the route tenant with `role='tenant_admin'`.

RLS on `tenant_users`, `tenant_invitations`,
`tenant_identity_audit_events`, and `identity_projection_outbox`
provides the fourth defensive layer at the DB level.

---

## RLS

No new tables — no new RLS policies. `tenant_users`,
`tenant_identity_audit_events`, and `identity_projection_outbox` are
already covered by `assert_tenant_rls()` in `api/db_migrations.py`.

---

## Audit behavior

Every mutation emits a `tenant_identity_audit_events` row with:

- `actor_user_id` — the authenticated subject (never spoofable — sourced
  from ActorContext).
- `affected_email` — normalized target email.
- `membership_id` — target tenant_users.id.
- `event_type` — one of:
  - `tenant.admin.bootstrap`
  - `tenant.member.invited`
  - `tenant.member.updated`
  - `tenant.portal_access.invited`
  - `tenant.portal_access.revoked`
- `reason_code` — machine-readable outcome
  (`TENANT_ADMIN_BOOTSTRAPPED`, `ALREADY_TENANT_ADMIN`,
  `TENANT_ADMIN_INVITED`, `TENANT_ADMIN_UPDATED`).
- `details_json` — filtered through the `safe_keys` allowlist in
  `emit_identity_audit_event` so no secrets/tokens/passwords can be
  recorded.
- Hash-chained via `previous_event_hash` + `event_hash` (existing
  tamper-evidence chain).

---

## Failure modes

| Scenario                                     | HTTP  | Code                     |
| -------------------------------------------- | ----- | ------------------------ |
| Missing/invalid API key                      | 401   | Invalid or missing API key |
| Wrong scope (`admin:read` on POST)           | 403   | scope mismatch           |
| Actor lacks `user.invite` permission         | 403   | PERMISSION_DENIED        |
| Route tenant != key-bound tenant             | 403   | tenant mismatch          |
| Route tenant != actor session tenant         | 403   | tenant mismatch (STALE_TENANT_SESSION event) |
| Actor is not a canonical tenant_admin for T  | 403   | TENANT_ADMIN_DENIED      |
| Actor targets another tenant's user          | 403 or 404 | TENANT_ADMIN_DENIED / TARGET_USER_NOT_FOUND |
| Payload role not delegatable                 | 403   | ROLE_NOT_DELEGATABLE     |
| Actor edits own role/active                  | 403   | SELF_ESCALATION_DENIED   |
| Bootstrap without `platform.admin`           | 403   | PERMISSION_DENIED        |
| Portal invite for other tenant's engagement  | 404   | ENGAGEMENT_NOT_FOUND     |

No stack traces or DB errors are surfaced to callers.

---

## Revocation behavior

- Deactivating a tenant_admin (`PATCH ... {"active": false}`) causes
  their next `check_tenant_admin_authority()` call to fail with
  `TENANT_ADMIN_DENIED`. Their JWT continues to claim tenant_admin
  until it expires, but the DB check overrides.
- Downgrading a tenant_admin (`PATCH ... {"role": "client_read_only"}`)
  has the same effect.
- Both mutations bump `membership_version` and enqueue an Auth0
  projection so `app_metadata.roles` converges within one worker pass.
- Portal grant revocation is soft-revoke via
  `credential_authority.revoke_credential()` — active portal sessions
  are terminated by the existing `lookup_portal_session_by_fingerprint()`
  path.

---

## Explicit non-goals

TENANT-ADMIN-001 does NOT:

- Replace Auth0 or any external identity provider.
- Replace canonical principals (`fg_principals`).
- Replace the invitation flow (`TenantIdentityStore.create_invitation`).
- Redesign portal authorization or the portal grant system.
- Introduce a second RBAC engine.
- Add a permanent bootstrap backdoor.
- Weaken existing scope, permission, or capability gates.
- Weaken tenant isolation or RLS.
- Make JWT roles canonical for authorization.
- Grant tenant admins any platform authority.
- Allow cross-tenant administration under any circumstance.
- Merge console and portal authorization surfaces.

---

## Next-phase boundaries (TENANT-ACCESS-001)

TENANT-ACCESS-001 will build on this by:

- Consolidating portal access management under a first-class
  invitation authority (currently portal grants are opaque secrets;
  named-user portal access is a separate T4 path).
- Adding client-side visibility (a tenant_admin can see their own
  invitations, resend, and revoke unified across console and portal).
- Providing the tenant-admin UX surface in the Console frontend
  (currently the routes exist but no dedicated UI page).

CLIENT-E2E-001 will then add the end-to-end client onboarding proof
(design partner walk-through with all invitation paths validated).

The interface surface between TENANT-ADMIN-001 and TENANT-ACCESS-001
is: `TenantAdminAuthority` (the dataclass returned by
`check_tenant_admin_authority`). Any TENANT-ACCESS-001 route can take
`Depends(require_tenant_admin())` to receive the same DB-canonical
authority proof.

---

## Files delivered

- `api/tenant_admin_authority.py` — authority module (checks, ceilings).
- `api/tenant_admin.py` — router (7 endpoints).
- `api/identity/store.py` — 5 new events in `IDENTITY_AUDIT_EVENTS`.
- `api/main.py` — router registration in both dev and prod app builders.
- `tests/test_tenant_admin_001.py` — 63 tests across 14 groups (A–N).
- `docs/architecture/tenant-admin-001.md` — this document.
