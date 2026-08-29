# TENANT-ACCESS-001 — Unified Tenant Console + Portal Access Enforcement

**Status:** Implementing
**Branch:** `feat/tenant-access-001-unified-access-enforcement`
**Predecessors:** TENANT-ADMIN-001 (PR #664)
**Successor:** CLIENT-E2E-001

---

## Purpose

Define and enforce the complete access boundary for every principal type
that interacts with FrostGate across the Console BFF, Portal, and Core
API surfaces.

Business objective:

> No actor — human or machine — can access any FrostGate surface unless
> ALL layers of the canonical authorization chain have independently
> confirmed that actor's identity, membership, and capability for the
> specific tenant and surface being accessed.

Non-negotiable properties:

1. **JWT role claims are advisory, not canonical.** Every authorization
   decision performs a fresh SELECT against `tenant_users` inside the
   current request's DB session. JWT claims drive UX routing only.
2. **Principal lifecycle is enforced at every layer.** `fg_principals.lifecycle_state='active'`
   is checked at principal resolution; `tenant_users.active=TRUE` and
   `identity_binding_status='bound'` are checked at membership resolution.
3. **Tenant context is enforced at three layers before route body.** Key-bound
   tenant, actor session tenant, and route-path tenant must all agree.
4. **Console and portal are distinct authorization surfaces.** A console
   `tenant_admin` is not automatically a portal grantee. Portal grants
   are managed independently via the credential authority.
5. **Cross-tenant denial is uniform and non-oracle.** All cross-tenant
   scenarios surface the same 403 — no information about the existence
   or shape of other tenants.
6. **Revocation is immediate.** Deactivating or downgrading a membership
   takes effect on the next request; JWT expiry is irrelevant to the
   DB-canonical check.
7. **RLS is a defense-in-depth layer, not the primary gate.** Every
   route enforces tenant context via application logic before any query
   runs; RLS provides a second independent enforcement.
8. **No authority is inferred from JWT roles.** `platform_admin` cannot
   be claimed by forging a JWT; every platform-authority check reads
   from `tenant_users` or requires an explicit API-key with the bound
   `platform.admin` permission.

---

## Access-Decision Diagram

```
HTTP request arrives
  │
  ▼
[1] AuthGateMiddleware
    → API key OR Bearer JWT (RS256, JWKS) OR dev-bypass
    → ActorContext populated: subject, email, roles (advisory), auth_source
    → FAIL: 401

  │ (OIDC actors only)
  ▼
[2] _bind_membership()  (api/auth_dispatch.py)
    → SELECT tenant_users WHERE principal_id = ? AND active AND bound
    → ActorContext.membership_id populated
    → FAIL: 403 MEMBERSHIP_NOT_FOUND / MEMBERSHIP_INACTIVE

  │
  ▼
[3] require_scopes(...)  (coarse scope gate)
    → e.g. admin:read, admin:write
    → FAIL: 403 scope mismatch

  │
  ▼
[4] require_permission(...)  (permission gate from roles → ROLE_PERMISSIONS map)
    → FAIL: 403 PERMISSION_DENIED

  │
  ▼
[5] resolve_authoritative_tenant(request, actor_ctx, tenant_id)
    → bind_tenant_id(): key-bound tenant == route tenant
    → explicit actor_ctx.tenant_id cross-check if present
    → emits STALE_TENANT_SESSION audit event on mismatch
    → FAIL: 403 tenant mismatch

  │ (tenant-admin routes only)
  ▼
[6] check_tenant_admin_authority(db, actor_ctx, tenant_id)
    → fresh SELECT: role='tenant_admin' AND active AND bound AND principal_id NOT NULL
    → FAIL: 403 TENANT_ADMIN_DENIED (uniform — no oracle differentiation)

  │
  ▼
[7] Route body executes
    → set_tenant_context(db, tenant_id)  — app.tenant_id for RLS
    → Business logic runs inside tenant RLS context
    → DB: Postgres row-level security enforces tenant isolation at query level

  │ (portal surface only, parallel track)
  ▼
[Portal] PortalClientScopeMiddleware
    → Validates pnu1. token on every portal path
    → Named-user: membership_version checked against DB (stale detection)
    → Grant-user: portal_grant_svc.validate_session() with tenant+engagement binding
    → FAIL: 401/403 SESSION_REVOKED_VERSION_MISMATCH / GRANT_INVALID

  │ (Console BFF, parallel track)
  ▼
[Console] resolveConsolePrincipal()  (apps/console/lib/consoleAccess.js)
    → Reads roles from JWT claims (multiple namespaces)
    → Classifies experienceClass: internal_console | console_enabled_client |
      portal_only | unsupported | anonymous
    → canAccessConsoleRoute(): CONSOLE_ROUTE_AUDITS allowedRoles check
    → canAccessCoreApiPath(): CORE_API_POLICIES allowedRoles check
    → resolveAuthorizedTenant(): internal_console → any tenant;
      console_enabled_client → own claims.tenantId only
    → FAIL: 403 CORE_ACCESS_DENIED (normalized)

──── TENANT-ACCESS-001 boundary ──────────────────────────────────
  ALLOW: principal_id + tenant_id + resource + capabilities + surface
  ▼
[Future] Data Classification / DLP
[Future] Regulatory Policy (HIPAA / SOC 2 / FINRA / state privacy)
[Future] Model / Provider Eligibility
[Future] Tool / Egress Policy
[Future] Output DLP
[Future] Evidence
──── (out of scope for this PR — see Section 19) ─────────────────
```

---

## 1. Authentication Authority

Implemented in `api/auth_dispatch.py`.

Resolution order (first match wins):

1. **Dev bypass** — `FG_DEV_TOKEN` header in development mode only.
   Never active in production.
2. **Bearer JWT** — RS256, validated against Auth0 JWKS. Claims extracted
   for advisory UX routing. Membership binding runs post-validation.
3. **API key** — `X-API-Key` header. Looked up in `tenant_credentials`
   table; provides `tenant_id` binding and explicit role list.
4. **Anonymous** — No credentials present. Routes gated behind any scope
   or permission deny the request.

**Auth boundary:** Authentication resolves WHO the actor is and WHAT
their advisory roles are. Authorization (layers 2–7 above) resolves
WHAT they may do.

---

## 2. Canonical Principal Authority

Implemented in `api/principal_authority.py`.

`resolve_or_create_principal_for_external_identity(db, provider, issuer, subject, email, name)`
→ `PrincipalResolution(principal_id, external_identity_id, created)`

- Queries `fg_principals` JOIN `fg_external_identities` by
  `(oidc_issuer, oidc_subject)`.
- Raises `PrincipalResolutionError(code="PRINCIPAL_INACTIVE")` if
  `fg_principals.lifecycle_state != 'active'`.
- Idempotent via `uq_fg_external_identities_binding` unique constraint;
  race-safe.

**Invariant:** A suspended or deactivated principal cannot resolve.
The principal layer is the first lifecycle gate.

---

## 3. Tenant Membership Authority

Implemented in `services/identity_resolver/service.py`.

`IdentityResolver.resolve_or_deny(db, provider, issuer, subject, tenant_id=None)`
→ `IdentityPrincipal`

SQL filter: `identity_binding_status = 'bound' AND active = TRUE`.

Raises:
- `IdentityResolutionError("MEMBERSHIP_NOT_FOUND")` — no matching row
- `IdentityResolutionError("MEMBERSHIP_INACTIVE")` — row exists but
  `active = FALSE` or `identity_binding_status != 'bound'`

**Invariant:** An actor whose DB membership is deactivated or whose
identity binding is revoked cannot proceed regardless of what their
JWT claims.

---

## 4. Capability Authority

Implemented in `api/actor_context.py` + `services/capability_bundles/`.

`ROLE_PERMISSIONS` maps canonical role strings to `frozenset[str]`
permission sets:

- `platform_admin` → `ALL_PERMISSIONS` (complete set)
- `tenant_admin` → `{admin:read, admin:write, user.invite, tenant.configure, ...}`
- `client_*` roles → read-only baseline (CLIENT-E2E-001 will refine)

`require_permission(perm)` FastAPI dependency: raises 403 if the
resolved `ActorContext.permissions` does not include `perm`.

**Capability layer is not tenant-scoped by itself.** The tenant-context
layer (layer 5) and DB-canonical checks (layer 6) add the tenant binding.

---

## 5. Tenant-Context Authority

Implemented in `api/auth_scopes/resolution.py`.

`resolve_authoritative_tenant(request, actor_ctx, tenant_id)` → `str`

Three independent checks in sequence:

1. `bind_tenant_id()` — API-key-bound tenant must equal route-path tenant.
   JWT actors pass through (no key binding).
2. If `actor_ctx.tenant_id` is present (non-None): must equal the
   route-path tenant. Mismatch emits `STALE_TENANT_SESSION` audit event
   and raises 403.
3. Returns the verified `tenant_id` string.

**STALE_TENANT_SESSION:** An actor whose session was issued for tenant A
cannot access tenant B's routes, even with a valid JWT. The session
tenant is resolved from the JWT `tenant_id` claim (Auth0 `app_metadata`)
at login time.

Admin gateway delegation: `_verify_delegation_proof()` validates the
HMAC delegation proof carried in request headers from the admin gateway.
`_verify_admin_gateway_tenant()` confirms the target tenant exists and is
`lifecycle_state='active'`.

---

## 6. Console Authority

Implemented in `apps/console/lib/consoleAccess.js` (runtime) and
`apps/console/app/api/core/[...path]/route.ts` (BFF).

### Experience Classification

`resolveConsolePrincipal(session)` → `ConsolePrincipal`

Experience classes:

| Class | Roles | Capability |
|-------|-------|-----------|
| `internal_console` | Administrator, Operator, CISO, Executive, Auditor, Developer, Support, Compliance, AssessmentEngineer, FieldAssessor, Consultant | Can act on any tenant via the BFF |
| `console_enabled_client` | tenant_admin, client_executive, client_compliance, client_auditor, client_remediation_owner, client_security_owner, client_read_only | Can act on own session `tenantId` only |
| `portal_only` | No console roles but valid session | Redirected to portal; cannot access console routes |
| `unsupported` | Authenticated but no recognized roles | Hard-denied at edge middleware |
| `anonymous` | No session | Redirected to login |

### Route Access

`canAccessConsoleRoute(principal, pathname)` — checks
`CONSOLE_ROUTE_AUDITS[path].allowedRoles` against principal roles.

`canAccessCoreApiPath(pathParts, method, session)` — checks
`CORE_API_POLICIES[prefix].allowedRoles`; also checks
`mutationRoles` for non-GET/HEAD methods.

### BFF Tenant Enforcement

`resolveAuthorizedTenant(session, tenantId)` in `route.ts`:

- `internal_console`: `tenantId` from query/path accepted unconditionally.
- `console_enabled_client`: only `claims.tenantId` (from JWT session) is
  accepted; cross-tenant access returns 403 `CORE_ACCESS_DENIED`.

### Tenant-Admin Paths

`isTenantAdminCorePath(pathParts)` → `true` for `admin/tenants/...` prefix.

Tenant-admin paths use:
1. Admin gateway token (not per-tenant API key).
2. HMAC delegation proof (`_buildDelegationProof()` in `route.ts`).
3. Core API validates proof in `_verify_delegation_proof()`.

All other paths use per-tenant API key from the tenant registry.

### Error Normalization

All 403 responses from Core API are normalized to `CORE_ACCESS_DENIED`
by the BFF. This prevents Core API internals from leaking through the
BFF layer. Callers must not bypass this normalization by calling Core
API directly.

---

## 7. Portal Authority

Implemented in `api/middleware/portal_scope.py` +
`api/portal_user_authority.py`.

### Token Prefixes

- `pni1.` — Portal invitation token (one-time use for named-user
  binding).
- `pnu1.` — Portal named-user session token (persistent per session).

### PortalClientScopeMiddleware

Validates ALL portal paths:

1. Extracts session token from cookie.
2. Decodes and verifies `pnu1.` token signature.
3. For named-user paths: checks `membership_version` against live DB
   (`tenant_users.membership_version`). Version mismatch → 401
   `SESSION_REVOKED_VERSION_MISMATCH`.
4. For legacy grant paths: `portal_grant_svc.validate_session()` with
   tenant + engagement binding. Grant revoked or expired → 403
   `GRANT_INVALID`.
5. Engagement binding: `named_result.engagement_id` must match the
   route's `engagement_id` path segment.

### Portal User Authority

`find_or_create_portal_user(db, tenant_id, oidc_issuer, oidc_subject, email, name)`
— UPSERT on `(tenant_id, oidc_issuer, oidc_subject)`. Raises
`PortalUserSuspendedError` if the portal user has been suspended.

`_set_tenant_rls(db, tenant_id)` — sets `app.tenant_id` for Postgres
RLS before any portal DB operations.

---

## 8. Object-Level Authority

Every query that fetches a resource scopes by both `tenant_id` AND the
route-path resource ID. This prevents IDOR (insecure direct object
reference):

- `SELECT … WHERE tenant_id = :t AND id = :id` — resource not found in
  this tenant returns 404 (not 403), preventing tenant oracle.
- Engagement access: portal sessions are bound to a specific
  `engagement_id`; cross-engagement access is blocked by the middleware
  binding check.
- `check_tenant_admin_authority()` verifies the actor is an admin of
  the route-path tenant before any object-level query runs.

**Exception to 404 pattern:** Cross-tenant admin operations return 403
`TENANT_ADMIN_DENIED` (not 404) to avoid leaking that the tenant
exists at all from an unauthorized actor's perspective.

---

## 9. Auth0 Projection Boundary

Auth0 is a **read-only projection target**, not an authorization source.

- Auth0 `app_metadata.roles` is populated by AUTH-ROLE-001B's outbox
  worker asynchronously. It may lag behind the DB state by up to one
  worker pass.
- The Console NextAuth JWT reads roles from `app_metadata` at login time.
  These are injected into session claims.
- Session claims drive **UX routing only** (experience class, sidebar
  visibility, console route guards). They are not used for any Core API
  authorization decision.
- Every Core API route performs a fresh DB SELECT and ignores the JWT
  role values entirely.

**Auth0 projection boundary invariant:** If Auth0 `app_metadata` is
stale, the user's UX experience may be incorrect, but they will be
denied by the DB-canonical layer (layers 3–6 above) on their next
request to a protected route.

---

## 10. Revocation Semantics

| Action | Effect | Latency |
|--------|--------|---------|
| Deactivate membership (`active=FALSE`) | `_bind_membership()` fails next request | Immediate (next request) |
| Downgrade role (e.g. tenant_admin → client_read_only) | `check_tenant_admin_authority()` fails next admin request | Immediate (next request) |
| Unbind identity (`identity_binding_status='unbound'`) | `resolve_or_deny()` fails next request | Immediate (next request) |
| Suspend principal (`lifecycle_state != 'active'`) | `resolve_or_create_principal_for_external_identity()` fails next request | Immediate (next request) |
| Bump membership_version | Portal named-user sessions fail on next portal request | Immediate (next request) |
| Revoke portal grant | `validate_session()` fails on next portal request | Immediate (next request) |
| Auth0 role claim stale | UX routing incorrect; DB-canonical gate still enforced | Eventual (one worker pass) |

**Key property:** Revocation does NOT require token invalidation, blocklists,
or sweep jobs. The DB state is checked on every request; the JWT is never
used as an authorization input.

---

## 11. Stale-Token Behavior

A valid, unexpired JWT can be presented by a principal whose DB state
has been revoked. The system handles this at multiple layers:

1. **Principal layer:** `lifecycle_state != 'active'` → 403
   `PRINCIPAL_INACTIVE`.
2. **Membership layer:** `active=FALSE` or `identity_binding_status!='bound'`
   → 403 `MEMBERSHIP_INACTIVE`.
3. **Tenant-context layer:** `actor_ctx.tenant_id` mismatch → 403 +
   `STALE_TENANT_SESSION` audit event.
4. **Tenant-admin layer:** DB row not `role='tenant_admin'` → 403
   `TENANT_ADMIN_DENIED`.
5. **Portal layer:** `membership_version` mismatch → 401
   `SESSION_REVOKED_VERSION_MISMATCH`.

A stale JWT is never sufficient to authorize a request against any of
these layers.

---

## 12. Tenant Switching

A `console_enabled_client` cannot switch tenants:

- Their session `tenantId` is resolved from `fg_principals.tenant_id`
  at login time via the Auth0 post-login action.
- `resolveAuthorizedTenant()` in the BFF enforces that only
  `claims.tenantId` is accepted for client sessions.
- `resolve_authoritative_tenant()` in Core API enforces that the
  actor's session tenant matches the route tenant.
- An actor who attempts to supply a different `tenant_id` in the query
  or path receives 403.

An `internal_console` principal can act on any tenant by specifying
the `tenant_id` in the path. This requires an Auth0 internal role AND
the correct admin gateway credentials.

**Tenant switching is not a supported user action.** The only valid
session change is logout + re-login. No "switch tenant" UI is provided.

---

## 13. RLS Defense

Row-Level Security is enforced at the Postgres layer as a defense-in-depth
mechanism.

`set_tenant_context(db, tenant_id)` in `api/db.py` calls:
```sql
SELECT set_config('app.tenant_id', :tenant_id, true)
```

RLS policies on `tenant_users`, `tenant_invitations`,
`tenant_identity_audit_events`, `identity_projection_outbox`, and all
FA tables use `current_setting('app.tenant_id', true)` to scope every
SELECT/INSERT/UPDATE/DELETE.

**Invariant:** No query can read or write another tenant's rows at the
Postgres level, even if the application layer has a bug that passes the
wrong `tenant_id`.

`assert_tenant_rls()` in `api/db_migrations.py` is the CI gate that
confirms all tables have RLS enabled.

---

## 14. Audit Behavior

Every authorization failure and cross-tenant attempt emits an
`tenant_identity_audit_events` row:

| Event | Trigger |
|-------|---------|
| `STALE_TENANT_SESSION` | `resolve_authoritative_tenant()` tenant mismatch |
| `MEMBERSHIP_INACTIVE` | `_bind_membership()` inactive membership |
| `MEMBERSHIP_NOT_FOUND` | `_bind_membership()` no membership row |
| `TENANT_ADMIN_DENIED` | `check_tenant_admin_authority()` any failure |
| `SESSION_REVOKED_VERSION_MISMATCH` | Portal membership_version mismatch |
| `tenant.admin.bootstrap` | Bootstrap admin endpoint called |
| `tenant.member.invited` | Console member invited |
| `tenant.member.updated` | Console member role/active updated |
| `tenant.portal_access.invited` | Portal grant created |
| `tenant.portal_access.revoked` | Portal grant revoked |

All events are:
- Hash-chained via `previous_event_hash` + `event_hash` (tamper-evident
  append-only chain).
- Filtered through the `safe_keys` allowlist — no secrets, tokens, or
  passwords can appear in `details_json`.
- Attributed to the authenticated actor (`actor_user_id` sourced from
  `ActorContext`, never from request body).

---

## 15. Failure Modes

| Scenario | HTTP | Code |
|----------|------|------|
| Missing/invalid credentials | 401 | Invalid or missing API key |
| Principal inactive | 403 | PRINCIPAL_INACTIVE |
| Membership not found | 403 | MEMBERSHIP_NOT_FOUND |
| Membership inactive | 403 | MEMBERSHIP_INACTIVE |
| Scope mismatch | 403 | scope mismatch |
| Permission denied | 403 | PERMISSION_DENIED |
| Route tenant ≠ key-bound tenant | 403 | tenant mismatch |
| Route tenant ≠ actor session tenant | 403 | tenant mismatch + STALE_TENANT_SESSION audit |
| Not a tenant admin | 403 | TENANT_ADMIN_DENIED |
| Cross-tenant admin attempt | 403 | TENANT_ADMIN_DENIED |
| Delegation ceiling exceeded | 403 | ROLE_NOT_DELEGATABLE |
| Self-escalation attempt | 403 | SELF_ESCALATION_DENIED |
| Bootstrap without platform.admin | 403 | PERMISSION_DENIED |
| IDOR: resource in wrong tenant | 404 | not found |
| Portal: stale session version | 401 | SESSION_REVOKED_VERSION_MISMATCH |
| Portal: revoked/expired grant | 403 | GRANT_INVALID |
| Portal: suspended portal user | 403 | PORTAL_USER_SUSPENDED |
| BFF: unauthorized Core API path | 403 | CORE_ACCESS_DENIED |
| BFF: portal_only session reaching console route | 403 | CORE_ACCESS_DENIED |
| BFF: client session reaching different tenant | 403 | CORE_ACCESS_DENIED |
| Internal error | 500 | INTERNAL_SERVER_ERROR (JSON, no stack trace) |

No stack traces, DB error messages, or internal field names are surfaced
to callers.

---

## 16. Threat Model

### Threats Addressed

| Threat | Mitigation |
|--------|-----------|
| Stale JWT presenting revoked role | DB-canonical check on every request |
| JWT forgery (alg:none, wrong key) | RS256 JWKS validation, no HS256 |
| Cross-tenant enumeration via route | `bind_tenant_id` + `resolve_authoritative_tenant` |
| Cross-tenant IDOR via object ID | All queries scope by `tenant_id AND id` |
| Portal session replay after revocation | `membership_version` check on every portal request |
| Portal grant escalation across engagements | Engagement binding in `PortalClientScopeMiddleware` |
| Tenant admin assigning internal roles | `FORBIDDEN_DELEGATION_ROLES` allowlist; `assert_role_delegatable()` |
| Tenant admin self-escalating | `SELF_ESCALATION_DENIED` on own membership mutations |
| Privileged principal bootstrapped by non-platform actor | `require_permission("platform.admin")` on bootstrap endpoint |
| SQL injection via tenant_id | Parameterized queries throughout; RLS adds defense layer |
| Console client accessing other tenant's data | `resolveAuthorizedTenant()` enforces `claims.tenantId` |
| Portal-only session reaching console paths | `canAccessConsoleRoute()` + `clientSafe: false` flag |
| Delegation proof forgery | HMAC-SHA256 proof validated by Core; secret never exposed to BFF |

### Residual Risks / Known Limitations

- **Auth0 role claim staleness:** Between a role downgrade and the Auth0
  projection completing, the user's JWT may still claim the old role.
  UX may show incorrect options, but all authorization decisions are
  DB-canonical and the stale claim has no security impact.
- **JWT expiry window:** A revoked user's JWT remains technically valid
  until expiry (15 minutes by default). The DB check denies them on
  every request, so the JWT expiry window has no practical security
  impact.
- **Anonymous engagement access:** Some portal paths that require an
  engagement ID allow access via a valid portal grant without named-user
  identity. This is intentional by design for the legacy portal grant
  model; named-user access is the preferred path.

---

## 17. Explicit Non-Goals

TENANT-ACCESS-001 does NOT:

- Replace Auth0 or any external identity provider.
- Replace canonical principals (`fg_principals`).
- Introduce a second RBAC engine.
- Add new invitation authority paths (that is P1-01 H2).
- Redesign the portal grant system (that is CLIENT-E2E-001).
- Provide a "switch tenant" UX feature.
- Weaken any existing scope, permission, capability, or RLS gate.
- Grant tenant admins any platform authority.
- Make JWT role claims canonical for any authorization decision.
- Remove or modify the delegation ceilings established by TENANT-ADMIN-001.
- Merge console and portal authorization surfaces.
- Add new DB tables or migrations.
- Provide a full client-onboarding proof (that is CLIENT-E2E-001).

---

## 18. CLIENT-E2E-001 Boundary

TENANT-ACCESS-001 establishes and documents the complete authorization
enforcement stack as it currently exists.

CLIENT-E2E-001 will build on this by:

1. **End-to-end client onboarding proof** — design partner walk-through
   validating all invitation paths from bootstrap through first portal
   session.
2. **Unified invitation authority** — consolidate `POST /admin/tenants/.../users/invite`,
   `POST /admin/identity/tenants/.../invitations`, and portal grant
   invite paths into one canonical flow (P1-01 H2 first PR).
3. **Named-user portal access in the Console** — a tenant_admin can
   manage their portal named-users from the Console UI alongside console
   users.
4. **`client_*` role permission refinement** — exact per-role permission
   sets (currently read-only baseline, marked CLIENT-E2E-001 in
   `actor_context.py`).
5. **`portal_only` experience class** — a client user who is a named-user
   portal grantee but has no console access should be onboarded via the
   portal flow; the Console redirects them without exposing console
   routes.

The interface surface between TENANT-ACCESS-001 and CLIENT-E2E-001 is:

- `ActorContext` — the resolved actor dataclass passed through every
  authorization layer.
- `check_tenant_admin_authority()` — the DB-canonical authority check
  used by all tenant-admin routes.
- `PortalClientScopeMiddleware` — the portal session validation
  middleware; CLIENT-E2E-001 may extend it for named-user invitation
  acceptance.
- `DELEGATABLE_ROLES` / `FORBIDDEN_DELEGATION_ROLES` — the static
  ceiling allowlists; CLIENT-E2E-001 may add new delegatable roles
  after explicit review.

---

## 19. Downstream Policy-Enforcement Boundary

**TENANT-ACCESS-001 ends at Resource Authorization.**

A successful result from `check_tenant_admin_authority()`, `resolve_authoritative_tenant()`,
or `PortalClientScopeMiddleware` means:

> The actor is authorized **to access the resource**.
> It does NOT mean the actor is authorized to transmit that resource's
> contents to an AI model, external provider, or egress channel.

The enforcement layers **downstream of TENANT-ACCESS-001** are:

```
[TENANT-ACCESS-001 ends here]
  │  ALLOW: principal_id, tenant_id, resource identity/ownership,
  │         capabilities, surface/purpose are now canonical
  ▼
Data Classification / DLP
  → Content inspection, PHI/PII detection, CUI marking
  → Scope: what data the resource contains
Regulatory Policy
  → HIPAA, SOC 2, FINRA, state privacy laws
  → Scope: what handling rules apply to the classified data
Model / Provider Eligibility
  → Which AI models/providers may process this data class
  → Tenant-configured routing constraints
Tool / Egress Policy
  → Which tools may operate on this data
  → Output format / redaction requirements
AI Execution
  → Guarded by all upstream layers
Output DLP
  → Re-inspect generated content before transmission
Evidence
  → Immutable audit record of the full chain
```

**Authorization context preserved for downstream consumers:**

The `ActorContext` dataclass (`api/actor_context.py`) exposes the
canonical fields that downstream DLP, regulatory-policy, and model
eligibility layers must consume:

| Field | Use |
|---|---|
| `principal_id` | Canonical identity; immutable across role/session changes |
| `tenant_id` | Tenant isolation; maps to tenant classification config |
| `permissions` | Capability set (read / write / export); governs DLP scope |
| `roles` | Advisory; downstream policy may use for content-routing rules |
| `auth_source` | Surface context (oidc_auth0 / api_key / portal / dev_bypass) |
| `membership_id` | Links to `tenant_users.role`; source of truth for capability class |

**Non-goals for this PR (preserved as future work):**

TENANT-ACCESS-001 explicitly does NOT implement, modify, or pre-empt:

- PHI / DOB / PII detection or redaction
- HIPAA, SOC 2, FINRA, or any regulatory compliance enforcement
- CUI marking or classification logic
- Financial instrument handling or data-residency rules
- AI model routing based on data classification
- Tool call egress filtering
- Output DLP / re-inspection pipelines
- Any data-residency or sovereign-cloud partition enforcement

These are deferred to the regulated-data track recorded in ROADMAP.md
(behind CLIENT-E2E-001, after a DLP/PHI controls audit to extend rather
than duplicate existing FrostGate controls).

**Invariant this PR must not break:**

No authorization shortcut in TENANT-ACCESS-001 may collapse the
`principal_id + tenant_id + resource + capability + surface` context
that downstream DLP layers require. Every `ALLOW` must carry canonical
context; no implicit or ambient grants that bypass this record.

---

## Files Delivered

- `tests/test_tenant_access_001.py` — comprehensive test suite: 93 passed
  across 23 groups (A–W) + authorization matrix.
- `apps/console/tests/console-access-policy.test.js` — 10 TENANT-ACCESS-001
  runtime behavior tests added to the existing JS test suite (31 total pass).
- `docs/architecture/tenant-access-001.md` — this document.
