# IA-0: Capability and Contract Audit

**Milestone:** IA-v1 / IA-0  
**Estimate:** 0.5 day  
**Status:** IN PROGRESS — inventory complete; ADR and Auth0 plan check pending  
**Exit criteria:** Auth0 plan capability confirmed; all integration points documented; ADR committed; no duplicate authorities introduced; no implementation started.

---

## 1. Auth0 Plan Capability Check

**Action required (operator, manual):** In the Auth0 dashboard for `dev-8rdpb1rmffldmj6w.us.auth0.com`:

- [ ] Navigate to **Organizations** in the sidebar.
- [ ] If Organizations is listed and accessible → record plan tier and proceed.
- [ ] If Organizations is absent or returns an upgrade prompt → **STOP**. IA-v1 cannot proceed without Organizations. Open a plan upgrade or re-scope IA-v1 to a non-Organizations architecture.

**Result:** _(fill in: plan tier, Organizations available Y/N)_

---

## 2. Auth0 M2M Application

**Action required (operator, manual):** Create a Machine-to-Machine application in Auth0:

- Name: `FrostGate Identity Authority`
- Authorize for the **Auth0 Management API** with least-privilege scopes only.

Minimal scope set for IA-v1 (confirm against Auth0 documentation before granting):

| Scope | Required for |
|-------|-------------|
| `create:organizations` | IA-1 client provisioning |
| `read:organizations` | IA-1 idempotency check, IA-4 reconciliation |
| `update:organizations` | IA-1 (enable connections) |
| `create:organization_members` | IA-2 membership |
| `delete:organization_members` | IA-3 suspend/offboard |
| `create:organization_invitations` | IA-2 invitation send |
| `delete:organization_invitations` | IA-2 revoke pending invite |
| `read:organization_invitations` | IA-2 status check |
| `create:organization_member_roles` | IA-2 role assignment mirror |
| `delete:organization_member_roles` | IA-3 role modification |
| `read:organization_member_roles` | IA-4 reconciliation |
| `read:users` | IA-2 lookup before invite (check if user exists) |

**Do not grant:**
- `delete:users` — use `block:users` if global disable is needed (IA-3)
- `update:clients`, `create:client_grants`, `update:client_grants` — highly privileged; not needed

**Result:** _(fill in: M2M Client ID noted; scopes confirmed)_

---

## 3. Existing Integration Point Inventory

*Completed by IA-0 research 2026-07-31. No further code reads required.*

### 3a. Console Tenant Provisioning (current state)

Flow: `POST /api/admin/provision-tenant` (console BFF)  
→ `POST /admin/tenants` (Core API — create tenant)  
→ `POST /admin/tenants/{id}/credentials` (Core API — issue BFF credential)  
→ Redis + Upstash persistence (portal auth key)

**No Auth0 interaction.** No organization is created. No invitation is sent.

IA-1 inserts Auth0 Organization creation as a new step after `POST /admin/tenants` succeeds and before the credential is issued.

### 3b. Portal Named-User Authority (current state)

**Function surface** (`api/portal_user_authority.py`):

| Function | Action | Tables written |
|----------|--------|---------------|
| `find_or_create_portal_user` | Upsert portal identity by OIDC sub | `portal_users` |
| `create_invitation` | Issue `pni1.` token | `portal_user_invitations` |
| `accept_invitation` | Consume invite; create user + membership | `portal_users`, `portal_user_memberships`, `portal_user_invitations` |
| `revoke_invitation` | pending → revoked | `portal_user_invitations` |
| `create_session` | Issue `pnu1.` token | `portal_user_sessions` |
| `validate_session` | Check fingerprint + auth_version | `portal_user_sessions` (last_validated_at) |
| `revoke_session` | by session_id | `portal_user_sessions` |
| `revoke_session_by_token` | by raw token (public path) | `portal_user_sessions` (SECURITY DEFINER) |

**Current invitation delivery gap**: `create_invitation` returns the raw `pni1.` token. No email is sent by the Core API. The console email route has no `portal_invite` type. Invitation URL must be manually constructed.

IA-2 adds Auth0 Organization invitation creation alongside FrostGate invitation creation, so Auth0 sends the invitation email through Auth0's own delivery.

### 3c. User / Membership / Role / Session Schema

**Tables relevant to IA-v1:**

| Table | Key columns | Lifecycle states | Notes |
|-------|-------------|-----------------|-------|
| `portal_users` | tenant_id, oidc_issuer, oidc_subject, email, status | active \| suspended \| deactivated | Unique on (tenant_id, oidc_issuer, oidc_subject) |
| `portal_user_invitations` | tenant_id, email, portal_role, engagement_id, token_fingerprint, status | pending \| accepted \| revoked \| expired | `idempotency_key` UNIQUE prevents re-issue |
| `portal_user_memberships` | portal_user_id, tenant_id, engagement_id, portal_role, auth_version, active | active (BOOL) | `auth_version` bump → immediate session revocation |
| `portal_user_sessions` | portal_user_id, tenant_id, token_fingerprint, auth_version_snapshot, status | active \| revoked \| expired | `revoke_session_by_token` is SECURITY DEFINER (bypasses RLS) |
| `portal_user_audit_events` | event_type (11 types), tenant_id, portal_user_id, outcome | append-only, UPDATE/DELETE forbidden by trigger | |
| `tenants` | tenant_id, display_name, lifecycle_state, tenant_kind | active \| (lifecycle states from migration 0157) | `tenant_kind`: customer \| internal_platform \| validation \| demo |
| `tenant_users` | tenant_id, email, role, identity_provider, identity_subject, identity_issuer | — | Workforce/operator identity; separate from portal_users |

### 3d. Existing Auth0 Schema Columns (unpopulated)

The following columns exist but contain no data and are not exercised by any active code path:

| Table | Column | Migration |
|-------|--------|-----------|
| `tenant_identity_configs` | `auth0_organization_id` (VARCHAR 256) | legacy |
| `tenant_identity_configs` | `auth0_connection_id` (VARCHAR 256) | legacy |
| `tenant_identity_providers` | `organization_id` (VARCHAR 256) | legacy |
| `tenant_identity_providers` | `connection_id` (VARCHAR 256) | legacy |
| `tenant_invitations` | `auth0_invitation_id` (VARCHAR 256) | legacy |

**IA-1 decision**: Use the new `tenant_identity_bindings` table (per spec) as the authoritative binding record. The legacy columns above become read-only archaeological artifacts until deprecated and dropped in a future cleanup migration.

### 3e. Auth0 Integration Points (current state)

| Component | What it does | Management API? |
|-----------|-------------|-----------------|
| `api/identity_authority/providers/auth0_provider.py` | JWKS fetch + RS256 JWT validation | No — read-only OIDC |
| `api/identity_providers/auth0.py` | Legacy JWKS validation (superseded) | No |
| Console NextAuth | Console operator login via Auth0 OIDC | No |
| Portal OIDC routes | Token exchange, code verifier, session issuance | No |

**Zero Management API calls exist anywhere in the codebase.** IA-v1 introduces the first.

---

## 4. Lifecycle State Definition

Stable lifecycle states to be used uniformly across IA-v1:

### Client tenant

| State | Meaning |
|-------|---------|
| `provisioning` | FrostGate tenant created; Auth0 Organization creation in flight |
| `active` | Both FrostGate tenant and Auth0 Organization confirmed active |
| `suspended` | Tenant suspended; all memberships inaccessible; Auth0 Organization disabled |
| `provisioning_failed` | Auth0 Organization creation failed; tenant not advertised as ready |
| `offboarded` | Tenant offboarded; memberships revoked; Auth0 Organization removed |

### Portal user invitation

*(existing states retained)*: `pending` → `accepted` | `revoked` | `expired`

### Portal user membership

| State | Meaning |
|-------|---------|
| `active` | Membership valid; portal access permitted |
| `suspended` | Membership suspended by operator; portal sessions revoked; Auth0 org membership removed |
| `revoked` | Membership permanently revoked; cannot be reactivated |
| `offboarded` | User offboarded from client; same as revoked at membership level |

### Portal session

*(existing states retained)*: `active` → `revoked` | `expired`

---

## 5. Idempotency and Compensation

### IA-1 (client organization provisioning)

| Operation | Idempotency key | Compensation on failure |
|-----------|----------------|------------------------|
| Create Auth0 Organization | `tenant_id` → `create:organizations` | If Auth0 fails → set `tenant_identity_bindings.provisioning_state = 'provisioning_failed'`; do not advertise tenant as active |
| Persist binding | DB `UNIQUE (tenant_id, provider)` | On conflict → update if in-progress |
| Auth0 org already exists | `organizations/{id}` read | Return existing binding (idempotent) |

### IA-2 (invitation)

| Operation | Idempotency key | Compensation |
|-----------|----------------|--------------|
| Create FrostGate invitation | `portal_user_invitations.idempotency_key` | On conflict → return existing invitation |
| Create Auth0 Organization invitation | Auth0 correlation ID sent as header | If Auth0 fails after FG invite created → mark FG invite as `auth0_pending`; operator retries |
| Accept invitation | `SELECT FOR UPDATE` on invitation row | CAS: if already `accepted`, return existing membership |

---

## 6. ADR — FrostGate/Auth0 Authority Boundaries

**ADR-IA-001: FrostGate is RBAC authority; Auth0 is authentication and organization-membership mirror**

**Status:** Proposed (pending operator approval)

**Context:**  
FrostGate already owns the full credential, session, membership, and audit lifecycle. Auth0 currently provides only OIDC token validation (JWKS/RS256). IA-v1 extends Auth0's role to include client-scoped authentication context (Organizations) and invitation email delivery, without ceding any authorization or lifecycle authority to Auth0.

**Decision:**

| Concern | Authority | Rationale |
|---------|-----------|-----------|
| Authentication | Auth0 | Auth0 issues JWTs; FrostGate validates them |
| Client tenant | FrostGate | `tenants` table is canonical; Auth0 Organization is a mirror |
| User lifecycle intent | FrostGate Console | Operator actions in Console trigger Auth0 side-effects |
| Tenant membership | FrostGate, mirrored to Auth0 Organization | FrostGate is authoritative; Auth0 membership scopes login context |
| RBAC and permissions | FrostGate | `portal_role` in `portal_user_memberships` is canonical; Auth0 org-member roles are a coarse mirror only |
| Organization login context | Auth0 | Auth0 Organization controls which connection a user logs in through |
| Portal sessions | FrostGate | `pnu1.` tokens + `portal_user_sessions` table; Auth0 session management APIs not depended on |
| Audit evidence | FrostGate | `portal_user_audit_events` is the evidence record; Auth0 logs are supplementary |
| User profile basics | Auth0, referenced by FrostGate | `oidc_subject` from Auth0 JWT; FrostGate stores only the binding, not a copy |

**Consequences:**

- Auth0 role changes do not propagate to FrostGate permissions without an explicit FrostGate operation.
- FrostGate session revocation does not depend on Auth0 session management endpoints (avoids Enterprise plan dependency).
- Drift between FrostGate membership and Auth0 Organization membership is expected and managed by the IA-4 reconciliation detector.
- Auth0 Organization deletion does not trigger FrostGate tenant lifecycle changes automatically in v1.

**Rejected alternatives:**

- Auth0 as sole RBAC source: rejected — Auth0 org-member roles are contextual and insufficient for FrostGate's permission graph.
- Per-client Auth0 tenants: rejected — operational cost; not in IA-v1 scope.
- SCIM sync: rejected — too complex; not in IA-v1 scope.

---

## 7. Exit Criteria

- [ ] Auth0 Organizations availability confirmed (manual, §1).
- [ ] Auth0 M2M application created with documented least-privilege scopes (manual, §2).
- [ ] All integration points documented (complete — §3).
- [ ] Lifecycle states defined (complete — §4).
- [ ] Idempotency and compensation behavior defined (complete — §5).
- [ ] ADR written and reviewed (complete — §6; pending operator approval).
- [ ] No implementation started.
- [ ] No duplicate user or tenant authorities introduced (confirmed — portal_users and tenant_users remain separate authorities; new tenant_identity_bindings table does not duplicate tenants).

**IA-0 is COMPLETE when all boxes above are checked and this document is committed to main.**
