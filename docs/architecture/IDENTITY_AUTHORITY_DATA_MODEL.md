# FrostGate Identity Authority Data Model

**Status:** FROZEN — do not change without explicit architectural decision  
**Supersedes:** ad-hoc identity schema decisions across migrations 0068–0178  
**Blocks:** PR-SEC-001, PR-AUTH-001, PR-AUTH-002, PR-AUTH-003, PR-CORE-001 through PR-CORE-005  
**Do not implement any PR in the auth/identity track without consulting this document first.**

---

## Purpose

This document answers the nine open questions left by the architecture audit before any
implementation begins. It defines the canonical target schema, maps every existing table
to its target role, specifies migration rules, states ownership boundaries, and enumerates
the invariants every PR must preserve.

The goal is to stop exploratory implementation. After this document, each PR is a
deterministic step toward a known target — not a local decision that may contradict
another PR written the same week.

---

## Nine Questions Answered

### 1. Which existing table becomes the canonical Principal?

`tenant_users` is **not** the canonical Principal. It is a Principal-Membership hybrid.
The canonical Principal is a **new table** `fg_principals`.

Rationale: `tenant_users` was designed per-tenant — it has a `tenant_id` column and
per-tenant RLS. A Principal that exists across multiple tenants cannot be represented
without duplicating rows and violating the global unique index on
`(identity_provider, identity_issuer, identity_subject)`. The two concepts must
be separated.

### 2. Whether `tenant_users` becomes Membership or remains a user-membership hybrid?

`tenant_users` becomes **Membership** — the record of a Principal's authorization within
one Tenant. The identity columns (`identity_provider`, `identity_issuer`,
`identity_subject`, `identity_binding_status`, and related fields) are **deprecated in
place**. They are not dropped immediately; they remain for the migration window and for
the `uq_tenant_users_bound_identity` index to stay valid during that window. They are
declared shadow authorities after cutover (see section 8).

A `principal_id` FK column is added to `tenant_users` via migration. Once all rows are
backfilled, `(tenant_id, principal_id)` becomes the membership identity — not the
identity columns.

### 3. Where does ExternalIdentity(provider, subject) live?

A **new table** `fg_external_identities`. It holds the immutable `(provider,
provider_issuer, provider_subject)` triple plus a `principal_id` FK. The global unique
constraint moves from `tenant_users` to this table. `tenant_users.identity_*` columns
become non-authoritative after backfill.

### 4. Whether `membership_version` can become the canonical `authority_version`?

Yes, with a rename. `tenant_users.membership_version` (BIGINT, added in migration 0117)
is already bumped on membership-relevant changes. It becomes `authority_version` in the
target schema — same column, renamed and given a documented increment contract.

Similarly `tenants.canonical_version` (INTEGER, added in migration 0156) becomes
`tenants.authority_version`. The column exists; only the contract changes: it must be
incremented whenever any membership or role within the tenant changes, so BFF
version-check logic can detect stale sessions.

### 5. Whether tenant lifecycle needs its own authority version?

`tenants.authority_version` (= current `canonical_version`) covers both: lifecycle state
changes AND membership/role changes cascade through it. The BFF checks one value per
tenant per request. One counter is sufficient.

Increment triggers for `tenants.authority_version`:
- `tenant_users.active` changed for any membership in the tenant
- `tenant_users.role` changed for any membership in the tenant
- `tenants.lifecycle_state` changed
- Any `tenant_users.identity_binding_status` changed to `bound` or `disabled`

### 6. How do service principals fit the same authority model without pretending they are humans?

Service principals stay in `platform_service_principals`. They are **not** merged into
`fg_principals`. The two models share no table.

Human principal auth path:
```
fg_external_identities → fg_principals → tenant_users (membership) → role → capability
```

Service principal auth path:
```
platform_service_principals → credential (fgk.) → explicit scope list → capability
```

The auth gate (`auth_gate.py`) already routes these separately. PSP credentials resolve
to a `ServiceActorContext`; human JWT/API-key credentials resolve to a
`HumanActorContext`; FrostGate operator sessions resolve to an `OperatorActorContext`.
The mandatory `actor_kind` field is the discriminator — see the ActorContext union
definition in the Authority Graph section.

### 7. Which of the three invitation systems survives?

**Flow B** (`admin_identity.py` + `TenantInvitation` in `tenant_invitations`) is the
canonical system. The `TenantInvitation` ORM model (`db_models_identity.py`) and its
migrations (0099, 0176) define the authoritative invitation lifecycle.

Flow A (`identity_administration/*` in-memory) → **RETIRE**. Wire a DB adapter that
writes to `tenant_invitations`. Delete the in-memory repositories after the adapter is
proven.

Flow C (`workforce.py` POST `/workforce/users`) → **MIGRATE** to a thin wrapper over
Flow B. It currently writes both `tenant_users` and `tenant_invitations`; after the
Principal/Membership split, it should create a `tenant_invitations` row via Flow B and
defer `tenant_users` row creation to invitation acceptance.

Flow D (portal) → **KEEP** unchanged. `portal_users` is a separate principal model for
portal-only users with its own session model (`pnu1.` tokens). It does not intersect
with the human Console principal model.

### 8. What data must be migrated versus derived?

**Must be migrated (explicit data movement):**
- Each unique `(identity_provider, identity_issuer, identity_subject)` triple in
  `tenant_users` where `identity_binding_status = 'bound'` → one row in
  `fg_principals` + one row in `fg_external_identities`.
- `tenant_users.id` for each row → `tenant_users.principal_id` FK populated with the
  derived `fg_principals.id`.
- `membership_version` column renamed to `authority_version` (ALTER COLUMN or
  application-level alias).
- `tenants.canonical_version` → declared as `authority_version` in contract (same
  column; no data movement needed).

**Can be derived (no explicit migration):**
- `fg_principals.primary_email` — derived from `tenant_users.email` at backfill time
  (use any row's email for a given principal; email is an attribute, not identity).
- `fg_principals.lifecycle_state` — derived from `tenant_users.active` across all
  memberships (if any membership is active, principal is active).
- `tenant_users.authority_version` initial value — derived from current
  `membership_version` value (already set to 1 for all rows by migration 0117).

**Must be dropped / declared shadow after cutover (see section 8):**
- `tenant_users.identity_provider`, `identity_issuer`, `identity_subject`,
  `identity_binding_status`, and related columns — not dropped until all callers
  use `principal_id` exclusively.
- `uq_tenant_users_bound_identity` partial index — replaced by
  `uq_fg_external_identities_binding` on `fg_external_identities`. Drop only after
  backfill is verified.

### 9. Which tables become forbidden/shadow authorities after cutover?

**Forbidden (must not be written or read for authorization after cutover):**
- `identity_administration/*` in-memory repositories — zero durability; retire entirely.
- JWT `{namespace}/tenant_id` claim as authoritative tenant source — replaced by Core
  membership lookup at session issuance.
- JWT `{namespace}/roles` claim as authoritative role source — replaced by Core
  `tenant_users.role` at session issuance.
- `tenant_users.identity_*` columns for authorization decisions — replaced by
  `principal_id FK → fg_external_identities`.
- `legacy_internal` experience class in Console session — must not exist in production.
- `legacy_console_user` role — must not appear in any role set.
- Scope `"*"` on any credential — forbidden after operator credential re-issuance.

**Shadow (present in DB, not authoritative, pending cleanup):**
- `tenant_users.identity_provider`, `identity_issuer`, `identity_subject`,
  `identity_binding_status` columns — kept during migration window; not read for
  authorization once `principal_id` is populated.
- `auth0.app_metadata` fields (`fg_principal_id`, etc.) — written for debugging only,
  never read as authorization input by Core.
- `uq_tenant_users_bound_identity` partial index — shadow during migration; dropped
  after `fg_external_identities` unique constraint is proven.

---

## Current Schema — Annotated

### `tenants` (migration 0156, 0166, 0167)

| Column | Type | Authority status |
|---|---|---|
| `tenant_id` | TEXT PK | **CANONICAL** — immutable slug |
| `lifecycle_state` | TEXT | **CANONICAL** — checked per-request |
| `tenant_kind` | TEXT | **CANONICAL** — `customer \| internal_platform \| validation \| demo` |
| `canonical_version` | INTEGER DEFAULT 1 | **CANONICAL** — becomes `authority_version` |
| `display_name`, `metadata` | TEXT/JSON | Attribute |

No `principal_id`. No `authority_version` by name (exists as `canonical_version`).
RLS: none on `tenants` — operator-only table, no tenant-scoped policy needed.

### `tenant_users` (migrations 0068, 0099, 0117)

| Column | Type | Authority status |
|---|---|---|
| `id` | TEXT PK | **CANONICAL** membership ID |
| `tenant_id` | TEXT NOT NULL | **CANONICAL** FK to tenants |
| `email` | TEXT NOT NULL | Attribute (not identity key) |
| `role` | TEXT | **CANONICAL** for authorization |
| `active` | BOOLEAN | **CANONICAL** — membership active state |
| `identity_provider` | TEXT | **SHADOW after cutover** — move to `fg_external_identities` |
| `identity_issuer` | TEXT | **SHADOW after cutover** |
| `identity_subject` | TEXT | **SHADOW after cutover** |
| `identity_binding_status` | TEXT | **SHADOW after cutover** |
| `identity_email` | TEXT | Attribute, shadow |
| `membership_version` | BIGINT DEFAULT 1 | **CANONICAL** — rename to `authority_version` |
| `invite_token` | TEXT UNIQUE | **SHADOW** — legacy invite mechanism, replaced by `tenant_invitations` |
| `principal_id` | UUID | **DOES NOT EXIST YET** — to be added |

Critical constraint: `uq_tenant_users_bound_identity` on
`(identity_provider, identity_issuer, identity_subject) WHERE identity_binding_status='bound'`
is **global** (no `tenant_id`). This blocks multi-tenant users. The constraint moves to
`fg_external_identities` after migration.

RLS: `tenant_id = current_setting('app.tenant_id', TRUE)`.

### `tenant_invitations` (ORM: `TenantInvitation`, migrations 0099, 0176)

| Column | Authority status |
|---|---|
| `id` | Canonical invitation ID |
| `tenant_id`, `membership_id` | Canonical scope |
| `status` | Canonical lifecycle: `pending → auth_started → accepted_identity_pending_binding → bound → expired/revoked/failed` |
| `email`, `normalized_email` | Attribute |
| `role` | Role grant at acceptance |
| `required_provider`, `required_connection_id` | IdP routing hint |
| `auth0_invitation_id` | Mirror for Auth0 org invitation (not authoritative) |
| `expires_at`, `revoked_at`, `accepted_at`, `bound_at` | Lifecycle timestamps |

RLS: `tenant_id = current_setting('app.tenant_id', TRUE)`.

This is the **canonical invitation table**. All three invitation flows must write here.

### `tenant_identity_configs` (ORM: `TenantIdentityConfig`)

Single row per tenant. Holds IdP routing configuration. `auth0_organization_id`,
`auth0_connection_id` are used for routing only — not for authorization. Not a
membership table. **KEEP** unchanged.

### `tenant_identity_bindings` (migration 0169)

IdP org-level binding (one per `(tenant_id, provider)` pair). Records the FrostGate ↔
Auth0 org provisioning state. Not a per-user table. **KEEP** unchanged.

### `tenant_credential_roles` (migration 0177)

Single active role per `(tenant_id, credential_id)`. Partial unique index on
`revoked_at IS NULL`. **CANONICAL** for API key / service credential authorization.
**KEEP** unchanged.

### `platform_service_principals` (migration 0168)

Machine identity table. `authority_version INTEGER DEFAULT 1` already exists. Explicit
`granted_permissions` field. Separate auth path from human principals. **KEEP** as
canonical service identity — do not merge with `fg_principals`.

### `identity_administration/*` in-memory models

`IdentityRecord`, `Invitation`, `Group`, `GroupMember`, `AdminAuditRecord` — all
in-memory. **RETIRE**. No migration needed — no data to move.

---

## Target Schema

### NEW: `fg_principals`

```sql
CREATE TABLE fg_principals (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name     TEXT,
    primary_email    TEXT,                    -- attribute only; not an identity key
    principal_type   TEXT        NOT NULL DEFAULT 'human'
                                 CHECK (principal_type IN ('human')),
    lifecycle_state  TEXT        NOT NULL DEFAULT 'active'
                                 CHECK (lifecycle_state IN ('active', 'suspended', 'deactivated')),
    mfa_verified     BOOLEAN     NOT NULL DEFAULT FALSE,
    authority_version BIGINT     NOT NULL DEFAULT 1,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- No RLS: principal table is not tenant-scoped.
-- Row-level isolation is enforced through the tenant_users membership, not here.
```

**Increment contract for `authority_version`:**
- Incremented when `lifecycle_state` changes.
- Does NOT cascade to tenant-level `authority_version` directly — the tenant version
  is incremented separately when a membership's `active` state or `role` changes.

**Ownership:** Core identity service only. No direct write from Console BFF.

### NEW: `fg_external_identities`

```sql
CREATE TABLE fg_external_identities (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id       UUID        NOT NULL REFERENCES fg_principals(id),
    provider           TEXT        NOT NULL
                                   CHECK (provider IN ('auth0', 'entra', 'okta', 'saml', 'oidc_generic')),
    provider_issuer    TEXT        NOT NULL,   -- OIDC issuer URL; Auth0 domain for auth0 provider
    provider_subject   TEXT        NOT NULL,   -- sub claim; immutable per IdP account
    provider_email     TEXT,                   -- attribute; may change; not an identity key
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at       TIMESTAMPTZ,
    CONSTRAINT uq_fg_external_identities_binding
        UNIQUE (provider, provider_issuer, provider_subject)
);

CREATE INDEX ix_fg_external_identities_principal ON fg_external_identities (principal_id);
```

**Authority rule:** `(provider, provider_issuer, provider_subject)` is the immutable
identity key. `provider_email` is an attribute — it may change and must not be used as
a lookup key for authorization.

**Lookup path at session issuance:**
```
Auth0 token sub claim
  → SELECT * FROM fg_external_identities
    WHERE provider = 'auth0'
      AND provider_issuer = $issuer
      AND provider_subject = $sub
  → returns principal_id
  → SELECT * FROM tenant_users WHERE principal_id = $principal_id AND active = TRUE
  → returns membership(s)
```

**Ownership:** Written only during invitation binding. Not writable from Console or BFF.

### EXTENDED: `tenant_users` (becomes Membership)

New columns added via migration, existing identity columns deprecated:

```sql
-- Add principal_id FK (migration 0179)
ALTER TABLE tenant_users
    ADD COLUMN IF NOT EXISTS principal_id UUID REFERENCES fg_principals(id);

-- Rename membership_version → authority_version (migration 0180)
-- Option A: rename column
ALTER TABLE tenant_users RENAME COLUMN membership_version TO authority_version;
-- Option B: add alias column, backfill, deprecate old (lower risk for callers)

-- New unique constraint after principal_id is populated (migration 0181)
CREATE UNIQUE INDEX uq_tenant_users_principal_membership
    ON tenant_users (tenant_id, principal_id)
    WHERE active = TRUE AND principal_id IS NOT NULL;
```

**Post-migration column states:**

| Column | State | Notes |
|---|---|---|
| `id` | CANONICAL | Membership ID, unchanged |
| `tenant_id` | CANONICAL | Unchanged |
| `role` | CANONICAL | `user \| admin \| auditor` |
| `active` | CANONICAL | Membership active state |
| `authority_version` | CANONICAL | (= renamed `membership_version`) |
| `principal_id` | CANONICAL (after backfill) | FK to `fg_principals` |
| `identity_provider` | SHADOW | Deprecated after backfill; not read for auth |
| `identity_issuer` | SHADOW | Same |
| `identity_subject` | SHADOW | Same |
| `identity_binding_status` | SHADOW | Same |
| `identity_email` | ATTRIBUTE | Not identity key |
| `invite_token` | SHADOW | Legacy; nulled on binding |
| `membership_version` | SHADOW | Renamed; kept for migration compatibility |

**RLS:** unchanged — `tenant_id = current_setting('app.tenant_id', TRUE)`.

**Membership state model:**

`tenant_users` rows represent only realized memberships — states where an identity has
been successfully bound to a tenant. Pre-acceptance states (INVITED,
BINDING_IN_PROGRESS) live entirely on `tenant_invitations`. A `tenant_users` row is
created exactly once: at the moment identity binding completes successfully, atomically
with populating `tenant_invitations.membership_id`.

| Condition | Effective state |
|---|---|
| `active = TRUE`, `principal_id IS NOT NULL` | ACTIVE |
| `active = FALSE`, `principal_id IS NOT NULL` | SUSPENDED |
| `identity_binding_status = 'disabled'` (shadow column, checked during migration window) | REVOKED |

Pre-acceptance lifecycle lives on `tenant_invitations.status`:

| `tenant_invitations.status` | Meaning |
|---|---|
| `pending` | Invitation created; user has not yet acted |
| `auth_started` | User is authenticating at IdP |
| `accepted_identity_pending_binding` | Auth complete; Core binding in progress |
| `bound` | Binding succeeded; `tenant_users` row exists; `membership_id` populated |
| `expired` | TTL elapsed before acceptance |
| `revoked` | Admin cancelled before acceptance |
| `failed` | Binding error; invitation is non-recoverable |

`tenant_invitations.membership_id` is NULL until status reaches `bound`. It is
populated atomically in the same transaction that inserts the `tenant_users` row.
This FK is the canonical link between invitation intent and realized membership
authority. An invitation with `status != 'bound'` grants no authority, regardless of
what the user has done on the Auth0 side.

### EXTENDED: `tenants` (authority_version)

```sql
-- canonical_version already exists (migration 0156) — declare it as authority_version
-- No column rename needed; application code uses it under the contract below.
-- A view alias may be added for clarity without a schema change.
COMMENT ON COLUMN tenants.canonical_version IS
    'Tenant authority version. Increment on: lifecycle_state change, any membership '
    'active/role/binding_status change in this tenant. Used by BFF session staleness check.';
```

**Increment contract for `tenants.canonical_version` (authority_version):**
- `tenants.lifecycle_state` changes → increment.
- Any `tenant_users` row in this tenant: `active`, `role`, `identity_binding_status`,
  or `principal_id` changes → increment tenant version.
- Implemented as: application service call or DB trigger on `tenant_users`.

**BFF staleness check:** On every proxied request, the BFF reads
`SELECT canonical_version FROM tenants WHERE tenant_id = $1`. If this value > the
`tenant_authority_version` snapshot in the session token, the BFF re-issues the
session against the Core identity resolve endpoint before proceeding.
30-second application-level cache is acceptable (resolves within one cache TTL).

---

## Current → Target Mapping

| Current | Role | Target | Migration action |
|---|---|---|---|
| `tenant_users` | Principal-Membership hybrid | `tenant_users` as Membership + `fg_principals` + `fg_external_identities` | Add `principal_id` FK; backfill; deprecate identity columns |
| `tenant_users.membership_version` | Authority version for membership | `tenant_users.authority_version` | Rename column (or alias) |
| `tenant_users.identity_*` columns | Identity binding | `fg_external_identities` | Migrate to new table; deprecate in `tenant_users` |
| `uq_tenant_users_bound_identity` index | Global identity uniqueness | `uq_fg_external_identities_binding` | Move constraint; drop old index post-backfill |
| `tenants.canonical_version` | Tenant authority version | `tenants.canonical_version` (contract updated) | Document increment contract; no column change |
| `tenant_invitations` | Canonical invitation | Unchanged (Flow B canonical) | Wire Flow A and C to write here |
| `identity_administration/*` in-memory | Shadow invitation system | Retired | Wire DB adapter; delete in-memory code |
| `workforce.py` invitation (Flow C) | Duplicate invitation path | Thin wrapper over Flow B | Remove direct `tenant_users` row creation; delegate to Flow B |
| `platform_service_principals` | Machine identity | Unchanged | Keep; no merge with `fg_principals` |
| `tenant_credential_roles` | API key RBAC | Unchanged | Remove wildcard scope grant from operator credential |
| `tenant_identity_configs` | Per-tenant IdP config | Unchanged | Wire to login routing |
| `tenant_identity_bindings` | IdP org binding | Unchanged | Wire to invitation binding flow |
| `tenant_identity_audit_events` | Hash-chained audit | Unchanged | Extend event types for `principal_bound`, `membership_created` |
| `portal_users` | Portal principal model | Unchanged | Keep separate; do not merge |

---

## Authority Graph (Canonical)

After migration, the single canonical authorization path for a human Console user:

```
Auth0 ID token
  { sub, iss, email }
       │
       ▼
fg_external_identities
  (provider='auth0', provider_issuer, provider_subject=sub)
       │ principal_id FK
       ▼
fg_principals
  { id, lifecycle_state='active' }
       │ principal_id FK (in tenant_users)
       ▼
tenant_users (Membership)
  { tenant_id, role, active=TRUE, authority_version }
       │ tenant_id FK
       ▼
tenants
  { lifecycle_state='active', canonical_version }
       │
       ▼
HumanActorContext
  { actor_kind='human', principal_id, membership_id,
    tenant_id, roles, permissions, authority_version,
    membership_authority_version }
       │
       ▼
capability check
  PERMIT or DENY
```

**Invariant:** Every node in this graph must be traversed for every session issuance.
A missing or inactive node at any position → DENY. No fallback promotes a missing node
to a higher-authority context.

**Service principal path (separate, non-intersecting):**

```
fgk. credential
  (Argon2id verified, tenant_credentials.tenant_id immutable)
       │ credential_id FK
       ▼
tenant_credential_roles
  { role_name, revoked_at IS NULL }
       │
       ▼
ServiceActorContext
  { actor_kind='service', service_principal_id,
    tenant_id, permissions, credential_id }
       │
       ▼
capability check
```

**ActorContext — discriminated union:**

`actor_kind` is the mandatory discriminator. No field is optional because of uncertainty
about which kind of actor this is — fields impossible for one actor type simply do not
exist on that type.

```python
@dataclass
class HumanActorContext:
    actor_kind: Literal['human']
    principal_id: str            # fg_principals.id
    membership_id: str           # tenant_users.id
    tenant_id: str
    roles: list[str]
    permissions: frozenset[str]
    authority_version: int       # tenant canonical_version snapshot at session issuance
    membership_authority_version: int  # tenant_users.authority_version snapshot

@dataclass
class ServiceActorContext:
    actor_kind: Literal['service']
    service_principal_id: str    # platform_service_principals.id or credential fingerprint
    tenant_id: str
    permissions: frozenset[str]
    credential_id: str

@dataclass
class OperatorActorContext:
    actor_kind: Literal['operator']
    principal_id: str            # fg_principals.id for the FrostGate employee
    tenant_id: str               # always 'frostgate-internal'
    permissions: frozenset[str]
    elevation_state: str | None  # None = base operator; 'elevated' = JIT-elevated session

ActorContext = HumanActorContext | ServiceActorContext | OperatorActorContext
```

`tenant_id` and `permissions` are shared across all three kinds and safe to access
without narrowing. All other fields are kind-specific and must only be accessed after
narrowing on `actor_kind` via `match` or `isinstance`. Any existing code using
`is_service_principal`, `is_operator`, or similar boolean flags must be migrated to
`actor_kind` narrowing when the relevant path is touched.

---

## Ownership Boundaries

| Table | May write | May not write |
|---|---|---|
| `fg_principals` | Core identity service (invitation binding, SCIM future) | Console BFF, portal, Auth0 |
| `fg_external_identities` | Core identity service (invitation binding only) | Console BFF, portal, Auth0 |
| `tenant_users` | Core identity service (binding); Core workforce API; Core identity admin API (tenant_admin-capability requests, own tenant only) | Console BFF directly; Auth0; other-tenant requests |
| `tenants` | Core tenant provisioning service; operator-authorized actions | Console BFF; customer-origin requests |
| `tenant_invitations` | Core invitation service (Flows B and C); Core identity admin API (tenant_admin-capability requests, own tenant only) | Console BFF directly; other-tenant requests |
| `tenant_identity_configs` | Core tenant provisioning; tenant_admin-capability requests (own tenant only) | Customer sessions on other tenants; operator-origin required for creation |
| `tenant_identity_bindings` | Core provisioning service | All other callers |
| `tenant_credential_roles` | Core RBAC service (`tenant_rbac.py`) | Console BFF directly |
| `tenant_identity_audit_events` | Core identity service; append-only | Updates/deletes forbidden at DB level |
| `platform_service_principals` | Core internal platform authority | All human-origin paths |

**Write rules:**

Customer-origin sessions with `tenant_admin` capability may request tenant-scoped
authorization mutations through the Core identity API. The session never touches DB
authorization tables directly — all writes go through Core's API layer, which performs
its own capability check, enforces tenant scope, and emits audit events.

What a `tenant_admin` session **may** request (via Core API, own tenant only):
- Create invitations for their tenant (`tenant_invitations`)
- Change a tenant-local user's role (`tenant_users.role`)
- Suspend or reactivate a tenant-local user (`tenant_users.active`)
- Revoke a membership (`tenant_users → 'disabled'`)
- Configure tenant identity policy (`tenant_identity_configs`) if granted

What **no** customer session may request, regardless of role:
- Mutations to any other tenant's data
- Mutations to `fg_principals` or `fg_external_identities`
- Mutations to `tenants` lifecycle, kind, or existence
- Mutations to `platform_service_principals`
- Mutations to `tenant_identity_bindings`
- Any mutation touching the operator tenant (`frostgate-internal`)

Operator-origin sessions (verified `actor_kind = 'operator'` at BFF middleware) may
issue provisioning writes across tenants via the admin-gateway path.

---

## Forbidden Shadow Authorities

These must not be consulted for authorization after their respective cutover milestones.

| Authority | Forbidden from | Reason |
|---|---|---|
| `tenant_users.identity_*` columns | After PR-AUTH-003 (backfill complete) | Replaced by `fg_external_identities` + `fg_principals` |
| `uq_tenant_users_bound_identity` index | After backfill verified | Replaced by `uq_fg_external_identities_binding` |
| `identity_administration/*` in-memory stores | After PR-CORE-004 (DB adapter wired) | Zero durability; non-functional in multi-instance |
| JWT `{namespace}/tenant_id` claim as sole authority | After PR-AUTH-002 ships | Replaced by Core membership lookup at session issuance |
| JWT `{namespace}/roles` claim as sole authority | After PR-AUTH-002 ships | Replaced by `tenant_users.role` via Core lookup |
| `legacy_internal` session experienceClass | After PR-SEC-001 ships | Forbidden immediately |
| `legacy_console_user` role constant | After PR-SEC-001 ships | Removed from all role sets |
| Scope `"*"` on any `tenant_credentials` row | After PR-CORE-001 ships | Replaced by explicit PSP scope list |
| `_permissions_from_legacy_scopes({"*"})` → `platform_admin` | After PR-CORE-001 ships | Guard added in `api_key.py` |
| `X-Tenant-Id` header as authoritative tenant for internal tokens | After PR-CORE-002 ships | Replaced by signed delegated assertion |
| `auth0.app_metadata` fields as authorization input | Permanently | Auth0 authenticates; FrostGate authorizes |

---

## Uniqueness, FK, RLS, Lifecycle, and Audit Constraints

### Uniqueness

| Constraint | Table | Columns | Notes |
|---|---|---|---|
| `uq_fg_external_identities_binding` | `fg_external_identities` | `(provider, provider_issuer, provider_subject)` | Global — one binding per IdP identity across all tenants |
| `uq_tenant_users_principal_membership` | `tenant_users` | `(tenant_id, principal_id) WHERE active=TRUE` | Partial — enables multi-tenant users; one active membership per principal per tenant |
| `uq_tenant_identity_configs_tenant` | `tenant_identity_configs` | `(tenant_id)` | One IdP config per tenant |
| `uq_tenant_users_single_internal_platform_authority` | `tenants` | `(tenant_kind) WHERE tenant_kind='internal_platform'` | At most one internal platform tenant |
| `uidx_tcr_active_role` | `tenant_credential_roles` | `(tenant_id, credential_id) WHERE revoked_at IS NULL` | One active role per credential per tenant |

### Foreign Keys

| Table | FK column | References | On delete |
|---|---|---|---|
| `fg_external_identities` | `principal_id` | `fg_principals(id)` | RESTRICT (identity cannot be deleted while external binding exists) |
| `tenant_users` | `principal_id` | `fg_principals(id)` | RESTRICT (principal cannot be deleted while membership exists) |
| `tenant_users` | `tenant_id` | `tenants(tenant_id)` | RESTRICT |
| `tenant_invitations` | `membership_id` | `tenant_users(id)` | SET NULL (invitation can outlive membership for audit) |
| `tenant_credential_roles` | `credential_id` | `tenant_credentials(credential_id)` | CASCADE (role removed when credential deleted) |

### RLS

| Table | Policy | Bypass |
|---|---|---|
| `tenant_users` | `tenant_id = current_setting('app.tenant_id', TRUE)` | SECURITY DEFINER functions only |
| `fg_principals` | None — not tenant-scoped | N/A |
| `fg_external_identities` | None — not tenant-scoped | N/A |
| `tenant_invitations` | `tenant_id = current_setting('app.tenant_id', TRUE)` | Same |
| `tenant_identity_configs` | Same | Same |
| `tenant_credential_roles` | Same | Same |
| `tenant_identity_audit_events` | Same + append-only trigger | Same |
| `platform_service_principals` | `authority_tenant_id = current_setting('app.tenant_id', TRUE)` | Same |

`fg_principals` and `fg_external_identities` have no RLS because they are cross-tenant
by design. Access is controlled by application-layer permission checks (`platform_admin`
or `platform.identity.resolve` capability required), not DB policy.

### Lifecycle States

**`fg_principals.lifecycle_state`:**
- `active` → `suspended` (admin action or cascade from all memberships suspended)
- `active` → `deactivated` (IdP account disabled, SCIM deactivate, or admin)
- `suspended` → `active` (admin reactivation)
- `deactivated` → terminal (new principal required; new invitation needed)

**`tenant_users` membership state:**
- `ACTIVE` → `SUSPENDED` (admin action via Core identity admin API)
- `SUSPENDED` → `ACTIVE` (admin reactivation)
- `ACTIVE` or `SUSPENDED` → `REVOKED` (admin action; terminal — new invitation required)

Pre-acceptance lifecycle (INVITED, BINDING_IN_PROGRESS) belongs to
`tenant_invitations.status`, not to `tenant_users`. No `tenant_users` row exists
before `tenant_invitations.status = 'bound'`.

**`tenants.lifecycle_state`:**
- `validating` → `active`
- `active` → `suspended` | `archived`
- `suspended` → `active` | `archived`
- `archived` → `deleted` (terminal)

**`tenant_invitations.status`:**
- `pending` → `auth_started` → `accepted_identity_pending_binding` → `bound`
- `pending` → `expired` (TTL elapsed)
- Any non-terminal state → `revoked` (admin action)
- `accepted_identity_pending_binding` → `failed` (binding error)

### Audit

**`tenant_identity_audit_events`** must emit events for:
- `invitation.created`
- `invitation.accepted_identity_started`
- `invitation.identity_bound` (includes `identity_subject` and `principal_id`)
- `invitation.expired`
- `invitation.revoked`
- `membership.activated`
- `membership.suspended`
- `membership.revoked`
- `membership.role_changed` (old_role, new_role)
- `principal.created` (NEW — currently not emitted)
- `principal.external_identity_bound` (NEW — currently not emitted)
- `principal.lifecycle_changed`

Events are hash-chained (`previous_event_hash → event_hash`). Append-only trigger on
the table prevents UPDATE/DELETE. This is the SOC 2 evidence record — do not weaken it.

---

## Migration Sequence

These are DB migrations that must ship as part of the PR roadmap, in this order.
Each is additive and replay-safe. Column drops are deferred to a separate cleanup PR
after the migration window closes.

| Migration | Scope | PR | Rollback |
|---|---|---|---|
| 0179 — `fg_principals` table | Create table; no data movement | PR-AUTH-001 | DROP TABLE (no FK dependencies yet) |
| 0180 — `fg_external_identities` table | Create table + `uq_fg_external_identities_binding` | PR-AUTH-001 | DROP TABLE |
| 0181 — `tenant_users.principal_id` FK column | ADD COLUMN nullable; no constraint yet | PR-AUTH-002 | DROP COLUMN |
| 0182 — Backfill `fg_principals` + `fg_external_identities` from `tenant_users` | Data migration for all bound rows | PR-AUTH-003 | No rollback needed — additive only |
| 0183 — Backfill `tenant_users.principal_id` | Populate FK for all bound rows | PR-AUTH-003 | Set NULL (restore pre-backfill state) |
| 0184 — `uq_tenant_users_principal_membership` partial index | Create after backfill verified | PR-AUTH-003 | DROP INDEX |
| 0185 — `tenants.canonical_version` increment triggers | DB trigger on `tenant_users` changes | PR-HARD-001 | DROP TRIGGER |
| 0186 — `tenant_users` rename `membership_version` → `authority_version` | ALTER COLUMN (or add alias column) | PR-HARD-001 | Rename back |
| 0187 — Identity administration DB adapter | Remove in-memory wiring; no schema change | PR-CORE-004 | Revert service wiring |
| 0188 — Drop shadow identity columns from `tenant_users` | DROP deprecated identity columns | Post-migration cleanup PR | Not rollbackable — schedule after full cutover |
| 0189 — Drop `uq_tenant_users_bound_identity` index | After 0184 is proven in production | Post-migration cleanup PR | Recreate index |

---

## Architecture Decision Confirmations

The following ADRs from the architecture audit are confirmed binding by this document:

**ADR-IDENTITY-001 confirmed:** `fg_external_identities` + `fg_principals` establish that
Auth0 provides identity; FrostGate (`tenant_users`) provides authorization. These are
separate tables with separate ownership.

**ADR-IDENTITY-002 confirmed:** `tenant_users` is the canonical membership record.
`fg_principals` is the canonical identity record. Both are Core DB tables. Neither is
Auth0 state.

**ADR-IDENTITY-003 confirmed:** The authority graph has no fallback node. A missing
`fg_external_identities` row → DENY. A missing `fg_principals` row → DENY. A missing
`tenant_users` row → DENY. An inactive node at any position → DENY.

**ADR-IDENTITY-006 confirmed:** `session.tenant_id` comes from `tenant_users.tenant_id`
(verified at session issuance via the Core identity resolve endpoint). No query parameter,
cookie, or header from the browser ever overrides this.

**ADR-IDENTITY-007 confirmed:** The invitation binding event (migration 0182/0183 +
`POST /internal/identity/bind-invitation`) is the moment that creates `fg_principals`,
`fg_external_identities`, and populates `tenant_users.principal_id`. The session is
first issued after this event completes. Before it completes, DENY.

**ADR-IDENTITY-008 confirmed:** `tenant_users.authority_version` (= `membership_version`)
and `tenants.canonical_version` are the version counters for BFF staleness detection.
Both columns exist. The increment contracts are defined above.

---

*This document is frozen after approval. Changes require explicit architectural decision
and must be reflected in the migration sequence above before any implementing PR begins.*
