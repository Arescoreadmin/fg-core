# FrostGate Canonical Tenant Model (Foundation Contract)

## 1) Core Entities

### Tenant
A **tenant** is the highest isolation boundary for all customer-owned FrostGate data and operations.

**Required fields**
- `tenant_id` (string, immutable, globally unique)
- `status` (`active|suspended|deprovisioned`)
- `created_at` (UTC timestamp)
- `updated_at` (UTC timestamp)

**Rules**
- `tenant_id` is assigned by platform control-plane logic and is never client-generated.
- `tenant_id` is immutable after creation.
- A deprovisioned tenant remains queryable only by platform break-glass paths with explicit audit.

### User
A **user** is a human principal authenticated only by Admin-Gateway.

**Required fields**
- `actor_id` (string, immutable principal id)
- `tenant_id` (nullable only for approved global-admin identity class)
- `identity_provider` (string)
- `status` (`active|disabled`)
- `created_at` (UTC timestamp)

**Rules**
- Tenant-bound users must have exactly one `tenant_id`.
- Global-admin users MUST be explicitly marked and constrained by policy; they are not default.
- Core services never validate human credentials directly.

### Role
A **role** is a permission bundle bound to a tenant context.

**Required fields**
- `role_id` (string)
- `tenant_id` (string; required for tenant roles)
- `name` (string)
- `permissions` (set/list of scoped actions)
- `created_at` (UTC timestamp)

**Rules**
- Role grants are evaluated in tenant context.
- No role may include an unscoped wildcard allowing implicit cross-tenant read/write.

### Workspace (optional logical partition)
A **workspace** is an optional partition below tenant used for organization and policy segmentation.

**Required fields**
- `workspace_id` (string, unique within tenant)
- `tenant_id` (string, required)
- `name` (string)
- `status` (`active|archived`)
- `created_at` (UTC timestamp)

**Rules**
- Workspace uniqueness scope is `(tenant_id, workspace_id)`.
- Workspace records and child assets cannot be reassigned across tenants.

---

## 2) Ownership Rules

1. Every persisted tenant-owned record MUST carry `tenant_id`.
2. If workspace is used, workspace-owned records MUST carry both `tenant_id` and `workspace_id`.
3. Derived artifacts (embeddings, caches, indexes, event logs, snapshots, exports) inherit source `tenant_id`.
4. Any asynchronous job must include tenant context in input payload and in persistence writes.

---

## 3) Isolation Rules (Hard)

1. **Query isolation**: all reads/writes MUST include tenant predicate (or equivalent bound DB context).
2. **Execution isolation**: workers MUST process tenant context explicitly; no unscoped batch access.
3. **Storage isolation**: object keys, queues, vector namespaces, cache keys, and audit streams MUST be tenant-namespaced.
4. **Crypto isolation**: encryption key selection MUST be tenant-aware (or tenant-bound via envelope metadata).
5. **API isolation**: tenant identity source of truth is trusted auth context, not user-supplied payload.

---

## 4) Forbidden Cross-Tenant Patterns

The following are forbidden:

- Accepting `tenant_id` from request body as authority.
- Queries without tenant filter on tenant-owned tables/collections.
- Reusing one tenant’s credential/token/state for another tenant.
- Shared global cache keys for tenant-owned responses.
- Background jobs that iterate all tenants without explicit privileged control-plane workflow.
- Returning distinguishable errors that leak existence of another tenant’s resource.

Any detected path violating these rules is a **security defect** and must be blocked.
