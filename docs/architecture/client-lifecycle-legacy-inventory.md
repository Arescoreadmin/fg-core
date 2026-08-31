# CLIENT-LIFECYCLE-001: Legacy Surface Inventory

**Purpose:** Record pre-existing lifecycle-adjacent code that was audited and deliberately NOT replaced by CLIENT-LIFECYCLE-001.

---

## What was audited

| File | What it does | Decision |
|------|-------------|----------|
| `api/tenant_lifecycle.py` | State machine for tenant lifecycle transitions (active→suspended→archived→deleted). `execute_transition()`, `get_transition_history()`. | Untouched. Manages durable state transitions, not readiness evaluation. Different concern. |
| `api/tenant_authority.py` | Tenant existence + config lookup. `get_tenant()`, `assert_tenant_active()`. | Untouched. Lower-level existence check used by many routes. |
| `api/tenant_repository.py` | ORM-backed tenant CRUD. | Untouched. Not relevant to readiness evaluation. |
| `api/tenant_admin.py` | Delegated admin routes (invite, bootstrap, portal-access). | Added `GET /{tenant_id}/lifecycle` endpoint only. No existing routes modified. |
| `api/tenant_admin_authority.py` | `check_tenant_admin_authority()`, `DELEGATABLE_ROLES`, delegation ceiling. | Untouched and reused as auth check in the new lifecycle route. |

---

## Why no new table / migration

The readiness state is entirely derivable from existing canonical facts. Adding a stored `readiness_state` column would introduce a second source of truth that could diverge from the canonical `tenant_users` and `tenants` tables under concurrent mutations.

The evaluator accepts the trade-off: a small per-request query overhead in exchange for guaranteed consistency with the canonical authority.

---

## Bootstrap repair path

`STATE_ADMIN_UNSET` → `repairable=true` because the repair operation (seating the first tenant_admin) already exists as `POST /admin/tenants/{tenant_id}/bootstrap-admin`. Clients can call that endpoint directly — no new repair endpoint is needed.

`STATE_ADMIN_UNBOUND` → `repairable=false` because identity binding requires the admin to complete an external OIDC or invitation flow that CLIENT-LIFECYCLE-001 does not control.
