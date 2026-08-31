# CLIENT-LIFECYCLE-001: Canonical Client Readiness Evaluator

**Track:** CLIENT-LIFECYCLE-001  
**Status:** Complete — `feat/client-lifecycle-001-canonical-foundation`  
**lifecycle_version:** 1

---

## Purpose

Expose a stable, machine-readable snapshot of a client tenant's operational readiness. The evaluator derives state entirely from durable canonical facts — no new stored state, no external calls, no side effects.

Consumers: Console dashboard, AI Workspace, operator tooling, automated onboarding flows.

---

## Canonical facts used

| Table | Field(s) | Gate |
|-------|---------|------|
| `tenants` | `lifecycle_state` | Tenant must exist and be `active` |
| `tenant_users` | `role='tenant_admin'`, `active`, `identity_binding_status='bound'`, `principal_id IS NOT NULL` | Bound admin required |
| `tenant_users` | `role != 'tenant_admin'`, `active` | Active member count (warning only) |

No other tables are read. No Auth0 or external calls are made.

---

## State machine and precedence

States are derived, not stored. Precedence is deterministic — multiple simultaneous failures always yield the same primary state regardless of DB row ordering.

```
1. tenant_not_found   FATAL    Tenant row missing; nothing else checkable
2. tenant_suspended   CRITICAL lifecycle_state != 'active'
3. admin_unset        P0       No active tenant_admin row at all
4. admin_unbound      P1       Active admin exists but identity not bound
5. operational               All gates clear (warnings may apply)
```

### State table

| `lifecycle_state` | `operational` | `repairable` | Primary blocker |
|---|---|---|---|
| `tenant_not_found` | false | false | `TENANT_NOT_FOUND` |
| `tenant_suspended` | false | false | `TENANT_SUSPENDED` |
| `admin_unset` | false | true | `NO_BOUND_ADMIN` |
| `admin_unbound` | false | false | `NO_BOUND_ADMIN` |
| `operational` | true | false | — |

`repairable=true` means a platform admin can unblock the state by calling an existing canonical operation (bootstrap). `repairable=false` means the resolution requires external action (identity binding flow, tenant re-activation) or is already clear.

### Warning codes

| Code | Condition | Impact |
|------|-----------|--------|
| `NO_ACTIVE_MEMBERS` | No active non-admin users in tenant | Does not block `operational`; advisory |

---

## HTTP surface

### GET `/admin/tenants/{tenant_id}/lifecycle`

**Auth (dual-path):**
- `platform.admin` — cross-tenant read; may inspect any tenant
- DB-canonical `tenant_admin` — own tenant only; `check_tenant_admin_authority` enforced

**Response:**
```json
{
  "lifecycle_version": 1,
  "tenant_id": "...",
  "lifecycle_state": "operational",
  "operational": true,
  "repairable": false,
  "blockers": [],
  "warnings": [],
  "next_actions": [],
  "diagnostics": {
    "tenant_canonical_state": "active",
    "has_bound_admin": true,
    "active_member_count": 3
  }
}
```

**HTTP semantics:**
- `200` — state evaluated (including degraded states)
- `404` — tenant not found (distinct from degraded so provisioning gaps are visible)
- `403` — auth failed

---

## Security invariants

1. **Fail-closed:** Unknown or unreadable state → `operational=false`. The evaluator never returns `operational=true` under uncertainty.
2. **No JWT reliance:** All facts read from DB canonical tables under the same RLS context as authoritative mutations.
3. **Read-only:** The evaluator performs no writes, no projections, and no side-effect triggering.
4. **RLS prerequisite:** Callers must call `set_tenant_context(db, tenant_id)` before invoking `evaluate_client_lifecycle` when running under Postgres FORCE ROW LEVEL SECURITY.

---

## Contract stability

`lifecycle_version`, `lifecycle_state`, blocker codes, warning codes, and `next_action` codes are **versioned machine contracts**. Renaming or removing any of these fields requires:
1. Bumping `LIFECYCLE_VERSION` in `api/client_lifecycle.py`
2. Updating all consumers (Console, AI Workspace, automation pipelines)
3. A deprecation period if consumers cannot be updated atomically

Adding new fields to the response or new blocker/warning codes is non-breaking (additive).

---

## Non-goals

- Does NOT replace or extend `api/tenant_lifecycle.py` (which handles active→suspended→archived state transitions).
- Does NOT write any new state.
- Does NOT trigger any Auth0 projection.
- Does NOT evaluate portal grants, evidence readiness, or compliance posture.
- POST `/lifecycle/repair` is intentionally absent — repair operations must go through existing canonical endpoints (`POST /bootstrap-admin`) to prevent duplication of mutation logic.
