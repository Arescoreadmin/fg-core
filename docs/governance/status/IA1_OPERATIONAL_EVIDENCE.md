# IA-1 Operational Evidence

Status: BLOCKED

Gate sequence: G1-dev → G2-dev → G1-prod → G2-prod

Critical path:
1. Create Railway dev environment
2. Create restricted dev runtime role (fg_app)
3. Run G1-dev
4. Run G2-dev
5. Create restricted prod runtime role (fg_app)
6. Rerun G1-prod
7. Run G2-prod
8. IA-1 operationally complete → IA-2 deployment unlocked

---

## G1-dev — Migration 0169, Dev Environment

**Status: NOT EXECUTABLE**
**Reason: No Railway dev environment exists. This is a CONTROL GAP / LAUNCH RISK,
not an IA-1 code failure. A non-production environment must exist before IA-2
reaches runtime validation.**

| Field | Value |
|---|---|
| Environment | dev |
| Date/time (UTC) | |
| Operator | |
| Railway deploy/run ID | |
| Migration service exit status | |
| `SELECT version FROM schema_migrations WHERE version = '0169'` | |
| `SELECT to_regclass('public.tenant_identity_bindings')` | |
| `SELECT to_regclass('public.tenant_identity_binding_events')` | |
| API runtime role (`current_user`) | |
| `rolsuper` | |
| `rolbypassrls` | |
| `rolcreatedb` | |
| `rolcreaterole` | |

**G1-dev result: NOT EXECUTABLE — Railway dev environment missing**

---

## G2-dev — E2E Proof, Dev Environment

**Status: BLOCKED — blocked by G1-dev**

Disposable tenant: `fg-ia1-dev-validation-20260801`

| Field | Value |
|---|---|
| Environment | dev |
| Date/time (UTC) | |
| Operator | |
| Tenant ID | |
| Request ID | |
| `provisioning_state` | |
| `provider_org_id` | |
| `provider_org_name` | |
| Ownership metadata: `frostgate_tenant_id` matches tenant | |
| Audit event ID | |
| Audit event type | |
| Auth0 org count for this org name | |
| Retry: same `provider_org_id` returned | |
| Retry: no second `org_provisioning_started` event | |
| Retry: duplicate-org count in Auth0 | |
| Console UI binding state visible | (skip if not rendered) |

**G2-dev result: BLOCKED — blocked by G1-dev**

---

## G1-prod — Migration 0169, Production Environment

**Status: FAIL (role safety)**

Migration was applied automatically on PR #601 redeploy (FG_DB_MIGRATIONS_REQUIRED=1
was already set). No additional deploy required for migration conditions.

| Field | Value |
|---|---|
| Environment | prod |
| Date/time (UTC) | 2026-08-01 |
| Operator | jcosat |
| Railway deploy/run ID | 0cba6aa2-b9ff-4d00-b50b-f0f44d520ebb (current api deployment) |
| Migration service exit status | 0 (applied on PR #601 redeploy) |
| `SELECT version FROM schema_migrations WHERE version = '0169'` | **0169 — PASS** |
| `SELECT to_regclass('public.tenant_identity_bindings')` | **tenant_identity_bindings — PASS** |
| `SELECT to_regclass('public.tenant_identity_binding_events')` | **tenant_identity_binding_events — PASS** |
| API runtime role (`current_user`) | postgres |
| `rolsuper` | **true — FAIL** |
| `rolbypassrls` | **true — FAIL** |
| `rolcreatedb` | true |
| `rolcreaterole` | true |

**Migration SQL conditions: PASS**
**Runtime role safety: FAIL**

**G1-prod overall result: FAIL**

Root cause: The API runtime connects as the Railway-managed `postgres` superuser.
`rolbypassrls=true` means the API can bypass every RLS policy on every tenant table.
This is a pre-existing production architecture gap now made explicit by IA-1 evidence.
It is not an IA-1 code defect, but it is a real tenant-isolation control failure.

Required fix: Create `fg_app` restricted role (NOSUPERUSER, NOBYPASSRLS, NOCREATEDB,
NOCREATEROLE). Update API service FG_DB_URL to use fg_app. Leave migrator on the
elevated postgres credential. Prove in dev first, then promote to prod.

---

## G2-prod — E2E Proof, Production Environment

**Status: BLOCKED — G1-prod not complete**

Disposable tenant: `fg-ia1-prod-validation-20260801`

| Field | Value |
|---|---|
| Environment | prod |
| Date/time (UTC) | |
| Operator | |
| Tenant ID | |
| Request ID | |
| `provisioning_state` | |
| `provider_org_id` | |
| `provider_org_name` | |
| Ownership metadata: `frostgate_tenant_id` matches tenant | |
| Audit event ID | |
| Audit event type | |
| Auth0 org count for this org name | |
| Retry: same `provider_org_id` returned | |
| Retry: no second `org_provisioning_started` event | |
| Retry: duplicate-org count in Auth0 | |
| Console UI binding state visible | (skip if not rendered) |

**G2-prod result: BLOCKED — G1-prod not complete**

---

## Final Acceptance

_To be completed only after all four gates pass._

```
IA-1: OPERATIONALLY COMPLETE

Evidence:
- G1-dev PASS
- G2-dev PASS
- G1-prod PASS
- G2-prod PASS
- Migration 0169 verified in dev and prod
- One FrostGate tenant maps to one Auth0 Organization
- Retry proven idempotent
- Ownership metadata verified
- Audit trail verified
- Runtime DB role non-elevated

Next:
IA-2 unlocked
```

| Field | Value |
|---|---|
| Closed by | |
| Date/time (UTC) | |
