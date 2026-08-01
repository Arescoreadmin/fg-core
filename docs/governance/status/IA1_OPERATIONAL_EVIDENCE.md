# IA-1 Operational Evidence

Status: PENDING

Gate order: G1-dev → G2-dev → G1-prod → G2-prod

---

## G1-dev — Migration 0169, Dev Environment

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

**G1-dev result:** PENDING

---

## G2-dev — E2E Proof, Dev Environment

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

**G2-dev result:** PENDING

---

## G1-prod — Migration 0169, Production Environment

| Field | Value |
|---|---|
| Environment | prod |
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

**G1-prod result:** PENDING

---

## G2-prod — E2E Proof, Production Environment

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

**G2-prod result:** PENDING

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
