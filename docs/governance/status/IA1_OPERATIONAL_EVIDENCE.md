# IA-1 Operational Evidence

Status: G1-dev PASS (isolated) — G2-dev pending Auth0 decision

Gate sequence: G1-dev → G2-dev → G1-prod → G2-prod

Prerequisite: PR #602 (fix/db-migration-credential-separation) — must merge before G2-dev or prod work

Critical path:
1. ~~Create Railway dev environment~~ ✓ DONE
2. ~~Create restricted dev runtime role (fg_app)~~ ✓ DONE
3. ~~Run G1-dev~~ ✓ PASS
4. ~~Tighten dev isolation~~ ✓ DONE (2026-08-01)
5. Merge PR #602
6. Redeploy API-DEV from merged main
7. Run G2-dev (blocked pending Auth0 decision — see below)
8. Create restricted prod runtime role (fg_app)
9. Rerun G1-prod
10. Run G2-prod
11. IA-1 operationally complete → IA-2 deployment unlocked

Dev isolation status (2026-08-01):
- FG_JWT_SECRET, FG_ENCRYPTION_KEY, FG_KEY_PEPPER, FG_SIGNING_SECRET,
  FG_REPORT_SIGNING_KEY, FG_BILLING_EVIDENCE_HMAC_KEY, FG_ACKNOWLEDGMENT_KEY,
  FG_INTERNAL_AUTH_SECRET, FG_INTERNAL_GATEWAY_SECRET, FG_WEBHOOK_SECRET:
  replaced with dev-specific random values ✓
- FG_CORS_ORIGINS: restricted to dev origins ✓
- Stripe: already in test mode ✓
- Auth0 (FG_OIDC_ISSUER): PENDING DECISION — G2-dev will create Auth0 orgs
  in the shared production Auth0 tenant. Options:
  (a) Accept disposable test orgs + manual cleanup after G2-dev
  (b) Create a separate Auth0 dev tenant with its own Management API credentials

---

## G1-dev — Migration 0169, Dev Environment

**Status: PASS**

Infrastructure created this session:
- Railway dev environment provisioned (Postgres-dUxF, Redis-89wp, API-DEV services)
- `fg_app` restricted role created on dev Postgres
- `FG_DB_MIGRATION_URL` added to API-DEV (elevated postgres for DDL)
- `FG_DB_URL` set to fg_app (restricted runtime credential)
- Code change: `api/db.py` + `api/db_migrations.py` — added `FG_DB_MIGRATION_URL` support to decouple migration engine from runtime engine

| Field | Value |
|---|---|
| Environment | dev |
| Date/time (UTC) | 2026-08-01T16:13:40Z |
| Operator | jcosat |
| Railway deploy/run ID | 7c0daa93-36d6-4022-8742-ea2c9879f493 |
| Migration service exit status | 0 (169 migrations applied) |
| `SELECT version FROM schema_migrations WHERE version = '0169'` | **0169 — PASS** |
| `SELECT to_regclass('public.tenant_identity_bindings')` | **tenant_identity_bindings — PASS** |
| `SELECT to_regclass('public.tenant_identity_binding_events')` | **tenant_identity_binding_events — PASS** |
| `/health` HTTP status | **200 OK — PASS** |
| API runtime role (`current_user`) | **fg_app — PASS** |
| `rolsuper` | **false — PASS** |
| `rolbypassrls` | **false — PASS** |
| `rolcreatedb` | **false — PASS** |
| `rolcreaterole` | **false — PASS** |

**G1-dev result: PASS**

---

## G2-dev — E2E Proof, Dev Environment

**Status: PENDING — G1-dev complete, G2-dev not yet executed**

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

**G2-dev result: PENDING — execution required**

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
