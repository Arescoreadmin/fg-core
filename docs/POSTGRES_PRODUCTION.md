# Postgres Production Requirements (FrostGate-Core)

This repository **requires PostgreSQL in production**. SQLite is allowed **only** for local development.

## Production Requirements (Non-Negotiable)
- `FG_DB_BACKEND=postgres`
- `FG_DB_URL` set and reachable (e.g. `postgresql+psycopg://user:pass@host:5432/db`)
- Migrations applied (see `python -m api.db_migrations --backend postgres --apply`)
- Append-only enforcement for decisions + evidence artifacts (DB triggers)
- Tenant isolation via Postgres RLS (DB policies)
- Tenant context mode must be `db_session`

If any of the above is missing, startup **fails closed**.

## Environment Variables (Source of Truth)
- `FG_ENV`: `dev|test|staging|prod`
- `FG_DB_BACKEND`: `postgres` | `sqlite`
- `FG_DB_URL`: required when `FG_DB_BACKEND=postgres`
- `FG_TENANT_CONTEXT_MODE`: `db_session` (default) or `app_only` (dev only)
- `FG_DB_POOL_SIZE` (default 10), `FG_DB_MAX_OVERFLOW` (default 20)
- `FG_TRUST_PROXY_HEADERS` (default `false`): trust `X-Forwarded-For`/proxy IP headers for logging only when running behind a trusted reverse proxy.

## Migrations (Postgres)
Apply:
```bash
FG_DB_URL="postgresql+psycopg://user:pass@host:5432/db" \
python -m api.db_migrations --backend postgres --apply
```

Status:
```bash
FG_DB_URL="postgresql+psycopg://user:pass@host:5432/db" \
python -m api.db_migrations --backend postgres --status
```

Assertions (append-only + RLS):
```bash
FG_DB_URL="postgresql+psycopg://user:pass@host:5432/db" \
python -m api.db_migrations --backend postgres --assert
```

## Append-Only Enforcement
Postgres triggers block `UPDATE` and `DELETE` on:
- `decisions`
- `decision_evidence_artifacts`

Trigger names:
- `decisions_append_only_update` / `decisions_append_only_delete`
- `decision_evidence_artifacts_append_only_update` / `decision_evidence_artifacts_append_only_delete`

Expected error: `append-only violation on <table>`.

## Tenant Isolation via RLS
RLS is enabled and enforced for:
- `decisions`
- `decision_evidence_artifacts`
- `api_keys`
- `security_audit_log`

`api_keys.tenant_id` is enforced as NOT NULL (defaults to `unknown`).

Each DB session must set:
```sql
SET LOCAL app.tenant_id = '<tenant_id>';
```

The API uses `bind_tenant_id()` to set `request.state.tenant_id` and applies
`SET LOCAL app.tenant_id` on the request-scoped DB session.

## Local Development (Postgres)
```bash
make db-postgres-verify
```

## CI Verification
The `db-postgres-verify` lane:
1. Brings up Postgres (docker compose)
2. Applies migrations
3. Asserts append-only triggers + RLS policies
4. Runs Postgres tests
