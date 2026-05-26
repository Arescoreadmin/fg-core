# Auth Authority Roadmap

## Current state (PR 16)

FrostGate Core uses **SQLite as the auth authority** for API key storage,
verification, and minting. The SQLite file is located at:

```
/var/lib/frostgate/state/frostgate.db   ← default, on fg-core_fg_state volume
FG_SQLITE_PATH                          ← overridable via env
```

This is intentional for the current deployment model. The auth resolver
(`api/auth_scopes/resolution.py`) uses a direct `sqlite3` connection rather than
SQLAlchemy, which avoids ORM overhead on every authenticated request.

The application database (decisions, governance reports, audit logs) is
Postgres when `FG_DB_URL` is set, but **auth keys are not stored in Postgres**
and the Postgres `api_keys` table (created by migration 0001) is not used by
the live auth resolver.

## Why this is a temporary state

SQLite as the auth authority is incompatible with:

- **Horizontal scaling** — keys minted on instance A cannot be verified on
  instance B (each has its own file)
- **Kubernetes multi-replica deployments** — PVCs are not shared by default;
  `ReadWriteMany` or equivalent is required and adds failure modes
- **HA / failover** — no replication, no WAL archiving; a corrupted auth volume
  is an outage with no replay path
- **Backup coherence** — the auth SQLite must be backed up separately from
  Postgres; a partial restore leaves the system in an inconsistent state
- **Audit trail** — API key lifecycle events (create, revoke, rotate,
  last-used) should be in the same auditable, replayable store as everything else

The `deploy/frostgate-core/values.yaml` Kubernetes Helm chart confirms this
deployment is heading toward multi-replica production. SQLite auth authority
is a blocker for that path.

## Target state (PR 17)

**PR 17 — Postgres Auth Authority Consolidation** will:

1. Add a Postgres read path to `resolution.py` when `FG_DB_BACKEND=postgres`
2. Add a Postgres write path to `mapping.py::mint_key()` when
   `FG_DB_BACKEND=postgres`
3. Provide a migration script to copy existing SQLite rows to Postgres
   (timestamp conversion: INTEGER → TIMESTAMPTZ; hash_params: TEXT → JSONB)
4. Keep SQLite as the fallback for `FG_DB_BACKEND=sqlite` (dev/test)
5. Update startup guard to require a Postgres connection for auth when
   `FG_DB_BACKEND=postgres`

The Postgres `api_keys` table schema is already correct — migrations 0001–0004
created it with full column coverage, indexes, and RLS policies.

## Runtime guards added in PR 16

Until PR 17 ships, the following guards prevent the "healthy but unusable" state:

| Guard | Location | Behavior |
|-------|----------|----------|
| `FG_KEY_PEPPER` required | `StartupValidator._check_auth_store()` | Startup validation error → `/health/ready` 503 |
| `FG_SQLITE_PATH` required | `StartupValidator._check_auth_store()` | Startup validation error → `/health/ready` 503 |
| Auth store file exists | `health_ready()` in `main.py` | Readiness probe 503 |
| Auth store schema valid | `health_ready()` in `main.py` | Readiness probe 503 (checks 9 required columns via PRAGMA) |
| `FG_SQLITE_PATH` default | `docker-compose.yml` environment | Points to `fg-core_fg_state` named volume |
| `FG_KEY_PEPPER` required | `docker-compose.yml` environment | `${VAR:?message}` — fails `docker compose up` if unset |

## Review cadence

PR 17 scope and timeline should be reviewed at every dependency PR. The
SQLite auth authority is load-bearing for current single-node deployments but
is a hard blocker for any HA or multi-replica deployment.

_Last updated: 2026-05-26 (PR 16)_
