# Auth Authority Roadmap

## Current state (PR 17) — Postgres auth authority, SQLite retained as dev/test fallback

FrostGate Core dispatches auth authority based on `FG_DB_BACKEND`:

| `FG_DB_BACKEND` | Auth authority | Use case |
|-----------------|----------------|----------|
| `postgres`      | Postgres `api_keys` (via SQLAlchemy) | Production / HA / Kubernetes multi-replica |
| `sqlite` or unset | SQLite file at `FG_SQLITE_PATH` | Dev / test / single-node |

### Postgres mode

When `FG_DB_BACKEND=postgres`:

- Auth reads use Postgres `api_keys` (`api/auth_scopes/store.py`)
- `mint_key()` writes to Postgres `api_keys`
- `revoke_api_key()` and `rotate_api_key_by_prefix()` operate on Postgres
- Startup validation requires `FG_KEY_PEPPER` and `FG_DB_URL`; probes `api_keys` connectivity
- Readiness probe (`/health/ready`) confirms `api_keys` table is reachable in Postgres
- `FG_SQLITE_PATH` is not required (but may still be set for other tooling)

### SQLite mode

When `FG_DB_BACKEND=sqlite` or unset:

- All auth operations use the SQLite file at `FG_SQLITE_PATH` (PR 16 behavior unchanged)
- Startup validation requires `FG_KEY_PEPPER` and `FG_SQLITE_PATH`
- Readiness probe checks file existence, schema completeness, and directory writability

### Key invariants (both modes)

- `FG_KEY_PEPPER` is always required when `FG_AUTH_ENABLED=true`
- No silent fallback from Postgres to SQLite or vice versa
- No fail-open on auth store errors in production

---

## Why Postgres (completed PR 17)

SQLite as the auth authority was incompatible with:

- **Horizontal scaling** — keys minted on instance A cannot be verified on
  instance B (each has its own file)
- **Kubernetes multi-replica deployments** — PVCs are not shared by default
- **HA / failover** — no replication; a corrupted auth volume is an outage
- **Backup coherence** — auth SQLite must be backed up separately from Postgres
- **Audit trail** — API key lifecycle events should be in the same auditable store

The Postgres `api_keys` table schema was already correct — migrations 0001–0004
created it with full column coverage, indexes, and RLS policies.

---

## Runtime guards (PR 16, still active)

The PR 16 guards remain active and are extended by PR 17:

| Guard | Location | Behavior |
|-------|----------|----------|
| `FG_KEY_PEPPER` required (all modes) | `StartupValidator._check_auth_store()` | Error → `/health/ready` 503 |
| `FG_SQLITE_PATH` required (sqlite mode) | `StartupValidator._check_auth_store()` | Error → `/health/ready` 503 |
| `FG_DB_URL` required (postgres mode) | `StartupValidator._check_auth_store()` | Error → `/health/ready` 503 |
| Postgres `api_keys` connectivity | `StartupValidator._check_auth_store()` | Error → `/health/ready` 503 |
| SQLite file exists and schema valid | `health_ready()` in `main.py` | 503 (sqlite mode only) |
| Postgres `api_keys` probe | `health_ready()` in `main.py` | 503 (postgres mode only) |

---

## Operational migration: SQLite → Postgres

To move existing keys from SQLite to Postgres:

1. Run the migration script in dry-run mode to validate:
   ```
   FG_SQLITE_PATH=/var/lib/frostgate/state/frostgate.db \
   FG_DB_URL=postgresql+psycopg://fg_user:pass@host/frostgate \
   python tools/scripts/migrate_auth_sqlite_to_postgres.py --dry-run
   ```

2. Run the migration live:
   ```
   FG_SQLITE_PATH=/var/lib/frostgate/state/frostgate.db \
   FG_DB_URL=postgresql+psycopg://fg_user:pass@host/frostgate \
   python tools/scripts/migrate_auth_sqlite_to_postgres.py
   ```

3. Set `FG_DB_BACKEND=postgres` in your deployment.

4. Restart the service and verify `/health/ready` returns `"status": "ready"`.

5. Run the E2E auth/report smoke test:
   ```
   FG_E2E_HTTP=1 FG_DB_BACKEND=postgres \
   FG_SCOPED_KEY=fgk.xxx.yyy \
   pytest tests/test_e2e_auth_report_engine.py -v
   ```

---

## PR 16 completion status

**Complete.** PR 16 guards are active and verified by `tests/test_auth_startup_guard.py`.

## PR 17 completion status

**Complete.** Postgres auth authority is implemented and dispatched via
`api/auth_scopes/store.py`. SQLite is retained as dev/test fallback.

## PR 18 — future SQLite removal / deprecation

SQLite auth support remains for dev/test. A future PR 18 may deprecate or
remove the SQLite auth path once all deployments are confirmed on Postgres.
This PR does **not** remove SQLite support.

_Last updated: 2026-05-26 (PR 17)_
