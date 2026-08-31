# Identity Projection Worker — Railway Deployment Guide

**Component:** `fg-identity-projection-worker`
**Track:** AUTH-ROLE-001C-WORKER-DEPLOYMENT
**Status:** Prerequisites defined; deploy BEFORE running AUTH-ROLE-001C live production proof

---

## Overview

The identity projection worker consumes rows from `identity_projection_outbox` and
projects FrostGate identity state (principal_id, roles, membership_version) into
Auth0 `app_metadata` via the Auth0 Management API.

This is a **long-running polling service** — not a web server.  It has no HTTP port
and no health endpoint at the application layer (Railway restarts on process exit).

The worker is a production prerequisite.  Pending `identity_projection_outbox` rows
have no consumer until this service is running.

---

## MANUAL DEPLOYMENT PREREQUISITE: Auth0 M2M Configuration

**This step must be completed BEFORE deploying the Railway service.**

### Create a dedicated Auth0 M2M Application

1. Log in to the Auth0 dashboard for the FrostGate production tenant.
2. Navigate to **Applications → Create Application**.
3. Choose **Machine to Machine Applications**.
4. Name the application: **FrostGate Identity Projection Worker**
   - Do NOT reuse the existing org-management client (`AUTH0_MGMT_CLIENT_ID`).
   - This is a separate, least-privilege M2M application.
5. Select the **Auth0 Management API** as the authorized API.
6. Grant ONLY the following scopes (minimum required):
   - `read:users` — required to read `app_metadata.projection_revision` for stale-write safety
   - `update:users_app_metadata` — required to PATCH `app_metadata`
   - Do NOT grant `update:users`, `create:users`, `delete:users`, or any other scope.
7. Save the application and record the Client ID and Client Secret.
   - Store these in GitHub Secrets / Railway environment variables.
   - Never commit secrets to source control.
   - Never paste secrets in chat or issue comments.

### Auth0 Management API Operations Used

The worker performs exactly two Management API operations:

| Operation | Method | Endpoint | Scope Required |
|-----------|--------|----------|---------------|
| Read current `app_metadata` (stale-write check) | `GET` | `/api/v2/users/{id}?fields=app_metadata` | `read:users` |
| Write FrostGate identity state | `PATCH` | `/api/v2/users/{id}` body: `{app_metadata: {principal_id, roles, projection_revision}}` | `update:users_app_metadata` |

The worker does NOT call any other Management API endpoint.

### Why a dedicated M2M app?

- Least-privilege: the projection worker only needs two scopes.
- Blast-radius isolation: a compromised projection-worker credential cannot create
  or delete users, manage organizations, or access connections.
- Audit traceability: Auth0 Management API logs will show a distinct client ID.

---

## Railway Service Configuration

Railway is **dashboard-managed** for this repository.  No `railway.json` or
`railway.toml` is committed to source control.  Configure via the Railway UI.

### Service name

```
fg-identity-projection-worker
```

### Build settings

| Field | Value |
|-------|-------|
| Root directory | `admin_gateway/` |
| Dockerfile path | `admin_gateway/Dockerfile` |
| Build context | Repository root (so `services/`, `api/`, `contracts/` are available) |

The existing `admin_gateway/Dockerfile` multi-stage build produces an image that
contains all required Python packages.

### Start command

Override the default `CMD` in Railway's service settings:

```
python -m identity.worker_main
```

This invokes `admin_gateway/identity/worker_main.py` via the module path.

**Do NOT use the default uvicorn CMD** (`python -m uvicorn admin_gateway.asgi:app ...`).
The worker has no HTTP server.

### Required environment variables

Set these in Railway's **Variables** tab for the `fg-identity-projection-worker` service.
Values are never committed to source control.

| Variable name | Description | Required |
|---------------|-------------|----------|
| `AUTH0_DOMAIN` | Auth0 tenant domain (e.g. `example.us.auth0.com`) | YES |
| `AUTH0_MGMT_CLIENT_ID` | Client ID of the **FrostGate Identity Projection Worker** M2M app | YES |
| `AUTH0_MGMT_CLIENT_SECRET` | Client secret of the M2M app | YES — SECRET |
| `AUTH0_MGMT_AUDIENCE` | Management API audience (`https://<domain>/api/v2/`) | YES |
| `AG_IDENTITY_DB_URL` | PostgreSQL connection string (Railway provides this via `DATABASE_URL` reference) | YES |
| `PROJECTION_WORKER_POLL_SECONDS` | Poll interval in seconds (default: `30`) | NO |

**Note on `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_AUDIENCE`, `AUTH0_CALLBACK_URL`,
`AUTH0_LOGOUT_RETURN_URL`**: These are used by the `admin_gateway` web service for OIDC
authentication flows.  The projection worker does NOT need them.  However, the current
`get_auth0_config()` function (used at worker startup) requires these vars because it
loads the full Auth0Config.  Until a dedicated minimal config loader is added, set these
vars to non-empty placeholder values or reuse the values from the main admin_gateway
service.  The worker only uses the `AUTH0_MGMT_*` fields at runtime.

### Restart policy

Set Railway restart policy to **Restart on failure** (automatic).  The worker process
exits non-zero on unrecoverable startup failures (missing env vars, bad config).  On
transient pass failures the worker logs and continues — it does NOT exit on retryable
errors.

### Replica count

Start with **1 replica**.  Multiple replicas are safe because the worker uses
`SELECT ... FOR UPDATE SKIP LOCKED` (PostgreSQL advisory row-level locking) plus
per-subject advisory locks (`pg_try_advisory_xact_lock`) to prevent concurrent
processing of the same outbox row.

---

## Health expectations

The worker has no HTTP health endpoint.  Railway monitors process liveness:

- **Healthy:** process is running and logging `worker_main.pass_complete` lines.
- **Degraded:** `worker_main.pass_failed` logged repeatedly — check DB connectivity.
- **Critical:** `worker_main.permanent_failure_threshold` logged — an outbox row has
  exceeded 10 delivery attempts and requires ops investigation (manual retry or removal).
- **Failed:** process exited with non-zero code — check startup logs for config errors.

### Log signals to monitor

| Log key | Meaning |
|---------|---------|
| `worker_main.starting` | Worker startup — shows config summary (no secrets) |
| `worker_main.ready` | Loop started, config validated |
| `worker_main.pass_complete` | Normal operation — shows rows_claimed, rows_succeeded, pending_backlog |
| `worker_main.pass_failed` | Transient error (DB connection lost) — will retry next poll |
| `worker_main.rate_limited` | Auth0 429 received — Retry-After honored |
| `worker_main.permanent_failure_threshold` | Row exceeded 10 attempts — ops action required |
| `worker_main.stopped` | Graceful shutdown complete |

---

## Deployment steps

1. Complete the Auth0 M2M Configuration section above.
2. In Railway dashboard, create a new service in the `fg-core` project.
3. Connect to the same GitHub repository as the `admin-gateway` service.
4. Set Root Directory to `admin_gateway/` and Dockerfile to `admin_gateway/Dockerfile`.
5. Override Start Command to `python -m identity.worker_main`.
6. Set all required environment variables (see table above).
7. Link the same Railway PostgreSQL database as the `admin-gateway` service via the
   `AG_IDENTITY_DB_URL` variable.
8. Deploy.  Confirm `worker_main.ready` appears in logs within 30 seconds.
9. Confirm `worker_main.pass_complete rows_claimed=0` appears every 30 seconds
   (or your configured poll interval) when no outbox rows are pending.
10. After deployment: trigger a role change for a test user and verify the outbox row
    transitions from `pending` → `processing` → `done` within one poll cycle.

---

## Security notes

- The worker never logs `Authorization` headers, `access_token`, `client_secret`,
  `id_token`, or `refresh_token`.
- Auth0 subject IDs are logged only as SHA-256 prefixes (`subject_hash=...`).
- No customer data, role values, or metadata payloads appear in error-level log lines.
- The M2M credential is held in memory only — never written to the database or outbox.
- Projection failure does NOT affect FrostGate canonical authorization.  The outbox
  row is retried; the `tenant_users` record is unchanged.

---

## Schema gap note (permanent failures)

The `identity_projection_outbox` schema (migration `0184`) only supports statuses:
`pending | processing | done | failed`.  There is no `terminal` / `dead` status.

Adding a terminal status requires a migration (0185+).  This is intentionally deferred.

The current implementation detects rows with `attempt_count >= 10` and logs `CRITICAL`
with `action=skip_visible_for_ops`.  These rows remain in the table and are visible to
ops queries.  They will not be retried by a healthy worker (the max-backoff puts
`next_attempt_at` far in the future), but they will not be automatically purged.

Ops procedure for permanently failed rows:
```sql
-- Inspect permanent failures
SELECT id, provider_subject, last_error_code, attempt_count, created_at
FROM identity_projection_outbox
WHERE status = 'pending' AND attempt_count >= 10;

-- After investigation, mark as done (if user no longer exists in Auth0)
-- or reset to pending (if Auth0 is now healthy) via direct DB update.
```
