# FrostGate Tester Quickstart

End-to-end tester path for the FrostGate Admin Gateway.  
No manual DB access. No hidden steps. No shell hacks beyond documented commands.

---

## Canonical Tester Journey (Quick Path)

This is the minimum-viable path that proves the system works end-to-end. Execute top-to-bottom.

**Required env:**

```
FG_ENV=dev
FG_DEV_AUTH_BYPASS=1
FG_DEV_AUTH_TENANT_ID=tenant-seed-primary
FG_DEV_AUTH_TENANTS=tenant-seed-primary
FG_SQLITE_PATH=state/frostgate.db
AG_CORE_BASE_URL=http://localhost:8000
```

### CTJ-1: Seed the system

```bash
python tools/seed/run_seed.py
```

Captures from output (or from state file after first run):

```bash
EXPORT_PATH=$(python -c "import json; d=json.load(open('state/seed/bootstrap_state.json')); print(d['export_path'])")
SEED_SESSION_ID=$(python -c "import json; d=json.load(open('state/seed/bootstrap_state.json')); print(d['session_id'])")
```

Expected: JSON output with `"status": "seeded"` (or `"already_seeded"`), `session_id`, and `export_path`.

**Checkpoint:** `state/seed/bootstrap_state.json` exists. Audit cycle ran. Evidence bundle exported.

### CTJ-2: Create an audit API key

The seed admin key (`seedadmin_`) has `decisions:read,defend:write,ingest:write` scopes only. The audit proxy endpoints require `audit:read`. Create a scoped key:

```bash
AUDIT_KEY=$(python -c "
import os
os.environ.setdefault('FG_SQLITE_PATH', 'state/frostgate.db')
from api.auth_scopes import mint_key
print(mint_key('audit:read', 'audit:export', tenant_id='tenant-seed-primary', ttl_seconds=86400))
")
echo "Audit key: $AUDIT_KEY"
```

**Checkpoint:** `AUDIT_KEY` is set (format: `fgk.<base64>.<secret>`).

### CTJ-3: Start services

**Core API:**

```bash
export FG_SQLITE_PATH=state/frostgate.db
export FG_ADMIN_KEY=seedadmin_primary_key_000000000000
export FG_AGENT_KEY=seedagent_primary_key_000000000000
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

**Admin gateway** (in a separate terminal, with audit key):

```bash
export AG_CORE_BASE_URL=http://localhost:8000
export AG_CORE_API_KEY=$AUDIT_KEY
uvicorn admin_gateway.asgi:app --host 0.0.0.0 --port 8100
```

**Checkpoint:** `curl -s http://localhost:8100/health | python -m json.tool` → `"status": "ok"`.

### CTJ-4: Authenticate

```bash
curl -s -c cookies.txt -L http://localhost:8100/auth/login -o /dev/null -w "%{http_code}"
```

Expected: `200`

**Checkpoint:** `cookies.txt` contains a session cookie.

### CTJ-5: Retrieve audit log (proves seed data is visible)

```bash
curl -s -b cookies.txt \
  "http://localhost:8100/admin/audit/search?tenant_id=tenant-seed-primary&page_size=5" \
  | python -m json.tool
```

Expected: `200` with `items` array. At least one entry from the seed authentication and audit cycle.

**Checkpoint:** `items` array is non-empty. Tenant isolation: all items have `tenant_id = "tenant-seed-primary"`.

### CTJ-6: Export audit bundle (retrieve result)

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8100/admin/audit/export \
  -H "Content-Type: application/json" \
  -d '{"format":"json","tenant_id":"tenant-seed-primary","page_size":100}' \
  -o /tmp/audit_export.ndjson
echo "Exit: $?"
```

Expected: exit 0, `/tmp/audit_export.ndjson` written (Content-Type: application/x-ndjson).

**Checkpoint:** File is non-empty. Each line is a valid JSON object.

```bash
head -1 /tmp/audit_export.ndjson | python -m json.tool
```

### CTJ-7: Reproduce and verify evidence bundle

The seed ran `engine.run_cycle()` and stored the evidence bundle at `$EXPORT_PATH`. Verify its integrity:

```bash
python tools/verify_bundle.py --bundle "$EXPORT_PATH"
```

Expected output:

```
============================================================
FrostGate Evidence Bundle Verifier
...
Result: PASS: N passed, 0 failed
============================================================
```

**Checkpoint:** Exit code 0. Zero failures. `Merkle (actual)` matches `Merkle (stored)`.

This proves:
- Seed ran correctly (audit cycle completed)
- Evidence chain is intact (hash linkage verified)
- Tenant isolation holds (all events scoped to `tenant-seed-primary`)
- Export is reproducible (deterministic Merkle root)

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.12+ |
| Virtual environment | `.venv/` at repo root (see setup below) |
| Postman | Any version supporting Collection v2.1 |

### One-time environment setup

```bash
# From repo root
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Step 1 — Seed the System

Run the canonical bootstrap script. This is idempotent: safe to re-run.

```bash
python tools/seed/run_seed.py
```

Expected output (JSON):

```json
{
  "export_path": "state/seed/...",
  "registry_path": "state/tenants.json",
  "session_id": "<uuid>",
  "sqlite_path": "state/frostgate.db",
  "status": "seeded",
  "tenant_id": "tenant-seed-primary"
}
```

If `"status": "already_seeded"` appears, the environment was already bootstrapped. This is expected and correct.

**What the seed creates:**

| Resource | Value |
|---|---|
| Tenant ID | `tenant-seed-primary` |
| Admin API key prefix | `seedadmin_` |
| Agent API key prefix | `seedagent_` |
| SQLite database | `state/frostgate.db` |
| Tenant registry | `state/tenants.json` |

> The admin/agent API keys are for direct core API access. The admin gateway uses session-cookie auth (OIDC or dev bypass). The keys are not used in this tester flow.

---

## Step 2 — Start the Admin Gateway

### Environment variables (dev mode)

```bash
export FG_ENV=dev
export FG_DEV_AUTH_BYPASS=1
export FG_DEV_AUTH_TENANT_ID=tenant-seed-primary
export FG_DEV_AUTH_TENANTS=tenant-seed-primary
export AG_CORE_BASE_URL=http://localhost:8000   # core API address
export AG_CORE_API_KEY=seedadmin_primary_key_000000000000
```

### Start the gateway

```bash
source .venv/bin/activate
uvicorn admin_gateway.asgi:app --host 0.0.0.0 --port 8100 --reload
```

Verify the gateway is up:

```bash
curl -s http://localhost:8100/health | python -m json.tool
```

Expected:

```json
{
  "status": "ok",
  "service": "admin-gateway",
  "version": "0.2.0",
  "timestamp": "...",
  "request_id": "..."
}
```

---

## Step 3 — Start the Core API (required for proxied routes)

The admin gateway proxies audit, key, and tenant routes to the core API. Skip this step only if you are testing gateway-only routes (health, auth, products).

```bash
export FG_ENV=dev
export FG_AUTH_ENABLED=1
export FG_SQLITE_PATH=state/frostgate.db
export FG_ADMIN_KEY=seedadmin_primary_key_000000000000
export FG_AGENT_KEY=seedagent_primary_key_000000000000

uvicorn api.main:app --host 0.0.0.0 --port 8000
```

---

## Step 4 — Authenticate via Admin Gateway

The admin gateway uses session-cookie authentication. In dev mode (dev bypass), a session cookie is issued automatically at login with no OIDC setup required.

### Option A — Browser

Navigate to:

```
http://localhost:8100/auth/login
```

The gateway redirects to `/admin/me` and sets a signed session cookie automatically.

### Option B — Postman

Import `docs/tester_collection.json`. Run the **"Login (Dev Bypass)"** request.  
Postman follows the 302 redirect and stores the session cookie via its Cookie Jar.  
**Enable "Automatically follow redirects" in Postman settings** (default: on).

### Option C — curl

```bash
# Store cookies to a jar
curl -s -c cookies.txt -L http://localhost:8100/auth/login
# Verify session is active
curl -s -b cookies.txt http://localhost:8100/admin/me | python -m json.tool
```

Expected `/admin/me` response:

```json
{
  "user_id": "dev-user",
  "email": "dev@localhost",
  "scopes": ["console:admin"],
  "tenants": ["tenant-seed-primary"],
  "current_tenant": "tenant-seed-primary",
  "session_id": "...",
  "expires_in": 3600
}
```

> `console:admin` expands to all scopes: `product:read`, `product:write`, `keys:read`, `keys:write`, `audit:read`, `policies:write`.

---

## Step 5 — Execute the Primary Journey

Run requests in the order shown. In Postman, use the collection runner or run manually top-to-bottom.

### 5.1 Get a CSRF Token (required before write operations)

```
GET /admin/csrf-token
```

In Postman: the collection test script extracts `csrf_token` and stores it in `{{csrf_token}}` automatically.

In curl:

```bash
CSRF=$(curl -s -b cookies.txt http://localhost:8100/admin/csrf-token | python -c "import sys,json; print(json.load(sys.stdin)['csrf_token'])")
```

### 5.2 List Accessible Tenants

```
GET /admin/tenants
```

Expected: `{"tenants": [{"id": "tenant-seed-primary", "name": "tenant-seed-primary"}], "total": 1}`

### 5.3 Get Tenant Usage

```
GET /admin/tenants/tenant-seed-primary/usage
```

Proxied to core. Expected: usage counters (`request_count`, `decision_count`, `quota_remaining`).

### 5.4 List API Keys

```
GET /admin/keys?tenant_id=tenant-seed-primary
```

Proxied to core. Expected: key list with `seedadmin_` and `seedagent_` prefixes.

### 5.5 Search Audit Log

```
GET /admin/audit/search?tenant_id=tenant-seed-primary&page_size=25
```

Proxied to core. Expected: audit events from the seed bootstrap (run_cycle, export_bundle) and from the steps above.

### 5.6 Export Audit Events

```
POST /admin/audit/export
Content-Type: application/json

{
  "format": "json",
  "tenant_id": "tenant-seed-primary",
  "page_size": 100
}
```

Expected: streaming NDJSON response with `Content-Disposition: attachment; filename=...`.

For CSV:

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8100/admin/audit/export \
  -H "Content-Type: application/json" \
  -d '{"format":"csv","tenant_id":"tenant-seed-primary","page_size":100}' \
  -o audit_export.csv
```

---

## Step 6 — Optional: Product Registry

Products require the `X-Tenant-ID` header and CSRF token for write operations.

### List products

```bash
curl -s -b cookies.txt \
  -H "X-Tenant-ID: tenant-seed-primary" \
  http://localhost:8100/admin/products | python -m json.tool
```

### Create a product (requires CSRF token)

```bash
curl -s -b cookies.txt \
  -X POST http://localhost:8100/admin/products \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: tenant-seed-primary" \
  -H "X-CSRF-Token: $CSRF" \
  -d '{
    "slug": "tester-product",
    "name": "Tester Product",
    "env": "development",
    "enabled": true,
    "endpoints": []
  }' | python -m json.tool
```

Expected: `201 Created` with the product object. Repeating returns `409 Conflict` (slug uniqueness enforced per tenant).

---

## Environment Reference

| Variable | Required | Default | Notes |
|---|---|---|---|
| `FG_ENV` | Yes | — | `dev` for dev mode; `prod`/`staging` enforce OIDC |
| `FG_DEV_AUTH_BYPASS` | Yes (dev only) | `0` | Set to `1` to enable dev session; forbidden in prod |
| `FG_DEV_AUTH_TENANT_ID` | No | `default` | Default tenant for dev session |
| `FG_DEV_AUTH_TENANTS` | No | (empty) | Comma-separated allowed tenants for dev session |
| `AG_CORE_BASE_URL` | Yes (proxied routes) | — | Core API address, e.g. `http://localhost:8000` |
| `AG_CORE_API_KEY` | Yes (proxied routes) | — | Core API key for gateway→core calls |
| `FG_SQLITE_PATH` | Core only | `state/frostgate.db` | Overridable via env |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `GET /health` → connection refused | Gateway not started | Run uvicorn command in Step 2 |
| `GET /admin/me` → 401 | Session cookie missing | Re-run `GET /auth/login` |
| `POST /admin/products` → 403 | CSRF token missing or stale | Run `GET /admin/csrf-token` and retry |
| `GET /admin/keys` → 503 | Core API not reachable | Set `AG_CORE_BASE_URL` correctly and start core API (Step 3) |
| `GET /admin/audit/search` → 503 | Core API not reachable | Same as above |
| Seed fails with `SEED_CONFLICT` | DB state conflicts with env | Clear `state/` directory and re-run `run_seed.py` |
| `FG_DEV_AUTH_BYPASS=1` but 503 on login | OIDC partially configured | Unset all `FG_OIDC_*` and `FG_KEYCLOAK_*` vars |

---

## Production Auth (Non-Dev)

In production (`FG_ENV=prod`), dev bypass is forbidden. Auth uses OIDC:

1. Configure `FG_OIDC_*` or `FG_KEYCLOAK_*` environment variables.
2. For machine-to-machine: obtain an OIDC access token from your IdP using `client_credentials` flow, then exchange it:
   ```
   POST /auth/token-exchange
   Authorization: Bearer <access_token>
   ```
   Returns a session cookie and `{"session_id", "expires_in", "user_id"}`.
3. For human users: `GET /auth/login` redirects to the IdP login page. After authentication, the IdP redirects back to `GET /auth/callback`, which issues the session cookie.

---

## Collection Import

1. Open Postman.
2. Click **Import** → select `docs/tester_collection.json`.
3. Set collection variable `base_url` to match your gateway address (default: `http://localhost:8100`).
4. Run requests in folder order (1 through 7).

The collection does not reference any internal, debug, or direct core API routes.
