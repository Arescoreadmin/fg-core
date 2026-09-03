# Platform Administrator Credential Authority

**P-113.6** — Canonical Platform Administrator Credential Authority  
**P-113.6.1** — Canonical Cutover Defect Fix  
**Status**: IMPLEMENTED (P-113.6.1 deployed)  
**Date**: 2026-09-03

## P-113.6.1 — Authentication Resolution Defect Fix

**Defect**: `verify_api_key_detailed()` in `api/auth_scopes/resolution.py` evaluated
legacy Path E (admin_internal_token) BEFORE canonical fgk.* credential validation. When
the Console BFF operated in CANONICAL mode (sending `X-API-Key=FG_PLATFORM_ADMIN_KEY`
which is an fgk.* credential), Path E fired first — its comparison
`FG_PLATFORM_ADMIN_KEY != FG_INTERNAL_GATEWAY_SECRET` failed — and returned
`AuthResult(valid=False)`, blocking canonical credential validation entirely.

**Fix**: `api/auth_scopes/resolution.py` now consults `api/platform_auth_mode.py`
(the canonical mode authority) before executing Path E logic:

- **CANONICAL mode**: Path E is fully skipped. The request falls through to
  canonical credential validation. Gateway provenance remains independently enforced
  by `require_internal_admin_gateway()` at the route layer.
- **COMPATIBILITY mode**: Path E only fires if `X-API-Key` does NOT start with `"fgk."`.
  A canonical fgk.* credential on an admin route skips Path E and proceeds to
  canonical validation. Non-fgk credentials on admin routes are still checked
  against `FG_INTERNAL_GATEWAY_SECRET` (fail-closed on mismatch).

**Key module added**: `api/platform_auth_mode.py` — single source of truth for
`PLATFORM_AUTH_MODE` in Core. Values: `COMPATIBILITY` (default) | `CANONICAL`.
Unknown values fail safe as `COMPATIBILITY` (+ warning log, never silent CANONICAL).

**Startup validation**: `api/config/startup_validation.py` now calls
`_check_platform_auth_mode()`, which validates that in CANONICAL mode:
- `FG_PLATFORM_ADMIN_KEY` is present
- `FG_INTERNAL_GATEWAY_SECRET` is present
- They are distinct values

**New test file**: `tests/test_platform_admin_credential_authority.py` — N01–N20
negative security tests + M01–M04 migration regression tests.  

## Purpose

This document is the normative reference for the canonical platform_admin
credential authority introduced in P-113.6. It defines:

- The separation of `TENANT_ASSIGNABLE_ROLES` and `PLATFORM_CREDENTIAL_ROLES`
- The bootstrap, rotation, and lifecycle endpoints
- The Path E (admin_internal_token) compatibility path and its retirement plan
- The Console BFF migration path (COMPATIBILITY → CANONICAL mode)
- The six security invariants that must never be violated

## Background

Before P-113.6, `platform.admin` authority was granted exclusively via Path E:
the Console BFF sent `FG_INTERNAL_GATEWAY_SECRET` as both `X-API-Key` and
`X-FG-Internal-Token`. The resolution layer recognised this combination and
issued an `admin_internal_token` AuthResult, which the API key identity provider
bridged to `roles_to_permissions(["platform_admin"])` = `ALL_PERMISSIONS`.

**Three defects were identified:**

- **Defect 1**: `platform_admin` was not in `VALID_ROLE_NAMES`, so `assign_role()`
  returned 422 for any attempt to store the role in `tenant_credential_roles`.
- **Defect 2**: `FG_PLATFORM_ADMIN_KEY` did not exist as a Railway variable;
  no bootstrap endpoint existed.
- **Defect 3**: The Console BFF sent `FG_INTERNAL_GATEWAY_SECRET` as both
  `X-API-Key` and `X-FG-Internal-Token`, conflating two distinct secrets.

## Role Namespace Separation (Defect 1 Fix)

`api/tenant_rbac.py` now defines three constants:

```python
TENANT_ASSIGNABLE_ROLES  # {governance_admin, analyst, auditor, read_only}
PLATFORM_CREDENTIAL_ROLES  # {tenant_admin, platform_admin}
VALID_ROLE_NAMES = TENANT_ASSIGNABLE_ROLES | PLATFORM_CREDENTIAL_ROLES
```

`BUILTIN_ROLES` remains the tenant-facing role list (for the `/rbac/roles` endpoint).
`VALID_ROLE_NAMES` is now a superset — the storage validation set.

**Security invariant**: `TENANT_ASSIGNABLE_ROLES ∩ PLATFORM_CREDENTIAL_ROLES = ∅`

## Bootstrap Endpoint (Defect 2 Fix)

```
POST /admin/system/platform-admin/bootstrap
```

- Requires `X-FG-Internal-Token` (satisfies `require_internal_admin_gateway()`)
- Requires `platform.admin` permission (satisfies `require_permission("platform.admin")`)
- Issues a `tenant_api_key` credential under `frostgate-internal` tenant,
  slot `platform-admin-credential:v1`, via `credential_authority.issue_credential()`
- Assigns `platform_admin` role via `tenant_rbac.assign_role()`
- Returns `plaintext_key` exactly once; idempotent (409 if active credential exists)

## Lifecycle Endpoints

```
GET    /admin/system/platform-admin          — check if active credential exists
POST   /admin/system/platform-admin/rotate   — rotate credential (new generation)
POST   /admin/system/platform-admin/suspend  — suspend (reversible)
POST   /admin/system/platform-admin/resume   — resume suspended credential
POST   /admin/system/platform-admin/revoke   — permanently revoke
```

All require `X-FG-Internal-Token` + `platform.admin` permission.

## Console BFF Migration (Defect 3 Fix)

`apps/console/app/api/core/[...path]/route.ts` introduces `PLATFORM_AUTH_MODE`:

### COMPATIBILITY mode (default, current production)

```
X-API-Key          = FG_INTERNAL_GATEWAY_SECRET
X-FG-Internal-Token = FG_INTERNAL_GATEWAY_SECRET
```

Path E in `resolution.py` recognises this combination and issues
`reason="admin_internal_token"` → `platform.admin` via the legacy scope bridge.

### CANONICAL mode (post-migration)

```
X-API-Key          = FG_PLATFORM_ADMIN_KEY   (canonical credential)
X-FG-Internal-Token = FG_INTERNAL_GATEWAY_SECRET
```

The canonical credential is verified via `credential_authority.validate_credential()`,
its role (`platform_admin`) is resolved via `roles_to_permissions(["platform_admin"])`,
and `platform.admin` is granted.

**Migration checklist for CANONICAL mode:**
1. Run `POST /admin/system/platform-admin/bootstrap` to issue the credential.
2. Record the `plaintext_key` (shown exactly once).
3. Set `FG_PLATFORM_ADMIN_KEY=<plaintext_key>` in Railway console-bff service.
4. Set `PLATFORM_AUTH_MODE=CANONICAL` in Railway console-bff service.
5. Verify `FG_PLATFORM_ADMIN_KEY != FG_INTERNAL_GATEWAY_SECRET`.
6. Run `test_client_production_e2e_002.py` with `FG_LIVE_PROOF=1`.

## Path E — Legacy Compatibility (Retirement Plan)

Path E lives in `api/auth_scopes/resolution.py`, annotated with a retirement comment.

**Retirement sequence:**
1. All production environments switch to CANONICAL mode.
2. Verify production stability for ≥30 days.
3. Delete the Path E block from `resolution.py`.
4. Remove `FG_INTERNAL_GATEWAY_SECRET` from `X-API-Key` assignment in route.ts.

**DO NOT remove Path E before completing CANONICAL migration.** Removing it
prematurely breaks all console BFF admin operations in COMPATIBILITY mode.

## Security Invariants

These must NEVER be violated:

| # | Invariant |
|---|-----------|
| I-1 | `platform_admin` must NOT become tenant-self-assignable (`TENANT_ASSIGNABLE_ROLES` exclusion) |
| I-2 | PSP must NOT gain `platform.admin` (`PSP_CREDENTIAL_SCOPES` exclusion) |
| I-3 | `CORE_API_KEY` wildcard (`'*'`) must NOT grant `platform.admin` via `_permissions_from_legacy_scopes` |
| I-4 | `FG_INTERNAL_GATEWAY_SECRET` alone must NOT suffice for `platform.admin` in CANONICAL mode |
| I-5 | No direct SQL credential issuance — all writes go through `credential_authority.issue_credential()` |
| I-6 | `VALID_ROLE_NAMES` expansion must not widen any existing self-service endpoint |

## DB Migration

No new migration is required. The platform_admin credential is stored in existing tables:
- `tenant_credentials` — credential record under `frostgate-internal` tenant
- `tenant_credential_roles` — `platform_admin` role assignment
- `tenant_credential_events` — lifecycle audit trail

The `frostgate-internal` tenant was created in migration 0157. No new tables are needed.

## Resolution Chain

```
FG_PLATFORM_ADMIN_KEY (canonical credential)
  ↓ verify_api_key_detailed() → reason="credential_key"
  ↓ extract_api_key_actor()
  ↓ get_credential_role(tenant_id="frostgate-internal", credential_id=...)
  ↓ returns "platform_admin"
  ↓ roles_to_permissions(["platform_admin"])
  ↓ ALL_PERMISSIONS  ∋  "platform.admin"
```

## Audit Events

The platform_admin credential lifecycle generates audit records in two tables.

### `tenant_credential_events` (via CredentialAuthority — automatic)

| Operation | event_type | Table |
|-----------|-----------|-------|
| Bootstrap (issuance) | `issued` | `tenant_credential_events` |
| Rotation | `rotated` | `tenant_credential_events` |
| Suspension | `suspended` | `tenant_credential_events` |
| Resumption | `resumed` | `tenant_credential_events` |
| Revocation | `revoked` | `tenant_credential_events` |

Each record contains: `credential_id`, `credential_slot`, `generation`, `actor_id`,
`request_id`, `occurred_at`, `outcome`. No secret material.

### `internal_platform_authority_events` (explicit — bootstrap and lifecycle)

The bootstrap, rotate, and revoke endpoints additionally emit to
`internal_platform_authority_events` for unambiguous platform-level audit:

| Operation | event_type | Rationale |
|-----------|-----------|-----------|
| Bootstrap | `bootstrap_created` | Distinguishes platform_admin bootstrap from routine issuance |
| Rotation | `credential_rotated` | Visible in platform-level audit trail alongside bootstrap |
| Revocation | `credential_revoked` | Marks terminal platform_admin authority change |

Suspend and resume are recorded in `tenant_credential_events` only (not terminal operations;
no platform-level audit entry added to avoid duplication).

### `tenant_credential_role_audit` (via assign_role — automatic)

`assign_role()` appends an immutable record for every `platform_admin` role assignment:
bootstrap (initial assignment) and rotate (role carried to new generation both emit records).

Fields: `event_id`, `tenant_id`, `actor_key_prefix`, `action=assign_role`,
`target_credential_id`, `role_name=platform_admin`, `timestamp`, `success`.

---

## Path E — Retirement Plan (Phase 14)

Path E is the legacy compatibility authentication path where `X-API-Key == X-FG-Internal-Token == FG_INTERNAL_GATEWAY_SECRET`.
Located in `api/auth_scopes/resolution.py` as the `admin_internal_token` block.

**Retirement is BLOCKED until ALL five conditions are met simultaneously:**

| # | Condition | How to verify |
|---|-----------|---------------|
| C1 | Canonical platform_admin credential bootstrapped in all environments (prod, staging, CI) | `GET /admin/system/platform-admin` returns `exists=true` in each env |
| C2 | `FG_PLATFORM_ADMIN_KEY` stored in Railway (api, admin-gateway) and Vercel (console) | Check all three service environment variable panels |
| C3 | Console BFF `PLATFORM_AUTH_MODE=CANONICAL` deployed and stable | Vercel deployment logs show CANONICAL mode; no `[STARTUP_FATAL]` warnings |
| C4 | E2E-002 T1 live proof passes with `FG_PLATFORM_ADMIN_KEY != FG_INTERNAL_GATEWAY_SECRET` | `pytest tests/test_client_production_e2e_002.py` with `FG_LIVE_PROOF=1` exits 0 |
| C5 | 30-day production observation: zero `admin_internal_token` reliance in logs for `platform.admin` | Railway log filter: `reason=admin_internal_token` count → 0 over 30 days |

**Retirement PR:** `feat/platform-admin-path-e-retirement`

When all 5 conditions are met:
1. Delete the `admin_internal_token` detection block from `api/auth_scopes/resolution.py`
2. Remove the COMPATIBILITY fallback from `route.ts`
3. Remove `PLATFORM_AUTH_MODE` env var from Railway/Vercel (CANONICAL is now the only mode)
4. Update this document to mark Path E as `RETIRED`

**DO NOT remove Path E before all 5 conditions are met and documented.**

---

## Production Rollout Runbook (Phase 17)

This is the post-merge operator procedure. **Do not execute during implementation.**
All steps are non-destructive and reversible (except the revoke-to-recover path).

### STAGE 1 — Deploy code (COMPATIBILITY mode active, no production change)

```bash
# After PR merges to main, Railway and Vercel auto-deploy.
# Console BFF uses COMPATIBILITY mode by default — same behavior as before.
# Verify all services healthy before proceeding.
```

### STAGE 2 — Bootstrap canonical platform_admin credential

```bash
# Use Path E (gateway secret both headers) to call bootstrap.
# Run in a shell with no history, or pipe directly to the secret manager.
curl -s -X POST https://api.frostgate.ai/admin/system/platform-admin/bootstrap \
  -H "X-API-Key: ${FG_INTERNAL_GATEWAY_SECRET}" \
  -H "X-FG-Internal-Token: ${FG_INTERNAL_GATEWAY_SECRET}" \
  | jq '{"credential_id": .credential_id, "status": .status}'
# Record credential_id. Store plaintext_key securely — it is NOT retrievable again.
```

### STAGE 3 — Store plaintext in secret managers (no echo, no shell history)

Set `FG_PLATFORM_ADMIN_KEY` = `<plaintext_key>` in:
- Railway → api service → Variables
- Railway → admin-gateway service → Variables
- Vercel → console.frostgate.ai → Environment Variables (Production)

Also set `PLATFORM_AUTH_MODE=CANONICAL` in:
- Vercel → console.frostgate.ai → Environment Variables (Production)

### STAGE 4 — Redeploy affected services

```bash
# Railway: trigger redeploy for api and admin-gateway
# Vercel: trigger redeploy for console.frostgate.ai
# Monitor logs for [STARTUP_FATAL] — should be absent
```

### STAGE 5 — Verify credential separation

```bash
# Must be distinct non-empty values:
[[ -n "${FG_PLATFORM_ADMIN_KEY}" ]] && \
[[ -n "${FG_INTERNAL_GATEWAY_SECRET}" ]] && \
[[ "${FG_PLATFORM_ADMIN_KEY}" != "${FG_INTERNAL_GATEWAY_SECRET}" ]] && \
echo "CREDENTIAL_SEPARATION: PASS" || echo "CREDENTIAL_SEPARATION: FAIL"
```

### STAGE 6 — Non-mutating smoke test (T1 canonical path)

```bash
curl -s -o /dev/null -w "%{http_code}" \
  -H "X-API-Key: ${FG_PLATFORM_ADMIN_KEY}" \
  -H "X-FG-Internal-Token: ${FG_INTERNAL_GATEWAY_SECRET}" \
  https://api.frostgate.ai/admin/system/service-principal
# Expected: 200
```

### STAGE 7 — Run E2E-002 Phase 0 (T1 proof, non-mutating)

```bash
FG_LIVE_PROOF=1 \
FG_PLATFORM_ADMIN_KEY="${FG_PLATFORM_ADMIN_KEY}" \
FG_INTERNAL_GATEWAY_SECRET="${FG_INTERNAL_GATEWAY_SECRET}" \
FG_CORE_API_URL="https://api.frostgate.ai" \
.venv/bin/python -m pytest tests/test_client_production_e2e_002.py \
  -k "phase_0" -v
# Expected: PASS — T1 assertion green including FG_PLATFORM_ADMIN_KEY != FG_INTERNAL_GATEWAY_SECRET
```

### STAGE 8 — Run complete E2E-002 live proof

Follow `docs/architecture/client-production-e2e-002.md` (MP-001/MP-002 manual proofs required first).

### STAGE 9 — Monitor Path E retirement gate (30-day window, condition C5)

Begin clock for condition C5. After 30 days with zero `admin_internal_token` reliance,
file `feat/platform-admin-path-e-retirement` PR.

### Recovery — if FG_PLATFORM_ADMIN_KEY is lost

```bash
# Step 1: Revoke existing credential via Path E
curl -s -X POST https://api.frostgate.ai/admin/system/platform-admin/revoke \
  -H "X-API-Key: ${FG_INTERNAL_GATEWAY_SECRET}" \
  -H "X-FG-Internal-Token: ${FG_INTERNAL_GATEWAY_SECRET}"
# Expected: 200 {"action": "revoked"}

# Step 2: Re-bootstrap (idempotency guard cleared by revocation)
curl -s -X POST https://api.frostgate.ai/admin/system/platform-admin/bootstrap \
  -H "X-API-Key: ${FG_INTERNAL_GATEWAY_SECRET}" \
  -H "X-FG-Internal-Token: ${FG_INTERNAL_GATEWAY_SECRET}"
# Expected: 201 {"status": "bootstrapped", "plaintext_key": "fgk...."}
# Resume from STAGE 3.
```

This recovery path uses Path E intentionally — it is the authorized break-glass mechanism.
The event is recorded in `internal_platform_authority_events` with `event_type=credential_revoked`
and `event_type=bootstrap_created`, providing a complete audit trail without SQL access.

---

## Files Changed (P-113.6)

- `api/tenant_rbac.py` — `TENANT_ASSIGNABLE_ROLES`, `PLATFORM_CREDENTIAL_ROLES`, expanded `VALID_ROLE_NAMES`
- `api/admin.py` — bootstrap + lifecycle endpoints, Pydantic models, audit event emission
- `api/auth_scopes/resolution.py` — Path E retirement comment
- `apps/console/app/api/core/[...path]/route.ts` — `PLATFORM_AUTH_MODE`, `FG_PLATFORM_ADMIN_KEY`, header separation
- `tests/test_platform_admin_authority_p1136.py` — negative security test matrix (N-01 through N-16)
- `tests/test_platform_admin_authority_invariant.py` — authority invariant tests (I-01 through I-15)
- `tests/test_tenant_rbac.py` — updated `test_valid_role_names_covers_all_builtins` to reflect namespace expansion

## Files Changed (P-113.6.1)

- `api/platform_auth_mode.py` — **NEW** canonical `PLATFORM_AUTH_MODE` resolver for Core
- `api/auth_scopes/resolution.py` — Path E corrected semantics (mode-aware, fgk.* skip)
- `api/config/startup_validation.py` — `_check_platform_auth_mode()` startup validation
- `tests/test_platform_admin_credential_authority.py` — **NEW** N01–N20 + M01–M04 tests
