# CLIENT-PRODUCTION-E2E-002 Runbook

**Proof:** Complete FrostGate client lifecycle through canonical product boundaries  
**File:** `tests/test_client_production_e2e_002.py`  
**Evidence schema:** `contracts/artifacts/identity/client-production-e2e-002-evidence.json`  
**Runtime evidence:** `contracts/artifacts/identity/client-production-e2e-002-evidence-runtime.json` (gitignored)

---

## Authority Map

### T1 — Platform Admin

| Credential | Header | Value |
|---|---|---|
| `FG_PLATFORM_ADMIN_KEY` | `X-API-Key` | Platform admin key with `platform_admin` role |
| `FG_INTERNAL_GATEWAY_SECRET` | `X-FG-Internal-Token` | Internal gateway trust secret |

**These two values MUST be distinct.** Never use the PSP credential as `FG_PLATFORM_ADMIN_KEY` — `PSP_CREDENTIAL_SCOPES` intentionally excludes `platform.admin` (see `api/platform_service_principal.py:67-73`).

**Routes (all `/admin/*` — require both headers):**

| Operation | Route | File |
|---|---|---|
| Create tenant | `POST /admin/tenants` | `api/admin.py:1353` |
| Suspend tenant | `POST /admin/tenants/{id}/suspend` | `api/admin.py:693` |
| Activate tenant | `POST /admin/tenants/{id}/activate` | `api/admin.py:746` |
| Lifecycle eval | `GET /admin/tenants/{id}/lifecycle` | `api/tenant_admin.py:962` |
| Bootstrap admin | `POST /admin/tenants/{id}/bootstrap-admin` | `api/tenant_admin.py:322` |
| **BOUNDARY** | `GET /admin/tenants/{id}/users` | Returns **403** for platform.admin — no bypass |

### T2 — Bound Human OIDC Token

| Credential | Header | Value |
|---|---|---|
| `FG_TENANT_ADMIN_TOKEN` | `Authorization: Bearer` | Post-OIDC token from admin session |
| `FG_INTERNAL_GATEWAY_SECRET` | `X-FG-Internal-Token` | Internal gateway trust secret |

**Requires:** `require_tenant_admin()` — active, bound `tenant_admin` row in `tenant_users` (`principal_id IS NOT NULL`). A service credential CANNOT satisfy this.

**Routes:**

| Operation | Route | File |
|---|---|---|
| List users | `GET /admin/tenants/{id}/users` | `api/tenant_admin.py:446` |
| Invite user | `POST /admin/tenants/{id}/users/invite` | `api/tenant_admin.py:501` |
| Update user | `PATCH /admin/tenants/{id}/users/{uid}` | `api/tenant_admin.py:589` |
| Issue credential | `POST /admin/tenants/{id}/credential-administration` | `api/tenant_admin.py:1060` |
| Rotate credential | `POST /admin/tenants/{id}/credential-administration/{cid}/rotate` | `api/tenant_admin.py:1145` |
| Suspend credential | `POST /admin/tenants/{id}/credential-administration/{cid}/suspend` | `api/tenant_admin.py:1220` |
| Resume credential | `POST /admin/tenants/{id}/credential-administration/{cid}/resume` | `api/tenant_admin.py:1251` |
| Revoke credential | `DELETE /admin/tenants/{id}/credential-administration/{cid}` | `api/tenant_admin.py:1185` |

### T3 — Tenant Service Credential

Issued via T2 in Phase 9. Requires `admin:write` scope + `identity.scim` capability.

| Operation | Route | File |
|---|---|---|
| Update user | `PATCH /workforce/users/{uid}` | `api/workforce.py:411` |
| Revoke user | `POST /workforce/users/{uid}/revoke` | `api/workforce.py:622` |

**T3 capability is verified empirically in Phase 9** — the result is recorded as `T3_VERIFIED` or `T3_NOT_SUPPORTED`. Do not assume the outcome. Do not weaken `require_capability()` if T3 fails.

---

## Lifecycle State Machine

```
tenant_not_found
    ↓ POST /admin/tenants
admin_unset
    ↓ POST /admin/tenants/{id}/bootstrap-admin
admin_unbound
    ↓ OIDC binding (Manual Proof MP-001/MP-002)
operational
    ↓ POST /admin/tenants/{id}/suspend
tenant_suspended   ← overrides all other states
    ↓ POST /admin/tenants/{id}/activate
operational | admin_unbound (depending on admin binding state)
```

**Blocker codes:** `TENANT_NOT_FOUND`, `TENANT_SUSPENDED`, `NO_BOUND_ADMIN`

---

## Loading Credentials

Load credentials from environment only. Never hardcode values in tests or scripts.

```bash
# Required for T1 (platform admin operations)
export FG_PLATFORM_ADMIN_KEY="<platform admin key with platform_admin role>"
export FG_INTERNAL_GATEWAY_SECRET="<internal gateway trust secret>"

# Required for T2 (tenant admin operations — obtained after MP-001)
export FG_TENANT_ADMIN_TOKEN="<post-OIDC Bearer token>"

# Required for all live proof runs
export FG_LIVE_PROOF=1
export FG_WRITE_EVIDENCE=1
export FG_CORE_API_URL="https://api.frostgate.ai"

# Optional — enables projection worker health check in Phase 0
export FG_ADMIN_GATEWAY_URL="https://admin-gateway.frostgate.ai"
```

**Invariant:** `FG_PLATFORM_ADMIN_KEY` MUST NOT equal `FG_INTERNAL_GATEWAY_SECRET`. The harness asserts this before any mutation.

---

## Phase-by-Phase Execution Guide

### Phase 0 — Safety Preflight

**What it does:** Verifies reachability, dual-credential auth chain, cleanup path routability, and no tenant ID prefix collision before any mutation.

**Automated checks:**
- `GET /admin/system/service-principal` → 200 (proves both credentials are wired)
- `POST /admin/tenants/{sentinel}/suspend` → 404 (proves cleanup path routable)
- `GET /admin/tenants/{CLIENT_A_ID}/lifecycle` → 404 (proves no collision)
- `GET /admin/tenants/{CLIENT_B_ID}/lifecycle` → 404 (proves no collision)
- Admin gateway health (if `FG_ADMIN_GATEWAY_URL` set)

**Failure action:** If Phase 0 fails, DO NOT proceed. Check credentials and URL.

---

### Phase 1 — Create Client A

**What it does:** `POST /admin/tenants` → verify lifecycle = `admin_unset`.

---

### Phase 2 — Create Client B

**What it does:** Same as Phase 1, plus verify no state leakage from A.

---

### Phase 3 — Bootstrap Admins

**What it does:** `POST /admin/tenants/{id}/bootstrap-admin` for A and B. After this, lifecycle = `admin_unbound` (unbound admin row exists; OIDC binding not complete).

Bootstrap is idempotent — re-calling returns the same or a new admin row.

---

### Phase 4 — Identity Binding (MANUAL_PROOF boundary)

**What it does:** Records MP-001 and MP-002. Checks for `FG_TENANT_ADMIN_TOKEN`.

If `FG_TENANT_ADMIN_TOKEN` is not set, Phase 4 records `MANUAL_PROOF_REQUIRED` and returns without failing. All subsequent T2 phases (5–13) will skip gracefully.

#### MP-001: Auth0 Org Config + Admin OIDC for Tenant A

**Complete this before starting the test run.** The harness runs as a single uninterrupted session; tenant IDs are generated at process start and cannot be carried across separate pytest invocations.

1. In Auth0 Dashboard → Organizations → Create an organization for the proof tenant
2. Enable the FrostGate Auth0 application on the organization
3. Configure `tenant_id` metadata on the Auth0 organization matching the proof tenant ID
4. Navigate to your Auth0 application login URL scoped to the organization
   - Direct login URL format: `https://<auth0-domain>/authorize?organization=<org_id>&...`
   - **Note:** `POST /admin/tenants/{id}/bootstrap-admin` does NOT return an `invitation_url` — Auth0 org configuration is a separate platform-operator step
5. Sign in with `jcosat0211@gmail.com` via Auth0 Google OAuth flow
6. Verify binding: `GET /admin/tenants/{CLIENT_A_ID}/users` → `identity_binding_status=bound`
7. Capture the bound session Bearer token → `export FG_TENANT_ADMIN_TOKEN=<token>`
8. Confirm lifecycle: `GET /admin/tenants/{CLIENT_A_ID}/lifecycle` → `operational`

#### MP-002: Auth0 Org Config + Admin OIDC for Tenant B

Same steps as MP-001 for `{CLIENT_B_ID}`. Both must be completed before the full run.

#### Single-session execution

The proof is designed to run as **one uninterrupted pytest session** after all manual steps are complete. Restarting mid-proof regenerates tenant IDs and invalidates all prior state.

Workflow:
1. Complete Auth0 org setup for both proof tenants (MP-001 + MP-002)
2. Set all credentials including `FG_TENANT_ADMIN_TOKEN`
3. Run the full suite in a single invocation (see execution commands below)

---

### Phase 5 — Client Operational

**What it does:** `GET /admin/tenants/{id}/lifecycle` → `operational` for both A and B (requires OIDC binding complete).

---

### Phase 6 — Create Workforce Users + T3 Verification

**What it does:**
- Invites `analyst`, `auditor`, and `second_admin` via T2 (`POST /admin/tenants/{id}/users/invite`)
- Verifies list users returns all invited users
- Attempts T3 credential capability verification (deferred — credential issued first in Phase 9)

**T3 capability note:** The issued service credential (`analyst` role) attempts `PATCH /workforce/users/{uid}`. The result is recorded without assuming outcome:
- `T3_VERIFIED` — `identity.scim` capability satisfied; workforce update succeeded
- `T3_NOT_SUPPORTED` — 403 from `require_capability("identity.scim")` — credential lacks the capability

---

### Phase 7 — Role Administration

**What it does:** Verifies T1 lifecycle read authority and T2 list-users authority. Role boundary enforcement (analyst/auditor denial) is verified via credential-level checks in Phase 9.

---

### Phase 8 — Tenant Isolation (HARD GATE)

**What it does:** Verifies cross-tenant isolation. Any failure here immediately sets `overall_verdict=NOT_PROVEN` and raises `ProofFailure` with `TENANT_ISOLATION_FAILURE` classification.

**Checks:**
- `GET /admin/tenants/A/users` with T1 headers → must be 403
- `GET /admin/tenants/B/users` with T1 headers → must be 403
- `GET /admin/tenants/B/users` with T2 (A's token) headers → must be 403 or 404

**On failure:** Stop. The isolation invariant is broken. Report the exact route, actor, expected/actual codes. Do not merge.

---

### Phase 9 — Credential Lifecycle

**What it does:** Full credential lifecycle via T2:
1. `POST /credential-administration` → issue (plaintext returned once — not recorded in evidence)
2. `POST /credential-administration/{cid}/rotate` → new plaintext returned
3. `POST /credential-administration/{cid}/suspend` → deny auth
4. `POST /credential-administration/{cid}/resume` → allow auth again
5. `DELETE /credential-administration/{cid}` → permanent denial (`validate_credential()` hard-fails)

Also performs T3 capability verification using the issued credential.

**Security invariant:** Plaintext secret is NEVER recorded in evidence. `_secret_scan()` enforces this.

---

### Phase 10 — Workforce Suspension

**What it does:**
- Suspend analyst with mandatory `suspension_reason` → 200
- Attempt suspend without `suspension_reason` → must be 422 (mandatory reason enforcement)
- Reactivate analyst → 200

**Mandatory reason:** `suspension_reason` is required by `PATCH /admin/tenants/{id}/users/{uid}` on deactivation (P-113.5 enforcement).

---

### Phase 11 — Workforce Revocation (Terminal)

**What it does:**
- `POST /workforce/users/{uid}/revoke` → 200 or 204 (terminal state)
- Idempotent re-revoke → same status (no duplicate projection, no version bump)
- Attempt reactivate revoked user → must be 409 `MEMBERSHIP_REVOKED` (no resurrection)

---

### Phase 12 — Last Admin Protection

**What it does:**
- Attempt suspend last admin → must be 409
- Attempt revoke last admin → must be 409
- Attempt demote last admin → must be 409

**Mechanism:** `_assert_operational_admin_remains()` in `api/workforce.py` uses `SELECT ... FOR UPDATE` and the canonical operational-admin definition. Fires on suspend, revoke, and admin-role demotion.

---

### Phase 13 — Platform/Tenant Authority Boundaries

**What it does:** Re-verifies platform.admin user list denial (independent check), and verifies tenant_admin cannot create tenants (403 on `POST /admin/tenants`).

---

### Phase 14 — Projection Evidence

**What it does:** Records projection state based on observable evidence.

**Three states:**
- `PROJECTION_EVENT_GENERATED` — assumed from workforce mutations in phases 6/10/11
- `PROJECTION_DELIVERY_OBSERVED` — from admin_gateway operational logs (MP-003 — MANUAL_PROOF)
- `PROJECTION_DELIVERY_NOT_OBSERVABLE_VIA_PRODUCT_BOUNDARY` — if admin_gateway logs not accessible

#### MP-003: Projection Delivery via admin_gateway Logs

1. Access Railway dashboard → `fg-identity-projection-worker` service
2. View service logs for the proof session timestamp
3. Confirm `rows_claimed > 0` and `rows_succeeded > 0`
4. Confirm `status=done` for membership mutations from Phases 6/10/11
5. Optionally verify Auth0 `app_metadata` reflects canonical role state

**Note:** Direct DB inspection (`SELECT * FROM identity_projection_outbox`) is a last-resort diagnostic, not the canonical proof method.

---

### Phase 15 — Recovery

**What it does:** Re-calls bootstrap for Tenant B (idempotency proof). Verifies lifecycle returns to `admin_unbound` after recovery bootstrap. No SQL required.

---

### Phase 16 — Client Suspension

**What it does:**
- `POST /admin/tenants/{CLIENT_A_ID}/suspend` → 200
- Verify A lifecycle → `tenant_suspended` + `operational=false`
- Verify B lifecycle is unaffected (not `tenant_suspended`)
- Re-activate A so cleanup can succeed

---

### Phase 17 — Evidence Reconstruction + Final Verdict

**What it does:**
- Fresh fetch of lifecycle for both tenants (Cache-Control: no-cache)
- Verifies `tenant_id` matches and `lifecycle_version=1`
- Computes `overall_verdict`: `PASS | NOT_PROVEN | BLOCKED`
- Runs final `_secret_scan()` — aborts if any forbidden keyword found
- Writes evidence artifact (if `FG_WRITE_EVIDENCE=1`)

---

## Failure Classification Guide

| Class | When to use | Action |
|---|---|---|
| `AUTHORITY_DEFECT` | A permission check returns wrong result | Stop. Report. Fix authority before retry. |
| `AUTHENTICATION_CONFIGURATION` | Credentials rejected at auth layer | Check env vars, key validity, header wiring. |
| `AUTH0_CONFIGURATION` | Auth0 org not configured, OIDC fails | Follow MP-001/MP-002 manual steps. |
| `PROJECTION_FAILURE` | Projection outbox not delivered | Check admin_gateway logs (MP-003). |
| `TENANT_ISOLATION_FAILURE` | Cross-tenant data returned | **IMMEDIATE STOP. DO NOT MERGE.** Report security defect. |
| `LIFECYCLE_FAILURE` | Lifecycle state wrong after mutation | Check `evaluate_client_lifecycle()` in `api/client_lifecycle.py`. |
| `WORKFORCE_FAILURE` | Workforce mutation returned unexpected status | Check `api/workforce.py`. |
| `CREDENTIAL_FAILURE` | Credential lifecycle mutation failed | Check `api/tenant_admin.py` credential-administration routes. |
| `INFRASTRUCTURE_FAILURE` | Core API unreachable, timeout, 5xx | Check Railway deployment status. |
| `MANUAL_PROOF_REQUIRED` | Human OIDC step not complete | Follow MP-001/MP-002, set `FG_TENANT_ADMIN_TOKEN`. |
| `CLEANUP_FAILURE` | Proof tenant suspension failed | Manually suspend via `POST /admin/tenants/{id}/suspend`. |

---

## Cleanup Behavior

Cleanup runs in a pytest `scope="class"` `autouse=True` fixture. Both proof tenants are suspended via `POST /admin/tenants/{id}/suspend` regardless of test outcome.

**Cleanup is defensive:** If a tenant was already suspended (Phase 16), the cleanup call returns 200 (idempotent). If the tenant was never created (Phase 1 failed), the cleanup list is empty.

**Manual cleanup** if automation fails:
```bash
curl -X POST "${FG_CORE_API_URL}/admin/tenants/${CLIENT_A_ID}/suspend" \
  -H "X-API-Key: ${FG_PLATFORM_ADMIN_KEY}" \
  -H "X-FG-Internal-Token: ${FG_INTERNAL_GATEWAY_SECRET}"

curl -X POST "${FG_CORE_API_URL}/admin/tenants/${CLIENT_B_ID}/suspend" \
  -H "X-API-Key: ${FG_PLATFORM_ADMIN_KEY}" \
  -H "X-FG-Internal-Token: ${FG_INTERNAL_GATEWAY_SECRET}"
```

---

## Evidence Artifact

- **Schema template:** `contracts/artifacts/identity/client-production-e2e-002-evidence.json` (committed)
- **Runtime output:** `contracts/artifacts/identity/client-production-e2e-002-evidence-runtime.json` (gitignored)

The runtime artifact is written only when `FG_WRITE_EVIDENCE=1`. It MUST pass `_secret_scan()` before being considered valid. The schema template is never overwritten by runtime output.

**Prohibited fields in runtime output:** `api_keys`, `tokens`, `secrets`, `credentials`, `passwords`, `authorization_headers`.

---

## Verdict Definitions

| Verdict | Meaning |
|---|---|
| `PASS` | All phases passed (≥10), no isolation failures, no blockers, evidence is CLEAN |
| `NOT_PROVEN` | Some phases were `MANUAL_PROOF_REQUIRED` (OIDC not complete) or a non-critical failure |
| `BLOCKED` | `TENANT_ISOLATION_FAILURE` or critical `AUTHORITY_DEFECT` — do not engage clients |

---

## Rollback / Recovery

If a proof run leaves orphaned tenants in production:

1. Identify tenant IDs from the failed run logs (format: `fg-e2e-{a,b}-{ts}-{hex}`)
2. Suspend via T1: `POST /admin/tenants/{id}/suspend`
3. Record the cleanup in evidence notes

No migration or DB mutation is needed — suspension is the canonical decommission path.

---

## T3 Capability Verification

Phase 9 issues a service credential and attempts `PATCH /workforce/users/{uid}` with it. The credential carries `analyst` role; `PATCH /workforce/users` requires `admin:write` scope + `identity.scim` capability.

**Outcome recording:**
- `T3_VERIFIED` — credential satisfied `require_capability("identity.scim")`; workforce update succeeded
- `T3_NOT_SUPPORTED` — 403 from capability check; credential type does not satisfy `identity.scim`
- `NOT_TESTED` — credential not issued (Phase 9 skipped) or analyst_user_id not available

**If T3 is NOT_SUPPORTED:** This is an expected outcome if the issued credential type (`tenant_api_key`) does not satisfy `identity.scim`. Classify it, record it. Do NOT weaken `require_capability()` and do NOT add a bypass. If this violates the intended authority model, file a remediation PR before re-running the proof.

---

## Production Live Execution Commands

### Full run (with T2 token already obtained)

```bash
FG_LIVE_PROOF=1 \
FG_WRITE_EVIDENCE=1 \
FG_PLATFORM_ADMIN_KEY="..." \
FG_INTERNAL_GATEWAY_SECRET="..." \
FG_TENANT_ADMIN_TOKEN="..." \
FG_CORE_API_URL="https://api.frostgate.ai" \
FG_ADMIN_GATEWAY_URL="https://admin-gateway.frostgate.ai" \
.venv/bin/python -m pytest tests/test_client_production_e2e_002.py::TestClientProductionE2E002LiveProof -v
```

### Phase 0–3 only (T1 only, before OIDC)

```bash
FG_LIVE_PROOF=1 \
FG_PLATFORM_ADMIN_KEY="..." \
FG_INTERNAL_GATEWAY_SECRET="..." \
FG_CORE_API_URL="https://api.frostgate.ai" \
.venv/bin/python -m pytest tests/test_client_production_e2e_002.py::TestClientProductionE2E002LiveProof -k "phase_0 or phase_1 or phase_2 or phase_3 or phase_4" -v
```

### Non-live CI validation only

```bash
.venv/bin/python -m pytest tests/test_client_production_e2e_002.py::TestClientProductionE2E002Gates -v
```
