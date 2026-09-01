# Production Synthetic Provisioning Proof Runbook

**Purpose:** Prove the complete provisioning chain against production infrastructure before Customer One.  
**Target tenant:** `fg-provisioning-proof-20260812-001`  
**Status:** READY TO EXECUTE  

---

## Pre-conditions

- [ ] `scripts/remediate_tenant_kinds.py --commit` has run (MANUAL_REVIEW count = 0)
- [ ] `scripts/attest_historical_role_assignments.py --commit` has run (3 attestation records exist)
- [ ] Backfill dry-run shows 0 MANUAL_REVIEW, exit code 0
- [ ] You have console admin access (frostgate.ai/console)

---

## Execution

### Step 1 — Provision through the console

Navigate to the admin tenant provisioning UI and create:

```
tenant_id:    fg-provisioning-proof-20260812-001
display_name: FG Provisioning Proof 2026-08-12
```

The console calls `POST /api/admin/provision-tenant` which:
1. Creates the tenant record in the DB
2. Issues a credential via `POST /admin/tenants/{id}/credentials`
3. Assigns `tenant_admin` via `POST /admin/tenants/{id}/credentials/{cid}/role`
4. Writes an audit record to `tenant_role_audit`

Record the returned credential ID and plaintext key.

### Step 2 — Automated verification

Run this query against production (via Railway psql or `FG_DB_OPERATOR_URL`):

```sql
-- G1: tenant exists
SELECT tenant_id, tenant_kind, lifecycle_state
FROM tenants
WHERE tenant_id = 'fg-provisioning-proof-20260812-001';

-- G2: credential exists and is active
SELECT credential_id, status, issued_at
FROM tenant_credentials
WHERE tenant_id = 'fg-provisioning-proof-20260812-001' AND status = 'active';

-- G3: tenant_admin role assigned (no manual SQL/backfill required)
SELECT role_name, granted_at, granted_by
FROM tenant_credential_roles
WHERE tenant_id = 'fg-provisioning-proof-20260812-001' AND revoked_at IS NULL;

-- G4: audit record exists
SELECT action, actor_key_prefix, role_name, timestamp
FROM tenant_role_audit
WHERE tenant_id = 'fg-provisioning-proof-20260812-001'
ORDER BY timestamp DESC;
```

Expected results:
- G1: 1 row, `tenant_kind='customer'`, `lifecycle_state='active'` ✓
- G2: 1 row, `status='active'` ✓
- G3: 1 row, `role_name='tenant_admin'`, `granted_by='operator:...'` ✓
- G4: 1 row, `action='assign_role'` ✓ (NO manual backfill touch)

### Step 3 — API authorization proof

```bash
# G5: own-tenant authorization passes
curl -f -H "Authorization: Bearer <plaintext-key>" \
  https://api.frostgate.ai/tenants/fg-provisioning-proof-20260812-001/rbac/assignments
# Expected: 200 with role data

# G6: cross-tenant read denied
curl -i -H "Authorization: Bearer <plaintext-key>" \
  https://api.frostgate.ai/tenants/odin-financial-group/rbac/assignments
# Expected: 403

# G7: admin list accessible (admin endpoint returns tenant in list)
# Requires two distinct credentials — inject from production secret manager.
# FG_PSP_CREDENTIAL: platform admin API key with platform_admin role in tenant_credential_roles.
#   NOTE: NOT the PSP (platform-service-principal) credential — PSP lacks platform.admin.
#   Obtain from the platform admin credential record; do NOT use the PSP credential here.
# FG_INTERNAL_GATEWAY_SECRET: internal gateway trust secret
#   Obtain from production secret manager; rotation is an exceptional key-replacement event.
# WARNING: avoid shell history — set in a non-logging shell or via secrets tooling.
#
# This is the direct PSP path (Path A). X-API-Key authenticates the PSP identity;
# X-FG-Internal-Token satisfies require_internal_admin_gateway() on all /admin/* routes.
# Do NOT use the same value for both headers — that activates the BFF path (Path B).
export FG_PSP_CREDENTIAL="fgk.<from-secret-manager>"
export FG_INTERNAL_GATEWAY_SECRET="<from-secret-manager>"
curl -i \
  -H "X-API-Key: $FG_PSP_CREDENTIAL" \
  -H "X-FG-Internal-Token: $FG_INTERNAL_GATEWAY_SECRET" \
  https://api.frostgate.ai/admin/tenants
# Expected: 200

# G8: cross-tenant role assignment rejected (write-path isolation)
curl -i \
  -H "Authorization: Bearer <plaintext-key>" \
  -H "Content-Type: application/json" \
  -d '{"role":"tenant_admin","credential_id":"<some-other-tenant-cid>"}' \
  https://api.frostgate.ai/admin/tenants/odin-financial-group/credentials/<cid>/role
# Expected: 403 or 422
```

> **Note on UI flows:** Console and Portal UI administration (original G7/G8 intent) are covered
> by T4 Portal Named-User Proof (PASS 2026-08-04). This synthetic proof targets API-layer
> correctness only; running the UI again on a synthetic tenant would not add signal.

### Step 4 — Decommission

```sql
-- Revoke the proof credential
UPDATE tenant_credentials
SET status = 'revoked', revoked_at = NOW()
WHERE tenant_id = 'fg-provisioning-proof-20260812-001';

-- Suspend the proof tenant
UPDATE tenants
SET lifecycle_state = 'suspended'
WHERE tenant_id = 'fg-provisioning-proof-20260812-001';
```

Or use the console tenant management UI to suspend + revoke.

---

## Pass criteria

| Gate | Check | Expected |
|------|-------|----------|
| G1 | Tenant created | `lifecycle_state='active'` |
| G2 | Credential created | `status='active'` |
| G3 | `tenant_admin` automatically assigned | `role_name='tenant_admin'`, no manual SQL |
| G4 | Audit record written | `action='assign_role'` in `tenant_role_audit` |
| G5 | Own-tenant API returns 200 | `/rbac/assignments` on own tenant |
| G6 | Cross-tenant API returns 403 | `/rbac/assignments` on `odin-financial-group` |
| G7 | Admin list accessible | Admin `/admin/tenants` returns 200 with tenant present |
| G8 | Cross-tenant write isolation | Cross-tenant role assignment rejected (403/422) |
| G9 | Synthetic tenant cleanly decommissioned | `status='revoked'`, `lifecycle_state='suspended'` |

All 9 gates PASS → **TENANT PROVISIONING: PRODUCTION PROVEN**

Any gate FAIL → document the failure, halt, fix before Customer One.

---

## Post-proof update

After all 9 gates pass, update the verdict in `docs/governance/status/EXECUTION_STATE.md`:

```
TENANT PROVISIONING: PRODUCTION PROVEN
Proof date: 2026-08-12
Proof tenant: fg-provisioning-proof-20260812-001
All 9 gates: PASS
```
