# Control Tower Single Source of Truth

## Canonical Surface
- Canonical UI surface: `console` Next.js route `/dashboard/control-tower`.
- Canonical dashboard contract: `ControlTowerSnapshotV1` from `GET /control-tower/snapshot` (via console BFF `/api/core/control-tower/snapshot`).
- Legacy `api/ui*` routes are deprecated/internal-only and MUST NOT receive new feature work.
- Admin-gateway is backend/proxy only; user workflows initiate from Control Tower.

## Data Contract Rules
1. Widgets MUST derive from `ControlTowerSnapshotV1` or explicit drilldown links in `snapshot.links`.
2. New section/widget requires:
   - snapshot schema update (versioned)
   - at least one test + CI gate
   - tenant isolation behavior (or explicit exemption rationale)
3. Snapshot responses must be deterministic (`sort_keys`) and include explicit nulls.

## Tenant Safety
- Tenant clamp metadata is included under `tenant.clamp`.
- Tenant mismatch behavior must be 403/404 according to policy.
- Dev tenant override (`FG_CONSOLE_ALLOW_TENANT_QUERY_OVERRIDE`) is development-only and gated.

## Architecture
```text
Browser
  -> Console (Next.js)
    -> BFF allowlisted routes (/api/core/*)
      -> frostgate-core API (/control-tower/snapshot + drilldowns)
        -> core services / admin-gateway proxy / DB
```

## Legacy UI deprecation
- `FG_UI_ENABLED` should remain explicitly enabled only for internal compatibility.
- Default posture is OFF unless explicitly set.


## Execution path for admin actions
- Canonical path: **Console -> BFF (`/api/core/*`) -> core endpoints**.
- The console never calls core/admin-gateway directly from the browser; all calls are mediated by BFF allowlist rules.
- If admin-gateway is used, it is backend-only behind core/BFF policy checks.

## Legacy UI toggle policy
- `FG_UI_ENABLED` controls legacy `/ui/*` endpoints.
- Default is `false` in every environment unless explicitly enabled.
- Production-like manifests must not set `FG_UI_ENABLED=true` (enforced by prod-unsafe-config gate).

## Change-control requirements for new widgets
- Add fields to snapshot schema (`ControlTowerSnapshotV*`) before UI consumption.
- Add tests (contract + allowlist/nav as applicable).
- Update BFF allowlist and docs in the same PR.
