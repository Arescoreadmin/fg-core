# Enterprise Additive Upgrade Plan (Revision)

## Discovery Inventory (Current State)
- Compliance APIs and registry are present (`api/compliance.py`, `services/compliance_registry`).
- Governance APIs and persistent change workflow are present (`api/governance.py`, `PolicyChangeRequest`).
- Evidence chain/artifact and audit engine are present (`api/evidence_chain.py`, `api/evidence_artifacts.py`, `services/audit_engine`).
- Tenant/auth scope enforcement patterns are present (`api/auth_scopes`, `api/deps`).

## Additions already in place
- Compliance Control Plane extension (`/compliance-cp/*`).
- Enterprise controls/crosswalk extension (`/enterprise-controls/*`).
- Exceptions + breakglass extension (`/exceptions/*`, `/breakglass/*`).
- Governance risk extension hook.
- Evidence anchors extension (`/evidence/anchors`).
- Federation extension (`/auth/federation/validate`).

## Additional Additive Scope (This Revision)
### 7) AI Plane (additive)
Add:
- `services/ai_plane_extension/`
- `api/ai_plane_extension.py`
- `migrations/postgres/0016_ai_plane_extension.sql`
- `seeds/ai_model_catalog_v1.json`

Routes:
- `GET /ai-plane/models`
- `GET /ai-plane/policies`
- `POST /ai-plane/policies`
- `POST /ai-plane/infer`
- `GET /ai-plane/inference`
- `POST /ai-plane/reviews`

Governance wiring:
- tenant-scoped via existing auth + tenant binding dependencies
- deterministic `error_code` responses for AI inference rejection paths
- additive only; no route removals or contract breaks

## Governance Surface Updates
- `docs/GOVERNANCE_RULES.md` updated with AI Plane governance note.
- `artifacts/SOC_AUDIT_GATES.md` updated with AI-specific gate ID.
- `tools/ci/check_security_regression_gates.py` updated to require AI extension directory and `ai-plane-spot` target.
- `Makefile` updated with `ai-plane-spot` target.
