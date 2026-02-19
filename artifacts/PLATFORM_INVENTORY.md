# Platform Inventory

## Planes
- `ai_plane` flags=`FG_AI_PLANE_ENABLED` targets=ai-plane-full, ai-plane-spot
- `breakglass` flags=`FG_BREAKGLASS_ENABLED` targets=breakglass-spot
- `compliance_cp` flags=`FG_COMPLIANCE_CP_ENABLED` targets=compliance-cp-spot
- `enterprise_controls` flags=`FG_ENTERPRISE_CONTROLS_ENABLED` targets=enterprise-controls-spot
- `evidence_anchor` flags=`FG_EVIDENCE_ANCHOR_ENABLED` targets=evidence-anchor-spot
- `federation` flags=`FG_FEDERATION_ENABLED` targets=federation-spot

## Enterprise readiness checklist status
- artifact_policy_enforced: PASS
- openapi_security_diff_enforced: PASS
- resilience_guard_present: PASS
- rls_sensitive_tables_present: PASS
- route_inventory_enforced: PASS
- self_heal_bounded_off_by_default: PASS
- tenant_binding_coverage: FAIL
