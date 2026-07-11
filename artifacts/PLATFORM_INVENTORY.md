# Platform Inventory

## Planes
- `agent` targets=agent-unit
- `ai` targets=ai-plane-spot
- `connector` targets=check-connectors-rls
- `control` targets=control-plane-check, plane-registry-spot
- `data` targets=soc-invariants
- `evidence` targets=audit-chain-verify
- `identity` targets=soc-invariants
- `rbac` targets=security-regression-gates
- `security` targets=security-regression-gates
- `ui` targets=test-quality-gate
- `workforce` targets=soc-invariants

## Enterprise readiness checklist status
- artifact_policy_enforced: PASS
- openapi_security_diff_enforced: PASS
- resilience_guard_present: PASS
- rls_sensitive_tables_present: PASS
- route_inventory_enforced: PASS
- self_heal_bounded_off_by_default: PASS
- tenant_binding_coverage: FAIL
