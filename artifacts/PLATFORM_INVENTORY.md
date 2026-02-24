# Platform Inventory

## Planes
- `agent` flags=`n/a` targets=agent-unit
- `ai` flags=`n/a` targets=ai-plane-spot
- `connector` flags=`n/a` targets=check-connectors-rls
- `control` flags=`n/a` targets=control-plane-check, plane-registry-spot
- `data` flags=`n/a` targets=soc-invariants
- `evidence` flags=`n/a` targets=audit-chain-verify
- `security` flags=`n/a` targets=security-regression-gates
- `ui` flags=`n/a` targets=test-quality-gate

## Enterprise readiness checklist status
- artifact_policy_enforced: PASS
- openapi_security_diff_enforced: PASS
- resilience_guard_present: PASS
- rls_sensitive_tables_present: PASS
- route_inventory_enforced: PASS
- self_heal_bounded_off_by_default: PASS
- tenant_binding_coverage: FAIL
