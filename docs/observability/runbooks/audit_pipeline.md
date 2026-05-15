# Runbook: FrostgateAuditPipelineFailure

**Alert:** `FrostgateAuditPipelineFailure`, `FrostgateAuditExportFailureHigh`
**Severity:** Critical (compliance-impacting)
**Metric:** `frostgate_audit_pipeline_failures_total`, `frostgate_audit_export_total`

## Immediate actions
1. Check failure type: `sum by (failure_type) (rate(frostgate_audit_pipeline_failures_total[5m]))`
2. Verify audit export status per tenant: `sum by (tenant_id, status) (rate(frostgate_audit_export_total[10m]))`
3. Check DB connectivity — audit records require durable write before acknowledging
4. Review merkle anchor job if cryptographic chaining is failing

## Escalation
Audit pipeline failures are compliance-impacting. If persistent (> 5 minutes):
- Page on-call compliance engineer
- Open P1 incident
- Notify affected tenant's compliance contact if contractually required

## Resolution
- Restore DB connectivity before reprocessing failed exports
- Do NOT delete or modify partial audit records — append-only semantics are required
