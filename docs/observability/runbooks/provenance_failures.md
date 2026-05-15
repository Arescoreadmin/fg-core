# Runbook: FrostgateProvenanceFailureSpike

**Alert:** `FrostgateProvenanceFailureSpike`
**Severity:** Critical
**Metric:** `frostgate_provenance_validation_total`
**Threshold:** Failure rate > 10% over 2 minutes

## Symptoms
This alert indicates a sudden increase in provenance validation failures.
Possible causes:
- Policy version mismatch between ingestion and validation
- Tampered or corrupted document hashes
- Infrastructure issue causing validation to skip or error

## Immediate actions
1. Check result breakdown: `sum by (result) (rate(frostgate_provenance_validation_total[5m]))`
2. Identify which tenants are affected via logs: filter `frostgate.provenance_validation` spans
3. Check if a policy version change was recently deployed
4. Review merkle anchor chain integrity

## Escalation
Provenance failures above 10% are a potential integrity signal.
- Open P1 incident immediately
- Notify compliance officer
- Preserve all validation logs for forensic review

## Resolution
- Do NOT auto-remediate — failed validations must be manually reviewed
- Restore correct policy version and re-validate affected documents
