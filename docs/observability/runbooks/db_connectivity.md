# Runbook: FrostgateDBConnectivityFailure

**Alert:** `FrostgateDBConnectivityFailure`
**Severity:** Critical
**Metric:** `frostgate_db_connectivity_failures_total`

## Immediate actions
1. Check `/health/ready` endpoint — it checks DB connectivity as part of readiness
2. Verify database host is reachable from the service pod/instance
3. Check connection pool exhaustion in application logs
4. Check DB server health, replication lag, or failover state

## Escalation
DB connectivity loss is a P1 incident. All tenant operations are impacted.

## Recovery
1. Restore DB connectivity
2. Verify `/health/ready` returns 200
3. Monitor `frostgate_db_errors_total` for residual errors
4. Check audit pipeline caught up on any missed writes
