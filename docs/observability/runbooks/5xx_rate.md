# Runbook: FrostgateHttp5xxRateHigh

**Alert:** `FrostgateHttp5xxRateHigh`
**Severity:** Warning
**Metric:** `frostgate_http_5xx_total`, `frostgate_http_request_duration_seconds`
**Threshold:** 5xx rate > 5% over 5 minutes

## Immediate actions
1. Check which methods are producing 5xx: `sum by (method) (rate(frostgate_http_5xx_total[5m]))`
2. Review application logs for unhandled exceptions (`level: ERROR`)
3. Check exception shield metrics: `frostgate_exception_shield_total`
4. Verify downstream dependencies (DB, providers, Redis)

## Common causes
- Unhandled exceptions propagating through middleware
- Database errors causing 500s on write paths
- Provider timeouts causing 502s on /defend

## Resolution
- Fix the root exception source
- If transient: verify 5xx rate returns to baseline after dependency recovery
