# Runbook: FrostgateProviderFailureHigh

**Alert:** `FrostgateProviderFailureHigh`
**Severity:** Critical
**Metric:** `frostgate_provider_failures_total` / `frostgate_provider_requests_total`
**Threshold:** Failure rate > 10% over 5 minutes for any provider

## Symptoms
- `FrostgateProviderFailureHigh` alert fires in Prometheus Alertmanager
- Provider failure rate panel in `frostgate_provider_health` dashboard shows spike
- Users may see increased `502` or `503` error rates

## Immediate actions
1. Check which provider is failing: `sum by (provider_id) (rate(frostgate_provider_failures_total[5m]))`
2. Check failure types: `sum by (provider_id, failure_type) (rate(frostgate_provider_failures_total[5m]))`
3. Verify provider credentials and API keys in the tenant key store
4. Check provider status page for the affected vendor
5. If a single provider: consider routing to a fallback provider

## Escalation
- If failure rate > 50%: page on-call platform engineer
- If all providers failing: escalate to site reliability immediately

## Resolution
- Rotate API keys if credentials were invalidated
- Confirm provider service restoration
- Monitor for 10 minutes post-resolution before silencing alert
