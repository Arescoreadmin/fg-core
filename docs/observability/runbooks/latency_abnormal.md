# Runbook: FrostgateRequestLatencyAbnormal

**Alert:** `FrostgateRequestLatencyAbnormal`
**Severity:** Warning
**Metric:** `frostgate_http_request_duration_seconds`
**Threshold:** p99 > 5s over 5 minutes

## Immediate actions
1. Check latency breakdown: `histogram_quantile(0.99, sum by (method, status_class, le) (rate(frostgate_http_request_duration_seconds_bucket[5m])))`
2. Check provider latency: `frostgate_provider_latency_seconds`
3. Check retrieval latency: `frostgate_retrieval_latency_seconds`
4. Check DB query latency: `frostgate_db_query_latency_seconds`
5. Review active connection count: `frostgate_active_connections`

## Resolution
- Identify which pipeline stage is slow via tracing (check Grafana Tempo or Jaeger)
- Scale the bottleneck resource
- Apply circuit breaker if a provider is the cause
