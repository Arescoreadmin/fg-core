# SLO Targets and Metrics Contract

## Service Level Objectives

Production SLOs for FrostGate. Each entry names the metric, the alert that fires
on breach, and the Grafana panel where the signal lives.

---

### Retrieval Latency SLO

| Field | Value |
|---|---|
| **SLO** | 99th percentile retrieval latency < 2 seconds |
| **Window** | 5 minutes rolling |
| **Metric** | `frostgate_retrieval_latency_seconds` |
| **Alert** | `FrostgateRetrievalLatencyHigh` |
| **Dashboard** | frostgate_pipelines → "Retrieval Latency p99" |

```promql
# SLI expression
histogram_quantile(0.99,
  sum by (mode, le) (rate(frostgate_retrieval_latency_seconds_bucket[5m]))
)
```

**Burn-rate alert (future):** 1h burn rate > 14.4× budget → page immediately.

---

### HTTP Success Rate SLO

| Field | Value |
|---|---|
| **SLO** | 99.5% of HTTP requests return non-5xx |
| **Window** | 5 minutes rolling |
| **Metrics** | `frostgate_http_5xx_total`, `frostgate_http_request_duration_seconds` |
| **Alert** | `FrostgateHttp5xxRateHigh` |
| **Dashboard** | frostgate_system_health → "HTTP Error Rate" |

```promql
# Error ratio (must stay below 0.005)
sum(rate(frostgate_http_5xx_total[5m]))
/
sum(rate(frostgate_http_request_duration_seconds_count[5m]))
```

---

### Provenance Validation SLO

| Field | Value |
|---|---|
| **SLO** | 95% of provenance validations succeed |
| **Window** | 2 minutes rolling |
| **Metric** | `frostgate_provenance_validation_total` |
| **Alert** | `FrostgateProvenanceFailureSpike` |
| **Dashboard** | frostgate_pipelines → "Provenance Validation" |

```promql
# Pass rate (must stay above 0.95)
sum(rate(frostgate_provenance_validation_total{result="pass"}[2m]))
/
sum(rate(frostgate_provenance_validation_total[2m]))
```

**Note:** This SLO has compliance implications. Failures below 90% trigger a P1
incident regardless of duration. See `docs/observability/runbooks/provenance_failures.md`.

---

### Ingestion Completion SLO

| Field | Value |
|---|---|
| **SLO** | 99% of ingestion requests complete successfully |
| **Window** | 5 minutes rolling |
| **Metric** | `frostgate_ingestion_requests_total` |
| **Alert** | `FrostgateIngestionFailureHigh` |
| **Dashboard** | frostgate_pipelines → "Ingestion Success Rate" |

```promql
sum(rate(frostgate_ingestion_requests_total{status="success"}[5m]))
/
sum(rate(frostgate_ingestion_requests_total[5m]))
```

---

### Provider Availability SLO

| Field | Value |
|---|---|
| **SLO** | Provider failure rate < 10% per provider |
| **Window** | 5 minutes rolling |
| **Metrics** | `frostgate_provider_failures_total`, `frostgate_provider_requests_total` |
| **Alert** | `FrostgateProviderFailureHigh` |
| **Dashboard** | frostgate_provider_health → "Provider Error Rate" |

---

### DB Connectivity SLO

| Field | Value |
|---|---|
| **SLO** | Zero DB connectivity failures in any 5-minute window |
| **Metric** | `frostgate_db_connectivity_failures_total` |
| **Alert** | `FrostgateDBConnectivityFailure` |
| **Dashboard** | frostgate_system_health → "DB Health" |

---

## Metrics Versioning Policy

**Metrics are a contract surface.** Dashboards, alert rules, SIEM integrations,
and customer-accessible observability exports all depend on stable metric names.

### Breaking changes

Any of the following require a deprecation notice, a migration window (minimum
2 weeks), and a PR_FIX_LOG entry with `BREAKING: metrics` in the title:

- Renaming a metric (e.g. `frostgate_provider_requests_total` → anything else)
- Removing a metric
- Changing label names on an existing metric
- Removing a label dimension
- Changing bucket boundaries on a histogram in a way that breaks existing queries

### Non-breaking changes

These do not require a deprecation window:

- Adding a new metric
- Adding a new label value to an existing bounded label set
- Adding new bucket boundaries without removing existing ones
- Adding new alert conditions
- Updating runbook text

### How to rename a metric

1. Add the new metric alongside the old one (both emitted simultaneously).
2. Update dashboards and alert rules to reference the new name.
3. Update `test_metric_name_contract` in `tests/test_observability.py` — this test
   is the registry of record.
4. After a 2-week dual-emission window, remove the old metric.
5. Add a `BREAKING: metrics` entry to `docs/ai/PR_FIX_LOG.md`.

### SIEM and external integrations

Metric names are referenced in:
- Prometheus alerting rules (`deploy/prometheus/alerts.yml`)
- Grafana dashboard panel expressions (`deploy/grafana/dashboards/`)
- Any external SIEM, CloudWatch metric filter, or Datadog monitor pointing at
  this service

Coordinate with the security/compliance team before renaming metrics used in
SIEM alerting, as those configurations may be outside the FrostGate repository.

---

## Future: SLO Burn-Rate Alerts

Multi-window burn-rate alerting (Google SRE model) to implement when
Prometheus alertmanager is production-deployed:

```yaml
# Example: retrieval latency burn-rate alert
- alert: FrostgateRetrievalSLOBurnRateFast
  expr: |
    (
      sum(rate(frostgate_retrieval_latency_seconds_bucket{le="2"}[1h]))
      / sum(rate(frostgate_retrieval_latency_seconds_bucket{le="+Inf"}[1h]))
    ) < 0.99 * 14.4
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "Retrieval SLO burning fast — 1h burn rate exceeds 14.4x error budget"
    runbook: "docs/observability/runbooks/latency_abnormal.md"
```

Burn-rate factor 14.4 = (1h / 30d × 100%) means this rate, sustained, exhausts
the monthly error budget in 2 hours. Standard Google SRE page threshold.
