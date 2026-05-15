# Observability Deployment Topology Guide

Reference architecture for deploying FrostGate's observability stack across
standard, regulated, and air-gapped environments.

---

## Environment variables controlling telemetry output

| Variable | Default | Effect |
|---|---|---|
| `FG_OTEL_ENABLED` | `1` | `0` disables all OTel spans (noop, zero overhead) |
| `FG_OTEL_ENDPOINT` | _(unset)_ | OTLP/HTTP collector URL; no export when unset |
| `FG_OTEL_SAMPLE_RATIO` | `1.0` | Trace sampling rate 0.0–1.0 |
| `FG_OTEL_CONSOLE` | _(unset)_ | `1` dumps spans to stdout (local debug only) |
| `FG_METRICS_ENABLED` | `1` | `0` disables `/metrics` endpoint |
| `FG_APP_VERSION` | `0.8.0` | Emitted as `service.version` in OTel resource |
| `FG_ENV` | `dev` | Emitted as `deployment.environment` in OTel resource |

---

## Topology 1: Local Prometheus (default / development)

```
FrostGate ──/metrics──► Prometheus (local)
                              │
                              └──► Grafana (local)
```

**When to use:** local development, single-node staging.

**Config:**
```yaml
# prometheus.yml
scrape_configs:
  - job_name: frostgate
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: /metrics
```

No OTel endpoint needed. Traces go to console (`FG_OTEL_CONSOLE=1`) or are
disabled (`FG_OTEL_ENABLED=0`).

**Important:** `/metrics` must not be exposed on the public customer-facing ingress.
Bind Prometheus scrape to an internal network interface or firewall the path.

---

## Topology 2: Remote Prometheus Scrape (standard production)

```
FrostGate ──/metrics──► Prometheus (remote, scrape interval 15s)
                              │
                         Alertmanager ──► PagerDuty / OpsGenie
                              │
                              └──► Grafana Cloud / self-hosted
```

**Config:** same as Topology 1 with remote `targets` and TLS.

Set `FG_ALERT_BACKEND=pagerduty` + `FG_PAGERDUTY_ROUTING_KEY=...` for
Python-level alerting hooks to fire alongside Prometheus Alertmanager.

---

## Topology 3: OTLP Collector (full distributed tracing)

```
FrostGate ──OTLP/HTTP──► OpenTelemetry Collector
                              │
                    ┌─────────┼──────────┐
                    ▼         ▼          ▼
               Grafana    Jaeger     Datadog
               Tempo      (open)     (cloud)
```

**Config:**
```bash
FG_OTEL_ENDPOINT=http://otel-collector:4318/v1/traces
FG_OTEL_SAMPLE_RATIO=0.1   # 10% sampling in high-volume prod
```

The OTLP collector handles batching, retry, and fan-out to multiple backends.
FrostGate connects to one OTLP endpoint; the collector routes to everything else.

**Supported backends via OTLP:** Grafana Tempo, Jaeger, Datadog, Honeycomb,
New Relic, Dynatrace, AWS X-Ray (via ADOT collector), Google Cloud Trace.

---

## Topology 4: Splunk Forwarding

```
FrostGate ──structured logs──► Fluentd / Fluent Bit
                                     │
                                     └──► Splunk HEC
```

**Config:** FrostGate emits JSON-formatted structured logs to stdout. Configure
Fluentd or Fluent Bit to forward to Splunk HTTP Event Collector (HEC).

Recommended Splunk index configuration:
- Operational logs (`frostgate.observability`): 90-day retention index
- Audit logs (from audit log store, not FrostGate stdout): 7-year retention index

Do not forward FrostGate operational logs to the audit index — see
`docs/observability/audit_telemetry_separation.md`.

**SIEM correlation:** structured log fields `trace_id`, `request_id`, `tenant_id`
are stable and indexed by Splunk. Build correlation searches against these fields.
The `trace_id` can correlate a Splunk log event with a Jaeger or Tempo trace.

---

## Topology 5: CloudWatch / AWS ADOT Bridge

```
FrostGate ──OTLP/HTTP──► AWS Distro for OpenTelemetry (ADOT) Collector
                              │
                    ┌─────────┴──────────┐
                    ▼                    ▼
              CloudWatch             X-Ray Traces
              Metrics
```

**Config:**
```bash
FG_OTEL_ENDPOINT=http://localhost:4318/v1/traces   # ADOT sidecar
```

ADOT translates OTLP → X-Ray trace format and forwards metrics to CloudWatch EMF.
Prometheus metrics can be scraped by the CloudWatch agent independently.

**IAM requirements:** the ADOT collector needs `xray:PutTraceSegments`,
`xray:PutTelemetryRecords`, `cloudwatch:PutMetricData`.

---

## Topology 6: Grafana-Only Mode (no Prometheus server)

```
FrostGate ──/metrics──► Grafana Agent ──► Grafana Cloud Metrics (remote_write)
          ──OTLP/HTTP──► Grafana Agent ──► Grafana Cloud Traces
                                   │
                              Grafana Cloud
                              (metrics + traces + logs)
```

**When to use:** teams without a self-hosted Prometheus, or when Grafana Cloud
is the single observability backend.

**Config:**
```yaml
# grafana-agent.yaml
metrics:
  configs:
    - name: frostgate
      scrape_configs:
        - job_name: frostgate
          static_configs:
            - targets: ['frostgate:8000']
      remote_write:
        - url: https://prometheus-prod-xx.grafana.net/api/prom/push

traces:
  configs:
    - name: frostgate
      receivers:
        otlp:
          protocols:
            http:
              endpoint: 0.0.0.0:4318
      remote_write:
        - endpoint: tempo-prod-xx.grafana.net:443
```

---

## Topology 7: No-External-Egress Mode (air-gapped / GovCon / HIPAA)

```
FrostGate ──/metrics──► Prometheus (internal VPC only)
          ──OTLP/HTTP──► Jaeger All-In-One (internal)
          ──stdout──────► Fluentd (internal) ──► Elasticsearch (internal)
                                                        │
                                                   Kibana (internal)
```

**Mandatory configuration for air-gapped:**

```bash
# Do NOT set FG_OTEL_ENDPOINT to any external host.
# Use internal collector only.
FG_OTEL_ENDPOINT=http://jaeger.internal:4318/v1/traces
FG_OTEL_SAMPLE_RATIO=1.0   # full fidelity in regulated environments

# Confirm no external DNS resolution needed:
# OTLP export goes to jaeger.internal (internal DNS only)
# /metrics is scraped by internal Prometheus only
```

**Network hardening:**
- `/metrics` must be accessible only from the Prometheus scraper IP range.
  Apply an ingress network policy or firewall rule; do not rely on auth.
- The OTLP endpoint (Jaeger) must not be reachable from the public internet.
- Structured log output goes to local stdout → Fluentd → internal Elasticsearch.
  No log forwarding to external SIEM in strict air-gap mode.

**For FedRAMP:** use the ADOT collector topology (Topology 5) within a GovCloud
VPC boundary. All telemetry stays within the authorization boundary.

**For HIPAA:** ensure structured logs containing `tenant_id` are forwarded only
to HIPAA-eligible log stores. Do not forward to non-covered SaaS log backends.
The `SecretRedactionFilter` strips PII-adjacent fields before log emission, but
`tenant_id` is intentionally retained as it is required for audit correlation.
Ensure the log store is under your HIPAA BAA.

---

## Topology comparison matrix

| Requirement | Topology |
|---|---|
| Local dev | 1 (local Prometheus + console spans) |
| Standard production | 2 or 3 |
| Multi-backend tracing | 3 (OTLP collector) |
| AWS native | 5 (ADOT) |
| Grafana Cloud only | 6 (Grafana Agent) |
| Enterprise SIEM (Splunk) | 4 |
| Air-gapped / GovCon / FedRAMP | 7 |
| HIPAA | 7 with HIPAA-eligible log store |
| No telemetry at all | Set `FG_OTEL_ENABLED=0`, `FG_METRICS_ENABLED=0` |
