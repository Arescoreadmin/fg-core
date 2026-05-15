# FrostGate Structured Log Schema

Every log record emitted by FrostGate services is a single-line JSON object.
This schema is authoritative for SOC 2, HIPAA, and GovCon audit evidence.

## Guaranteed fields (always present)

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO 8601 string | UTC emission time with millisecond precision (`2026-05-15T12:34:56.789Z`) |
| `level` | string | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `service` | string | Service identifier, e.g. `frostgate-core`, set via `FG_SERVICE` env var |
| `event` | string | Human-readable log message |
| `logger` | string | Python logger name, e.g. `frostgate.middleware` |

## Contextual fields (present when in scope)

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `request_id` | UUID v4 string | `RequestContextFilter` via `request.state` | Echoed from or generated for `X-Request-Id` header; correlates request across service boundaries |
| `trace_id` | 32-char hex string | `TraceContextFilter` via OTel span context | W3C TraceContext trace identifier; absent when OTel is disabled |
| `span_id` | 16-char hex string | `TraceContextFilter` via OTel span context | W3C TraceContext span identifier; absent when OTel is disabled |
| `tenant_id` | string | `RequestContextFilter` via `set_log_context()` | Tenant identifier; set by auth middleware and available in all authenticated request logs |
| `provider_id` | string | `RequestContextFilter` via `set_log_context()` | AI/data provider identifier; set when a provider routing decision is made |
| `policy_version` | string | `RequestContextFilter` via `set_log_context()` | Active policy version at time of request; set by policy enforcement layer |
| `retrieval_mode` | string | `RequestContextFilter` via `set_log_context()` | RAG retrieval strategy (`semantic`, `lexical`, `hybrid`); set by retrieval pipeline |

## Request log fields (emitted by `RequestLoggingMiddleware` per request)

| Field | Type | Description |
|-------|------|-------------|
| `method` | string | HTTP method: `GET`, `POST`, etc. |
| `path` | string | URL path (no query string) |
| `status_code` | integer | HTTP response status code |
| `duration_ms` | float | Wall time in milliseconds from first byte received to response sent |
| `client_ip` | string | Connecting client IP (may be proxy IP depending on deployment) |

## Security invariants

- **No credentials in logs.** The `SecretRedactionFilter` removes any field whose name contains: `authorization`, `bearer`, `api_key`, `token`, `password`, `secret`, `credential`, `private_key`, `signing_key`, `provider_payload`, `raw_prompt`, `raw_chunk`. Matching fields are replaced with the literal `[REDACTED]`.
- **No high-cardinality free-form values in metric labels.** `request_id`, `document_id`, `source_hash`, and raw route path segments are never used as Prometheus label values.
- **Exception details are redacted in production.** When `FG_ENV` is `prod`, `production`, or `staging`, non-string exception detail fields are replaced with the string `"error"` before logging.

## Example record

```json
{
  "timestamp": "2026-05-15T14:22:03.417Z",
  "level": "INFO",
  "service": "frostgate-core",
  "event": "request",
  "logger": "frostgate",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "tenant_id": "acme-corp",
  "method": "POST",
  "path": "/defend",
  "status_code": 200,
  "duration_ms": 42.3,
  "client_ip": "10.0.1.5"
}
```

## Log aggregation compatibility

This schema is compatible with:
- **Datadog Log Management** — `timestamp`, `level`, `service` map to standard Datadog attributes
- **Grafana Loki** — structure is parseable by Loki's JSON pipeline; `tenant_id` and `trace_id` become labels
- **AWS CloudWatch Logs Insights** — field access via `fields.tenant_id`, `fields.trace_id` etc.
- **Splunk** — JSON auto-extraction; `trace_id` and `span_id` enable correlation with APM
- **SIEM (Elastic SIEM, Sentinel)** — field naming follows ECS conventions where possible
