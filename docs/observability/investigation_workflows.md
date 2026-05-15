# Operational Investigation Workflows

Structured runbooks for on-call engineers. Each workflow starts from an alert or
symptom and walks through the trace → metric → log correlation chain.

---

## 1. Failed Ingestion Investigation

**Entry point:** `FrostgateIngestionFailureHigh` alert fires, or a tenant reports
documents not appearing after upload.

### Step 1 — Scope the failure

```promql
# Which doc types are failing?
sum by (doc_type, status) (
  rate(frostgate_ingestion_requests_total[5m])
)
```

Look for `status="error"` or `status="rejected"` spikes.

### Step 2 — Find the request_id

Tenant support ticket or API gateway access log provides the `request_id`.
Alternatively, filter structured logs:

```
level=error service=frostgate-core
  AND doc_type=<type>
  AND timestamp >= <alert_time - 5m>
```

Each log line for a failed ingestion carries:
```json
{
  "level": "error",
  "service": "frostgate-core",
  "request_id": "req-7a3f...",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "tenant_id": "acme-corp",
  "doc_type": "pdf",
  "message": "ingestion pipeline failed",
  "error": "..."
}
```

### Step 3 — Jump to the trace

Use `trace_id` from the log line to pull the full trace in Grafana Tempo or Jaeger:

```
trace_id = 4bf92f3577b34da6a3ce929d0e0e4736
```

The trace tree will show:
```
frostgate.http.request          [SERVER]   total=1.2s
  └─ frostgate.ingestion        [INTERNAL] total=1.1s  ← ERROR
       ├─ frostgate.provenance_validation  [INTERNAL] 50ms  OK
       └─ frostgate.provider_routing       [INTERNAL] 900ms ERROR
            └─ frostgate.provider_call     [CLIENT]   900ms TIMEOUT
```

The red span tells you exactly where the pipeline broke. Check its attributes:
- `tenant.id` — confirms the tenant
- `doc.type` — document type being ingested
- `provider.id` — which AI provider was called
- `error.type` — exception class
- `error.message` — human-readable cause

### Step 4 — Check provider health

If the trace shows a provider timeout:

```promql
# Provider error rate by provider
sum by (provider_id, failure_type) (
  rate(frostgate_provider_failures_total[5m])
)
```

Then check `docs/observability/runbooks/provider_failure.md` for escalation path.

### Step 5 — Check queue depth

```promql
frostgate_ingestion_queue_depth
```

A value > 0 with rising ingestion failures indicates backpressure, not a provider
issue. Scale the ingestion worker pool or investigate upstream rate limiting.

---

## 2. Provenance Spike Investigation

**Entry point:** `FrostgateProvenanceFailureSpike` alert — failure rate > 10% over
2 minutes. **This is a potential integrity signal. Do not auto-remediate.**

### Step 1 — Confirm scope

```promql
sum by (result) (
  rate(frostgate_provenance_validation_total[5m])
)
```

Distinguish `result="fail"` (validation rejected) vs `result="error"` (pipeline
exception). These have different implications:
- `fail` → hash mismatch, tampering, or policy version mismatch
- `error` → infrastructure / code issue during validation

### Step 2 — Identify affected tenants

Filter the structured log for `frostgate.provenance_validation` spans:

```
span.name = "frostgate.provenance_validation"
  AND span.status = "ERROR"
  AND timestamp >= <alert_time - 2m>
```

Group by `tenant.id` from span attributes to find blast radius.

### Step 3 — Check policy version

Span attribute `policy.version` tells you which policy was active at validation
time. If a deployment happened recently:

```bash
git log --oneline -10 -- policy/
```

A policy version change that wasn't propagated to the validation path causes a
mismatch → `fail` result with valid documents.

### Step 4 — Audit log preservation

**Before any remediation:** export validation logs for the affected window.

```
frostgate_provenance_validation_total{result="fail"}
  — window: [alert_time - 10m, now]
  — export format: JSONL with full request_id, trace_id, tenant_id, policy_version
```

See `docs/observability/runbooks/provenance_failures.md` — provenance failures
are a P1 incident. Notify compliance officer before proceeding.

### Step 5 — Correlate with trace

Take any `request_id` from the failing log entries, find its `trace_id`, and pull
the full trace. The `frostgate.provenance_validation` span's attributes include:
- `tenant.id`
- `policy.version` (active at validation time)

Compare `policy.version` in spans vs. current deployed version.

---

## 3. Provider Degradation Investigation

**Entry point:** `FrostgateProviderFailureHigh` alert, or rising latency on
customer-facing decision endpoints.

### Step 1 — Identify the degraded provider

```promql
# Failure rate by provider
sum by (provider_id, failure_type) (
  rate(frostgate_provider_failures_total[5m])
)
/
sum by (provider_id) (
  rate(frostgate_provider_requests_total[5m])
)
```

### Step 2 — Check latency distribution

```promql
histogram_quantile(0.99,
  sum by (provider_id, le) (
    rate(frostgate_provider_latency_seconds_bucket[5m])
  )
)
```

A p99 spike without a failure rate increase often indicates queuing on the
provider side (throttling, cold starts) rather than hard errors.

### Step 3 — Pull a representative trace

Filter logs for `provider_id=<degraded>` with `level=error` or `duration_ms > 2000`:

```json
{
  "trace_id": "...",
  "request_id": "...",
  "provider_id": "openai",
  "duration_ms": 8400,
  "status_code": 429
}
```

Open the trace. Check:
- Is the `frostgate.provider_routing` span slow, or is only the inner provider call slow?
- Are retry spans visible? (repeated child spans of the same type)
- What is the HTTP status returned by the provider? (429 = rate limit, 503 = overload)

### Step 4 — Check circuit breaker state

```promql
# Active connections being held open by provider
frostgate_active_connections
```

If active connections are saturated, the circuit breaker may need to trip manually.
See `docs/observability/runbooks/provider_failure.md`.

### Step 5 — Tenant impact

```promql
# Which tenants are affected?
sum by (tenant_id) (
  rate(frostgate_http_5xx_total[5m])
)
```

Cross-reference with the latency histogram grouped by tenant if available in
dashboards.

---

## 4. Tenant Latency Investigation

**Entry point:** A tenant reports slow responses, or `FrostgateRequestLatencyAbnormal`
fires for a specific tenant segment.

### Step 1 — Confirm the latency shape

```promql
histogram_quantile(0.99,
  sum by (method, status_class, le) (
    rate(frostgate_http_request_duration_seconds_bucket[5m])
  )
)
```

Is this p99 inflation (tail latency) or a median shift (systemic slowdown)?

- **Tail-only:** typically a single slow downstream call — trace one of the slow requests
- **Median shift:** usually DB saturation, provider pool exhaustion, or GC pressure

### Step 2 — Isolate the pipeline stage

```promql
# Provider latency
histogram_quantile(0.99, sum by (provider_id, le) (
  rate(frostgate_provider_latency_seconds_bucket[5m])
))

# Retrieval latency
histogram_quantile(0.99, sum by (mode, le) (
  rate(frostgate_retrieval_latency_seconds_bucket[5m])
))

# DB query latency
histogram_quantile(0.99, sum by (operation, le) (
  rate(frostgate_db_query_latency_seconds_bucket[5m])
))
```

The stage that's elevated is your bottleneck.

### Step 3 — Pull a slow trace

From the tenant's `request_id` (provided by tenant or from gateway logs), find the
`trace_id` in the structured log, then open in Grafana Tempo:

```
service.name = "frostgate-core"
  AND duration > 5000ms
  AND tenant.id = "<tenant>"
```

The trace waterfall will show which span is eating time. Common culprits:
- `frostgate.retrieval` — embedding lookup slow (vector DB saturation)
- `frostgate.provider_routing` — model cold start or rate limit
- DB span — missing index or lock contention

### Step 4 — Check DB health

```promql
frostgate_db_errors_total
frostgate_db_connectivity_failures_total
```

If DB errors spiked before the latency increase, the root cause is likely DB
connection pool exhaustion. Check `frostgate_active_connections` at the time.

### Step 5 — Tenant-specific isolation

If only one tenant is affected but overall metrics look healthy, check for:
- Tenant-specific data volume surge (large documents in ingestion)
- Policy configuration causing extra validation passes
- Per-tenant rate limits being applied upstream

Filter logs by `tenant_id` in the affected window to see per-request timing.
