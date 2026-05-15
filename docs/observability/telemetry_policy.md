# Dynamic Telemetry Policy

FrostGate's telemetry policy controls what is emitted, for whom, and where it
goes — at runtime, without code changes. Policy is loaded from environment
variables at startup and can be reloaded with `reload_policy()`.

---

## Quick reference

| Env var | Default | Effect |
|---|---|---|
| `FG_OBSERVABILITY_MODE` | `standard` | Master mode switch — see below |
| `FG_DISABLE_EXTERNAL_OTLP` | `0` | Block all OTLP export to external endpoints |
| `FG_RESTRICT_TRACE_ATTRIBUTES` | `0` | Limit span attributes to pre-approved set |
| `FG_TELEMETRY_SUPPRESSED_TENANTS` | _(unset)_ | CSV of tenant IDs to suppress entirely |

---

## Observability modes

### `standard` (default)

All telemetry is emitted. Span attributes pass through without filtering.
External OTLP export is allowed when `FG_OTEL_ENDPOINT` is set.

Use in: development, staging, standard production.

### `regulated`

Span attributes are restricted to the pre-approved set (see below). External
OTLP is still allowed — the assumption is that the OTLP collector is within
your compliance boundary. If you need to block external OTLP too, add
`FG_DISABLE_EXTERNAL_OTLP=1`.

Equivalent to `FG_RESTRICT_TRACE_ATTRIBUTES=1`.

Use in: HIPAA, SOC 2, PCI DSS deployments where attribute leakage in trace
backends is a concern.

### `strict`

Regulated mode + external OTLP blocked. No traces leave the deployment
boundary under any circumstances. Traces are either local (console exporter)
or dropped.

Equivalent to `FG_OBSERVABILITY_MODE=regulated` + `FG_DISABLE_EXTERNAL_OTLP=1`.

Use in: air-gapped, FedRAMP High, GovCon, environments with "no external
egress" network policy.

---

## External OTLP enforcement (`FG_DISABLE_EXTERNAL_OTLP`)

When set to `1`, `setup_tracing()` skips OTLP exporter configuration even if
`FG_OTEL_ENDPOINT` is set. A warning is logged at startup:

```
otel_otlp_blocked_by_policy mode=standard disable_external_otlp=True endpoint=https://...
```

The `TracerProvider` is still initialized (spans are created in memory).
Console export (`FG_OTEL_CONSOLE=1`) still works — only external network
egress is blocked.

This flag is also activated automatically by `FG_OBSERVABILITY_MODE=strict`.

**Use case:** an operator has set `FG_OTEL_ENDPOINT` in a shared config file
but a specific environment (e.g. a GovCloud VPC) must not emit traces outside
its boundary. Set `FG_DISABLE_EXTERNAL_OTLP=1` on the restricted environment
without touching the shared config.

---

## Span attribute restriction (`FG_RESTRICT_TRACE_ATTRIBUTES`)

When enabled (or implied by regulated/strict mode), only attributes in the
pre-approved set are attached to spans. Unapproved attributes are silently
dropped before `set_attribute()` is called.

### Pre-approved span attribute keys

```
tenant.id               frostgate.tenant_id     frostgate.request_id
doc.type                export.format
provider.id
retrieval.mode
policy.version
http.method             http.route              http.target
http.status_code        http.scheme             http.url
http.host               http.flavor
net.peer.ip
exception.type
```

**Notably excluded in restricted mode:**
- `exception.message` — error messages can contain user-supplied data
- `exception.stacktrace` — stack frames may contain file paths or data values
- Any free-form attribute key not in the list above

Adding a new key to the approved set requires a code change to
`APPROVED_SPAN_ATTRIBUTES` in `api/observability/telemetry_policy.py` and
a security review comment in the PR.

### Why `exception.message` is excluded

Error messages in FrostGate pipelines can include document content fragments,
provider responses, or tenant-supplied query text. In regulated/strict mode
these must not appear in the trace backend (which may have shorter retention
or less restrictive access control than the audit log). `exception.type`
(the exception class name) is retained because it is bounded and safe.

---

## Per-tenant telemetry suppression (`FG_TELEMETRY_SUPPRESSED_TENANTS`)

Set to a comma-separated list of tenant IDs whose telemetry should be fully
suppressed:

```bash
FG_TELEMETRY_SUPPRESSED_TENANTS=acme-corp,beta-inc,regulated-customer
```

When a pipeline span (`span_ingestion`, `span_retrieval`, etc.) is called for
a suppressed tenant, it yields a `NonRecordingSpan` — the call site works
identically but no trace data is created, exported, or stored. HTTP metrics
are still incremented (cardinality-safe; no tenant label on those metrics).

**Use cases:**
- A tenant has contractual requirements prohibiting their activity from
  appearing in shared observability backends.
- A regulated customer requires zero trace egress even in standard mode.
- A customer explicitly opted out of telemetry collection.

**Important:** suppression applies to spans only. Structured application logs
(which include `tenant_id`) are not suppressed by this flag. If full log
suppression is needed, implement it at the log sink/router level.

---

## Export approval policy

"Export approval" in FrostGate means: OTLP export to any external endpoint
requires explicit opt-in, and is blocked by policy in regulated/strict modes.

The check happens in `setup_tracing()` before the OTLP exporter is constructed:

```python
if not get_policy().allows_external_otlp():
    # Log warning, skip exporter construction entirely
```

There is no runtime "approve this export" flow — the policy is applied at
startup. To change export behavior, update the env var and restart the service
(or call `reload_policy()` if using programmatic reconfiguration).

---

## Combining flags

| Scenario | Config |
|---|---|
| Air-gapped — no external egress | `FG_OBSERVABILITY_MODE=strict` |
| Regulated — OTLP to internal collector, restricted attributes | `FG_OBSERVABILITY_MODE=regulated` |
| Regulated — no OTLP at all | `FG_OBSERVABILITY_MODE=regulated` + `FG_DISABLE_EXTERNAL_OTLP=1` |
| Standard — but one tenant opted out | `FG_TELEMETRY_SUPPRESSED_TENANTS=<tenant-id>` |
| Standard — block external OTLP only | `FG_DISABLE_EXTERNAL_OTLP=1` |
| Restrict attributes only | `FG_RESTRICT_TRACE_ATTRIBUTES=1` |
| Disable all tracing | `FG_OTEL_ENABLED=0` |
| Disable metrics endpoint | `FG_METRICS_ENABLED=0` |

---

## Runtime reload

```python
from api.observability.telemetry_policy import reload_policy

# After updating env vars (e.g. from a config reload):
policy = reload_policy()
```

`reload_policy()` re-reads all `FG_*` env vars and replaces the module-level
singleton. Useful in tests and operator-triggered reconfiguration flows.
The previous policy object is garbage-collected but any in-flight spans that
captured the old policy reference are unaffected.

---

## Integration with `setup_tracing()`

`setup_tracing()` calls `get_policy()` once during initialization:

1. If `FG_OTEL_ENABLED=0` → skip entirely (existing behavior, no policy involved).
2. If `FG_OTEL_ENDPOINT` is set AND `policy.allows_external_otlp()` is False → log warning, skip OTLP exporter construction.
3. If `FG_OTEL_ENDPOINT` is set AND `policy.allows_external_otlp()` is True → configure OTLP exporter (existing behavior).

The `TracerProvider` is always constructed when tracing is enabled, regardless
of policy. Only the exporter (network egress) is gated.

---

## Adding new span attributes

When adding a `span.set_attribute("new.key", value)` call anywhere in the
codebase:

1. Check if the key is in `APPROVED_SPAN_ATTRIBUTES` in `telemetry_policy.py`.
2. If not, and you want it to work in regulated/strict mode, add it there with a justification comment.
3. The `check_safe_telemetry.py` CI gate will catch forbidden field names (secrets, raw prompts, etc.) regardless of policy mode.
4. If you're unsure whether the value is bounded/safe, ask: could this value contain user-supplied text or a secret? If yes, don't emit it as a span attribute.
