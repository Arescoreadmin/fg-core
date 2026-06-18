"""Centralized Prometheus metrics registry for FrostGate.

All metric definitions live here so dashboards, alert rules, and instrumented
code share a single source of truth for label names and bucket boundaries.

Metrics are registered on import; repeated imports are safe (CollectorRegistry
de-dupes by name). Test isolation uses the `REGISTRY` reset mechanism in pytest
conftest when needed.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

_LATENCY_BUCKETS = (
    0.001,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
)

# ---------------------------------------------------------------------------
# Provider metrics
# ---------------------------------------------------------------------------

PROVIDER_REQUESTS = Counter(
    "frostgate_provider_requests_total",
    "Total provider routing requests by provider and outcome",
    ["provider_id", "status"],
)

PROVIDER_LATENCY = Histogram(
    "frostgate_provider_latency_seconds",
    "Provider response latency in seconds",
    ["provider_id"],
    buckets=_LATENCY_BUCKETS,
)

PROVIDER_FAILURES = Counter(
    "frostgate_provider_failures_total",
    "Provider hard failures (timeouts, errors, unavailability)",
    ["provider_id", "failure_type"],
)

# ---------------------------------------------------------------------------
# Retrieval pipeline metrics
# ---------------------------------------------------------------------------

RETRIEVAL_REQUESTS = Counter(
    "frostgate_retrieval_requests_total",
    "Total retrieval requests by mode and outcome",
    ["mode", "status"],
)

RETRIEVAL_LATENCY = Histogram(
    "frostgate_retrieval_latency_seconds",
    "Retrieval pipeline latency in seconds",
    ["mode"],
    buckets=_LATENCY_BUCKETS,
)

RETRIEVAL_CHUNK_COUNT = Histogram(
    "frostgate_retrieval_chunks_returned",
    "Number of chunks returned per retrieval request",
    ["mode"],
    buckets=(0, 1, 2, 5, 10, 20, 50, 100),
)

# ---------------------------------------------------------------------------
# Ingestion pipeline metrics
# ---------------------------------------------------------------------------

INGESTION_REQUESTS = Counter(
    "frostgate_ingestion_requests_total",
    "Total ingestion requests by tenant and outcome",
    ["tenant_id", "doc_type", "status"],
)

INGESTION_LATENCY = Histogram(
    "frostgate_ingestion_latency_seconds",
    "Ingestion pipeline latency in seconds",
    ["doc_type"],
    buckets=_LATENCY_BUCKETS,
)

INGESTION_BYTES = Counter(
    "frostgate_ingestion_bytes_total",
    "Total bytes ingested by document type",
    ["doc_type"],
)

# ---------------------------------------------------------------------------
# Audit pipeline metrics
# ---------------------------------------------------------------------------

AUDIT_EXPORT_TOTAL = Counter(
    "frostgate_audit_export_total",
    "Total audit export generations by tenant and outcome",
    ["tenant_id", "status"],
)

AUDIT_EXPORT_LATENCY = Histogram(
    "frostgate_audit_export_latency_seconds",
    "Audit export generation latency in seconds",
    ["tenant_id"],
    buckets=_LATENCY_BUCKETS,
)

AUDIT_PIPELINE_FAILURES = Counter(
    "frostgate_audit_pipeline_failures_total",
    "Audit pipeline failures by failure type",
    ["failure_type"],
)

# ---------------------------------------------------------------------------
# Provenance validation metrics
# ---------------------------------------------------------------------------

PROVENANCE_VALIDATION_TOTAL = Counter(
    "frostgate_provenance_validation_total",
    "Total provenance validations by result",
    ["result"],  # pass | fail | error
)

PROVENANCE_FAILURE_SPIKE = Gauge(
    "frostgate_provenance_failure_rate_1m",
    "Rolling 1-minute provenance failure rate (0.0–1.0); updated by the validation path",
)

# ---------------------------------------------------------------------------
# HTTP / infrastructure metrics
# ---------------------------------------------------------------------------

HTTP_5XX_TOTAL = Counter(
    "frostgate_http_5xx_total",
    "Total HTTP 5xx responses",
    ["method"],
    # NOTE: path is intentionally excluded — paths containing UUIDs/IDs would
    # produce unbounded label cardinality and a denial-of-wallet billing event.
)

HTTP_REQUEST_DURATION = Histogram(
    "frostgate_http_request_duration_seconds",
    "HTTP request duration including middleware overhead",
    ["method", "status_class"],  # status_class: 2xx | 3xx | 4xx | 5xx
    buckets=_LATENCY_BUCKETS,
)

# ---------------------------------------------------------------------------
# Database / connectivity metrics
# ---------------------------------------------------------------------------

DB_ERRORS_TOTAL = Counter(
    "frostgate_db_errors_total",
    "Database operation errors by operation type",
    ["operation"],
)

DB_QUERY_LATENCY = Histogram(
    "frostgate_db_query_latency_seconds",
    "Database query latency in seconds",
    ["operation"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0, 5.0),
)

DB_CONNECTIVITY_FAILURES = Counter(
    "frostgate_db_connectivity_failures_total",
    "Database connectivity failures (connection refused, timeout, etc.)",
)

# ---------------------------------------------------------------------------
# Alerting support: current state gauges
# ---------------------------------------------------------------------------

ACTIVE_CONNECTIONS = Gauge(
    "frostgate_active_connections",
    "Current number of active HTTP connections being processed",
)

INGESTION_QUEUE_DEPTH = Gauge(
    "frostgate_ingestion_queue_depth",
    "Current ingestion queue depth (pending documents)",
)

# ---------------------------------------------------------------------------
# P1.3: Capability enforcement metrics
# No tenant_id label — high cardinality; no sensitive data in telemetry.
# ---------------------------------------------------------------------------

CAPABILITY_CHECKS_TOTAL = Counter(
    "frostgate_capability_checks_total",
    "Total capability enforcement checks by capability and result",
    ["capability", "result"],  # result: granted | denied | dep_failure | unknown
)

CAPABILITY_GRANTS_TOTAL = Counter(
    "frostgate_capability_grants_total",
    "Total capability checks that resolved to granted, by capability and grant source",
    ["capability", "source"],  # source: explicit | bundle | tier
)

CAPABILITY_DENIALS_TOTAL = Counter(
    "frostgate_capability_denials_total",
    "Total capability checks that resolved to denied, by capability and denial reason",
    ["capability", "reason"],  # reason: missing | dep_failure | unknown | no_tenant
)

CAPABILITY_DEPENDENCY_FAILURES_TOTAL = Counter(
    "frostgate_capability_dependency_failures_total",
    "Capability checks denied because a prerequisite capability was missing",
    ["capability", "missing_dep"],
)

CAPABILITY_CACHE_HITS_TOTAL = Counter(
    "frostgate_capability_cache_hits_total",
    "Capability resolver cache hits (tenant capability set served from TTL cache)",
)

CAPABILITY_CACHE_MISSES_TOTAL = Counter(
    "frostgate_capability_cache_misses_total",
    "Capability resolver cache misses (tenant capability set fetched from DB)",
)

# ---------------------------------------------------------------------------
# P1.4: Subscription Assignment Engine metrics
# No tenant_id labels — high cardinality.
# ---------------------------------------------------------------------------

SUBSCRIPTION_CONTRACTS_CREATED_TOTAL = Counter(
    "frostgate_subscription_contracts_created_total",
    "Total subscription contracts created, by SKU package",
    ["sku_package"],
)

SUBSCRIPTION_ITEMS_CREATED_TOTAL = Counter(
    "frostgate_subscription_items_created_total",
    "Total subscription items created, by SKU code",
    ["sku_code"],
)

SUBSCRIPTION_ITEMS_STATUS_CHANGES_TOTAL = Counter(
    "frostgate_subscription_items_status_changes_total",
    "Total subscription item status transitions, by from/to status",
    ["from_status", "to_status"],
)

SUBSCRIPTION_EVENT_LEDGER_ENTRIES_TOTAL = Counter(
    "frostgate_subscription_event_ledger_entries_total",
    "Total immutable ledger entries appended, by event type",
    ["event_type"],
)

SUBSCRIPTION_EXPLAIN_REQUESTS_TOTAL = Counter(
    "frostgate_subscription_explain_requests_total",
    "Total explain-capability requests, by decision result",
    ["result"],  # granted | denied
)
