from __future__ import annotations

from prometheus_client import Counter, Histogram

# Total /defend requests by threat level
DECISION_REQUESTS = Counter(
    "frostgate_decision_requests_total",
    "Total /defend requests processed by Frostgate Core",
    ["threat_level"],
)

# Latency of /defend in seconds, bucketed by threat level
DECISION_LATENCY_SECONDS = Histogram(
    "frostgate_decision_latency_seconds",
    "Latency of /defend decisions in seconds",
    ["threat_level"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

# DB logging failures (we never want these, but they will happen)
DECISION_DB_ERRORS = Counter(
    "frostgate_decision_db_errors_total",
    "Count of failed decision log writes to the database",
)

# Re-export enterprise metrics so callers can import from either location.
from api.observability.metrics import (  # noqa: E402, F401
    PROVIDER_REQUESTS,
    PROVIDER_LATENCY,
    PROVIDER_FAILURES,
    RETRIEVAL_REQUESTS,
    RETRIEVAL_LATENCY,
    INGESTION_REQUESTS,
    INGESTION_LATENCY,
    AUDIT_EXPORT_TOTAL,
    AUDIT_EXPORT_LATENCY,
    AUDIT_PIPELINE_FAILURES,
    PROVENANCE_VALIDATION_TOTAL,
    DB_ERRORS_TOTAL,
    DB_CONNECTIVITY_FAILURES,
    HTTP_5XX_TOTAL,
    HTTP_REQUEST_DURATION,
)
