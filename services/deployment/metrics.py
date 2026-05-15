"""Deployment SLO metrics — Prometheus instrumentation.

Emitted by DeploymentStore on every lifecycle mutation. Dashboards, SLO
alerts, and on-call runbooks should reference these metric names.

All metrics use the frostgate_deployment_ prefix. Labels are bounded and
safe (no tenant IDs, no free-text, no secrets).
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram

_LATENCY_BUCKETS = (
    1.0,
    5.0,
    15.0,
    30.0,
    60.0,
    120.0,
    300.0,
    600.0,
    1800.0,
    3600.0,
)

# ---------------------------------------------------------------------------
# Deployment lifecycle counters
# ---------------------------------------------------------------------------

DEPLOYMENT_TRANSITIONS_TOTAL = Counter(
    "frostgate_deployment_transitions_total",
    "Total deployment state transitions by strategy, env_type, from_state, to_state.",
    ["strategy", "env_type", "from_state", "to_state"],
)

DEPLOYMENT_FAILURES_TOTAL = Counter(
    "frostgate_deployment_failures_total",
    "Total deployments that entered the failed state.",
    ["strategy", "env_type", "compliance_classification"],
)

ROLLBACK_TOTAL = Counter(
    "frostgate_deployment_rollback_total",
    "Total deployments that entered the rolled_back state.",
    ["strategy", "env_type"],
)

APPROVAL_DECISIONS_TOTAL = Counter(
    "frostgate_deployment_approval_decisions_total",
    "Total approval decisions recorded (granted or denied).",
    ["decision"],
)

# ---------------------------------------------------------------------------
# Duration histograms
# ---------------------------------------------------------------------------

DEPLOYMENT_DURATION_SECONDS = Histogram(
    "frostgate_deployment_duration_seconds",
    "Wall-clock time from deployment creation to first terminal/healthy state.",
    ["strategy", "env_type", "terminal_state"],
    buckets=_LATENCY_BUCKETS,
)

APPROVAL_WAIT_DURATION_SECONDS = Histogram(
    "frostgate_deployment_approval_wait_seconds",
    "Wall-clock time from deployment creation to approval decision.",
    ["decision"],
    buckets=_LATENCY_BUCKETS,
)

# ---------------------------------------------------------------------------
# Health state gauge-like counter
# ---------------------------------------------------------------------------

HEALTH_PROBE_RESULTS_TOTAL = Counter(
    "frostgate_deployment_health_probe_results_total",
    "Total health probe results recorded by probe type and result.",
    ["probe", "result"],
)
