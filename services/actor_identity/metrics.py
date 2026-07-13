"""services/actor_identity/metrics.py — Prometheus instrumentation for actor attribution (PR 535).

All metrics use the frostgate_actor_ / frostgate_attribution_ / frostgate_identity_ prefix.
No tenant_id labels — privacy-safe by design.
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram

# ---------------------------------------------------------------------------
# Actor resolution counters
# ---------------------------------------------------------------------------

ACTOR_RESOLUTIONS_TOTAL = Counter(
    "frostgate_actor_resolutions_total",
    "Total actor identity resolutions",
)

ACTOR_RESOLUTION_FAILURES_TOTAL = Counter(
    "frostgate_actor_resolution_failures_total",
    "Actor resolution failures",
)

UNKNOWN_ACTORS_TOTAL = Counter(
    "frostgate_unknown_actors_total",
    "Requests with no resolvable actor",
)

# ---------------------------------------------------------------------------
# Identity validation counters
# ---------------------------------------------------------------------------

IDENTITY_FAILURES_TOTAL = Counter(
    "frostgate_identity_failures_total",
    "Identity validation failures",
)

SPOOF_ATTEMPTS_TOTAL = Counter(
    "frostgate_spoof_attempts_total",
    "Detected identity spoofing attempts",
)

# ---------------------------------------------------------------------------
# Attribution counters
# ---------------------------------------------------------------------------

ATTRIBUTION_RECORDS_CREATED_TOTAL = Counter(
    "frostgate_attribution_records_created_total",
    "Attribution records created",
)

IDENTITY_SNAPSHOTS_CREATED_TOTAL = Counter(
    "frostgate_identity_snapshots_created_total",
    "Identity snapshots captured",
)

# ---------------------------------------------------------------------------
# Actor-type usage counters
# ---------------------------------------------------------------------------

SYSTEM_ACTOR_USAGE_TOTAL = Counter(
    "frostgate_system_actor_usage_total",
    "System actor requests",
)

AUTOMATION_ACTOR_USAGE_TOTAL = Counter(
    "frostgate_automation_actor_usage_total",
    "Automation actor requests",
)

# ---------------------------------------------------------------------------
# Security counters
# ---------------------------------------------------------------------------

CROSS_TENANT_DENIAL_TOTAL = Counter(
    "frostgate_actor_cross_tenant_denial_total",
    "Cross-tenant attribution denials",
)

# ---------------------------------------------------------------------------
# Latency histogram
# ---------------------------------------------------------------------------

ATTRIBUTION_LATENCY = Histogram(
    "frostgate_attribution_resolution_seconds",
    "Time to resolve and attach actor attribution",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5],
)
