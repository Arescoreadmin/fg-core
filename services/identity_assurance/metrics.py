"""services/identity_assurance/metrics.py — Prometheus metrics for Identity Assurance.

All metrics use the ``frostgate_actor_assurance_`` / ``frostgate_actor_trust_`` /
``frostgate_high_trust_`` / ``frostgate_low_trust_`` / ``frostgate_identity_provider_`` /
``frostgate_assurance_`` prefixes. No tenant_id labels — privacy-safe by design.
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram

# ---------------------------------------------------------------------------
# Assurance evaluation counters
# ---------------------------------------------------------------------------

ACTOR_ASSURANCE_TOTAL = Counter(
    "frostgate_actor_assurance_total",
    "Total assurance evaluations",
    ["level"],
)

ACTOR_ASSURANCE_CHANGES = Counter(
    "frostgate_actor_assurance_changes_total",
    "Assurance level changes",
)

ACTOR_TRUST_DISTRIBUTION = Histogram(
    "frostgate_actor_trust_score_distribution",
    "Trust score distribution",
    buckets=[0, 20, 40, 60, 80, 90, 95, 100],
)

HIGH_TRUST_ACTIONS = Counter(
    "frostgate_high_trust_actions_total",
    "Actions by high-trust actors",
)

LOW_TRUST_ACTIONS = Counter(
    "frostgate_low_trust_actions_total",
    "Actions by low-trust actors",
)

IDENTITY_PROVIDER_USAGE = Counter(
    "frostgate_assurance_provider_usage_total",
    "Identity provider usage observed during assurance evaluation",
    ["provider"],
)

ASSURANCE_FAILURES = Counter(
    "frostgate_assurance_failures_total",
    "Assurance evaluation failures",
)
