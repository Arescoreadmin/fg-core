"""api/identity_governance/metrics.py — Prometheus metrics for identity governance.

Labels are restricted to low-cardinality classification values (decision,
identity_type, event_type, band). Never label by subject, tenant, email,
IP, device fingerprint, correlation id, or route parameter — labels form
part of the timeseries and would enable identity reconstruction from
metrics scrape output.
"""

from __future__ import annotations

from prometheus_client import Counter

# ---------------------------------------------------------------------------
# Authorization decisions (require_permission / require_capability results)
# ---------------------------------------------------------------------------

IDENTITY_AUTHORIZATION_DECISIONS_TOTAL = Counter(
    "frostgate_identity_authorization_decisions_total",
    "Authorization decisions from the identity runtime",
    ["decision", "identity_type"],
)

# ---------------------------------------------------------------------------
# Session evaluation
# ---------------------------------------------------------------------------

IDENTITY_SESSION_EVALUATIONS_TOTAL = Counter(
    "frostgate_identity_session_evaluations_total",
    "Continuous session evaluation outcomes",
    ["decision"],
)

# ---------------------------------------------------------------------------
# Risk engine
# ---------------------------------------------------------------------------

IDENTITY_RISK_BAND_TOTAL = Counter(
    "frostgate_identity_risk_band_total",
    "Identity risk-band assignments",
    ["band"],
)

# ---------------------------------------------------------------------------
# Conditional access policy engine
# ---------------------------------------------------------------------------

IDENTITY_POLICY_DECISIONS_TOTAL = Counter(
    "frostgate_identity_policy_decisions_total",
    "Conditional access policy engine decisions",
    ["decision"],
)

# ---------------------------------------------------------------------------
# Timeline event emission
# ---------------------------------------------------------------------------

IDENTITY_TIMELINE_EVENTS_TOTAL = Counter(
    "frostgate_identity_timeline_events_total",
    "Identity timeline events emitted",
    ["event_type"],
)


__all__ = [
    "IDENTITY_AUTHORIZATION_DECISIONS_TOTAL",
    "IDENTITY_POLICY_DECISIONS_TOTAL",
    "IDENTITY_RISK_BAND_TOTAL",
    "IDENTITY_SESSION_EVALUATIONS_TOTAL",
    "IDENTITY_TIMELINE_EVENTS_TOTAL",
]
