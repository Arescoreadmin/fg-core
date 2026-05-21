"""Governance Posture Score (GPS) and drift severity computation.

GPS: 0–100 integer measuring current governance health.
  Computed from open findings weight, drift severity, and attestation coverage.
  A GPS delta (current − baseline) shows net posture change since last assessment.

Drift severity: categorical classification of how much posture changed.
  critical_regression  — previously resolved CRITICAL finding returned
  posture_degraded     — net new high/critical findings vs baseline
  posture_improved     — net resolved findings, no new high/critical
  stable               — delta below significance threshold
  no_baseline          — first run; establishes reference point

Drift confidence: 0–100, time-decayed by days since current scan.
  Clients who haven't run a scan recently see a lower confidence score,
  prompting a fresh assessment.

NIST-AI-RMF domain subscores: GPS broken down by framework function.
  Derived from nist_ai_rmf_mappings on FaNormalizedFinding rows.
  Domains: GOVERN, MAP, MEASURE, MANAGE, IMPROVE
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime

from services.connectors.drift.engine import DriftResult

# Per-severity weight for GPS deduction (mirrors open_findings_weight weights)
_GPS_WEIGHTS: dict[str, float] = {
    "critical": 12.0,
    "high": 6.0,
    "medium": 2.0,
    "low": 0.5,
    "informational": 0.0,
}

# Per-severity cap: excess findings do not deepen the deduction further
_GPS_CAPS: dict[str, int] = {
    "critical": 5,
    "high": 8,
    "medium": 15,
    "low": 20,
    "informational": 0,
}

# Drift significance threshold: net new high/critical below this → stable
_SIGNIFICANCE_THRESHOLD = 2

# Days-since-scan decay table for drift_confidence (days → confidence)
_CONFIDENCE_DECAY: list[tuple[int, int]] = [
    (3, 100),
    (7, 85),
    (14, 70),
    (30, 50),
    (math.inf, 30),  # type: ignore[arg-type]
]

_NIST_FUNCTIONS = ("GOVERN", "MAP", "MEASURE", "MANAGE", "IMPROVE")


@dataclass(frozen=True)
class DomainSubscore:
    function: str  # NIST-AI-RMF function label
    score: int     # 0–100
    open_finding_count: int


@dataclass(frozen=True)
class PostureDelta:
    """GPS and drift severity for a drift computation."""

    baseline_gps: int
    current_gps: int
    gps_delta: int                    # current − baseline; negative = degraded
    drift_severity: str               # critical_regression | posture_degraded | posture_improved | stable | no_baseline
    drift_confidence: int             # 0–100 time-decayed
    drift_confidence_reason: str
    domain_subscores: list[DomainSubscore] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


def _score_from_severity_counts(counts: dict[str, int]) -> int:
    """Compute 0–100 GPS from {severity: count} dict."""
    deduction = sum(
        _GPS_WEIGHTS.get(sev, 0.0) * min(cnt, _GPS_CAPS.get(sev, cnt))
        for sev, cnt in counts.items()
    )
    return max(0, min(100, round(100.0 - deduction)))


def _drift_confidence(current_scan_collected_at: str) -> tuple[int, str]:
    """Return (confidence_int, reason_str) based on days since scan was collected."""
    try:
        collected = datetime.fromisoformat(
            current_scan_collected_at.replace("Z", "+00:00")
        )
        days = (datetime.now(UTC) - collected).days
    except (ValueError, TypeError):
        return 50, "scan collection timestamp unparseable"

    for threshold, conf in _CONFIDENCE_DECAY:
        if days <= threshold:
            if days <= 3:
                return conf, f"scan is {days}d old — high confidence"
            if days <= 7:
                return conf, f"scan is {days}d old — good confidence"
            if days <= 14:
                return conf, f"scan is {days}d old — moderate confidence"
            if days <= 30:
                return conf, f"scan is {days}d old — reduced confidence; consider a fresh scan"
            return conf, f"scan is {days}d old — low confidence; fresh assessment recommended"
    return 30, "scan age exceeds 30 days — low confidence"


def _classify_drift_severity(
    drift: DriftResult,
    current_open_counts: dict[str, int],
    baseline_open_counts: dict[str, int],
) -> str:
    """Classify drift severity from delta counts."""
    if drift.has_critical_regression:
        return "critical_regression"

    net_new_high_critical = (
        drift.counts.get("new", 0)
        + drift.counts.get("regressed", 0)
        + drift.counts.get("escalated", 0)
    )
    net_resolved = drift.counts.get("resolved", 0) + drift.counts.get("de_escalated", 0)

    if net_new_high_critical >= _SIGNIFICANCE_THRESHOLD:
        # Only degrade if the new findings are actually high/critical
        high_crit_new = sum(
            1
            for f in drift.findings
            if f.delta_class in ("new", "regressed", "escalated")
            and f.severity in ("critical", "high")
        )
        if high_crit_new >= _SIGNIFICANCE_THRESHOLD:
            return "posture_degraded"

    if net_resolved > 0 and net_new_high_critical == 0:
        return "posture_improved"

    return "stable"


def _nist_subscores(
    open_findings: list[dict],
) -> list[DomainSubscore]:
    """Compute per-NIST-AI-RMF-function subscores from open finding dicts.

    Each dict must have keys: severity, nist_ai_rmf_mappings (list of {function, ...}).
    """
    domain_counts: dict[str, dict[str, int]] = {fn: {} for fn in _NIST_FUNCTIONS}
    domain_finding_counts: dict[str, int] = {fn: 0 for fn in _NIST_FUNCTIONS}

    for f in open_findings:
        sev = f.get("severity", "informational")
        for mapping in f.get("nist_ai_rmf_mappings", []):
            fn = str(mapping.get("function", "")).upper()
            if fn in domain_counts:
                domain_counts[fn][sev] = domain_counts[fn].get(sev, 0) + 1
                domain_finding_counts[fn] += 1

    result = []
    for fn in _NIST_FUNCTIONS:
        score = _score_from_severity_counts(domain_counts[fn]) if domain_counts[fn] else 100
        result.append(
            DomainSubscore(
                function=fn,
                score=score,
                open_finding_count=domain_finding_counts[fn],
            )
        )
    return result


def compute_posture_delta(
    drift: DriftResult,
    *,
    current_open_findings: list[dict],
    baseline_open_findings: list[dict],
    current_scan_collected_at: str,
    baseline_scan_collected_at: str | None = None,
    no_baseline: bool = False,
) -> PostureDelta:
    """Compute GPS delta and drift severity from engine DriftResult.

    current_open_findings / baseline_open_findings: list of dicts with keys
      severity, nist_ai_rmf_mappings (from FaNormalizedFinding rows).

    no_baseline=True: first run, returns no_baseline severity without computation.
    """
    if no_baseline:
        current_counts = {
            f.get("severity", "informational"): 0 for f in current_open_findings
        }
        for f in current_open_findings:
            s = f.get("severity", "informational")
            current_counts[s] = current_counts.get(s, 0) + 1
        current_gps = _score_from_severity_counts(current_counts)
        conf, conf_reason = _drift_confidence(current_scan_collected_at)
        return PostureDelta(
            baseline_gps=current_gps,
            current_gps=current_gps,
            gps_delta=0,
            drift_severity="no_baseline",
            drift_confidence=conf,
            drift_confidence_reason=conf_reason,
            domain_subscores=_nist_subscores(current_open_findings),
            counts={},
        )

    # Severity counts for current and baseline
    current_counts: dict[str, int] = {}
    for f in current_open_findings:
        s = f.get("severity", "informational")
        current_counts[s] = current_counts.get(s, 0) + 1

    baseline_counts: dict[str, int] = {}
    for f in baseline_open_findings:
        s = f.get("severity", "informational")
        baseline_counts[s] = baseline_counts.get(s, 0) + 1

    current_gps = _score_from_severity_counts(current_counts)
    baseline_gps = _score_from_severity_counts(baseline_counts)
    conf, conf_reason = _drift_confidence(current_scan_collected_at)

    severity = _classify_drift_severity(drift, current_counts, baseline_counts)

    return PostureDelta(
        baseline_gps=baseline_gps,
        current_gps=current_gps,
        gps_delta=current_gps - baseline_gps,
        drift_severity=severity,
        drift_confidence=conf,
        drift_confidence_reason=conf_reason,
        domain_subscores=_nist_subscores(current_open_findings),
        counts=drift.counts,
    )
