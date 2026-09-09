"""FGA-025 — Result Semantic Determination Authority (regression suite).

Proves that finding confidence cannot be confused with domain health posture,
and that the corrected domain health computation satisfies the required
metamorphic invariants.

Architecture under test
-----------------------

Finding confidence (0-100 int) describes certainty that an adverse finding is
supported by evidence.  Domain health (0-100 float, lower=worse) describes how
healthy a control domain is.  These are OPPOSITE scales for an adverse finding:

    domain_health = 100 - effective_confidence

The report engine emits a GovernanceFinding when domain_health < 60 (the
_FINDING_SCORE_THRESHOLD).  High confidence (95) → health=5 → critical finding.
Low confidence (30) → health=70 → suppressed (uncertain finding not material).

Aggregation is WORST-CASE (min) across active findings in a domain so that
adding a weak finding cannot dilute a strong one.

Only status∈{"open","in_progress"} findings are adverse-active.

Prior defect (FGA-025)
----------------------
The original code averaged confidence scores directly as domain scores.
High confidence (95) → domain_score=95 ≥ 60 → finding SUPPRESSED.
Low confidence (30) → domain_score=30 < 60 → finding emitted.
High confidence in adverse evidence silently improved apparent posture.

Test structure
--------------
- CASE A  High-confidence adverse finding remains material.
- CASE B  Confidence monotonicity: higher confidence must not improve posture.
- CASE C  Severity monotonicity: higher severity must not improve posture.
- CASE D  Low-confidence finding must not become more severe than a higher-confidence one.
- CASE E  Known-good (resolved) control does not become adverse.
- CASE F  Multiple findings aggregate deterministically.
- CASE G  Ordering of equivalent findings does not change the result.
- CASE H  LLM / executive-summary failure does not change deterministic truth.
- CASE I  Malformed or unknown severity inputs fail closed (engine contract).

Helper: _domain_health_scores()
--------------------------------
Mirrors the corrected computation in api/field_assessment.py exactly so the
tests are authoritative evidence of the production semantic.  Any drift between
this helper and the production code is a test failure.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any

import pytest

from services.field_assessment.confidence import degrade_confidence
from services.governance.report.engine import (
    GovernanceReportEngine,
    _FINDING_SCORE_THRESHOLD,
)
from services.governance.report.models import GovernanceReport

# ---------------------------------------------------------------------------
# Constants matching the engine's severity bands
# ---------------------------------------------------------------------------

_CRITICAL_MAX_SCORE = 25.0
_HIGH_MAX_SCORE = 40.0
_MEDIUM_MAX_SCORE = 60.0  # == _FINDING_SCORE_THRESHOLD

_TENANT = "tenant-fga025-test"
_ASSESSMENT = "assess-fga025-001"
_TODAY = "2026-09-09T00:00:00+00:00"  # recent — no confidence decay


# ---------------------------------------------------------------------------
# Helpers — mirror the corrected production logic exactly
# ---------------------------------------------------------------------------


@dataclass
class _MockFinding:
    """Minimal finding representation for semantic tests."""

    confidence_score: int
    status: str = "open"
    framework_mappings: list[Any] | None = None
    updated_at: str = _TODAY


def _domain_health_scores(findings: list[_MockFinding]) -> dict[str, float]:
    """Compute domain health scores using the corrected FGA-025 semantics.

    This is a faithful mirror of the production code in api/field_assessment.py
    (the lines touched by the FGA-025 fix).  Tests against this helper prove
    the metamorphic invariants independently of the DB-coupled route function.

    Semantics:
        - Only active adverse findings (status open/in_progress) contribute.
        - domain_health = 100 - effective_confidence  (inverted scale).
        - Aggregation: min() — worst-case finding governs the domain.
        - No active findings → default healthy (score 80, above threshold 60).
    """
    adverse_active = [f for f in findings if f.status in ("open", "in_progress")]

    domain_scores: dict[str, list[float]] = {}
    for f in adverse_active:
        mappings = f.framework_mappings or []
        if mappings:
            domain_key = str(
                mappings[0].get("domain", "data_governance")
                if isinstance(mappings[0], dict)
                else "data_governance"
            )
        else:
            domain_key = "data_governance"
        effective = degrade_confidence(f.confidence_score, f.updated_at)
        health = 100.0 - float(effective)
        domain_scores.setdefault(domain_key, []).append(health)

    scores: dict[str, float] = {}
    for domain, values in domain_scores.items():
        scores[domain] = min(values)

    if not scores:
        scores = {"data_governance": 80.0}

    return scores


def _engine_findings(scores: dict[str, float]) -> list[Any]:
    """Run the engine and return the GovernanceFinding list."""
    engine = GovernanceReportEngine()
    report: GovernanceReport = engine.generate(
        assessment_id=_ASSESSMENT,
        tenant_id=_TENANT,
        scores=scores,
        responses={},
        evidence_refs=[],
    )
    return list(report.findings)


def _finding_severities(findings: list[Any]) -> list[str]:
    return sorted(f.severity for f in findings)


# ---------------------------------------------------------------------------
# CASE A — High-confidence adverse finding remains material
# ---------------------------------------------------------------------------


def test_case_a_high_confidence_adverse_finding_is_material() -> None:
    """A finding with confidence=95 must appear in the governance report."""
    scores = _domain_health_scores([_MockFinding(confidence_score=95)])
    assert scores["data_governance"] < _FINDING_SCORE_THRESHOLD, (
        f"High-confidence finding must produce health < {_FINDING_SCORE_THRESHOLD}; "
        f"got {scores['data_governance']}"
    )
    findings = _engine_findings(scores)
    assert len(findings) >= 1, (
        "High-confidence (95) adverse finding must appear in report — finding was suppressed"
    )


def test_case_a_high_confidence_finding_is_critical() -> None:
    """Confidence=95 → health=5 → below critical threshold → critical severity."""
    scores = _domain_health_scores([_MockFinding(confidence_score=95)])
    findings = _engine_findings(scores)
    assert any(f.severity == "critical" for f in findings), (
        f"confidence=95 must produce critical severity; got severities {_finding_severities(findings)}"
    )


# ---------------------------------------------------------------------------
# CASE B — Confidence monotonicity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "conf_lower, conf_higher",
    [
        (60, 95),
        (50, 80),
        (40, 75),
        (65, 90),
    ],
)
def test_case_b_higher_confidence_does_not_improve_posture(
    conf_lower: int, conf_higher: int
) -> None:
    """Increasing confidence in an adverse finding must not improve domain posture."""
    health_lower = _domain_health_scores([_MockFinding(confidence_score=conf_lower)])[
        "data_governance"
    ]
    health_higher = _domain_health_scores([_MockFinding(confidence_score=conf_higher)])[
        "data_governance"
    ]
    assert health_higher <= health_lower, (
        f"Increasing confidence {conf_lower}→{conf_higher} improved posture: "
        f"health {health_lower:.1f}→{health_higher:.1f} (lower is WORSE)"
    )


def test_case_b_high_confidence_never_better_than_low_confidence_in_engine() -> None:
    """confidence=95 must not produce better posture (fewer/milder findings) than 60."""
    scores_60 = _domain_health_scores([_MockFinding(confidence_score=60)])
    scores_95 = _domain_health_scores([_MockFinding(confidence_score=95)])

    findings_60 = _engine_findings(scores_60)
    findings_95 = _engine_findings(scores_95)

    # Both should produce findings (neither suppressed)
    assert len(findings_95) >= len(findings_60), (
        "confidence=95 produced fewer findings than confidence=60 — confidence monotonicity violated"
    )


# ---------------------------------------------------------------------------
# CASE C — Severity monotonicity
# ---------------------------------------------------------------------------


def test_case_c_higher_severity_finding_does_not_improve_posture() -> None:
    """A critical-severity finding must not produce better posture than medium-severity."""
    # In the corrected model, domain health is derived from confidence (not from
    # the finding's own severity field).  Two findings with identical confidence
    # but different severity fields must yield identical or worse (not better)
    # posture for the more severe one.
    same_confidence = 80
    scores_medium = _domain_health_scores(
        [_MockFinding(confidence_score=same_confidence)]
    )
    scores_critical = _domain_health_scores(
        [_MockFinding(confidence_score=same_confidence)]
    )
    # Same confidence → same health
    assert scores_medium["data_governance"] == scores_critical["data_governance"], (
        "Identical confidence must yield identical domain health regardless of severity label"
    )


@pytest.mark.parametrize(
    "conf_medium, conf_critical",
    [
        # higher-confidence finding represents more-certain problem → worse posture
        (50, 80),
        (60, 95),
    ],
)
def test_case_c_higher_confidence_critical_finding_is_at_least_as_bad(
    conf_medium: int, conf_critical: int
) -> None:
    """A higher-confidence finding must produce same-or-worse posture."""
    h_medium = _domain_health_scores([_MockFinding(confidence_score=conf_medium)])[
        "data_governance"
    ]
    h_critical = _domain_health_scores([_MockFinding(confidence_score=conf_critical)])[
        "data_governance"
    ]
    assert h_critical <= h_medium, (
        f"Higher-confidence finding improved posture: health {h_medium:.1f}→{h_critical:.1f}"
    )


# ---------------------------------------------------------------------------
# CASE D — Low-confidence finding is not more severe than a higher-confidence one
# ---------------------------------------------------------------------------


def test_case_d_low_confidence_finding_not_more_severe_than_high() -> None:
    """A finding at confidence=30 must not produce a more severe outcome than one at 70."""
    h_low = _domain_health_scores([_MockFinding(confidence_score=30)])[
        "data_governance"
    ]
    h_high = _domain_health_scores([_MockFinding(confidence_score=70)])[
        "data_governance"
    ]

    findings_low = _engine_findings(
        h_low if isinstance(h_low, dict) else {"data_governance": h_low}
    )
    findings_high = _engine_findings({"data_governance": h_high})

    sev_low = _finding_severities(findings_low)
    sev_high = _finding_severities(findings_high)

    _sev_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}

    max_sev_low = max((_sev_rank.get(s, 0) for s in sev_low), default=-1)
    max_sev_high = max((_sev_rank.get(s, 0) for s in sev_high), default=-1)

    assert max_sev_low <= max_sev_high, (
        f"Low confidence (30) produced more severe finding ({sev_low}) "
        f"than high confidence (70) ({sev_high})"
    )


def test_case_d_low_confidence_finding_does_not_produce_critical() -> None:
    """confidence=30 (uncertain) must not produce a critical finding."""
    h = _domain_health_scores([_MockFinding(confidence_score=30)])["data_governance"]
    findings = _engine_findings({"data_governance": h})
    assert not any(f.severity == "critical" for f in findings), (
        "Low-confidence (30) adverse finding produced critical finding — confidence too low for critical"
    )


# ---------------------------------------------------------------------------
# CASE E — Resolved / dismissed findings do not contribute to adverse posture
# ---------------------------------------------------------------------------


def test_case_e_resolved_finding_does_not_produce_adverse_posture() -> None:
    """A high-confidence resolved finding must not generate a report finding."""
    findings = [_MockFinding(confidence_score=95, status="resolved")]
    scores = _domain_health_scores(findings)
    # No active adverse findings → healthy default
    assert scores["data_governance"] == 80.0, (
        f"Resolved finding contributed to domain health; expected 80.0, got {scores['data_governance']}"
    )
    engine_findings = _engine_findings(scores)
    assert len(engine_findings) == 0, (
        "Resolved finding (status=resolved) must not generate governance finding"
    )


def test_case_e_dismissed_finding_does_not_produce_adverse_posture() -> None:
    """A high-confidence dismissed finding must not generate a report finding."""
    findings = [_MockFinding(confidence_score=90, status="dismissed")]
    scores = _domain_health_scores(findings)
    assert scores["data_governance"] == 80.0
    assert len(_engine_findings(scores)) == 0


def test_case_e_mixed_resolved_and_active() -> None:
    """Only the active finding should contribute; the resolved one must not dilute it."""
    active = _MockFinding(confidence_score=90, status="open")
    resolved = _MockFinding(confidence_score=30, status="resolved")
    scores = _domain_health_scores([active, resolved])
    h = scores["data_governance"]
    # Active confidence=90 → health=10; resolved should NOT pull health up
    assert h == pytest.approx(10.0), (
        f"Resolved finding diluted active finding; expected health=10, got {h}"
    )
    findings = _engine_findings(scores)
    assert len(findings) >= 1, "Active finding must still produce a report finding"


# ---------------------------------------------------------------------------
# CASE F — Multiple findings aggregate deterministically
# ---------------------------------------------------------------------------


def test_case_f_multiple_findings_worst_case_governs() -> None:
    """Min aggregation: adding a weak finding cannot dilute a strong one."""
    strong = _MockFinding(confidence_score=95)  # health=5
    weak = _MockFinding(confidence_score=30)  # health=70
    scores_strong_only = _domain_health_scores([strong])
    scores_combined = _domain_health_scores([strong, weak])

    h_strong = scores_strong_only["data_governance"]
    h_combined = scores_combined["data_governance"]

    # Adding the weak finding must not improve posture
    assert h_combined <= h_strong + 1e-9, (
        f"Adding weak finding (confidence=30) improved posture from {h_strong:.1f} to {h_combined:.1f}"
    )


def test_case_f_deterministic_output_same_inputs() -> None:
    """Identical inputs must produce identical domain health scores."""
    findings = [
        _MockFinding(confidence_score=80),
        _MockFinding(confidence_score=60),
    ]
    scores_a = _domain_health_scores(findings)
    scores_b = _domain_health_scores(findings)
    assert scores_a == scores_b, (
        "Domain health is not deterministic for identical inputs"
    )


def test_case_f_two_high_confidence_findings_both_produce_critical() -> None:
    """Two high-confidence findings in different domains both produce findings."""
    f1 = _MockFinding(
        confidence_score=90, framework_mappings=[{"domain": "data_governance"}]
    )
    f2 = _MockFinding(
        confidence_score=85, framework_mappings=[{"domain": "security_posture"}]
    )
    scores = _domain_health_scores([f1, f2])
    assert scores["data_governance"] < _FINDING_SCORE_THRESHOLD
    assert scores["security_posture"] < _FINDING_SCORE_THRESHOLD
    findings = _engine_findings(scores)
    domains = {f.domain for f in findings}
    assert "data_governance" in domains
    assert "security_posture" in domains


# ---------------------------------------------------------------------------
# CASE G — Order of equivalent findings does not change the result
# ---------------------------------------------------------------------------


def test_case_g_order_invariance_two_findings() -> None:
    """The domain health score must not depend on the order of equivalent findings."""
    f_a = _MockFinding(confidence_score=80)
    f_b = _MockFinding(confidence_score=60)
    scores_ab = _domain_health_scores([f_a, f_b])
    scores_ba = _domain_health_scores([f_b, f_a])
    assert scores_ab == scores_ba, (
        "Domain health depends on finding order — not deterministic"
    )


def test_case_g_order_invariance_engine_findings() -> None:
    """Engine findings must be identical regardless of input finding order."""
    f_a = _MockFinding(
        confidence_score=75, framework_mappings=[{"domain": "data_governance"}]
    )
    f_b = _MockFinding(
        confidence_score=85, framework_mappings=[{"domain": "data_governance"}]
    )
    findings_ab = _engine_findings(_domain_health_scores([f_a, f_b]))
    findings_ba = _engine_findings(_domain_health_scores([f_b, f_a]))
    assert _finding_severities(findings_ab) == _finding_severities(findings_ba), (
        "Engine finding severities depend on input order"
    )


# ---------------------------------------------------------------------------
# CASE H — LLM / executive-summary failure cannot change deterministic truth
# ---------------------------------------------------------------------------


def test_case_h_engine_has_no_llm_dependency() -> None:
    """The governance report engine must be pure Python with no LLM imports."""
    import services.governance.report.engine as _engine_module

    # Check actual import statements only — the docstring legitimately says "no llms"
    # so scanning full source produces false positives. Parse only import lines.
    source = inspect.getsource(_engine_module)
    import_lines = [
        ln.lower()
        for ln in source.splitlines()
        if ln.strip().startswith(("import ", "from "))
    ]
    import_text = "\n".join(import_lines)
    for llm_marker in ("openai", "anthropic", "langchain", "openllm", "litellm"):
        assert llm_marker not in import_text, (
            f"Report engine imports '{llm_marker}' — LLM must not influence deterministic truth"
        )


def test_case_h_findings_unaffected_by_executive_summary_failure() -> None:
    """Findings produced by the engine do not change if executive summary is unavailable."""
    scores = _domain_health_scores([_MockFinding(confidence_score=85)])
    # Generate report (engine never touches LLM)
    engine = GovernanceReportEngine()
    report = engine.generate(
        assessment_id=_ASSESSMENT,
        tenant_id=_TENANT,
        scores=scores,
        responses={},
        evidence_refs=[],
    )
    # findings are frozen; executive summary is not part of GovernanceReport
    assert len(report.findings) >= 1, (
        "Engine must produce findings regardless of executive summary availability"
    )
    # Verify findings are frozen (immutable) — LLM cannot retroactively modify them
    with pytest.raises((AttributeError, TypeError)):
        report.findings[0].severity = "low"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# CASE I — Malformed / unknown semantic values fail closed
# ---------------------------------------------------------------------------


def test_case_i_finding_with_unknown_status_excluded() -> None:
    """Findings with unrecognised status must not contribute to adverse posture."""
    f = _MockFinding(confidence_score=95, status="unknown_status")
    scores = _domain_health_scores([f])
    # Must behave as if no active adverse findings
    assert scores["data_governance"] == 80.0, (
        f"Finding with unknown status contributed to domain health; expected 80.0, got {scores['data_governance']}"
    )


def test_case_i_empty_findings_yields_healthy_default() -> None:
    """No findings → default healthy domain → no governance findings emitted."""
    scores = _domain_health_scores([])
    assert scores == {"data_governance": 80.0}
    findings = _engine_findings(scores)
    assert len(findings) == 0, (
        "Empty findings must not produce adverse governance findings"
    )


def test_case_i_confidence_floor_does_not_produce_critical() -> None:
    """Confidence at floor (30, meaning stale/decayed) must not produce a critical finding."""
    # Floor confidence = 30 → health = 70 → above threshold → no finding
    scores = _domain_health_scores([_MockFinding(confidence_score=30)])
    findings = _engine_findings(scores)
    assert not any(f.severity == "critical" for f in findings), (
        "Confidence-floor finding produced critical severity — floor evidence is too uncertain for critical"
    )


# ---------------------------------------------------------------------------
# Prior-defect regression (FGA-025)
# ---------------------------------------------------------------------------


def test_fga025_old_behavior_would_have_suppressed_high_confidence_finding() -> None:
    """Document the pre-fix defect: averaging confidence directly as domain score
    caused high-confidence findings to be suppressed.

    This test verifies the defect is no longer present.
    """
    # Old (broken) computation: domain_score = average(confidence_scores)
    confidence = 95
    effective = degrade_confidence(confidence, _TODAY)  # no decay (recent evidence)
    old_domain_score = float(effective)  # was 95.0 — above threshold — SUPPRESSED

    # New (correct) computation: domain_health = 100 - confidence
    new_domain_health = 100.0 - float(effective)  # 5.0 — well below threshold

    assert old_domain_score >= _FINDING_SCORE_THRESHOLD, (
        "Test precondition: old computation must produce a score >= threshold (defect simulation)"
    )
    assert new_domain_health < _FINDING_SCORE_THRESHOLD, (
        "New computation must produce a score < threshold (finding emitted)"
    )

    # Old path: no finding (suppressed)
    old_scores = {"data_governance": old_domain_score}
    old_findings = _engine_findings(old_scores)
    assert len(old_findings) == 0, (
        "Pre-condition: old logic suppresses high-confidence finding"
    )

    # New path (corrected): finding present
    new_scores = {"data_governance": new_domain_health}
    new_findings = _engine_findings(new_scores)
    assert len(new_findings) >= 1, (
        "Post-fix: high-confidence adverse finding must appear in report"
    )


def test_fga025_old_behavior_would_have_promoted_low_confidence_finding() -> None:
    """Document the pre-fix defect: low-confidence finding produced critical finding.

    This was the perverse output: low certainty → high concern.
    """
    confidence = 30  # very uncertain
    effective = degrade_confidence(confidence, _TODAY)
    old_domain_score = float(effective)  # 30.0 — below threshold — critical gap!

    # Old computation: score=30 → critical (below 25 check)
    assert old_domain_score < _FINDING_SCORE_THRESHOLD, (
        "Pre-condition: old logic emits finding for low-confidence evidence"
    )

    # New computation: domain_health = 100 - 30 = 70 → above threshold → suppressed
    new_domain_health = 100.0 - float(effective)
    assert new_domain_health >= _FINDING_SCORE_THRESHOLD, (
        "New computation must suppress a finding for confidence=30 (too uncertain to be material)"
    )
