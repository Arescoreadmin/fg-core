"""Tests for msgraph posture score calculator."""

from __future__ import annotations

import pytest

from services.connectors.msgraph.posture_score import (
    PostureScore,
    compute_posture_score,
)
from services.connectors.msgraph.schema.scan_result import Finding


def _finding(
    severity: str,
    title: str = "Test Finding",
    finding_id: str = "abc123",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        control_id="NIST-AI-RMF-GOVERN-1.2",
        framework_refs=["NIST-AI-RMF"],
        severity=severity,  # type: ignore[arg-type]
        title=title,
        evidence_summary="test",
        affected_count=1,
        recommendation="fix it",
        remediation_effort="low",
        remediation_owner="IT",
    )


class TestPostureScoreEmpty:
    def test_no_findings_is_perfect_score(self) -> None:
        score = compute_posture_score([])
        assert score.overall == 100
        assert score.security == 100
        assert score.compliance == 100
        assert score.ai_governance == 100
        assert score.finding_count == 0
        assert score.band == "good"

    def test_informational_only_is_perfect_score(self) -> None:
        findings = [_finding("informational", finding_id=f"f{i}") for i in range(10)]
        score = compute_posture_score(findings)
        assert score.overall == 100
        assert score.informational_count == 10


class TestPostureScoreDeductions:
    def test_single_critical_deducts(self) -> None:
        score = compute_posture_score([_finding("critical")])
        assert score.overall == 88  # 100 - 12
        assert score.critical_count == 1
        assert score.band == "good"

    def test_single_high_deducts(self) -> None:
        score = compute_posture_score([_finding("high")])
        assert score.overall == 94  # 100 - 6

    def test_single_medium_deducts(self) -> None:
        score = compute_posture_score([_finding("medium")])
        assert score.overall == 98  # 100 - 2

    def test_multiple_criticals_deduct(self) -> None:
        findings = [_finding("critical", finding_id=f"c{i}") for i in range(3)]
        score = compute_posture_score(findings)
        assert score.overall == 64  # 100 - 3*12
        assert score.critical_count == 3

    def test_cap_prevents_score_below_zero(self) -> None:
        # 100 critical findings — cap is 5 so deduction = 5*12 = 60
        findings = [_finding("critical", finding_id=f"c{i}") for i in range(100)]
        score = compute_posture_score(findings)
        assert score.overall == 40  # 100 - 5*12
        assert score.critical_count == 100

    def test_saturated_mix_floors_at_zero(self) -> None:
        findings = (
            [_finding("critical", finding_id=f"cr{i}") for i in range(5)]
            + [_finding("high", finding_id=f"hi{i}") for i in range(8)]
            + [_finding("medium", finding_id=f"me{i}") for i in range(15)]
        )
        # deduction = 5*12 + 8*6 + 15*2 = 60 + 48 + 30 = 138 → capped at 0
        score = compute_posture_score(findings)
        assert score.overall == 0
        assert score.band == "critical"


class TestPostureBand:
    @pytest.mark.parametrize(
        "overall,expected_band",
        [
            (100, "good"),
            (85, "good"),
            (84, "fair"),
            (65, "fair"),
            (64, "poor"),
            (40, "poor"),
            (39, "critical"),
            (0, "critical"),
        ],
    )
    def test_band_thresholds(self, overall: int, expected_band: str) -> None:
        score = PostureScore(
            overall=overall,
            security=overall,
            compliance=overall,
            ai_governance=overall,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            informational_count=0,
            finding_count=0,
        )
        assert score.band == expected_band


class TestDomainClassification:
    def test_ai_keyword_routes_to_ai_domain(self) -> None:
        findings = [_finding("high", title="Shadow AI app detected")]
        score = compute_posture_score(findings)
        assert score.ai_governance < 100
        assert score.security == 100  # no security findings
        assert score.compliance == 100

    def test_oauth_routes_to_compliance_domain(self) -> None:
        findings = [_finding("high", title="OAuth consent grant risky")]
        score = compute_posture_score(findings)
        assert score.compliance < 100
        assert score.ai_governance == 100
        assert score.security == 100

    def test_mfa_routes_to_security_domain(self) -> None:
        findings = [_finding("critical", title="Admin account with no MFA")]
        score = compute_posture_score(findings)
        assert score.security < 100
        assert score.compliance == 100
        assert score.ai_governance == 100

    def test_domain_scores_independent_of_overall(self) -> None:
        # Two criticals, one in each domain — overall is lower than any domain
        findings = [
            _finding("critical", title="Shadow AI app detected", finding_id="ai1"),
            _finding("critical", title="Admin account with no MFA", finding_id="sec1"),
        ]
        score = compute_posture_score(findings)
        # overall = 100 - 2*12 = 76
        assert score.overall == 76
        # each domain has one critical: 100 - 12 = 88
        assert score.ai_governance == 88
        assert score.security == 88
