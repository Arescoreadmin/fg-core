"""Unit tests for the remediation priority scoring formula.

Covers:
  - Score components (severity base, exploitability, confidence, source)
  - All-connector finding_type families: MS Graph and new connectors
  - Phase assignment at threshold boundaries
  - Effort level mapping (family defaults + per-finding-type overrides)
  - Step template dispatch for new connector families
  - Quick-wins classification (high impact / low effort)
"""

from __future__ import annotations

import types
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from services.field_assessment.remediation import (
    PHASE_IMMEDIATE,
    PHASE_IMMEDIATE_THRESHOLD,
    PHASE_PLANNED,
    PHASE_SHORT_TERM,
    PHASE_SHORT_TERM_THRESHOLD,
    assign_phase,
    compute_effort_level,
    compute_priority_score,
    generate_remediation_steps,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def _finding(
    *,
    finding_type: str = "network.unsafe_services_exposed",
    severity: str = "high",
    evidence_ref_ids: list[str] | None = None,
    confidence_score: int = 80,
    updated_at: str | None = None,
    remediation_hint: str | None = None,
    title: str = "Test finding",
) -> Any:
    return types.SimpleNamespace(
        finding_type=finding_type,
        title=title,
        severity=severity,
        evidence_ref_ids=evidence_ref_ids or [],
        confidence_score=confidence_score,
        updated_at=updated_at or _iso(0),
        remediation_hint=remediation_hint,
        nist_ai_rmf_mappings=[],
    )


# ---------------------------------------------------------------------------
# Severity base
# ---------------------------------------------------------------------------


class TestSeverityBase:
    @pytest.mark.parametrize(
        "severity,min_score",
        [
            ("critical", 40),
            ("high", 30),
            ("medium", 20),
            ("low", 10),
            ("info", 0),
        ],
    )
    def test_severity_drives_base_score(self, severity: str, min_score: int) -> None:
        f = _finding(severity=severity, finding_type="dns_email.dmarc_missing")
        assert compute_priority_score(f) >= min_score

    def test_critical_always_outscores_high_same_type(self) -> None:
        critical = _finding(
            severity="critical", finding_type="network.unsafe_services_exposed"
        )
        high = _finding(severity="high", finding_type="network.unsafe_services_exposed")
        assert compute_priority_score(critical) > compute_priority_score(high)

    def test_score_never_negative(self) -> None:
        f = _finding(severity="info", confidence_score=30, updated_at=_iso(365))
        assert compute_priority_score(f) >= 0


# ---------------------------------------------------------------------------
# Exploitability bonus
# ---------------------------------------------------------------------------


class TestExploitabilityBonus:
    def test_network_outscores_dns_same_severity(self) -> None:
        net = _finding(severity="high", finding_type="network.unsafe_services_exposed")
        dns = _finding(severity="high", finding_type="dns_email.dmarc_missing")
        assert compute_priority_score(net) > compute_priority_score(dns)

    def test_mfa_outscores_app_same_severity(self) -> None:
        mfa = _finding(severity="high", finding_type="msgraph.MFA-001")
        app = _finding(severity="high", finding_type="msgraph.APP-001")
        assert compute_priority_score(mfa) > compute_priority_score(app)

    def test_unknown_family_uses_default_bonus(self) -> None:
        f = _finding(finding_type="unknown.something", severity="medium")
        score = compute_priority_score(f)
        # medium base (20) + default bonus (5) + confidence bonus (5, score>=80) = 30
        assert score == 30

    def test_sharepoint_and_sharepoint_onedrive_equal(self) -> None:
        sp = _finding(finding_type="sharepoint.anonymous_sharing", severity="high")
        spo = _finding(
            finding_type="sharepoint_onedrive.anonymous_sharing", severity="high"
        )
        assert compute_priority_score(sp) == compute_priority_score(spo)

    @pytest.mark.parametrize(
        "finding_type,expected_bonus",
        [
            ("network.unsafe_services_exposed", 15),
            ("msgraph.MFA-001", 12),
            ("msgraph.PRIV-001", 12),
            ("entra.permanent_global_admin", 10),
            ("msgraph.CA-001", 10),
            ("oauth.admin_consented_grants", 10),
            ("endpoint.non_compliant_devices", 10),
            ("sharepoint.anonymous_sharing", 8),
            ("sharepoint_onedrive.anonymous_sharing", 8),
            ("msgraph.GUEST-001", 8),
            ("msgraph.AI-001", 8),
            ("msgraph.APP-001", 7),
            ("dns_email.dmarc_missing", 5),
            ("web_headers.hsts_missing", 5),
        ],
    )
    def test_exploitability_bonus_values(
        self, finding_type: str, expected_bonus: int
    ) -> None:
        # Use fresh evidence, confidence=80 → +5 confidence, no source → +0
        # score = severity_base + exploitability + 5 + 0
        # Use medium severity (base=20) to isolate exploitability
        f = _finding(
            finding_type=finding_type,
            severity="medium",
            confidence_score=80,
            updated_at=_iso(0),
        )
        score = compute_priority_score(f)
        assert (
            score == 20 + expected_bonus + 5
        )  # base + exploitability + confidence(+5)


# ---------------------------------------------------------------------------
# Confidence factor
# ---------------------------------------------------------------------------


class TestConfidenceFactor:
    def test_high_confidence_adds_5(self) -> None:
        f = _finding(
            confidence_score=80, updated_at=_iso(0), finding_type="dns_email.x"
        )
        f2 = _finding(
            confidence_score=79, updated_at=_iso(0), finding_type="dns_email.x"
        )
        assert compute_priority_score(f) == compute_priority_score(f2) + 5

    def test_mid_confidence_adds_0(self) -> None:
        f60 = _finding(
            confidence_score=60, updated_at=_iso(0), finding_type="dns_email.x"
        )
        f79 = _finding(
            confidence_score=79, updated_at=_iso(0), finding_type="dns_email.x"
        )
        assert compute_priority_score(f60) == compute_priority_score(f79)

    def test_low_confidence_subtracts_5(self) -> None:
        f59 = _finding(
            confidence_score=59, updated_at=_iso(0), finding_type="dns_email.x"
        )
        f60 = _finding(
            confidence_score=60, updated_at=_iso(0), finding_type="dns_email.x"
        )
        assert compute_priority_score(f59) == compute_priority_score(f60) - 5

    def test_stale_evidence_degrades_confidence(self) -> None:
        fresh = _finding(
            confidence_score=80, updated_at=_iso(5), finding_type="dns_email.x"
        )
        stale = _finding(
            confidence_score=80, updated_at=_iso(95), finding_type="dns_email.x"
        )
        # 80 - 30 (91+days decay) = 50 < 60 → stale gets -5 instead of +5 → 10 pt gap
        assert compute_priority_score(fresh) > compute_priority_score(stale)


# ---------------------------------------------------------------------------
# Source bonus
# ---------------------------------------------------------------------------


class TestSourceBonus:
    def test_scan_confirmed_adds_5(self) -> None:
        confirmed = _finding(evidence_ref_ids=["e1"], finding_type="dns_email.x")
        unconfirmed = _finding(evidence_ref_ids=[], finding_type="dns_email.x")
        assert (
            compute_priority_score(confirmed) == compute_priority_score(unconfirmed) + 5
        )

    def test_multiple_refs_same_as_one(self) -> None:
        one = _finding(evidence_ref_ids=["e1"], finding_type="dns_email.x")
        many = _finding(evidence_ref_ids=["e1", "e2", "e3"], finding_type="dns_email.x")
        assert compute_priority_score(one) == compute_priority_score(many)


# ---------------------------------------------------------------------------
# Phase assignment
# ---------------------------------------------------------------------------


class TestPhaseAssignment:
    def test_at_immediate_threshold(self) -> None:
        assert assign_phase(PHASE_IMMEDIATE_THRESHOLD) == PHASE_IMMEDIATE

    def test_just_below_immediate(self) -> None:
        assert assign_phase(PHASE_IMMEDIATE_THRESHOLD - 1) == PHASE_SHORT_TERM

    def test_at_short_term_threshold(self) -> None:
        assert assign_phase(PHASE_SHORT_TERM_THRESHOLD) == PHASE_SHORT_TERM

    def test_just_below_short_term(self) -> None:
        assert assign_phase(PHASE_SHORT_TERM_THRESHOLD - 1) == PHASE_PLANNED

    def test_zero_score_is_planned(self) -> None:
        assert assign_phase(0) == PHASE_PLANNED

    def test_critical_network_scan_confirmed_is_immediate(self) -> None:
        f = _finding(
            severity="critical",
            finding_type="network.unsafe_services_exposed",
            evidence_ref_ids=["e1"],
            confidence_score=90,
            updated_at=_iso(5),
        )
        assert assign_phase(compute_priority_score(f)) == PHASE_IMMEDIATE

    def test_low_dns_questionnaire_only_is_planned(self) -> None:
        f = _finding(
            severity="low",
            finding_type="dns_email.dnssec_missing",
            evidence_ref_ids=[],
            confidence_score=70,
        )
        assert assign_phase(compute_priority_score(f)) == PHASE_PLANNED

    @pytest.mark.parametrize(
        "severity,finding_type,refs,expected_phase",
        [
            # Scan-confirmed network criticals → immediate
            ("critical", "network.unsafe_services_exposed", ["e1"], PHASE_IMMEDIATE),
            # Scan-confirmed high network → immediate (30+15+5+5=55)
            ("high", "network.unsafe_services_exposed", ["e1"], PHASE_IMMEDIATE),
            # Medium network scan-confirmed → short_term (20+15+5+5=45)
            ("medium", "network.unsafe_services_exposed", ["e1"], PHASE_SHORT_TERM),
            # High MFA scan-confirmed → immediate (30+12+5+5=52)
            ("high", "msgraph.MFA-001", ["e1"], PHASE_IMMEDIATE),
            # High web headers scan-confirmed → short_term (30+5+5+5=45)
            ("high", "web_headers.hsts_missing", ["e1"], PHASE_SHORT_TERM),
            # Medium questionnaire-only DNS → planned (20+5+0+0=25)
            ("medium", "dns_email.dmarc_missing", [], PHASE_PLANNED),
            # Low network scan-confirmed hits short_term (10+15+5+5=35, at threshold)
            ("low", "network.plain_http_services", ["e1"], PHASE_SHORT_TERM),
        ],
    )
    def test_phase_assignment_archetypes(
        self,
        severity: str,
        finding_type: str,
        refs: list[str],
        expected_phase: str,
    ) -> None:
        f = _finding(
            severity=severity,
            finding_type=finding_type,
            evidence_ref_ids=refs,
            confidence_score=80,
            updated_at=_iso(5),
        )
        assert assign_phase(compute_priority_score(f)) == expected_phase


# ---------------------------------------------------------------------------
# Effort level
# ---------------------------------------------------------------------------


class TestEffortLevel:
    @pytest.mark.parametrize(
        "finding_type,expected_effort",
        [
            ("msgraph.MFA-001", "low"),
            ("msgraph.GUEST-001", "low"),
            ("dns_email.dmarc_missing", "low"),
            ("web_headers.hsts_missing", "low"),
            ("network.invalid_tls_certificates", "low"),  # per-type override
            ("endpoint.stale_devices", "low"),  # per-type override
            ("msgraph.CA-001", "medium"),
            ("msgraph.PRIV-001", "medium"),
            ("network.unsafe_services_exposed", "medium"),
            ("endpoint.non_compliant_devices", "medium"),
            ("entra.permanent_global_admin", "medium"),
            ("sharepoint.anonymous_sharing", "medium"),
            ("oauth.unverified_publishers", "medium"),  # per-type override
            ("endpoint.unmanaged_devices", "high"),  # per-type override
            ("msgraph.APP-001", "high"),
            ("msgraph.OAUTH-001", "high"),
            ("msgraph.AI-001", "high"),
        ],
    )
    def test_effort_level_by_finding_type(
        self, finding_type: str, expected_effort: str
    ) -> None:
        f = _finding(finding_type=finding_type)
        assert compute_effort_level(f) == expected_effort

    def test_unknown_family_defaults_to_medium(self) -> None:
        f = _finding(finding_type="unknown.something")
        assert compute_effort_level(f) == "medium"


# ---------------------------------------------------------------------------
# Remediation step dispatch (new connector families)
# ---------------------------------------------------------------------------


class TestStepDispatch:
    def test_network_unsafe_services_steps_mention_firewall(self) -> None:
        f = _finding(finding_type="network.unsafe_services_exposed")
        steps = generate_remediation_steps(f)
        text = " ".join(steps).lower()
        assert "firewall" in text or "vpn" in text or "restrict" in text

    def test_network_plain_http_steps_mention_tls(self) -> None:
        f = _finding(finding_type="network.plain_http_services")
        steps = generate_remediation_steps(f)
        text = " ".join(steps).lower()
        assert "tls" in text or "https" in text

    def test_network_tls_cert_steps_mention_renewal(self) -> None:
        f = _finding(finding_type="network.invalid_tls_certificates")
        steps = generate_remediation_steps(f)
        text = " ".join(steps).lower()
        assert "renew" in text or "certificate" in text

    def test_endpoint_non_compliant_steps_mention_intune(self) -> None:
        f = _finding(finding_type="endpoint.non_compliant_devices")
        steps = generate_remediation_steps(f)
        text = " ".join(steps).lower()
        assert "intune" in text

    def test_endpoint_stale_devices_steps(self) -> None:
        f = _finding(finding_type="endpoint.stale_devices")
        steps = generate_remediation_steps(f)
        assert len(steps) >= 3

    def test_dns_dmarc_steps_mention_dmarc(self) -> None:
        f = _finding(finding_type="dns_email.dmarc_missing")
        steps = generate_remediation_steps(f)
        text = " ".join(steps).lower()
        assert "dmarc" in text

    def test_dns_spf_steps_mention_spf(self) -> None:
        f = _finding(finding_type="dns_email.spf_missing")
        steps = generate_remediation_steps(f)
        text = " ".join(steps).lower()
        assert "spf" in text

    def test_web_headers_hsts_steps_mention_hsts(self) -> None:
        f = _finding(finding_type="web_headers.hsts_missing")
        steps = generate_remediation_steps(f)
        text = " ".join(steps).lower()
        assert "strict-transport-security" in text or "hsts" in text

    def test_sharepoint_anonymous_steps_mention_sharing(self) -> None:
        f = _finding(finding_type="sharepoint.anonymous_sharing")
        steps = generate_remediation_steps(f)
        text = " ".join(steps).lower()
        assert "sharing" in text or "sharepoint" in text

    def test_entra_pim_steps_mention_pim(self) -> None:
        f = _finding(finding_type="entra.permanent_global_admin")
        steps = generate_remediation_steps(f)
        text = " ".join(steps).lower()
        assert "pim" in text or "privileged identity" in text

    def test_generic_fallback_uses_remediation_hint(self) -> None:
        f = _finding(
            finding_type="unknown.something",
            remediation_hint="Apply the vendor patch.",
        )
        steps = generate_remediation_steps(f)
        assert steps[0] == "Apply the vendor patch."

    def test_generic_fallback_no_hint(self) -> None:
        f = _finding(finding_type="unknown.something", remediation_hint=None)
        steps = generate_remediation_steps(f)
        assert len(steps) >= 1


# ---------------------------------------------------------------------------
# Quick-wins classification (high impact × low effort)
# ---------------------------------------------------------------------------


class TestQuickWins:
    def test_dns_high_finding_is_quick_win(self) -> None:
        f = _finding(
            severity="high",
            finding_type="dns_email.dmarc_missing",
            evidence_ref_ids=["e1"],
        )
        effort = compute_effort_level(f)
        phase = assign_phase(compute_priority_score(f))
        # High severity + low effort = quick win
        assert effort == "low"
        assert phase in (PHASE_IMMEDIATE, PHASE_SHORT_TERM)

    def test_web_headers_high_finding_is_quick_win(self) -> None:
        f = _finding(
            severity="high",
            finding_type="web_headers.hsts_missing",
            evidence_ref_ids=["e1"],
        )
        assert compute_effort_level(f) == "low"
        assert assign_phase(compute_priority_score(f)) in (
            PHASE_IMMEDIATE,
            PHASE_SHORT_TERM,
        )

    def test_unmanaged_devices_is_not_quick_win(self) -> None:
        f = _finding(
            severity="high",
            finding_type="endpoint.unmanaged_devices",
            evidence_ref_ids=["e1"],
        )
        # High impact but high effort
        assert compute_effort_level(f) == "high"
