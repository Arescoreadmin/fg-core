"""Comprehensive tests for the deterministic governance report core.

All tests are pure unit tests — no DB, no network, no seeded question banks.
Tests assert determinism, immutability, replay equivalence, and fail-closed behavior.
"""

from __future__ import annotations

import dataclasses
import pytest

from services.governance.report.confidence import calculate_confidence
from services.governance.report.engine import (
    GovernanceReportEngine,
    GovernanceReportError,
)
from services.governance.report.framework_mappings import (
    get_framework_mappings,
    get_supported_frameworks,
)
from services.governance.report.identity import (
    derive_evidence_id,
    derive_finding_id,
    derive_remediation_id,
)
from services.governance.report.models import (
    ConfidenceScore,
    EvidenceRef,
    FrameworkMapping,
    GovernanceFinding,
    RemediationEntry,
    ValidationState,
)
from services.governance.report.serialization import (
    deserialize_report,
    export_html,
    serialize_for_manifest,
    serialize_report,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_evidence_ref(
    source: str = "security_posture_scan",
    validation_state: ValidationState = ValidationState.VALIDATED,
    classification: str = "internal",
    provenance: str = "scanner-v1",
    freshness_days: int | None = 10,
) -> EvidenceRef:
    from services.governance.report.identity import derive_evidence_id

    return EvidenceRef(
        evidence_id=derive_evidence_id(source, classification, provenance),
        source=source,
        validation_state=validation_state,
        classification=classification,
        provenance=provenance,
        freshness_days=freshness_days,
    )


def _low_scores() -> dict[str, float]:
    return {
        "data_governance": 30.0,
        "security_posture": 20.0,
        "ai_maturity": 50.0,
        "infra_readiness": 70.0,
        "compliance_awareness": 80.0,
        "automation_potential": 90.0,
    }


def _high_scores() -> dict[str, float]:
    return {
        "data_governance": 80.0,
        "security_posture": 85.0,
        "ai_maturity": 75.0,
        "infra_readiness": 70.0,
        "compliance_awareness": 90.0,
        "automation_potential": 95.0,
    }


def _sample_evidence_refs() -> list[EvidenceRef]:
    return [
        _make_evidence_ref(
            "security_posture_scan", ValidationState.VALIDATED, freshness_days=5
        ),
        _make_evidence_ref(
            "data_governance_audit",
            ValidationState.VALIDATED,
            classification="confidential",
            provenance="audit-2025",
            freshness_days=30,
        ),
        _make_evidence_ref(
            "compliance_framework_check", ValidationState.PENDING, freshness_days=60
        ),
    ]


_ENGINE = GovernanceReportEngine()


# ---------------------------------------------------------------------------
# TestDeterministicFindingIds
# ---------------------------------------------------------------------------


class TestDeterministicFindingIds:
    def test_same_inputs_produce_same_finding_id(self):
        id1 = derive_finding_id(
            "tenant-1", "NIST_AI_RMF", "security_posture", "high_gap", "abc123"
        )
        id2 = derive_finding_id(
            "tenant-1", "NIST_AI_RMF", "security_posture", "high_gap", "abc123"
        )
        assert id1 == id2

    def test_different_inputs_produce_different_finding_ids(self):
        id1 = derive_finding_id(
            "tenant-1", "NIST_AI_RMF", "security_posture", "high_gap", "abc123"
        )
        id2 = derive_finding_id(
            "tenant-1", "NIST_AI_RMF", "data_governance", "high_gap", "abc123"
        )
        id3 = derive_finding_id(
            "tenant-2", "NIST_AI_RMF", "security_posture", "high_gap", "abc123"
        )
        id4 = derive_finding_id(
            "tenant-1", "NIST_AI_RMF", "security_posture", "critical_gap", "abc123"
        )
        assert len({id1, id2, id3, id4}) == 4

    def test_finding_id_is_hex_string(self):
        fid = derive_finding_id("t", "NIST_AI_RMF", "ctrl", "gap", "hash")
        assert len(fid) == 16
        assert all(c in "0123456789abcdef" for c in fid)

    def test_cross_tenant_finding_ids_are_unique(self):
        # Security invariant: identical inputs from different tenants must produce different IDs.
        fid_a = derive_finding_id(
            "tenant-a", "NIST_AI_RMF", "data_governance", "gap", "abc123"
        )
        fid_b = derive_finding_id(
            "tenant-b", "NIST_AI_RMF", "data_governance", "gap", "abc123"
        )
        assert fid_a != fid_b

    def test_remediation_id_deterministic(self):
        r1 = derive_remediation_id("tenant-1", "security_posture", "high", "high")
        r2 = derive_remediation_id("tenant-1", "security_posture", "high", "high")
        assert r1 == r2

    def test_remediation_id_different_inputs(self):
        r1 = derive_remediation_id("tenant-1", "security_posture", "high", "high")
        r2 = derive_remediation_id("tenant-1", "data_governance", "high", "high")
        assert r1 != r2

    def test_evidence_id_deterministic(self):
        e1 = derive_evidence_id("scanner", "internal", "prov-1")
        e2 = derive_evidence_id("scanner", "internal", "prov-1")
        assert e1 == e2

    def test_evidence_id_different_inputs(self):
        e1 = derive_evidence_id("scanner-a", "internal", "prov-1")
        e2 = derive_evidence_id("scanner-b", "internal", "prov-1")
        assert e1 != e2


# ---------------------------------------------------------------------------
# TestConfidenceScoring
# ---------------------------------------------------------------------------


class TestConfidenceScoring:
    def test_full_evidence_high_confidence(self):
        refs = [
            _make_evidence_ref(
                source=f"src-{i}",
                validation_state=ValidationState.VALIDATED,
                freshness_days=5,
            )
            for i in range(5)
        ]
        score = calculate_confidence(refs, 100.0, reviewer_validated=True)
        assert score.overall > 0.7
        assert score.evidence_completeness == 1.0
        assert score.control_coverage == 1.0
        assert score.reviewer_validated is True

    def test_no_evidence_zero_confidence(self):
        score = calculate_confidence([], 100.0, reviewer_validated=True)
        assert score.overall == 0.0
        assert "no evidence" in score.degradation_reasons

    def test_missing_evidence_degrades_confidence(self):
        refs = [
            _make_evidence_ref(
                source="a", validation_state=ValidationState.MISSING, freshness_days=10
            ),
            _make_evidence_ref(
                source="b", validation_state=ValidationState.MISSING, freshness_days=10
            ),
            _make_evidence_ref(
                source="c",
                validation_state=ValidationState.VALIDATED,
                freshness_days=10,
            ),
        ]
        score = calculate_confidence(refs, 100.0, reviewer_validated=False)
        assert score.evidence_completeness < 1.0
        assert any("completeness" in r for r in score.degradation_reasons)

    def test_stale_evidence_degrades_freshness(self):
        refs = [
            _make_evidence_ref(
                source="a",
                validation_state=ValidationState.VALIDATED,
                freshness_days=180,
            ),
            _make_evidence_ref(
                source="b",
                validation_state=ValidationState.VALIDATED,
                freshness_days=200,
            ),
        ]
        score = calculate_confidence(refs, 100.0, reviewer_validated=True)
        # All refs are > 90 days → freshness = 0
        assert score.evidence_freshness == 0.0
        assert any("freshness" in r for r in score.degradation_reasons)

    def test_degradation_reasons_populated(self):
        refs = [
            _make_evidence_ref(
                source="a", validation_state=ValidationState.MISSING, freshness_days=200
            ),
        ]
        score = calculate_confidence(refs, 10.0, reviewer_validated=False)
        assert len(score.degradation_reasons) > 0

    def test_overall_is_zero_for_zero_completion(self):
        refs = [
            _make_evidence_ref(
                validation_state=ValidationState.VALIDATED, freshness_days=5
            )
        ]
        score = calculate_confidence(refs, 0.0, reviewer_validated=True)
        assert score.overall == 0.0

    def test_confidence_score_is_frozen(self):
        score = calculate_confidence([], 50.0, reviewer_validated=False)
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            score.overall = 1.0  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TestFrameworkMappings
# ---------------------------------------------------------------------------


class TestFrameworkMappings:
    def test_nist_mapping_deterministic(self):
        m1 = get_framework_mappings("security_posture", "security_posture")
        m2 = get_framework_mappings("security_posture", "security_posture")
        assert m1 == m2

    def test_soc2_mapping_deterministic(self):
        m1 = get_framework_mappings("data_governance", "data_governance")
        m2 = get_framework_mappings("data_governance", "data_governance")
        assert m1 == m2

    def test_same_control_always_maps_same_frameworks(self):
        for _ in range(3):
            mappings = get_framework_mappings("access_control", "security_posture")
            frameworks = {m.framework for m in mappings}
            assert (
                "NIST_AI_RMF" in frameworks
                or "SOC2" in frameworks
                or "HIPAA" in frameworks
            )

    def test_unsupported_control_returns_empty(self):
        mappings = get_framework_mappings(
            "zzz_unknown_control_xyz", "zzz_unknown_domain_xyz"
        )
        assert mappings == []

    def test_supported_frameworks_list(self):
        frameworks = get_supported_frameworks()
        assert "NIST_AI_RMF" in frameworks
        assert "SOC2" in frameworks
        assert "HIPAA" in frameworks
        assert frameworks == sorted(frameworks)

    def test_nist_ai_rmf_has_govern_categories(self):
        mappings = get_framework_mappings("data_governance", "data_governance")
        nist_refs = [m.control_ref for m in mappings if m.framework == "NIST_AI_RMF"]
        assert any("GOVERN" in ref for ref in nist_refs)

    def test_mapping_confidence_is_valid(self):
        mappings = get_framework_mappings("security_posture", "security_posture")
        for m in mappings:
            assert 0.0 <= m.confidence <= 1.0

    def test_framework_mapping_is_frozen(self):
        m = FrameworkMapping(
            framework="NIST_AI_RMF", control_ref="GOVERN 1.1", confidence=0.9
        )
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            m.framework = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TestGovernanceReportEngine
# ---------------------------------------------------------------------------


class TestGovernanceReportEngine:
    def test_same_inputs_produce_same_report(self):
        evidence = _sample_evidence_refs()
        r1 = _ENGINE.generate("assess-1", "tenant-1", _low_scores(), {}, evidence)
        r2 = _ENGINE.generate("assess-1", "tenant-1", _low_scores(), {}, evidence)
        # Same findings, same remediations, same framework_summary
        assert len(r1.findings) == len(r2.findings)
        assert {f.finding_id for f in r1.findings} == {
            f.finding_id for f in r2.findings
        }
        assert r1.framework_summary == r2.framework_summary

    def test_same_inputs_produce_same_manifest_hash(self):
        evidence = _sample_evidence_refs()
        r1 = _ENGINE.generate("assess-1", "tenant-1", _low_scores(), {}, evidence)
        r2 = _ENGINE.generate("assess-1", "tenant-1", _low_scores(), {}, evidence)
        assert r1.manifest_hash == r2.manifest_hash

    def test_low_score_domain_creates_finding(self):
        scores = {"security_posture": 20.0}
        report = _ENGINE.generate("assess-2", "tenant-1", scores, {}, [])
        finding_domains = {f.domain for f in report.findings}
        assert "security_posture" in finding_domains

    def test_high_score_domain_no_finding(self):
        scores = {"security_posture": 85.0}
        report = _ENGINE.generate("assess-3", "tenant-1", scores, {}, [])
        finding_domains = {f.domain for f in report.findings}
        assert "security_posture" not in finding_domains

    def test_missing_scores_raises_governance_report_error(self):
        with pytest.raises(GovernanceReportError):
            _ENGINE.generate("assess-4", "tenant-1", None, {}, [])  # type: ignore[arg-type]

    def test_empty_assessment_id_raises(self):
        with pytest.raises(GovernanceReportError):
            _ENGINE.generate("", "tenant-1", {}, {}, [])

    def test_empty_tenant_id_raises(self):
        with pytest.raises(GovernanceReportError):
            _ENGINE.generate("assess-5", "", {}, {}, [])

    def test_finding_ids_stable_across_runs(self):
        evidence = _sample_evidence_refs()
        r1 = _ENGINE.generate("assess-6", "tenant-1", _low_scores(), {}, evidence)
        r2 = _ENGINE.generate("assess-6", "tenant-1", _low_scores(), {}, evidence)
        ids1 = sorted(f.finding_id for f in r1.findings)
        ids2 = sorted(f.finding_id for f in r2.findings)
        assert ids1 == ids2

    def test_report_is_frozen(self):
        report = _ENGINE.generate("assess-7", "tenant-1", _low_scores(), {}, [])
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            report.manifest_hash = "tampered"  # type: ignore[misc]

    def test_threshold_boundary_exactly_60(self):
        scores = {"data_governance": 60.0}
        report = _ENGINE.generate("assess-8", "tenant-1", scores, {}, [])
        finding_domains = {f.domain for f in report.findings}
        assert "data_governance" not in finding_domains

    def test_threshold_boundary_just_below_60(self):
        scores = {"data_governance": 59.9}
        report = _ENGINE.generate("assess-9", "tenant-1", scores, {}, [])
        finding_domains = {f.domain for f in report.findings}
        assert "data_governance" in finding_domains


# ---------------------------------------------------------------------------
# TestReplayVerification
# ---------------------------------------------------------------------------


class TestReplayVerification:
    def test_replay_matches_original_hash(self):
        evidence = _sample_evidence_refs()
        original = _ENGINE.generate(
            "assess-r1", "tenant-r", _low_scores(), {}, evidence
        )
        _, hash_matches = _ENGINE.replay(
            report=original,
            assessment_id="assess-r1",
            tenant_id="tenant-r",
            scores=_low_scores(),
            responses={},
            evidence_refs=evidence,
        )
        assert hash_matches is True

    def test_replay_detects_tampered_evidence(self):
        evidence = _sample_evidence_refs()
        original = _ENGINE.generate(
            "assess-r2", "tenant-r", _low_scores(), {}, evidence
        )

        # Tampered evidence — different validation state
        tampered_evidence = [
            EvidenceRef(
                evidence_id=ref.evidence_id,
                source=ref.source,
                validation_state=ValidationState.MISSING,  # changed
                classification=ref.classification,
                provenance=ref.provenance,
                freshness_days=ref.freshness_days,
            )
            for ref in evidence
        ]
        _, hash_matches = _ENGINE.replay(
            report=original,
            assessment_id="assess-r2",
            tenant_id="tenant-r",
            scores=_low_scores(),
            responses={},
            evidence_refs=tampered_evidence,
        )
        assert hash_matches is False

    def test_canonical_serialization_stable(self):
        evidence = _sample_evidence_refs()
        report = _ENGINE.generate("assess-r3", "tenant-r", _low_scores(), {}, evidence)
        s1 = serialize_for_manifest(report)
        s2 = serialize_for_manifest(report)
        assert s1 == s2

    def test_serialize_deserialize_roundtrip(self):
        evidence = _sample_evidence_refs()
        report = _ENGINE.generate("assess-r4", "tenant-r", _low_scores(), {}, evidence)
        data = serialize_report(report)
        restored = deserialize_report(data)
        assert restored.report_id == report.report_id
        assert restored.manifest_hash == report.manifest_hash
        assert len(restored.findings) == len(report.findings)

    def test_deserialize_rejects_unknown_schema_version(self):
        data = {
            "report_id": "r1",
            "assessment_id": "a1",
            "tenant_id": "t1",
            "version": 1,
            "schema_version": "9.9",  # unknown
            "generated_at": "2026-01-01T00:00:00+00:00",
            "findings": [],
            "remediations": [],
            "evidence_appendix": [],
            "framework_summary": {},
            "confidence": {
                "overall": 0.0,
                "evidence_completeness": 0.0,
                "evidence_freshness": 0.0,
                "control_coverage": 0.0,
                "reviewer_validated": False,
                "degradation_reasons": [],
            },
            "manifest_hash": "abc",
        }
        with pytest.raises(ValueError, match="schema_version"):
            deserialize_report(data)


# ---------------------------------------------------------------------------
# TestAINarrativeContainment
# ---------------------------------------------------------------------------


class TestAINarrativeContainment:
    def test_ai_narrative_cannot_mutate_findings(self):
        """GovernanceReport frozen=True — setattr raises FrozenInstanceError."""
        report = _ENGINE.generate("assess-ai1", "tenant-ai", _low_scores(), {}, [])
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            report.findings = ()  # type: ignore[misc]

    def test_ai_narrative_cannot_mutate_manifest_hash(self):
        report = _ENGINE.generate("assess-ai2", "tenant-ai", _low_scores(), {}, [])
        original_hash = report.manifest_hash
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            report.manifest_hash = "ai_override_attempt"  # type: ignore[misc]
        assert report.manifest_hash == original_hash

    def test_governance_finding_is_frozen(self):
        finding = GovernanceFinding(
            finding_id="abc",
            control_id="ctrl",
            domain="security_posture",
            severity="high",
            confidence=0.5,
            evidence_ids=(),
            framework_mappings=(),
            remediation_id="rem",
            gap_classification="high_gap",
            description="test",
        )
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            finding.severity = "low"  # type: ignore[misc]

    def test_remediation_entry_is_frozen(self):
        rem = RemediationEntry(
            remediation_id="r1",
            linked_finding_ids=(),
            linked_controls=(),
            severity="high",
            priority="high",
            confidence_impact=0.3,
            evidence_gaps=(),
            operational_impact="test",
        )
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            rem.severity = "low"  # type: ignore[misc]

    def test_evidence_ref_is_frozen(self):
        ref = _make_evidence_ref()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            ref.source = "tampered"  # type: ignore[misc]

    def test_report_confidence_is_frozen(self):
        report = _ENGINE.generate("assess-ai3", "tenant-ai", _low_scores(), {}, [])
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            report.confidence = ConfidenceScore(  # type: ignore[misc]
                overall=1.0,
                evidence_completeness=1.0,
                evidence_freshness=1.0,
                control_coverage=1.0,
                reviewer_validated=True,
                degradation_reasons=(),
            )


# ---------------------------------------------------------------------------
# TestEvidenceAppendix
# ---------------------------------------------------------------------------


class TestEvidenceAppendix:
    def test_evidence_appendix_deterministic(self):
        evidence = _sample_evidence_refs()
        r1 = _ENGINE.generate("assess-ev1", "tenant-ev", _low_scores(), {}, evidence)
        r2 = _ENGINE.generate("assess-ev1", "tenant-ev", _low_scores(), {}, evidence)
        assert len(r1.evidence_appendix) == len(r2.evidence_appendix)
        ids1 = sorted(e.evidence_id for e in r1.evidence_appendix)
        ids2 = sorted(e.evidence_id for e in r2.evidence_appendix)
        assert ids1 == ids2

    def test_missing_evidence_reflected_in_appendix(self):
        evidence = [
            _make_evidence_ref(
                source="src-missing",
                validation_state=ValidationState.MISSING,
                freshness_days=None,
            ),
        ]
        report = _ENGINE.generate(
            "assess-ev2", "tenant-ev", _low_scores(), {}, evidence
        )
        states = {e.validation_state for e in report.evidence_appendix}
        assert ValidationState.MISSING in states

    def test_empty_evidence_creates_empty_appendix(self):
        report = _ENGINE.generate("assess-ev3", "tenant-ev", _high_scores(), {}, [])
        assert report.evidence_appendix == ()


# ---------------------------------------------------------------------------
# TestHTMLExport
# ---------------------------------------------------------------------------


class TestHTMLExport:
    def test_html_export_contains_manifest_hash(self):
        report = _ENGINE.generate(
            "assess-html1", "tenant-html", _low_scores(), {}, _sample_evidence_refs()
        )
        html = export_html(report)
        assert report.manifest_hash in html

    def test_html_export_contains_finding_ids(self):
        report = _ENGINE.generate(
            "assess-html2", "tenant-html", _low_scores(), {}, _sample_evidence_refs()
        )
        html = export_html(report)
        for finding in report.findings:
            assert finding.finding_id in html

    def test_html_export_deterministic(self):
        evidence = _sample_evidence_refs()
        report = _ENGINE.generate(
            "assess-html3", "tenant-html", _low_scores(), {}, evidence
        )
        html1 = export_html(report)
        html2 = export_html(report)
        assert html1 == html2

    def test_html_export_no_ai_prose_markers(self):
        report = _ENGINE.generate("assess-html4", "tenant-html", _low_scores(), {}, [])
        html = export_html(report)
        # The HTML must contain the mandatory isolation notice
        assert "advisory-only" in html
        assert "deterministically" in html

    def test_html_export_contains_all_frameworks(self):
        report = _ENGINE.generate("assess-html5", "tenant-html", _low_scores(), {}, [])
        html = export_html(report)
        if report.framework_summary:
            for fw in report.framework_summary:
                assert fw in html
