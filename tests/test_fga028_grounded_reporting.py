from __future__ import annotations

import pytest

from services.governance.report import (
    EvidenceRef,
    GovernanceReportEngine,
    ValidationState,
)
from services.governance.report.epistemic import (
    EpistemicDetermination,
    EpistemicState,
    assess_report_epistemic_states,
    determine_epistemic_state,
)
from services.governance.report.grounded import (
    GroundedClaimError,
    build_material_claims,
    claims_fingerprint,
    enforce_grounded_summary,
)


def _report(
    *, tenant: str = "tenant-a", engagement: str = "eng-a", score: float = 10.0
):
    evidence = [
        EvidenceRef(
            evidence_id="ev-1",
            source="data_governance_scan",
            validation_state=ValidationState.VALIDATED,
            classification="scan_result",
            provenance=f"engagement:{engagement}",
            freshness_days=1,
        )
    ]
    report = GovernanceReportEngine().generate(
        assessment_id=engagement,
        tenant_id=tenant,
        scores={"data_governance": score},
        responses={},
        evidence_refs=evidence,
    )
    return report


def test_verified_deficiency_has_resolvable_lineage_and_fingerprint() -> None:
    report = _report()
    determinations = assess_report_epistemic_states(report, report.evidence_appendix)
    claims = build_material_claims(report, determinations)
    assert claims and claims[0].disposition == "verified_deficient"
    assert claims[0].finding_id == report.findings[0].finding_id
    assert "evidence:ev-1" in claims[0].lineage
    assert len(claims_fingerprint(claims)) == 64
    assert (
        claims_fingerprint(tuple(reversed(claims))) != claims_fingerprint(claims)
        if len(claims) > 1
        else True
    )


def test_claim_order_and_fingerprint_are_replay_deterministic() -> None:
    first = _report()
    second = _report()
    c1 = build_material_claims(
        first, assess_report_epistemic_states(first, first.evidence_appendix)
    )
    c2 = build_material_claims(
        second, assess_report_epistemic_states(second, second.evidence_appendix)
    )
    assert [c.claim_id for c in c1] == [c.claim_id for c in c2]
    assert claims_fingerprint(c1) == claims_fingerprint(c2)


def test_unknown_or_missing_lineage_fails_closed() -> None:
    report = _report()
    with pytest.raises(GroundedClaimError):
        build_material_claims(report, {})
    bad = dict(assess_report_epistemic_states(report, report.evidence_appendix))
    finding_id = report.findings[0].finding_id
    bad[finding_id] = EpistemicDetermination(
        state=EpistemicState.VERIFIED_EFFECTIVE,
        reason_codes=(),
        evidence_ids=("other-tenant-evidence",),
        contradictory_evidence_ids=(),
        stale_evidence_ids=(),
        invalid_evidence_ids=(),
        missing_requirements=(),
        methodology_version="1.0",
    )
    with pytest.raises(GroundedClaimError):
        build_material_claims(report, bad)


@pytest.mark.parametrize("state", list(EpistemicState))
def test_epistemic_states_never_become_unqualified_positive_claims(
    state: EpistemicState,
) -> None:
    report = _report()
    finding_id = report.findings[0].finding_id
    determination = EpistemicDetermination(
        state=state,
        reason_codes=(),
        evidence_ids=tuple(report.findings[0].evidence_ids),
        contradictory_evidence_ids=(),
        stale_evidence_ids=(),
        invalid_evidence_ids=(),
        missing_requirements=(),
        methodology_version="1.0",
    )
    claim = build_material_claims(report, {finding_id: determination})[0]
    if state != EpistemicState.VERIFIED_EFFECTIVE:
        assert claim.disposition != "verified_effective"


def test_summary_cannot_override_adverse_truth_or_omit_it() -> None:
    report = _report()
    claims = build_material_claims(
        report, assess_report_epistemic_states(report, report.evidence_appendix)
    )
    result = enforce_grounded_summary(
        {
            "narrative": "Everything is compliant.",
            "risk_posture": "low",
            "key_concerns": [],
        },
        claims,
    )
    assert result["risk_posture"] == "critical"
    assert "verified critical governance deficiency" in str(result["narrative"])
    assert "Everything is compliant" not in str(result["narrative"])
    assert claims[0].statement in result["key_concerns"]


def test_epistemic_order_is_invariant() -> None:
    refs = [
        EvidenceRef(
            "b", "security", ValidationState.VALIDATED, "scan", "engagement:eng-a", 1
        ),
        EvidenceRef(
            "a", "security", ValidationState.VALIDATED, "scan", "engagement:eng-a", 1
        ),
    ]
    assert determine_epistemic_state(refs).evidence_ids == ("a", "b")
    assert determine_epistemic_state(list(reversed(refs))) == determine_epistemic_state(
        refs
    )
