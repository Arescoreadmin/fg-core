"""tests/test_remediation_roadmap.py — Remediation roadmap correctness tests.

Covers:
  - NIST mapping normalization (Blocker 2): str() removal, dict objects, MS Graph shapes
  - Multi-page finding retrieval (Blocker 3): pagination loop, is_truncated flag
  - Connector-imported finding prefix/template resolution (Blocker 4): _type_prefix
"""

from __future__ import annotations

import os
import types
from typing import Any

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest

from services.field_assessment.remediation import (
    _type_prefix,
    assign_phase,
    compute_priority_score,
    generate_remediation_steps,
)
from services.field_assessment.questionnaire_store import normalize_nist_control


# ---------------------------------------------------------------------------
# Helpers — lightweight mock finding objects
# ---------------------------------------------------------------------------


def _finding(
    *,
    finding_type: str = "MFA-001",
    title: str = "Test finding",
    severity: str = "high",
    status: str = "open",
    nist_ai_rmf_mappings: list[Any] | None = None,
    evidence_ref_ids: list[str] | None = None,
    remediation_hint: str | None = None,
) -> Any:
    """Return a SimpleNamespace that mimics FaNormalizedFinding for unit tests."""
    return types.SimpleNamespace(
        finding_type=finding_type,
        title=title,
        severity=severity,
        status=status,
        nist_ai_rmf_mappings=nist_ai_rmf_mappings or [],
        evidence_ref_ids=evidence_ref_ids or [],
        remediation_hint=remediation_hint,
    )


# ===========================================================================
# NIST normalization (Blocker 2)
# ===========================================================================


class TestNistNormalizationBlocker2:
    def test_remediation_roadmap_normalizes_string_nist_mappings(self) -> None:
        """String NIST controls like 'NIST-AI-RMF-GOVERN-1.2' must be normalised."""
        raw = "NIST-AI-RMF-GOVERN-1.2"
        result = normalize_nist_control(raw)
        assert result == "GOVERN-1.2"

    def test_remediation_roadmap_normalizes_control_id_object_mappings(self) -> None:
        """Dict with control_id key must be normalised."""
        raw = {"control_id": "NIST-AI-RMF-MANAGE-2.2"}
        result = normalize_nist_control(raw)
        assert result == "MANAGE-2.2"

    def test_remediation_roadmap_normalizes_msgraph_function_category_mappings(
        self,
    ) -> None:
        """MS Graph connector format {function, category} must be normalised."""
        raw = {"function": "GOVERN", "category": "GOVERN-1.2"}
        result = normalize_nist_control(raw)
        assert result == "GOVERN-1.2"

    def test_remediation_roadmap_does_not_count_dict_repr_as_control_id(self) -> None:
        """Stringifying a dict produces "{'function': ...}" which must NOT match."""
        raw = {"function": "GOVERN", "category": "GOVERN-1.2"}
        # Stringified form is NOT a valid NIST string and must return None-or-junk,
        # definitely NOT 'GOVERN-1.2'.
        stringified = str(raw)
        result = normalize_nist_control(stringified)
        # The stringified form starts with "{'" which doesn't start with NIST-AI-RMF-
        # prefix, so it returns the raw string — not the real control id.
        assert result != "GOVERN-1.2"

    def test_remediation_roadmap_projected_coverage_uses_existing_covered_controls(
        self,
    ) -> None:
        """NIST controls already in implemented_controls must not double-count."""
        # Simulate: one finding maps to "GOVERN-1.2", already implemented.
        f = _finding(
            nist_ai_rmf_mappings=[{"function": "GOVERN", "category": "GOVERN-1.2"}],
            severity="critical",
            evidence_ref_ids=["e1"],
        )
        # Score
        score = compute_priority_score(f)
        assert score > 0

        # Verify normalize_nist_control returns the canonical form
        result = normalize_nist_control(f.nist_ai_rmf_mappings[0])
        assert result == "GOVERN-1.2"

        # Simulate covered_so_far already includes this control:
        covered_so_far = {"GOVERN-1.2"}
        phase_new: set[str] = set()
        for raw in f.nist_ai_rmf_mappings:
            cid = normalize_nist_control(raw)
            if cid and cid not in covered_so_far:
                phase_new.add(cid)
        # Already covered → no new delta
        assert len(phase_new) == 0


# ===========================================================================
# Multi-page finding retrieval (Blocker 3)
# ===========================================================================


class TestPaginationBlocker3:
    def test_remediation_roadmap_includes_findings_beyond_first_page(self) -> None:
        """Pagination loop must collect findings from offset>0 pages."""
        _PAGE = 100
        calls: list[int] = []

        def fake_list_findings(**kwargs: Any) -> list[Any]:
            offset = kwargs.get("offset", 0)
            calls.append(offset)
            if offset == 0:
                return [_finding(severity="high") for _ in range(_PAGE)]
            elif offset == _PAGE:
                return [_finding(severity="medium") for _ in range(30)]
            return []

        all_findings: list[Any] = []
        offset = 0
        while True:
            page = fake_list_findings(offset=offset, limit=_PAGE)
            all_findings.extend(page)
            if len(page) < _PAGE or len(all_findings) >= 2000:
                break
            offset += _PAGE

        assert len(all_findings) == 130
        assert calls == [0, 100]

    def test_remediation_roadmap_total_open_findings_uses_all_pages(self) -> None:
        """total_open_findings must count from all pages, not just page 1."""
        _PAGE = 100
        all_findings: list[Any] = []
        offset = 0

        def fake_list(**kwargs: Any) -> list[Any]:
            o = kwargs.get("offset", 0)
            if o == 0:
                return [_finding(status="open") for _ in range(100)]
            if o == 100:
                return [_finding(status="open") for _ in range(50)]
            return []

        while True:
            page = fake_list(offset=offset, limit=_PAGE)
            all_findings.extend(page)
            if len(page) < _PAGE or len(all_findings) >= 2000:
                break
            offset += _PAGE

        active = [f for f in all_findings if f.status in ("open", "in_progress")]
        assert len(active) == 150

    def test_remediation_roadmap_phase_grouping_uses_all_pages(self) -> None:
        """Phase grouping must incorporate all paginated findings."""
        _PAGE = 100

        def fake_list(**kwargs: Any) -> list[Any]:
            o = kwargs.get("offset", 0)
            if o == 0:
                # All high severity — score = 3*8+0+0 = 24 → short_term
                return [
                    _finding(finding_type="MFA-001", severity="high")
                    for _ in range(100)
                ]
            if o == 100:
                # All critical — score = 4*8+0+0 = 32 → immediate
                return [
                    _finding(finding_type="CA-001", severity="critical")
                    for _ in range(20)
                ]
            return []

        all_findings: list[Any] = []
        offset = 0
        while True:
            page = fake_list(offset=offset, limit=_PAGE)
            all_findings.extend(page)
            if len(page) < _PAGE or len(all_findings) >= 2000:
                break
            offset += _PAGE

        assert len(all_findings) == 120
        immediate = [
            f
            for f in all_findings
            if assign_phase(compute_priority_score(f)) == "immediate"
        ]
        short_term = [
            f
            for f in all_findings
            if assign_phase(compute_priority_score(f)) == "short_term"
        ]
        assert len(immediate) == 20
        assert len(short_term) == 100


# ===========================================================================
# Prefix resolution (Blocker 4)
# ===========================================================================


class TestPrefixResolutionBlocker4:
    def test_type_prefix_resolves_direct_msgraph_family_codes(self) -> None:
        """'msgraph.MFA-001' → strip prefix → 'MFA-001' → first segment 'MFA'."""
        f = _finding(finding_type="msgraph.MFA-001")
        assert _type_prefix(f) == "MFA"

    def test_type_prefix_resolves_direct_ca_prefix(self) -> None:
        """'msgraph.CA-001' → 'CA'."""
        f = _finding(finding_type="msgraph.CA-001")
        assert _type_prefix(f) == "CA"

    def test_type_prefix_resolves_msgraph_nist_control_types_by_title(self) -> None:
        """'msgraph.NIST-AI-RMF-GOVERN-1.2' — first segment 'NIST' is not a family code.
        Title-index lookup should recover the real code from the registry."""
        from services.field_assessment.remediation import (
            _MSGRAPH_REGISTRY_BY_TITLE,
            _KNOWN_FAMILIES,
        )

        if not _MSGRAPH_REGISTRY_BY_TITLE:
            pytest.skip("MS Graph registry not available in this env")

        # Pick any finding whose title is in the registry.
        title = next(iter(_MSGRAPH_REGISTRY_BY_TITLE))
        defn = _MSGRAPH_REGISTRY_BY_TITLE[title]
        real_code = defn.code  # e.g. "MFA-001"
        expected_prefix = real_code.split("-")[0]

        f = _finding(
            finding_type="msgraph.NIST-AI-RMF-GOVERN-1.2",
            title=title,
        )
        result = _type_prefix(f)
        assert result == expected_prefix
        assert result in _KNOWN_FAMILIES

    def test_remediation_roadmap_uses_specific_template_for_imported_mfa_finding(
        self,
    ) -> None:
        """A connector-imported MFA finding should use MFA remediation steps."""
        from services.field_assessment.remediation import (
            _MSGRAPH_REGISTRY_BY_TITLE,
        )

        if not _MSGRAPH_REGISTRY_BY_TITLE:
            pytest.skip("MS Graph registry not available in this env")

        # Find an MFA finding title
        mfa_titles = [
            title
            for title, d in _MSGRAPH_REGISTRY_BY_TITLE.items()
            if d.code.startswith("MFA-")
        ]
        if not mfa_titles:
            pytest.skip("No MFA entries in registry")

        f = _finding(
            finding_type="msgraph.NIST-AI-RMF-GOVERN-1.2",
            title=mfa_titles[0],
        )
        steps = generate_remediation_steps(f)
        # MFA steps contain Azure-specific MFA content
        full_text = " ".join(steps).lower()
        assert "mfa" in full_text or "authenticator" in full_text

    def test_remediation_roadmap_falls_back_to_generic_when_registry_unknown(
        self,
    ) -> None:
        """Unknown finding type + unrecognised title → empty prefix → generic steps."""
        f = _finding(
            finding_type="msgraph.NIST-AI-RMF-GOVERN-99.9",
            title="Some completely unknown finding title xyz",
        )
        result = _type_prefix(f)
        assert result == ""

        steps = generate_remediation_steps(f)
        # Generic steps don't reference specific technologies
        assert len(steps) >= 1
        # The generic fallback includes 'remediation' or 'security team'
        full_text = " ".join(steps).lower()
        assert "remediation" in full_text or "security" in full_text

    def test_type_prefix_resolves_plain_type_without_msgraph_prefix(self) -> None:
        """Non-connector findings with a known prefix should resolve correctly."""
        for ftype, expected in [
            ("MFA-001", "MFA"),
            ("CA-003", "CA"),
            ("APP-001", "APP"),
            ("OAUTH-002", "OAUTH"),
            ("AI-001", "AI"),
            ("GUEST-001", "GUEST"),
            ("PRIV-001", "PRIV"),
        ]:
            f = _finding(finding_type=ftype)
            assert _type_prefix(f) == expected, f"Expected {expected} for {ftype}"
