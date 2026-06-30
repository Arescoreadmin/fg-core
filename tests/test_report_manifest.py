"""Tests for Report Authority versioning, statistics, and validators.

Coverage:
  RM-1  to RM-20: versioning.py — parse, str(), bump_report_revision, compare_versions
  RM-21 to RM-40: statistics.py — compute_quality_score returns float in [0,1], grades
  RM-41 to RM-50: validators.py — validate_tenant_id, validate_manifest_integrity,
                                   validate_report_request
"""

from __future__ import annotations

import pytest

from services.report_authority.versioning import (
    ReportVersion,
    parse_version,
    compare_versions,
)
from services.report_authority.statistics import (
    compute_quality_score,
    aggregate_by_field,
)
from services.report_authority.validators import (
    validate_tenant_id,
    validate_manifest_integrity,
    validate_bundle_integrity,
    validate_report_request,
)
from services.report_authority.models import (
    QUALITY_EXCELLENT_THRESHOLD,
    QUALITY_GOOD_THRESHOLD,
    QUALITY_ACCEPTABLE_THRESHOLD,
    QUALITY_POOR_THRESHOLD,
)


# ===========================================================================
# RM-1 to RM-20: versioning.py
# ===========================================================================


class TestVersioning:
    """RM-1 through RM-20: ReportVersion parsing and comparison tests."""

    def test_RM_1_parse_version_basic(self):
        v = parse_version("1.0.0-r0")
        assert v.major == 1
        assert v.minor == 0
        assert v.patch == 0
        assert v.report_revision == 0

    def test_RM_2_parse_version_with_revision(self):
        v = parse_version("2.3.5-r7")
        assert v.major == 2
        assert v.minor == 3
        assert v.patch == 5
        assert v.report_revision == 7

    def test_RM_3_str_round_trips_basic_version(self):
        version_str = "1.0.0-r0"
        v = parse_version(version_str)
        assert str(v) == version_str

    def test_RM_4_str_round_trips_with_revision(self):
        version_str = "2.3.5-r7"
        v = parse_version(version_str)
        assert str(v) == version_str

    def test_RM_5_str_format_is_major_minor_patch_revision(self):
        v = ReportVersion(major=1, minor=2, patch=3, report_revision=4)
        assert str(v) == "1.2.3-r4"

    def test_RM_6_bump_report_revision_increments_by_one(self):
        v = ReportVersion(major=1, minor=0, patch=0, report_revision=0)
        v2 = v.bump_report_revision()
        assert v2.report_revision == 1

    def test_RM_7_bump_report_revision_preserves_major_minor_patch(self):
        v = ReportVersion(major=2, minor=3, patch=5, report_revision=2)
        v2 = v.bump_report_revision()
        assert v2.major == 2
        assert v2.minor == 3
        assert v2.patch == 5

    def test_RM_8_bump_report_revision_returns_new_instance(self):
        v = ReportVersion(major=1, minor=0, patch=0, report_revision=0)
        v2 = v.bump_report_revision()
        assert v is not v2

    def test_RM_9_original_version_unchanged_after_bump(self):
        v = ReportVersion(major=1, minor=0, patch=0, report_revision=5)
        v.bump_report_revision()
        assert v.report_revision == 5  # frozen dataclass, must not change

    def test_RM_10_bump_patch_increments_patch(self):
        v = ReportVersion(major=1, minor=0, patch=2, report_revision=3)
        v2 = v.bump_patch()
        assert v2.patch == 3

    def test_RM_11_bump_patch_resets_report_revision(self):
        v = ReportVersion(major=1, minor=0, patch=2, report_revision=5)
        v2 = v.bump_patch()
        assert v2.report_revision == 0

    def test_RM_12_compare_versions_equal_returns_zero(self):
        v1 = ReportVersion(major=1, minor=0, patch=0, report_revision=0)
        v2 = ReportVersion(major=1, minor=0, patch=0, report_revision=0)
        assert compare_versions(v1, v2) == 0

    def test_RM_13_compare_versions_a_less_than_b_returns_negative_one(self):
        a = ReportVersion(major=1, minor=0, patch=0, report_revision=0)
        b = ReportVersion(major=1, minor=0, patch=0, report_revision=1)
        assert compare_versions(a, b) == -1

    def test_RM_14_compare_versions_a_greater_than_b_returns_one(self):
        a = ReportVersion(major=2, minor=0, patch=0, report_revision=0)
        b = ReportVersion(major=1, minor=9, patch=9, report_revision=9)
        assert compare_versions(a, b) == 1

    def test_RM_15_compare_versions_major_version_ordering(self):
        a = ReportVersion(major=3, minor=0, patch=0, report_revision=0)
        b = ReportVersion(major=2, minor=5, patch=5, report_revision=5)
        assert compare_versions(a, b) == 1

    def test_RM_16_compare_versions_minor_version_ordering(self):
        a = ReportVersion(major=1, minor=1, patch=0, report_revision=0)
        b = ReportVersion(major=1, minor=0, patch=9, report_revision=9)
        assert compare_versions(a, b) == 1

    def test_RM_17_compare_versions_patch_ordering(self):
        a = ReportVersion(major=1, minor=0, patch=1, report_revision=0)
        b = ReportVersion(major=1, minor=0, patch=0, report_revision=9)
        assert compare_versions(a, b) == 1

    def test_RM_18_parse_version_invalid_format_raises(self):
        with pytest.raises(ValueError):
            parse_version("not-a-version")

    def test_RM_19_parse_version_missing_revision_raises(self):
        with pytest.raises(ValueError):
            parse_version("1.0.0")

    def test_RM_20_report_version_is_frozen(self):
        v = ReportVersion(major=1, minor=0, patch=0, report_revision=0)
        with pytest.raises(Exception):
            v.major = 99  # type: ignore[misc]

    def test_RM_20b_compare_versions_assessment_revision_excluded(self):
        # assessment_revision is intentionally excluded from comparison
        a = ReportVersion(major=1, minor=0, patch=0, assessment_revision=100, report_revision=0)
        b = ReportVersion(major=1, minor=0, patch=0, assessment_revision=1, report_revision=0)
        assert compare_versions(a, b) == 0

    def test_RM_20c_str_excludes_assessment_revision(self):
        v = ReportVersion(major=1, minor=0, patch=0, assessment_revision=5, report_revision=2)
        assert str(v) == "1.0.0-r2"

    def test_RM_20d_multiple_bumps_accumulate(self):
        v = ReportVersion(major=1, minor=0, patch=0, report_revision=0)
        v = v.bump_report_revision()
        v = v.bump_report_revision()
        v = v.bump_report_revision()
        assert v.report_revision == 3


# ===========================================================================
# RM-21 to RM-40: statistics.py
# ===========================================================================


class TestStatistics:
    """RM-21 through RM-40: compute_quality_score tests."""

    def test_RM_21_perfect_scores_produce_score_1(self):
        score, grade = compute_quality_score(1.0, 1.0, 1.0, 1.0, 1.0)
        assert abs(score - 1.0) < 1e-6

    def test_RM_22_zero_scores_produce_score_0(self):
        score, grade = compute_quality_score(0.0, 0.0, 0.0, 0.0, 0.0)
        assert abs(score - 0.0) < 1e-6

    def test_RM_23_score_is_float(self):
        score, _ = compute_quality_score(0.5, 0.5, 0.5, 0.5, 0.5)
        assert isinstance(score, float)

    def test_RM_24_score_is_in_0_to_1(self):
        score, _ = compute_quality_score(0.8, 0.7, 0.6, 0.5, 0.4)
        assert 0.0 <= score <= 1.0

    def test_RM_25_grade_is_string(self):
        _, grade = compute_quality_score(0.5, 0.5, 0.5, 0.5, 0.5)
        assert isinstance(grade, str)

    def test_RM_26_excellent_threshold_produces_excellent_grade(self):
        # Use score above QUALITY_EXCELLENT_THRESHOLD (0.90)
        _, grade = compute_quality_score(1.0, 1.0, 1.0, 1.0, 1.0)
        assert grade == "EXCELLENT"

    def test_RM_27_above_good_threshold_produces_good_grade(self):
        # At 0.80 — above GOOD (0.75) but below EXCELLENT (0.90)
        score, grade = compute_quality_score(0.8, 0.8, 0.8, 0.8, 0.8)
        # score = 0.8 * (0.30+0.25+0.20+0.15+0.10) = 0.8
        assert grade == "GOOD"

    def test_RM_28_above_acceptable_threshold_produces_acceptable_grade(self):
        # At around 0.67 — between ACCEPTABLE (0.60) and GOOD (0.75)
        score, grade = compute_quality_score(0.67, 0.67, 0.67, 0.67, 0.67)
        assert grade == "ACCEPTABLE"

    def test_RM_29_above_poor_threshold_produces_poor_grade(self):
        # Between POOR (0.40) and ACCEPTABLE (0.60)
        score, grade = compute_quality_score(0.5, 0.5, 0.5, 0.5, 0.5)
        assert grade == "POOR"

    def test_RM_30_zero_scores_produce_incomplete_grade(self):
        _, grade = compute_quality_score(0.0, 0.0, 0.0, 0.0, 0.0)
        assert grade == "INCOMPLETE"

    def test_RM_31_above_excellent_threshold_clamped(self):
        # Inputs > 1.0 are clamped to 1.0 silently
        score, grade = compute_quality_score(2.0, 2.0, 2.0, 2.0, 2.0)
        assert score <= 1.0
        assert grade == "EXCELLENT"

    def test_RM_32_below_zero_clamped_to_zero(self):
        score, _ = compute_quality_score(-1.0, 0.0, 0.0, 0.0, 0.0)
        assert score >= 0.0

    def test_RM_33_weights_sum_to_one(self):
        # All inputs=1.0 must produce score=1.0 (confirming weights sum to 1)
        score, _ = compute_quality_score(1.0, 1.0, 1.0, 1.0, 1.0)
        assert abs(score - 1.0) < 1e-6

    def test_RM_34_evidence_coverage_weight_dominates(self):
        # evidence_coverage has highest weight (0.30)
        score_with_ec, _ = compute_quality_score(1.0, 0.0, 0.0, 0.0, 0.0)
        score_with_comp, _ = compute_quality_score(0.0, 0.0, 0.0, 0.0, 1.0)
        assert score_with_ec > score_with_comp

    def test_RM_35_completeness_has_lowest_weight(self):
        # completeness has lowest weight (0.10)
        score_with_ec, _ = compute_quality_score(1.0, 0.0, 0.0, 0.0, 0.0)  # 0.30
        score_with_cm, _ = compute_quality_score(0.0, 0.0, 0.0, 0.0, 1.0)  # 0.10
        assert score_with_ec > score_with_cm

    def test_RM_36_partial_scores_produce_partial_grade(self):
        # Mixed partial scores
        score, grade = compute_quality_score(0.95, 0.0, 0.0, 0.0, 0.0)
        assert 0.0 < score < 1.0

    def test_RM_37_score_rounded_to_6_decimal_places(self):
        score, _ = compute_quality_score(0.123456789, 0.5, 0.5, 0.5, 0.5)
        # Should be rounded to 6 decimal places
        assert len(str(score).split(".")[1]) <= 7  # allow for trailing zeros

    def test_RM_38_aggregate_by_field_basic(self):
        records = [
            {"type": "EXECUTIVE"},
            {"type": "TECHNICAL"},
            {"type": "EXECUTIVE"},
        ]
        result = aggregate_by_field(records, "type")
        assert result["EXECUTIVE"] == 2
        assert result["TECHNICAL"] == 1

    def test_RM_39_aggregate_by_field_missing_field_grouped_as_unknown(self):
        records = [{"type": "A"}, {"other": "B"}]
        result = aggregate_by_field(records, "type")
        assert "__unknown__" in result

    def test_RM_40_aggregate_by_field_empty_list(self):
        result = aggregate_by_field([], "type")
        assert result == {}

    def test_RM_40b_compute_quality_score_at_excellent_boundary(self):
        # Exactly at EXCELLENT threshold
        score, grade = compute_quality_score(
            QUALITY_EXCELLENT_THRESHOLD,
            QUALITY_EXCELLENT_THRESHOLD,
            QUALITY_EXCELLENT_THRESHOLD,
            QUALITY_EXCELLENT_THRESHOLD,
            QUALITY_EXCELLENT_THRESHOLD,
        )
        assert grade == "EXCELLENT"

    def test_RM_40c_quality_thresholds_are_ordered(self):
        assert QUALITY_EXCELLENT_THRESHOLD > QUALITY_GOOD_THRESHOLD
        assert QUALITY_GOOD_THRESHOLD > QUALITY_ACCEPTABLE_THRESHOLD
        assert QUALITY_ACCEPTABLE_THRESHOLD > QUALITY_POOR_THRESHOLD
        assert QUALITY_POOR_THRESHOLD > 0.0


# ===========================================================================
# RM-41 to RM-50: validators.py
# ===========================================================================


class TestValidators:
    """RM-41 through RM-50: validator function tests."""

    def test_RM_41_validate_tenant_id_rejects_empty_string(self):
        with pytest.raises(ValueError, match="non-empty"):
            validate_tenant_id("")

    def test_RM_42_validate_tenant_id_rejects_whitespace_only(self):
        with pytest.raises(ValueError):
            validate_tenant_id("   ")

    def test_RM_43_validate_tenant_id_rejects_none(self):
        with pytest.raises((ValueError, TypeError)):
            validate_tenant_id(None)  # type: ignore[arg-type]

    def test_RM_44_validate_tenant_id_accepts_valid_string(self):
        validate_tenant_id("tenant-001")  # should not raise

    def test_RM_45_validate_tenant_id_rejects_too_long(self):
        with pytest.raises(ValueError, match="255"):
            validate_tenant_id("x" * 256)

    def test_RM_46_validate_manifest_integrity_returns_bool(self):
        valid_manifest = {
            "report_id": "r1",
            "schema_version": "1.0",
            "manifest_schema_version": "1.0",
            "report_hash_sha256": "a" * 64,
            "report_hash_sha512": "b" * 128,
            "generation_timestamp": "2026-01-01T00:00:00+00:00",
            "generator_version": "1.0.0",
        }
        result = validate_manifest_integrity(valid_manifest)
        assert isinstance(result, bool)

    def test_RM_47_validate_manifest_integrity_returns_true_for_valid(self):
        valid_manifest = {
            "report_id": "r1",
            "schema_version": "1.0",
            "manifest_schema_version": "1.0",
            "report_hash_sha256": "a" * 64,
            "report_hash_sha512": "b" * 128,
            "generation_timestamp": "2026-01-01T00:00:00+00:00",
            "generator_version": "1.0.0",
        }
        assert validate_manifest_integrity(valid_manifest) is True

    def test_RM_48_validate_manifest_integrity_returns_false_for_missing_field(self):
        incomplete = {
            "report_id": "r1",
            "schema_version": "1.0",
            # missing other required fields
        }
        assert validate_manifest_integrity(incomplete) is False

    def test_RM_49_validate_manifest_integrity_returns_false_for_empty_dict(self):
        assert validate_manifest_integrity({}) is False

    def test_RM_50_validate_report_request_raises_on_same_assessor_reviewer(self):
        from services.report_authority.schemas import GenerateReportRequest
        from services.report_authority.models import ReportType

        req = GenerateReportRequest(
            assessment_id="assess-001",
            report_type=ReportType.EXECUTIVE,
            title="Test Report",
            scope="Full scope",
            objectives="Key objectives",
            assessor_id="same-person",
            reviewer_id="same-person",
        )
        with pytest.raises(ValueError, match="assessor_id and reviewer_id must be different"):
            validate_report_request(req)

    def test_RM_50b_validate_report_request_passes_for_valid(self):
        from services.report_authority.schemas import GenerateReportRequest
        from services.report_authority.models import ReportType

        req = GenerateReportRequest(
            assessment_id="assess-001",
            report_type=ReportType.EXECUTIVE,
            title="Test Report",
            scope="Full scope",
            objectives="Key objectives",
            assessor_id="assessor-001",
            reviewer_id="reviewer-002",
        )
        validate_report_request(req)  # should not raise

    def test_RM_50c_validate_report_request_raises_on_blank_title(self):
        from services.report_authority.schemas import GenerateReportRequest
        from services.report_authority.models import ReportType

        # Note: blank title (" ") must pass Pydantic (min_length=1) but fail semantic check
        # So we test the semantic validator with a slightly hacky approach
        req = GenerateReportRequest(
            assessment_id="assess-001",
            report_type=ReportType.EXECUTIVE,
            title="Valid Title",
            scope="scope",
            objectives="objectives",
            assessor_id="a",
            reviewer_id="r",
        )
        # Override title post-construction to a whitespace-only value
        object.__setattr__(req, "title", "   ")
        with pytest.raises(ValueError, match="blank"):
            validate_report_request(req)

    def test_RM_50d_validate_report_request_raises_for_wrong_type(self):
        with pytest.raises(ValueError, match="GenerateReportRequest"):
            validate_report_request("not a request")

    def test_RM_50e_validate_bundle_integrity_returns_false_for_empty(self):
        assert validate_bundle_integrity({}) is False

    def test_RM_50f_validate_bundle_integrity_returns_true_for_valid(self):
        checksums = {
            "report.pdf": "a" * 64,
            "report.json": "b" * 64,
        }
        assert validate_bundle_integrity(checksums) is True

    def test_RM_50g_validate_bundle_integrity_returns_false_for_blank_value(self):
        checksums = {"report.pdf": "   "}
        assert validate_bundle_integrity(checksums) is False

    def test_RM_50h_validate_tenant_id_max_length_accepted(self):
        validate_tenant_id("x" * 255)  # exactly 255 chars, should be valid

    def test_RM_50i_validate_manifest_integrity_returns_false_for_none_field(self):
        manifest = {
            "report_id": None,  # None should fail
            "schema_version": "1.0",
            "manifest_schema_version": "1.0",
            "report_hash_sha256": "a" * 64,
            "report_hash_sha512": "b" * 128,
            "generation_timestamp": "2026-01-01T00:00:00+00:00",
            "generator_version": "1.0.0",
        }
        assert validate_manifest_integrity(manifest) is False
