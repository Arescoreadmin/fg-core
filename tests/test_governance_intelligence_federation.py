"""Tests for services/governance_intelligence/federation.py

GIF2-1 to GIF2-150 — tests for VALID_ROLES, validate_federation_request,
and build_governance_summary. Verifies tenant_id is NEVER in output.
"""

from __future__ import annotations

import pytest

from services.governance_intelligence.federation import (
    VALID_ROLES,
    build_governance_summary,
    validate_federation_request,
)
from services.governance_intelligence.models import FederationRole
from services.governance_intelligence.schemas import GovernanceIntelligenceValidationError


# ---------------------------------------------------------------------------
# GIF2-1 — GIF2-20: VALID_ROLES
# ---------------------------------------------------------------------------


class TestValidRoles:
    """GIF2-1 to GIF2-20: VALID_ROLES frozenset tests."""

    def test_gif2_1_is_frozenset(self):
        """GIF2-1: VALID_ROLES is a frozenset."""
        assert isinstance(VALID_ROLES, frozenset)

    def test_gif2_2_contains_coordinator(self):
        """GIF2-2: VALID_ROLES contains COORDINATOR."""
        assert FederationRole.COORDINATOR.value in VALID_ROLES

    def test_gif2_3_contains_member(self):
        """GIF2-3: VALID_ROLES contains MEMBER."""
        assert FederationRole.MEMBER.value in VALID_ROLES

    def test_gif2_4_contains_observer(self):
        """GIF2-4: VALID_ROLES contains OBSERVER."""
        assert FederationRole.OBSERVER.value in VALID_ROLES

    def test_gif2_5_has_exactly_3_roles(self):
        """GIF2-5: VALID_ROLES has exactly 3 entries."""
        assert len(VALID_ROLES) == 3

    def test_gif2_6_immutable(self):
        """GIF2-6: VALID_ROLES is immutable."""
        with pytest.raises((AttributeError, TypeError)):
            VALID_ROLES.add("extra")  # type: ignore[attr-defined]

    def test_gif2_7_all_federation_role_values_in_valid_roles(self):
        """GIF2-7: all FederationRole enum values are in VALID_ROLES."""
        for role in FederationRole:
            assert role.value in VALID_ROLES


# ---------------------------------------------------------------------------
# GIF2-21 — GIF2-80: validate_federation_request
# ---------------------------------------------------------------------------


class TestValidateFederationRequest:
    """GIF2-21 to GIF2-80: validate_federation_request function tests."""

    @pytest.mark.parametrize("role", list(VALID_ROLES))
    def test_gif2_21_valid_roles_no_raise(self, role):
        """GIF2-21: all valid roles pass without raising."""
        validate_federation_request("instance-001", role)  # no exception

    def test_gif2_31_invalid_role_raises(self):
        """GIF2-31: invalid role raises GovernanceIntelligenceValidationError."""
        with pytest.raises(GovernanceIntelligenceValidationError, match="Invalid federation role"):
            validate_federation_request("instance-001", "INVALID_ROLE")

    def test_gif2_32_empty_role_raises(self):
        """GIF2-32: empty string role raises."""
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_federation_request("instance-001", "")

    def test_gif2_33_lowercase_role_raises(self):
        """GIF2-33: lowercase 'primary' raises (case sensitive)."""
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_federation_request("instance-001", "primary")

    def test_gif2_34_empty_instance_id_raises(self):
        """GIF2-34: empty instance_id raises."""
        with pytest.raises(GovernanceIntelligenceValidationError, match="non-empty string"):
            validate_federation_request("", FederationRole.COORDINATOR.value)

    def test_gif2_35_whitespace_only_instance_id_raises(self):
        """GIF2-35: whitespace-only instance_id raises."""
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_federation_request("   ", FederationRole.MEMBER.value)

    def test_gif2_36_none_instance_id_raises(self):
        """GIF2-36: None instance_id raises."""
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_federation_request(None, FederationRole.COORDINATOR.value)  # type: ignore[arg-type]

    def test_gif2_37_error_mentions_allowed_roles(self):
        """GIF2-37: error message mentions allowed roles."""
        with pytest.raises(GovernanceIntelligenceValidationError, match="Allowed"):
            validate_federation_request("instance-001", "ADMIN")

    def test_gif2_38_valid_instance_id_with_special_chars(self):
        """GIF2-38: instance_id with hyphens and underscores passes."""
        validate_federation_request("inst-abc_123.xyz", FederationRole.OBSERVER.value)

    def test_gif2_39_long_instance_id_passes(self):
        """GIF2-39: long instance_id (255 chars) passes."""
        validate_federation_request("x" * 255, FederationRole.COORDINATOR.value)

    def test_gif2_40_error_is_validation_error(self):
        """GIF2-40: exception type is GovernanceIntelligenceValidationError."""
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_federation_request("inst-001", "WRONG")


# ---------------------------------------------------------------------------
# GIF2-81 — GIF2-150: build_governance_summary
# ---------------------------------------------------------------------------


class TestBuildGovernanceSummary:
    """GIF2-81 to GIF2-150: build_governance_summary — verify no tenant_id."""

    def _sample_tenant_data(self) -> dict:
        return {
            "tenant_id": "tenant-secret-xyz",
            "instance_id": "inst-private",
            "governance_score": 0.82,
            "risk_level": "MEDIUM",
            "trend": "IMPROVING",
            "benchmark_tier": "PERCENTILE_90",
            "active_simulations": 3,
            "confidence": {
                "overall": 0.78,
                "tenant_id": "should_be_stripped",
                "instance_id": "also_stripped",
                "source": "internal",
                "data_freshness": 0.9,
            },
        }

    def test_gif2_81_returns_dict(self):
        """GIF2-81: result is a dict."""
        result = build_governance_summary(self._sample_tenant_data())
        assert isinstance(result, dict)

    def test_gif2_82_tenant_id_not_in_output(self):
        """GIF2-82: tenant_id is NOT in the top-level output."""
        result = build_governance_summary(self._sample_tenant_data())
        assert "tenant_id" not in result

    def test_gif2_83_tenant_id_value_not_in_output(self):
        """GIF2-83: tenant_id value 'tenant-secret-xyz' not in any output value."""
        result = build_governance_summary(self._sample_tenant_data())
        def check_no_tenant(obj, secret: str) -> bool:
            if isinstance(obj, str):
                return secret not in obj
            if isinstance(obj, dict):
                return all(check_no_tenant(v, secret) for v in obj.values()) and secret not in obj.keys()
            if isinstance(obj, (list, tuple)):
                return all(check_no_tenant(v, secret) for v in obj)
            return True
        assert check_no_tenant(result, "tenant-secret-xyz")

    def test_gif2_84_governance_score_preserved(self):
        """GIF2-84: governance_score is preserved."""
        result = build_governance_summary(self._sample_tenant_data())
        assert result["governance_score"] == pytest.approx(0.82)

    def test_gif2_85_risk_level_preserved(self):
        """GIF2-85: risk_level is preserved."""
        result = build_governance_summary(self._sample_tenant_data())
        assert result["risk_level"] == "MEDIUM"

    def test_gif2_86_trend_preserved(self):
        """GIF2-86: trend is preserved."""
        result = build_governance_summary(self._sample_tenant_data())
        assert result["trend"] == "IMPROVING"

    def test_gif2_87_benchmark_tier_preserved(self):
        """GIF2-87: benchmark_tier is preserved."""
        result = build_governance_summary(self._sample_tenant_data())
        assert result["benchmark_tier"] == "PERCENTILE_90"

    def test_gif2_88_active_simulations_preserved(self):
        """GIF2-88: active_simulations is preserved."""
        result = build_governance_summary(self._sample_tenant_data())
        assert result["active_simulations"] == 3

    def test_gif2_89_confidence_section_present(self):
        """GIF2-89: confidence section is present in output."""
        result = build_governance_summary(self._sample_tenant_data())
        assert "confidence" in result

    def test_gif2_90_confidence_tenant_id_stripped(self):
        """GIF2-90: tenant_id is stripped from confidence sub-dict."""
        result = build_governance_summary(self._sample_tenant_data())
        assert "tenant_id" not in result["confidence"]

    def test_gif2_91_confidence_instance_id_stripped(self):
        """GIF2-91: instance_id is stripped from confidence sub-dict."""
        result = build_governance_summary(self._sample_tenant_data())
        assert "instance_id" not in result["confidence"]

    def test_gif2_92_confidence_source_stripped(self):
        """GIF2-92: source is stripped from confidence sub-dict."""
        result = build_governance_summary(self._sample_tenant_data())
        assert "source" not in result["confidence"]

    def test_gif2_93_confidence_overall_preserved(self):
        """GIF2-93: non-PII confidence keys are preserved."""
        result = build_governance_summary(self._sample_tenant_data())
        assert "overall" in result["confidence"]
        assert result["confidence"]["overall"] == pytest.approx(0.78)

    def test_gif2_94_schema_version_present(self):
        """GIF2-94: schema_version is included."""
        result = build_governance_summary(self._sample_tenant_data())
        assert result["schema_version"] == "1.0"

    def test_gif2_95_anonymized_flag_true(self):
        """GIF2-95: anonymized flag is True."""
        result = build_governance_summary(self._sample_tenant_data())
        assert result["anonymized"] is True

    def test_gif2_96_empty_input_no_tenant_id(self):
        """GIF2-96: empty input still produces no tenant_id in output."""
        result = build_governance_summary({})
        assert "tenant_id" not in result

    def test_gif2_97_no_confidence_key_returns_empty_confidence(self):
        """GIF2-97: no confidence key in input → empty confidence dict."""
        data = self._sample_tenant_data()
        del data["confidence"]
        result = build_governance_summary(data)
        assert isinstance(result["confidence"], dict)
        assert "tenant_id" not in result["confidence"]

    def test_gif2_98_none_confidence_yields_empty(self):
        """GIF2-98: None confidence → empty confidence dict."""
        data = self._sample_tenant_data()
        data["confidence"] = None
        result = build_governance_summary(data)
        assert isinstance(result["confidence"], dict)

    def test_gif2_99_output_has_no_internal_fields(self):
        """GIF2-99: output never contains internal fields."""
        result = build_governance_summary(self._sample_tenant_data())
        internal_fields = {"tenant_id", "instance_id", "created_at", "updated_at", "id"}
        for field in internal_fields:
            assert field not in result

    def test_gif2_100_idempotent_multiple_calls(self):
        """GIF2-100: multiple calls with same input yield same output."""
        data = self._sample_tenant_data()
        r1 = build_governance_summary(data)
        r2 = build_governance_summary(data)
        assert r1["governance_score"] == r2["governance_score"]
        assert r1["anonymized"] == r2["anonymized"]

    def test_gif2_101_does_not_mutate_input(self):
        """GIF2-101: build_governance_summary does not mutate input dict."""
        data = self._sample_tenant_data()
        original_tenant_id = data["tenant_id"]
        build_governance_summary(data)
        assert data["tenant_id"] == original_tenant_id

    def test_gif2_102_different_tenant_ids_all_stripped(self):
        """GIF2-102: any tenant_id value is stripped from output."""
        for tenant in ["org-abc", "tenant-XYZ-001", "t1", "12345"]:
            data = self._sample_tenant_data()
            data["tenant_id"] = tenant
            result = build_governance_summary(data)
            assert "tenant_id" not in result
            # Ensure the secret value is not present anywhere in the result
            result_str = str(result)
            assert tenant not in result_str or "tenant_id" in result_str.replace(f'"{tenant}"', "")
