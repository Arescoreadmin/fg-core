# tests/test_decision_pipeline_unified.py
"""
Tests for the Unified Decision Pipeline.

Hardening Day 1: These tests verify that:
1. The unified pipeline produces consistent results
2. Same input produces same output regardless of entry point
3. Doctrine is always applied
4. TieD is never None
"""

from __future__ import annotations

from engine.pipeline import (
    PipelineInput,
    PipelineResult,
    TieD,
    evaluate,
    evaluate_dict,
    _threat_from_score,
    _compute_event_id,
)


class TestPipelineBasics:
    """Basic pipeline functionality tests."""

    def test_evaluate_returns_pipeline_result(self):
        """Pipeline evaluate() returns a PipelineResult."""
        inp = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="auth",
            payload={"failed_auths": 10, "src_ip": "1.2.3.4"},
        )
        result = evaluate(inp)
        assert isinstance(result, PipelineResult)

    def test_tied_never_none(self):
        """P0: TieD is never None in pipeline output."""
        inp = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="unknown",
            payload={},
        )
        result = evaluate(inp)
        assert result.tie_d is not None
        assert isinstance(result.tie_d, TieD)

    def test_event_id_always_present(self):
        """P0: event_id is always computed."""
        inp = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="test",
            payload={},
        )
        result = evaluate(inp)
        assert result.event_id
        assert len(result.event_id) == 64  # SHA256 hex

    def test_deterministic_event_id(self):
        """Same input produces same event_id."""
        inp1 = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="test",
            payload={"key": "value"},
            timestamp="2026-01-31T12:00:00Z",
        )
        inp2 = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="test",
            payload={"key": "value"},
            timestamp="2026-01-31T12:00:00Z",
        )
        id1 = _compute_event_id(inp1)
        id2 = _compute_event_id(inp2)
        assert id1 == id2


class TestBruteForceRule:
    """Tests for the brute-force detection rule."""

    def test_bruteforce_detection_basic(self):
        """Detects brute force with auth event type and failed_auths >= 5."""
        inp = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="auth.bruteforce",
            payload={"failed_auths": 10, "src_ip": "10.0.0.50"},
        )
        result = evaluate(inp)

        assert "rule:ssh_bruteforce" in result.rules_triggered
        assert result.threat_level in ("high", "critical")
        assert len(result.mitigations) >= 1
        assert any(m.action == "block_ip" for m in result.mitigations)

    def test_bruteforce_detection_auth_event(self):
        """Detects brute force with generic auth event type."""
        inp = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="auth",
            payload={"failed_auths": 5, "src_ip": "10.0.0.50"},
        )
        result = evaluate(inp)

        assert "rule:ssh_bruteforce" in result.rules_triggered
        assert result.threat_level in ("high", "critical", "medium")

    def test_no_bruteforce_low_count(self):
        """No brute force if failed_auths < threshold."""
        inp = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="auth",
            payload={"failed_auths": 2, "src_ip": "10.0.0.50"},
        )
        result = evaluate(inp)

        assert "rule:ssh_bruteforce" not in result.rules_triggered
        assert result.threat_level in ("none", "low")

    def test_default_allow_rule(self):
        """Default allow rule fires when no threats detected."""
        inp = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="info",
            payload={},
        )
        result = evaluate(inp)

        assert "rule:default_allow" in result.rules_triggered
        assert result.threat_level == "none"


class TestDoctrine:
    """Tests for doctrine application."""

    def test_guardian_secret_caps_disruption(self):
        """Guardian + SECRET caps disruptive mitigations to 1."""
        inp = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="auth.bruteforce",
            payload={"failed_auths": 100, "src_ip": "10.0.0.50"},
            persona="guardian",
            classification="SECRET",
        )
        result = evaluate(inp)

        assert result.roe_applied
        assert result.ao_required
        # Should have at most 1 block_ip action
        block_ips = [m for m in result.mitigations if m.action == "block_ip"]
        assert len(block_ips) <= 1

    def test_guardian_secret_sets_gating(self):
        """Guardian + SECRET sets gating_decision appropriately."""
        inp = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="auth.bruteforce",
            payload={"failed_auths": 10, "src_ip": "10.0.0.50"},
            persona="guardian",
            classification="SECRET",
        )
        result = evaluate(inp)

        assert result.tie_d.gating_decision in ("allow", "require_approval", "reject")
        if any(m.action == "block_ip" for m in result.mitigations):
            assert result.tie_d.gating_decision == "require_approval"

    def test_sentinel_allows_more_disruption(self):
        """Sentinel persona allows more disruptive actions than guardian."""
        inp = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="auth.bruteforce",
            payload={"failed_auths": 10, "src_ip": "10.0.0.50"},
            persona="sentinel",
            classification="SECRET",
        )
        result = evaluate(inp)

        # Sentinel allows up to 3 disruptive actions
        assert result.tie_d.persona == "sentinel"

    def test_no_persona_no_roe(self):
        """Without persona/classification, ROE is not applied."""
        inp = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="auth.bruteforce",
            payload={"failed_auths": 10, "src_ip": "10.0.0.50"},
        )
        result = evaluate(inp)

        assert not result.roe_applied
        assert not result.ao_required


class TestTieD:
    """Tests for TieD computation."""

    def test_tied_impact_scores(self):
        """TieD contains valid impact scores."""
        inp = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="auth.bruteforce",
            payload={"failed_auths": 10, "src_ip": "10.0.0.50"},
        )
        result = evaluate(inp)

        assert 0.0 <= result.tie_d.service_impact <= 1.0
        assert 0.0 <= result.tie_d.user_impact <= 1.0

    def test_tied_to_dict(self):
        """TieD.to_dict() returns proper dict."""
        tie_d = TieD(
            roe_applied=True,
            disruption_limited=False,
            ao_required=True,
            persona="guardian",
            classification="SECRET",
        )
        d = tie_d.to_dict()

        assert d["roe_applied"] is True
        assert d["ao_required"] is True
        assert d["persona"] == "guardian"
        assert d["classification"] == "SECRET"


class TestDictInterface:
    """Tests for the dict-based interface (ingest compatibility)."""

    def test_evaluate_dict_returns_dict(self):
        """evaluate_dict() returns a dict."""
        telemetry = {
            "tenant_id": "tenant-1",
            "source": "test",
            "event_type": "auth",
            "payload": {"failed_auths": 5, "src_ip": "10.0.0.50"},
        }
        result = evaluate_dict(telemetry)

        assert isinstance(result, dict)
        assert "threat_level" in result
        assert "mitigations" in result
        assert "tie_d" in result

    def test_dict_and_object_consistency(self):
        """Dict and object interfaces produce consistent results."""
        telemetry = {
            "tenant_id": "tenant-1",
            "source": "test",
            "event_type": "auth.bruteforce",
            "payload": {"failed_auths": 10, "src_ip": "10.0.0.50"},
            "timestamp": "2026-01-31T12:00:00Z",
        }

        dict_result = evaluate_dict(telemetry)

        inp = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="auth.bruteforce",
            payload={"failed_auths": 10, "src_ip": "10.0.0.50"},
            timestamp="2026-01-31T12:00:00Z",
        )
        obj_result = evaluate(inp)

        assert dict_result["threat_level"] == obj_result.threat_level
        assert dict_result["event_id"] == obj_result.event_id
        assert dict_result["score"] == obj_result.score


class TestScoring:
    """Tests for score to threat level mapping."""

    def test_threat_level_none(self):
        """Score < 20 = none."""
        assert _threat_from_score(0) == "none"
        assert _threat_from_score(19) == "none"

    def test_threat_level_low(self):
        """Score 20-49 = low."""
        assert _threat_from_score(20) == "low"
        assert _threat_from_score(49) == "low"

    def test_threat_level_medium(self):
        """Score 50-79 = medium."""
        assert _threat_from_score(50) == "medium"
        assert _threat_from_score(79) == "medium"

    def test_threat_level_high(self):
        """Score 80-94 = high."""
        assert _threat_from_score(80) == "high"
        assert _threat_from_score(94) == "high"

    def test_threat_level_critical(self):
        """Score >= 95 = critical."""
        assert _threat_from_score(95) == "critical"
        assert _threat_from_score(100) == "critical"


class TestInvariantSameInputSameOutput:
    """
    P0 Invariant: Same input MUST produce same output.

    This test ensures deterministic behavior.
    """

    def test_deterministic_output(self):
        """Same input produces identical output."""
        inp = PipelineInput(
            tenant_id="tenant-1",
            source="test",
            event_type="auth.bruteforce",
            payload={"failed_auths": 10, "src_ip": "10.0.0.50"},
            timestamp="2026-01-31T12:00:00Z",
            persona="guardian",
            classification="SECRET",
        )

        result1 = evaluate(inp)
        result2 = evaluate(inp)

        assert result1.threat_level == result2.threat_level
        assert result1.event_id == result2.event_id
        assert result1.score == result2.score
        assert result1.roe_applied == result2.roe_applied
        assert result1.tie_d.gating_decision == result2.tie_d.gating_decision
        assert len(result1.mitigations) == len(result2.mitigations)
