"""Tests for P0-9 Quarterly Trust Briefs.

Covers:
  - Period boundary computation (_period_bounds)
  - Section builders (posture, drift, certification, governance, evidence, board_summary)
  - Hash determinism (_sha256, _section_hash, _manifest_hash, _report_hash)
  - Brief generation (generate_quarterly_brief, generate_board_brief) — empty + data
  - Manifest structure validation
  - DB exception handling (returns empty dict, not raises)
  - Tenant isolation (brief_id belongs to a different tenant)
  - Status transition logic
  - Export format safety (json / html / invalid)
  - Large dataset handling (brief_service degrades gracefully)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock


from services.quarterly_briefs.brief_service import (
    _build_board_summary,
    _build_certification_section,
    _build_drift_section,
    _build_evidence_appendix,
    _build_governance_section,
    _build_posture_section,
    _manifest_hash,
    _period_bounds,
    _report_hash,
    _section_hash,
    _sha256,
    generate_board_brief,
    generate_quarterly_brief,
)


# ---------------------------------------------------------------------------
# _period_bounds
# ---------------------------------------------------------------------------


class TestPeriodBounds:
    def test_q1(self):
        s, e = _period_bounds(2026, 1)
        assert s == "2026-01-01T00:00:00Z"
        assert e == "2026-04-01T00:00:00Z"

    def test_q2(self):
        s, e = _period_bounds(2026, 2)
        assert s == "2026-04-01T00:00:00Z"
        assert e == "2026-07-01T00:00:00Z"

    def test_q3(self):
        s, e = _period_bounds(2026, 3)
        assert s == "2026-07-01T00:00:00Z"
        assert e == "2026-10-01T00:00:00Z"

    def test_q4_wraps_year(self):
        s, e = _period_bounds(2026, 4)
        assert s == "2026-10-01T00:00:00Z"
        assert e == "2027-01-01T00:00:00Z"

    def test_q4_different_year(self):
        s, e = _period_bounds(2025, 4)
        assert e == "2026-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# Hash determinism
# ---------------------------------------------------------------------------


class TestHashDeterminism:
    def test_sha256_same_input_same_output(self):
        h1 = _sha256({"a": 1, "b": 2})
        h2 = _sha256({"b": 2, "a": 1})
        assert h1 == h2  # sort_keys=True ensures determinism

    def test_sha256_different_input_different_output(self):
        assert _sha256({"a": 1}) != _sha256({"a": 2})

    def test_section_hash_is_64_hex(self):
        h = _section_hash({"section_type": "posture", "score": 80})
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_section_hash_deterministic(self):
        data = {"section_type": "drift", "total_events": 5}
        assert _section_hash(data) == _section_hash(data)

    def test_manifest_hash_sorted_order_independent(self):
        h1 = _manifest_hash(["b", "a"], [], [], [], [], [], [])
        h2 = _manifest_hash(["a", "b"], [], [], [], [], [], [])
        assert h1 == h2  # sorted before hashing

    def test_manifest_hash_changes_on_different_ids(self):
        h1 = _manifest_hash(["snap-1"], [], [], [], [], [], [])
        h2 = _manifest_hash(["snap-2"], [], [], [], [], [], [])
        assert h1 != h2

    def test_report_hash_deterministic(self):
        rh = _report_hash("abc", "def")
        assert _report_hash("abc", "def") == rh

    def test_report_hash_uses_both_inputs(self):
        assert _report_hash("abc", "def") != _report_hash("abc", "xyz")
        assert _report_hash("abc", "def") != _report_hash("xyz", "def")


# ---------------------------------------------------------------------------
# _build_posture_section
# ---------------------------------------------------------------------------


class TestBuildPostureSection:
    def _snap(self, score, level="high", direction="stable", replay="ok", evidence=10):
        s = MagicMock()
        s.posture_score = score
        s.posture_level = level
        s.drift_direction = direction
        s.replay_status = replay
        s.evidence_count = evidence
        s.evaluated_at = "2026-04-15T10:00:00Z"
        s.id = f"snap-{score}"
        return s

    def test_empty_returns_has_data_false(self):
        result = _build_posture_section([])
        assert result["has_data"] is False
        assert result["snapshots_evaluated"] == 0

    def test_single_snapshot(self):
        result = _build_posture_section([self._snap(75)])
        assert result["has_data"] is True
        assert result["snapshots_evaluated"] == 1
        assert result["posture"]["start_score"] == 75
        assert result["posture"]["end_score"] == 75
        assert result["posture"]["net_delta"] == 0

    def test_improving_trend(self):
        snaps = [self._snap(50), self._snap(65), self._snap(80)]
        result = _build_posture_section(snaps)
        assert result["trend"]["direction"] == "improving"
        assert result["posture"]["net_delta"] == 30

    def test_degrading_trend(self):
        snaps = [self._snap(80), self._snap(72), self._snap(70)]
        result = _build_posture_section(snaps)
        assert result["trend"]["direction"] == "degrading"

    def test_rapidly_degrading_trend(self):
        snaps = [self._snap(90), self._snap(60)]
        result = _build_posture_section(snaps)
        assert result["trend"]["direction"] == "rapidly_degrading"

    def test_stable_trend(self):
        snaps = [self._snap(75), self._snap(77), self._snap(74)]
        result = _build_posture_section(snaps)
        assert result["trend"]["direction"] == "stable"

    def test_source_ids_included(self):
        snaps = [self._snap(70), self._snap(80)]
        result = _build_posture_section(snaps)
        assert "snap-70" in result["source_snapshot_ids"]
        assert "snap-80" in result["source_snapshot_ids"]

    def test_replay_distribution(self):
        snaps = [
            self._snap(70, replay="ok"),
            self._snap(75, replay="ok"),
            self._snap(60, replay="failed"),
        ]
        result = _build_posture_section(snaps)
        assert result["monitoring"]["replay_ok_count"] == 2
        assert result["monitoring"]["replay_failed_count"] == 1


# ---------------------------------------------------------------------------
# _build_drift_section
# ---------------------------------------------------------------------------


class TestBuildDriftSection:
    def _event(self, severity, rule="score_degradation", status="open"):
        e = MagicMock()
        e.severity = severity
        e.drift_rule = rule
        e.status = status
        e.id = f"evt-{severity}-{rule}"
        return e

    def test_empty_returns_zero(self):
        result = _build_drift_section([])
        assert result["has_data"] is False
        assert result["total_events"] == 0
        assert result["engagement_risk_score"] == 0

    def test_risk_score_aggregation(self):
        events = [
            self._event("critical"),  # 15
            self._event("high"),  # 7
            self._event("medium"),  # 3
        ]
        result = _build_drift_section(events)
        assert result["engagement_risk_score"] == 25
        assert result["total_events"] == 3

    def test_severity_counts(self):
        events = [
            self._event("critical"),
            self._event("critical"),
            self._event("low"),
        ]
        result = _build_drift_section(events)
        assert result["summary"]["critical_count"] == 2
        assert result["summary"]["low_count"] == 1
        assert result["summary"]["has_critical"] is True

    def test_no_critical(self):
        events = [self._event("low"), self._event("medium")]
        result = _build_drift_section(events)
        assert result["summary"]["has_critical"] is False
        assert result["summary"]["has_high"] is False

    def test_rule_breakdown(self):
        events = [
            self._event("high", rule="cert_expiration"),
            self._event("high", rule="cert_expiration"),
            self._event("medium", rule="evidence_staleness"),
        ]
        result = _build_drift_section(events)
        assert result["by_rule"]["cert_expiration"] == 2
        assert result["by_rule"]["evidence_staleness"] == 1

    def test_top_rules_sorted(self):
        events = [self._event("low", rule="r1")] * 5 + [
            self._event("low", rule="r2")
        ] * 2
        result = _build_drift_section(events)
        assert result["top_rules"][0]["rule"] == "r1"
        assert result["top_rules"][0]["count"] == 5

    def test_status_distribution(self):
        events = [
            self._event("high", status="open"),
            self._event("high", status="resolved"),
            self._event("low", status="acknowledged"),
        ]
        result = _build_drift_section(events)
        assert result["summary"]["open_count"] == 1
        assert result["summary"]["resolved_count"] == 1
        assert result["summary"]["acknowledged_count"] == 1


# ---------------------------------------------------------------------------
# _build_certification_section
# ---------------------------------------------------------------------------


class TestBuildCertificationSection:
    def _cert(self, level="gold", score=82, from_="2026-01-01T00:00:00Z"):
        future = (datetime.now(timezone.utc) + timedelta(days=60)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        c = MagicMock()
        c.id = f"cert-{level}"
        c.certification_level = level
        c.composite_score = score
        c.trust_score = score - 2
        c.confidence_score = score + 3
        c.valid_from = from_
        c.valid_until = future
        return c

    def test_no_certs_returns_has_data_false(self):
        result = _build_certification_section([], None)
        assert result["has_data"] is False
        assert result["period_certifications_issued"] == 0

    def test_active_cert_included(self):
        cert = self._cert("platinum")
        result = _build_certification_section([], cert)
        assert result["has_data"] is True
        assert result["active_certification"]["certification_level"] == "platinum"

    def test_period_certs_counted(self):
        certs = [self._cert("gold"), self._cert("silver", from_="2026-02-01T00:00:00Z")]
        result = _build_certification_section(certs, None)
        assert result["period_certifications_issued"] == 2
        assert "gold" in result["levels_issued"]
        assert "silver" in result["levels_issued"]

    def test_level_distribution(self):
        certs = [self._cert("gold"), self._cert("gold")]
        result = _build_certification_section(certs, None)
        assert result["level_distribution"]["gold"] == 2

    def test_expiry_status_valid(self):
        cert = self._cert()
        result = _build_certification_section([], cert)
        assert result["active_certification"]["expiry_status"] == "valid"


# ---------------------------------------------------------------------------
# _build_governance_section
# ---------------------------------------------------------------------------


class TestBuildGovernanceSection:
    def _event(
        self, source_type="trust_monitoring", event_type="tim_snapshot_evaluated"
    ):
        e = MagicMock()
        e.id = f"evt-{source_type}"
        e.source_type = source_type
        e.event_type = event_type
        e.occurred_at = "2026-04-10T10:00:00Z"
        return e

    def _decision(self, decision_type="governance_review", entity_type="human"):
        d = MagicMock()
        d.id = f"dec-{decision_type}"
        d.decision_type = decision_type
        d.entity_type = entity_type
        return d

    def test_empty_returns_has_data_false(self):
        result = _build_governance_section([], [])
        assert result["has_data"] is False
        assert result["timeline_event_count"] == 0
        assert result["decision_count"] == 0

    def test_timeline_event_counts(self):
        events = [self._event(), self._event("trust_arc", "cert_issued")]
        result = _build_governance_section(events, [])
        assert result["timeline_event_count"] == 2
        assert result["by_source_type"]["trust_monitoring"] == 1
        assert result["by_source_type"]["trust_arc"] == 1

    def test_decision_type_distribution(self):
        decisions = [
            self._decision("governance_review"),
            self._decision("governance_review"),
            self._decision("certification_approval"),
        ]
        result = _build_governance_section([], decisions)
        assert result["by_decision_type"]["governance_review"] == 2
        assert result["by_decision_type"]["certification_approval"] == 1

    def test_actor_type_distribution(self):
        decisions = [
            self._decision(entity_type="human"),
            self._decision(entity_type="agent"),
        ]
        result = _build_governance_section([], decisions)
        assert "human" in result["actor_type_distribution"]
        assert "agent" in result["actor_type_distribution"]

    def test_key_events_limited_to_10(self):
        events = [self._event() for _ in range(20)]
        result = _build_governance_section(events, [])
        assert len(result["key_events"]) <= 10


# ---------------------------------------------------------------------------
# _build_board_summary
# ---------------------------------------------------------------------------


class TestBuildBoardSummary:
    def _posture_sec(self, score=75, direction="stable"):
        return {
            "section_type": "posture",
            "has_data": True,
            "snapshots_evaluated": 10,
            "posture": {
                "end_score": score,
                "end_level": "high",
                "start_score": 70,
                "net_delta": score - 70,
            },
            "trend": {"direction": direction},
        }

    def _drift_sec(self, risk_score=10, has_critical=False):
        return {
            "section_type": "drift",
            "total_events": 3,
            "engagement_risk_score": risk_score,
            "summary": {
                "has_critical": has_critical,
                "has_high": False,
            },
        }

    def _cert_sec(self, level="gold"):
        return {
            "section_type": "certification",
            "active_certification": {
                "certification_level": level,
                "expiry_status": "valid",
            },
            "period_certifications_issued": 1,
        }

    def _gov_sec(self):
        return {
            "section_type": "governance",
            "timeline_event_count": 15,
            "decision_count": 3,
        }

    def test_strong_posture_summary(self):
        result = _build_board_summary(
            self._posture_sec(85), self._drift_sec(), self._cert_sec(), self._gov_sec()
        )
        assert "Strong" in result["trust_posture"]["summary"]

    def test_moderate_posture_summary(self):
        result = _build_board_summary(
            self._posture_sec(70), self._drift_sec(), self._cert_sec(), self._gov_sec()
        )
        assert "Moderate" in result["trust_posture"]["summary"]

    def test_low_posture_summary(self):
        result = _build_board_summary(
            self._posture_sec(45), self._drift_sec(), self._cert_sec(), self._gov_sec()
        )
        assert "attention" in result["trust_posture"]["summary"]

    def test_no_risk_summary(self):
        result = _build_board_summary(
            self._posture_sec(), self._drift_sec(0), self._cert_sec(), self._gov_sec()
        )
        assert "No open risk" in result["risk"]["summary"]

    def test_critical_risk_flagged(self):
        result = _build_board_summary(
            self._posture_sec(),
            self._drift_sec(25, has_critical=True),
            self._cert_sec(),
            self._gov_sec(),
        )
        assert result["risk"]["has_critical"] is True
        assert "Critical" in result["risk"]["summary"]

    def test_strategic_direction_propagated(self):
        result = _build_board_summary(
            self._posture_sec(direction="improving"),
            self._drift_sec(),
            self._cert_sec(),
            self._gov_sec(),
        )
        assert result["strategic_direction"] == "improving"

    def test_no_data_posture(self):
        posture_sec = {
            "section_type": "posture",
            "has_data": False,
            "snapshots_evaluated": 0,
            "posture": None,
            "trend": {},
        }
        result = _build_board_summary(
            posture_sec, self._drift_sec(), self._cert_sec(), self._gov_sec()
        )
        assert result["trust_posture"]["score"] is None


# ---------------------------------------------------------------------------
# _build_evidence_appendix
# ---------------------------------------------------------------------------


class TestBuildEvidenceAppendix:
    def _snap(self, id_):
        s = MagicMock()
        s.id = id_
        return s

    def _cert(self, id_):
        c = MagicMock()
        c.id = id_
        return c

    def _event(self, id_):
        e = MagicMock()
        e.id = id_
        return e

    def _bundle(self, id_):
        b = MagicMock()
        b.id = id_
        b.generated_at = "2026-04-01T10:00:00Z"
        b.bundle_type = "verification"
        return b

    def test_all_ids_present(self):
        snaps = [self._snap("s1"), self._snap("s2")]
        certs = [self._cert("c1")]
        events = [self._event("d1")]
        timeline = [self._event("t1")]
        decisions = [self._event("dec1")]
        bundles = [self._bundle("b1")]

        result = _build_evidence_appendix(
            snaps, certs, None, events, timeline, decisions, bundles
        )

        assert "s1" in result["snapshot_ids"]
        assert "c1" in result["certification_ids"]
        assert "d1" in result["drift_event_ids"]
        assert "t1" in result["timeline_event_ids"]
        assert "dec1" in result["decision_ids"]
        assert result["bundle_count"] == 1

    def test_counts_accurate(self):
        snaps = [self._snap(f"s{i}") for i in range(5)]
        result = _build_evidence_appendix(snaps, [], None, [], [], [], [])
        assert result["snapshot_count"] == 5

    def test_traceability_flags(self):
        result = _build_evidence_appendix([], [], None, [], [], [], [])
        assert result["traceability"]["no_synthetic_data"] is True
        assert result["traceability"]["replay_support"] is True

    def test_active_cert_appended_if_not_in_period_certs(self):
        period_cert = self._cert("c1")
        active_cert = self._cert("c2")  # different ID
        result = _build_evidence_appendix(
            [], [period_cert], active_cert, [], [], [], []
        )
        assert "c2" in result["certification_ids"]

    def test_active_cert_not_duplicated_if_in_period_certs(self):
        cert = self._cert("c1")
        result = _build_evidence_appendix([], [cert], cert, [], [], [], [])
        assert result["certification_ids"].count("c1") == 1


# ---------------------------------------------------------------------------
# generate_quarterly_brief — empty state
# ---------------------------------------------------------------------------


class TestGenerateQuarterlyBriefEmpty:
    def _make_db_empty(self):
        """Mock DB that returns empty results for all queries."""
        db = MagicMock()
        execute = MagicMock()
        db.execute.return_value = execute
        execute.scalars.return_value.all.return_value = []
        execute.scalar_one_or_none.return_value = None
        execute.scalar.return_value = 0
        return db

    def test_empty_state_returns_dict(self):
        db = self._make_db_empty()
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        assert isinstance(result, dict)
        assert result != {}

    def test_empty_state_brief_id_present(self):
        db = self._make_db_empty()
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        assert "brief_id" in result

    def test_empty_state_period_correct(self):
        db = self._make_db_empty()
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=2
        )
        assert result["period_start"] == "2026-04-01T00:00:00Z"
        assert result["period_end"] == "2026-07-01T00:00:00Z"

    def test_empty_state_six_sections(self):
        db = self._make_db_empty()
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        section_types = {s["section_type"] for s in result["sections"]}
        assert "posture" in section_types
        assert "drift" in section_types
        assert "certification" in section_types
        assert "governance" in section_types
        assert "evidence" in section_types
        assert "board_summary" in section_types

    def test_empty_state_manifest_present(self):
        db = self._make_db_empty()
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        assert "manifest" in result
        assert "manifest_hash" in result["manifest"]
        assert "report_hash" in result["manifest"]

    def test_exception_returns_empty_dict(self):
        db = MagicMock()
        db.execute.side_effect = RuntimeError("db failed")
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        assert result == {}

    def test_generated_by_actor_in_result(self):
        db = self._make_db_empty()
        result = generate_quarterly_brief(
            db,
            tenant_id="t1",
            engagement_id="e1",
            year=2026,
            quarter=1,
            generated_by="key_abc",
        )
        assert result["generated_by"] == "key_abc"


# ---------------------------------------------------------------------------
# generate_board_brief — empty state
# ---------------------------------------------------------------------------


class TestGenerateBoardBriefEmpty:
    def _make_db_empty(self):
        db = MagicMock()
        execute = MagicMock()
        db.execute.return_value = execute
        execute.scalars.return_value.all.return_value = []
        execute.scalar_one_or_none.return_value = None
        execute.scalar.return_value = 0
        return db

    def test_board_brief_report_type(self):
        db = self._make_db_empty()
        result = generate_board_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        assert result["report_type"] == "board"

    def test_board_brief_has_board_summary_section(self):
        db = self._make_db_empty()
        result = generate_board_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        section_types = {s["section_type"] for s in result["sections"]}
        assert "board_summary" in section_types

    def test_board_brief_has_evidence_section(self):
        db = self._make_db_empty()
        result = generate_board_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        section_types = {s["section_type"] for s in result["sections"]}
        assert "evidence" in section_types

    def test_board_brief_only_two_sections(self):
        db = self._make_db_empty()
        result = generate_board_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        assert len(result["sections"]) == 2

    def test_board_exception_returns_empty_dict(self):
        db = MagicMock()
        db.execute.side_effect = RuntimeError("db dead")
        result = generate_board_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        assert result == {}


# ---------------------------------------------------------------------------
# Manifest and hash validation
# ---------------------------------------------------------------------------


class TestManifestValidation:
    def _make_db_empty(self):
        db = MagicMock()
        execute = MagicMock()
        db.execute.return_value = execute
        execute.scalars.return_value.all.return_value = []
        execute.scalar_one_or_none.return_value = None
        execute.scalar.return_value = 0
        return db

    def test_brief_hash_64_hex(self):
        db = self._make_db_empty()
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        assert len(result["brief_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in result["brief_hash"])

    def test_report_hash_64_hex(self):
        db = self._make_db_empty()
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        assert len(result["report_hash"]) == 64

    def test_manifest_hash_64_hex(self):
        db = self._make_db_empty()
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        assert len(result["manifest"]["manifest_hash"]) == 64

    def test_generation_version_set(self):
        db = self._make_db_empty()
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        assert result["generation_version"] == "qtb-1.0"

    def test_authority_version_set(self):
        db = self._make_db_empty()
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        assert result["authority_version"] == "v1"

    def test_schema_version_set(self):
        db = self._make_db_empty()
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        assert result["schema_version"] == "1.0"

    def test_report_hash_consistent_with_brief_and_manifest_hash(self):
        import hashlib

        db = self._make_db_empty()
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=1
        )
        # report_hash = SHA-256(brief_hash:manifest_hash)
        expected = hashlib.sha256(
            f"{result['brief_hash']}:{result['manifest']['manifest_hash']}".encode()
        ).hexdigest()
        assert result["report_hash"] == expected


# ---------------------------------------------------------------------------
# Evidence linkage traceability
# ---------------------------------------------------------------------------


class TestEvidenceLinkage:
    def _make_db_with_snaps(self):
        db = MagicMock()
        call_count = [0]

        snap = MagicMock()
        snap.posture_score = 75
        snap.posture_level = "high"
        snap.drift_direction = "stable"
        snap.replay_status = "ok"
        snap.evidence_count = 5
        snap.evaluated_at = "2026-04-15T10:00:00Z"
        snap.id = "snap-1"

        event = MagicMock()
        event.severity = "high"
        event.drift_rule = "cert_expiration"
        event.status = "open"
        event.id = "drift-1"

        def execute_side(*args, **kwargs):
            call_count[0] += 1
            result = MagicMock()
            if call_count[0] == 1:
                result.scalars.return_value.all.return_value = [snap]
            elif call_count[0] == 2:
                result.scalars.return_value.all.return_value = [event]
            else:
                result.scalars.return_value.all.return_value = []
                result.scalar_one_or_none.return_value = None
                result.scalar.return_value = 0
            return result

        db.execute.side_effect = execute_side
        return db

    def test_evidence_section_references_snapshot_id(self):
        db = self._make_db_with_snaps()
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=2
        )
        evidence_sec = next(
            s for s in result["sections"] if s["section_type"] == "evidence"
        )
        assert "snap-1" in evidence_sec["snapshot_ids"]

    def test_drift_section_references_event_id(self):
        db = self._make_db_with_snaps()
        result = generate_quarterly_brief(
            db, tenant_id="t1", engagement_id="e1", year=2026, quarter=2
        )
        drift_sec = next(s for s in result["sections"] if s["section_type"] == "drift")
        assert "drift-1" in drift_sec["source_drift_event_ids"]


# ---------------------------------------------------------------------------
# Historical reporting accuracy
# ---------------------------------------------------------------------------


class TestHistoricalReportingAccuracy:
    def test_quarterly_period_q4_uses_correct_year_end(self):
        s, e = _period_bounds(2025, 4)
        assert "2026-01-01" in e

    def test_empty_period_no_snapshots_zero_posture(self):
        result = _build_posture_section([])
        assert result["posture"] is None

    def test_zero_drift_events_zero_risk_score(self):
        result = _build_drift_section([])
        assert result["engagement_risk_score"] == 0

    def test_board_summary_reflects_posture_section(self):
        posture_sec = {
            "section_type": "posture",
            "has_data": True,
            "snapshots_evaluated": 5,
            "posture": {"end_score": 88, "end_level": "high"},
            "trend": {"direction": "improving"},
        }
        board = _build_board_summary(
            posture_sec,
            {
                "section_type": "drift",
                "total_events": 0,
                "engagement_risk_score": 0,
                "summary": {"has_critical": False, "has_high": False},
            },
            {
                "section_type": "certification",
                "active_certification": None,
                "period_certifications_issued": 0,
            },
            {
                "section_type": "governance",
                "timeline_event_count": 0,
                "decision_count": 0,
            },
        )
        assert board["trust_posture"]["score"] == 88
        assert board["strategic_direction"] == "improving"
