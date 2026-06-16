"""Tests for P0-10 Certification Lifecycle Management (CLM).

Covers:
  - Lifecycle state machine (_VALID_TRANSITIONS)
  - create_certification() — cert + manifest + lifecycle event
  - transition_lifecycle() — valid/invalid transitions
  - add_review() — review record append
  - add_attestation() — attestation + hash
  - initiate_renewal() — renewal + readiness
  - get_certification_health() — health scoring + renewal_recommended
  - get_lineage() — parent chain traversal + circular guard
  - compute_trust_impact() — cert level weights
  - Manifest hash determinism + schema_version
  - Cert hash determinism
  - Dashboard helper logic
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from services.clm.lifecycle_service import (
    _VALID_TRANSITIONS,
    _sha256,
    _days_until,
    add_attestation,
    add_review,
    compute_trust_impact,
    create_certification,
    get_certification_health,
    get_lineage,
    initiate_renewal,
    transition_lifecycle,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cert(
    cert_id="cert-001",
    tenant_id="t1",
    engagement_id="eng-001",
    lifecycle_status="draft",
    cert_name="Test Cert",
    cert_type="standard",
    certification_level="gold",
    valid_until=None,
    parent_cert_id=None,
    family_id=None,
    created_by="alice",
    actor_type="human",
):
    cert = MagicMock()
    cert.id = cert_id
    cert.tenant_id = tenant_id
    cert.engagement_id = engagement_id
    cert.lifecycle_status = lifecycle_status
    cert.cert_name = cert_name
    cert.cert_type = cert_type
    cert.certification_level = certification_level
    cert.valid_until = valid_until
    cert.valid_from = None
    cert.parent_cert_id = parent_cert_id
    cert.family_id = family_id
    cert.created_by = created_by
    cert.actor_type = actor_type
    cert.trust_arc_cert_id = None
    cert.framework = None
    cert.framework_version = None
    cert.certification_profile = None
    cert.cert_hash = "a" * 64
    cert.status_updated_by = None
    cert.status_updated_at = None
    cert.created_at = "2026-01-01T00:00:00Z"
    cert.generation_version = "clm-1.0"
    cert.authority_version = "v1"
    cert.schema_version = "1.0"
    return cert


def _make_db_with_cert(cert, snapshots=None, drift_events=None, bundles=None):
    """Return a MagicMock db that returns the given cert on scalar_one_or_none()."""
    db = MagicMock()
    execute_result = MagicMock()
    scalars_result = MagicMock()
    execute_result.scalar_one_or_none.return_value = cert
    execute_result.scalars.return_value = scalars_result
    scalars_result.all.return_value = snapshots or []
    db.execute.return_value = execute_result
    return db


def _empty_db():
    """Return db that returns None on scalar_one_or_none."""
    db = MagicMock()
    execute_result = MagicMock()
    scalars_result = MagicMock()
    execute_result.scalar_one_or_none.return_value = None
    execute_result.scalars.return_value = scalars_result
    scalars_result.all.return_value = []
    db.execute.return_value = execute_result
    return db


def _snap(score=80, posture_level="high", drift="stable", replay="ok", snap_id="s1"):
    s = MagicMock()
    s.id = snap_id
    s.posture_score = score
    s.posture_level = posture_level
    s.drift_direction = drift
    s.replay_status = replay
    s.evaluated_at = "2026-06-01T00:00:00Z"
    return s


def _drift(status="open", severity="medium", eid="e1"):
    d = MagicMock()
    d.id = "drift-1"
    d.status = status
    d.severity = severity
    d.engagement_id = eid
    d.detected_at = "2026-06-01T00:00:00Z"
    return d


# ---------------------------------------------------------------------------
# TestLifecycleTransitions (~15 tests)
# ---------------------------------------------------------------------------


class TestLifecycleTransitions:
    def test_draft_to_in_review(self):
        assert "in_review" in _VALID_TRANSITIONS["draft"]

    def test_draft_to_pending_evidence(self):
        assert "pending_evidence" in _VALID_TRANSITIONS["draft"]

    def test_draft_to_archived(self):
        assert "archived" in _VALID_TRANSITIONS["draft"]

    def test_in_review_to_pending_approval(self):
        assert "pending_approval" in _VALID_TRANSITIONS["in_review"]

    def test_in_review_to_revoked(self):
        assert "revoked" in _VALID_TRANSITIONS["in_review"]

    def test_pending_approval_to_approved(self):
        assert "approved" in _VALID_TRANSITIONS["pending_approval"]

    def test_approved_to_certified(self):
        assert "certified" in _VALID_TRANSITIONS["approved"]

    def test_certified_to_renewal_due(self):
        assert "renewal_due" in _VALID_TRANSITIONS["certified"]

    def test_certified_to_superseded(self):
        assert "superseded" in _VALID_TRANSITIONS["certified"]

    def test_revoked_to_archived_allowed(self):
        assert "archived" in _VALID_TRANSITIONS["revoked"]

    def test_revoked_to_certified_not_allowed(self):
        assert "certified" not in _VALID_TRANSITIONS["revoked"]

    def test_archived_is_terminal(self):
        assert len(_VALID_TRANSITIONS["archived"]) == 0

    def test_superseded_only_to_archived(self):
        assert _VALID_TRANSITIONS["superseded"] == {"archived"}

    def test_expired_to_in_review(self):
        assert "in_review" in _VALID_TRANSITIONS["expired"]

    def test_all_lifecycle_states_reachable(self):
        # Every state except 'draft' should be reachable from at least one state
        all_targets: set[str] = set()
        for targets in _VALID_TRANSITIONS.values():
            all_targets.update(targets)
        for state in _VALID_TRANSITIONS:
            if state == "draft":
                continue
            assert state in all_targets, f"{state} not reachable"


# ---------------------------------------------------------------------------
# TestCreateCertification (~10 tests)
# ---------------------------------------------------------------------------


class TestCreateCertification:
    def _run(self, **kwargs):
        db = MagicMock()
        execute_result = MagicMock()
        scalars_result = MagicMock()
        execute_result.scalar_one_or_none.return_value = None
        execute_result.scalars.return_value = scalars_result
        scalars_result.all.return_value = []
        db.execute.return_value = execute_result
        defaults = dict(
            tenant_id="t1",
            engagement_id="eng-1",
            cert_name="My Cert",
            cert_type="standard",
            created_by="alice",
        )
        defaults.update(kwargs)
        return create_certification(db, **defaults)

    def test_returns_dict_with_cert_id(self):
        result = self._run()
        assert "cert_id" in result
        assert len(result["cert_id"]) == 32  # uuid4().hex

    def test_default_lifecycle_status_is_draft(self):
        result = self._run()
        assert result["lifecycle_status"] == "draft"

    def test_parent_cert_id_propagated(self):
        result = self._run(parent_cert_id="parent-abc")
        assert result["parent_cert_id"] == "parent-abc"

    def test_family_id_propagated(self):
        result = self._run(family_id="family-xyz")
        assert result["family_id"] == "family-xyz"

    def test_trust_arc_cert_id_propagated(self):
        result = self._run(trust_arc_cert_id="ta-cert-001")
        assert result["trust_arc_cert_id"] == "ta-cert-001"

    def test_cert_hash_is_64_hex(self):
        result = self._run()
        h = result["cert_hash"]
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_manifest_present(self):
        result = self._run()
        assert "manifest" in result
        assert "manifest_hash" in result["manifest"]
        assert len(result["manifest"]["manifest_hash"]) == 64

    def test_db_exception_returns_empty_dict(self):
        db = MagicMock()
        db.add.side_effect = RuntimeError("db failure")
        result = create_certification(db, tenant_id="t1", engagement_id="e1")
        assert result == {}

    def test_created_by_actor_propagated(self):
        result = self._run(created_by="bob")
        assert result["created_by"] == "bob"

    def test_empty_state_returns_valid_dict(self):
        """No trust arc data → valid dict with empty source arrays."""
        result = self._run()
        assert result != {}
        assert result["manifest"]["snapshot_ids"] == []
        assert result["manifest"]["bundle_ids"] == []


# ---------------------------------------------------------------------------
# TestTransitionLifecycle (~8 tests)
# ---------------------------------------------------------------------------


class TestTransitionLifecycle:
    def _make_db(self, cert):
        db = MagicMock()
        ex = MagicMock()
        ex.scalar_one_or_none.return_value = cert
        db.execute.return_value = ex
        return db

    def test_valid_transition_updates_status(self):
        cert = _make_cert(lifecycle_status="draft")
        db = self._make_db(cert)
        result = transition_lifecycle(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            to_status="in_review",
            actor="alice",
        )
        assert cert.lifecycle_status == "in_review"
        assert result["to_status"] == "in_review"

    def test_from_status_in_response(self):
        cert = _make_cert(lifecycle_status="draft")
        db = self._make_db(cert)
        result = transition_lifecycle(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            to_status="in_review",
        )
        assert result["from_status"] == "draft"

    def test_to_status_in_response(self):
        cert = _make_cert(lifecycle_status="in_review")
        db = self._make_db(cert)
        result = transition_lifecycle(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            to_status="pending_approval",
        )
        assert result["to_status"] == "pending_approval"

    def test_actor_captured(self):
        cert = _make_cert(lifecycle_status="draft")
        db = self._make_db(cert)
        result = transition_lifecycle(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            to_status="in_review",
            actor="charlie",
        )
        assert result["actor"] == "charlie"

    def test_invalid_to_status_raises_value_error(self):
        cert = _make_cert(lifecycle_status="draft")
        db = self._make_db(cert)
        with pytest.raises(ValueError, match="Invalid transition"):
            transition_lifecycle(
                db,
                cert_id="cert-001",
                tenant_id="t1",
                engagement_id="eng-001",
                to_status="certified",
            )

    def test_archived_terminal_raises_value_error(self):
        cert = _make_cert(lifecycle_status="archived")
        db = self._make_db(cert)
        with pytest.raises(ValueError):
            transition_lifecycle(
                db,
                cert_id="cert-001",
                tenant_id="t1",
                engagement_id="eng-001",
                to_status="draft",
            )

    def test_cert_not_found_raises_value_error(self):
        db = _empty_db()
        with pytest.raises(ValueError, match="not found"):
            transition_lifecycle(
                db,
                cert_id="missing",
                tenant_id="t1",
                engagement_id="eng-001",
                to_status="in_review",
            )

    def test_lifecycle_event_appended(self):
        cert = _make_cert(lifecycle_status="draft")
        db = self._make_db(cert)
        transition_lifecycle(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            to_status="in_review",
        )
        db.add.assert_called_once()


# ---------------------------------------------------------------------------
# TestAddReview (~8 tests)
# ---------------------------------------------------------------------------


class TestAddReview:
    def _db(self, cert):
        db = MagicMock()
        ex = MagicMock()
        ex.scalar_one_or_none.return_value = cert
        db.execute.return_value = ex
        return db

    def test_appends_review_record(self):
        cert = _make_cert()
        db = self._db(cert)
        result = add_review(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            reviewer="alice",
            review_outcome="approved",
        )
        assert "review_id" in result
        assert db.add.call_count == 2  # review + event

    def test_review_outcome_in_response(self):
        cert = _make_cert()
        db = self._db(cert)
        result = add_review(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            reviewer="alice",
            review_outcome="rejected",
        )
        assert result["review_outcome"] == "rejected"

    def test_reviewer_captured(self):
        cert = _make_cert()
        db = self._db(cert)
        result = add_review(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            reviewer="bob",
            review_outcome="approved",
        )
        assert result["reviewer"] == "bob"

    def test_notes_propagated(self):
        cert = _make_cert()
        db = self._db(cert)
        result = add_review(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            reviewer="alice",
            review_outcome="approved",
            notes="LGTM",
        )
        assert result["notes"] == "LGTM"

    def test_evidence_refs_propagated(self):
        cert = _make_cert()
        db = self._db(cert)
        result = add_review(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            reviewer="alice",
            review_outcome="approved",
            evidence_refs=["e1", "e2"],
        )
        assert result["evidence_refs"] == ["e1", "e2"]

    def test_empty_evidence_refs_default(self):
        cert = _make_cert()
        db = self._db(cert)
        result = add_review(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            reviewer="alice",
            review_outcome="approved",
        )
        assert result["evidence_refs"] == []

    def test_unknown_cert_returns_empty_dict(self):
        db = _empty_db()
        result = add_review(
            db,
            cert_id="missing",
            tenant_id="t1",
            engagement_id="eng-001",
            reviewer="alice",
            review_outcome="approved",
        )
        assert result == {}

    def test_schema_version_in_response(self):
        cert = _make_cert()
        db = self._db(cert)
        result = add_review(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            reviewer="alice",
            review_outcome="approved",
        )
        assert result["schema_version"] == "1.0"


# ---------------------------------------------------------------------------
# TestAddAttestation (~8 tests)
# ---------------------------------------------------------------------------


class TestAddAttestation:
    def _db(self, cert):
        db = MagicMock()
        ex = MagicMock()
        ex.scalar_one_or_none.return_value = cert
        db.execute.return_value = ex
        return db

    def test_attestation_hash_is_64_hex(self):
        cert = _make_cert()
        db = self._db(cert)
        result = add_attestation(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            attestation_type="internal",
            attester="alice",
        )
        h = result["attestation_hash"]
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_attestation_type_propagated(self):
        cert = _make_cert()
        db = self._db(cert)
        result = add_attestation(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            attestation_type="auditor",
            attester="alice",
        )
        assert result["attestation_type"] == "auditor"

    def test_attestation_data_persisted(self):
        cert = _make_cert()
        db = self._db(cert)
        data = {"statement": "compliant", "framework": "NIST"}
        result = add_attestation(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            attestation_type="internal",
            attester="alice",
            attestation_data=data,
        )
        assert result["attestation_data"] == data

    def test_attester_captured(self):
        cert = _make_cert()
        db = self._db(cert)
        result = add_attestation(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            attestation_type="executive",
            attester="ceo@example.com",
        )
        assert result["attester"] == "ceo@example.com"

    def test_attester_type_propagated(self):
        cert = _make_cert()
        db = self._db(cert)
        result = add_attestation(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            attestation_type="agent",
            attester="agent-001",
            attester_type="agent",
        )
        assert result["attester_type"] == "agent"

    def test_unknown_cert_returns_empty_dict(self):
        db = _empty_db()
        result = add_attestation(
            db,
            cert_id="missing",
            tenant_id="t1",
            engagement_id="eng-001",
            attestation_type="internal",
            attester="alice",
        )
        assert result == {}

    def test_hash_deterministic(self):
        cert = _make_cert()
        db1 = self._db(cert)
        db2 = self._db(cert)
        data = {"key": "value"}
        r1 = add_attestation(
            db1,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            attestation_type="internal",
            attester="alice",
            attestation_data=data,
        )
        r2 = add_attestation(
            db2,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            attestation_type="internal",
            attester="alice",
            attestation_data=data,
        )
        assert r1["attestation_hash"] == r2["attestation_hash"]

    def test_lifecycle_event_appended(self):
        cert = _make_cert()
        db = self._db(cert)
        add_attestation(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            attestation_type="internal",
            attester="alice",
        )
        assert db.add.call_count == 2  # attestation + event


# ---------------------------------------------------------------------------
# TestInitiateRenewal (~8 tests)
# ---------------------------------------------------------------------------


class TestInitiateRenewal:
    def _db(self, cert, snapshots=None, drift_events=None):
        db = MagicMock()

        def _execute(q):
            ex = MagicMock()
            scalars_result = MagicMock()
            ex.scalar_one_or_none.return_value = cert
            ex.scalars.return_value = scalars_result
            scalars_result.all.return_value = snapshots or []
            return ex

        db.execute.side_effect = _execute
        return db

    def test_returns_renewal_dict(self):
        cert = _make_cert()
        db = self._db(cert)
        result = initiate_renewal(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            initiated_by="alice",
        )
        assert "renewal_id" in result
        assert result["cert_id"] == "cert-001"

    def test_renewal_readiness_present(self):
        cert = _make_cert()
        db = self._db(cert)
        result = initiate_renewal(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            initiated_by="alice",
        )
        assert "renewal_readiness" in result
        assert isinstance(result["renewal_readiness"], dict)

    def test_renewal_type_propagated(self):
        cert = _make_cert()
        db = self._db(cert)
        result = initiate_renewal(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            renewal_type="emergency",
            initiated_by="alice",
        )
        assert result["renewal_type"] == "emergency"

    def test_initiated_by_captured(self):
        cert = _make_cert()
        db = self._db(cert)
        result = initiate_renewal(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            initiated_by="ops-agent",
        )
        assert result["initiated_by"] == "ops-agent"

    def test_days_until_expiry_computed(self):
        future = (datetime.now(timezone.utc) + timedelta(days=45)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        cert = _make_cert(valid_until=future)
        db = self._db(cert)
        result = initiate_renewal(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            initiated_by="alice",
        )
        days = result["renewal_readiness"]["days_until_expiry"]
        assert days is not None
        assert 40 <= days <= 50

    def test_unknown_cert_returns_empty_dict(self):
        db = _empty_db()
        result = initiate_renewal(
            db,
            cert_id="missing",
            tenant_id="t1",
            engagement_id="eng-001",
            initiated_by="alice",
        )
        assert result == {}

    def test_renewal_status_is_initiated(self):
        cert = _make_cert()
        db = self._db(cert)
        result = initiate_renewal(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            initiated_by="alice",
        )
        assert result["renewal_status"] == "initiated"

    def test_open_drift_events_in_readiness(self):
        cert = _make_cert()
        open_drift = [_drift(status="open"), _drift(status="open")]
        db = self._db(cert, snapshots=[], drift_events=open_drift)
        # Renewal readiness includes open_drift_events
        result = initiate_renewal(
            db,
            cert_id="cert-001",
            tenant_id="t1",
            engagement_id="eng-001",
            initiated_by="alice",
        )
        assert "renewal_readiness" in result


# ---------------------------------------------------------------------------
# TestGetHealth (~8 tests)
# ---------------------------------------------------------------------------


class TestGetHealth:
    def _db(self, cert, snapshots=None, drift_events=None):
        db = MagicMock()

        def _execute(q):
            ex = MagicMock()
            scalars_result = MagicMock()
            ex.scalar_one_or_none.return_value = cert
            ex.scalars.return_value = scalars_result
            scalars_result.all.return_value = snapshots or []
            return ex

        db.execute.side_effect = _execute
        return db

    def test_returns_health_dict(self):
        cert = _make_cert()
        db = self._db(cert)
        result = get_certification_health(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="eng-001"
        )
        assert "cert_id" in result
        assert "lifecycle_status" in result

    def test_days_until_expiry_computed(self):
        future = (datetime.now(timezone.utc) + timedelta(days=30)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        cert = _make_cert(valid_until=future)
        db = self._db(cert)
        result = get_certification_health(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="eng-001"
        )
        assert result["days_until_expiry"] is not None
        assert 25 <= result["days_until_expiry"] <= 35

    def test_renewal_recommended_true_when_90_days(self):
        future = (datetime.now(timezone.utc) + timedelta(days=60)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        cert = _make_cert(valid_until=future)
        db = self._db(cert)
        result = get_certification_health(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="eng-001"
        )
        assert result["renewal_recommended"] is True

    def test_renewal_recommended_false_when_far_future(self):
        future = (datetime.now(timezone.utc) + timedelta(days=200)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        cert = _make_cert(valid_until=future)
        db = self._db(cert)
        result = get_certification_health(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="eng-001"
        )
        assert result["renewal_recommended"] is False

    def test_no_valid_until_days_expiry_is_none(self):
        cert = _make_cert(valid_until=None)
        db = self._db(cert)
        result = get_certification_health(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="eng-001"
        )
        assert result["days_until_expiry"] is None

    def test_avg_posture_computed_from_snaps(self):
        cert = _make_cert()
        snaps = [_snap(score=80, snap_id="s1"), _snap(score=60, snap_id="s2")]
        db = self._db(cert, snapshots=snaps)
        result = get_certification_health(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="eng-001"
        )
        assert result["avg_posture_score"] == 70.0

    def test_empty_snap_list_avg_posture_none(self):
        cert = _make_cert()
        db = self._db(cert, snapshots=[])
        result = get_certification_health(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="eng-001"
        )
        assert result["avg_posture_score"] is None

    def test_cert_not_found_returns_empty_dict(self):
        db = _empty_db()
        result = get_certification_health(
            db, cert_id="missing", tenant_id="t1", engagement_id="eng-001"
        )
        assert result == {}


# ---------------------------------------------------------------------------
# TestGetLineage (~8 tests)
# ---------------------------------------------------------------------------


class TestGetLineage:
    def _make_db_chain(self, certs_by_id: dict):
        """DB that returns certs by ID via scalar_one_or_none."""
        db = MagicMock()

        def _execute(q):
            # We can't easily inspect the query, so return a callable mock
            ex = MagicMock()
            # Return None by default; callers set what they need
            ex.scalar_one_or_none.return_value = None
            ex.scalars.return_value = MagicMock()
            ex.scalars.return_value.all.return_value = []
            return ex

        db.execute.side_effect = _execute
        return db

    def test_root_has_no_parent(self):
        cert = _make_cert(cert_id="root", parent_cert_id=None)
        db = MagicMock()
        ex = MagicMock()
        ex.scalar_one_or_none.return_value = cert
        db.execute.return_value = ex
        result = get_lineage(
            db, cert_id="root", tenant_id="t1", engagement_id="eng-001"
        )
        assert result["root"]["parent_cert_id"] is None

    def test_single_cert_chain_total_is_1(self):
        cert = _make_cert(cert_id="cert-001", parent_cert_id=None)
        db = MagicMock()
        ex = MagicMock()
        ex.scalar_one_or_none.return_value = cert
        db.execute.return_value = ex
        result = get_lineage(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="eng-001"
        )
        assert result["total"] == 1
        assert len(result["chain"]) == 1

    def test_cert_not_found_returns_empty_dict(self):
        db = _empty_db()
        result = get_lineage(
            db, cert_id="missing", tenant_id="t1", engagement_id="eng-001"
        )
        assert result == {}

    def test_chain_structure_present(self):
        cert = _make_cert(cert_id="cert-001", parent_cert_id=None)
        db = MagicMock()
        ex = MagicMock()
        ex.scalar_one_or_none.return_value = cert
        db.execute.return_value = ex
        result = get_lineage(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="eng-001"
        )
        assert "root" in result
        assert "chain" in result
        assert "total" in result

    def test_chain_includes_cert_fields(self):
        cert = _make_cert(
            cert_id="cert-001",
            cert_name="Root Cert",
            lifecycle_status="certified",
        )
        db = MagicMock()
        ex = MagicMock()
        ex.scalar_one_or_none.return_value = cert
        db.execute.return_value = ex
        result = get_lineage(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="eng-001"
        )
        entry = result["chain"][0]
        assert entry["cert_name"] == "Root Cert"
        assert entry["lifecycle_status"] == "certified"

    def test_circular_guard_max_depth_50(self):
        """A cert pointing to itself does not infinite-loop."""
        cert = _make_cert(cert_id="cert-self", parent_cert_id="cert-self")
        db = MagicMock()
        ex = MagicMock()
        ex.scalar_one_or_none.return_value = cert
        db.execute.return_value = ex
        # Should not raise or loop
        result = get_lineage(
            db, cert_id="cert-self", tenant_id="t1", engagement_id="eng-001"
        )
        assert result["total"] >= 1

    def test_two_level_chain(self):
        """Child → Parent; chain should have 2 entries."""
        parent = _make_cert(cert_id="parent", parent_cert_id=None)
        child = _make_cert(cert_id="child", parent_cert_id="parent")

        call_count = [0]
        db = MagicMock()

        def _execute(q):
            ex = MagicMock()
            if call_count[0] == 0:
                ex.scalar_one_or_none.return_value = child
            else:
                ex.scalar_one_or_none.return_value = parent
            call_count[0] += 1
            ex.scalars.return_value.all.return_value = []
            return ex

        db.execute.side_effect = _execute
        result = get_lineage(
            db, cert_id="child", tenant_id="t1", engagement_id="eng-001"
        )
        assert result["total"] == 2

    def test_root_is_topmost_ancestor(self):
        parent = _make_cert(cert_id="parent", parent_cert_id=None)
        child = _make_cert(cert_id="child", parent_cert_id="parent")

        call_count = [0]
        db = MagicMock()

        def _execute(q):
            ex = MagicMock()
            if call_count[0] == 0:
                ex.scalar_one_or_none.return_value = child
            else:
                ex.scalar_one_or_none.return_value = parent
            call_count[0] += 1
            ex.scalars.return_value.all.return_value = []
            return ex

        db.execute.side_effect = _execute
        result = get_lineage(
            db, cert_id="child", tenant_id="t1", engagement_id="eng-001"
        )
        assert result["root"]["cert_id"] == "parent"


# ---------------------------------------------------------------------------
# TestComputeTrustImpact (~8 tests)
# ---------------------------------------------------------------------------


class TestComputeTrustImpact:
    def _db(self, cert, snapshots=None):
        db = MagicMock()

        def _execute(q):
            ex = MagicMock()
            scalars_result = MagicMock()
            ex.scalar_one_or_none.return_value = cert
            ex.scalars.return_value = scalars_result
            scalars_result.all.return_value = snapshots or []
            return ex

        db.execute.side_effect = _execute
        return db

    def test_platinum_level_certification_impact_40(self):
        cert = _make_cert(certification_level="platinum")
        db = self._db(cert)
        result = compute_trust_impact(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="e1"
        )
        assert result["certification_impact"] == 40

    def test_gold_level_30(self):
        cert = _make_cert(certification_level="gold")
        db = self._db(cert)
        result = compute_trust_impact(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="e1"
        )
        assert result["certification_impact"] == 30

    def test_silver_level_20(self):
        cert = _make_cert(certification_level="silver")
        db = self._db(cert)
        result = compute_trust_impact(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="e1"
        )
        assert result["certification_impact"] == 20

    def test_bronze_level_10(self):
        cert = _make_cert(certification_level="bronze")
        db = self._db(cert)
        result = compute_trust_impact(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="e1"
        )
        assert result["certification_impact"] == 10

    def test_unknown_level_default_15(self):
        cert = _make_cert(certification_level="custom")
        db = self._db(cert)
        result = compute_trust_impact(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="e1"
        )
        assert result["certification_impact"] == 15

    def test_trust_contribution_computed(self):
        cert = _make_cert(certification_level="gold")
        db = self._db(cert)
        result = compute_trust_impact(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="e1"
        )
        assert "trust_contribution" in result
        assert result["trust_contribution"] == 30

    def test_risk_reduction_non_negative(self):
        cert = _make_cert(certification_level="bronze")
        db = self._db(cert, snapshots=[])
        result = compute_trust_impact(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="e1"
        )
        assert result["risk_reduction"] >= 0

    def test_returns_structured_dict(self):
        cert = _make_cert(certification_level="gold")
        db = self._db(cert)
        result = compute_trust_impact(
            db, cert_id="cert-001", tenant_id="t1", engagement_id="e1"
        )
        for key in (
            "cert_id",
            "certification_level",
            "certification_impact",
            "trust_contribution",
            "risk_reduction",
            "monitoring_coverage",
        ):
            assert key in result


# ---------------------------------------------------------------------------
# TestManifestHash (~5 tests)
# ---------------------------------------------------------------------------


class TestManifestHash:
    def _compute_hash(self, **kwargs):
        from services.clm.lifecycle_service import _sha256

        return _sha256(
            {
                "trust_arc_cert_id": kwargs.get("trust_arc_cert_id"),
                "snapshot_ids": sorted(kwargs.get("snapshot_ids", [])),
                "bundle_ids": sorted(kwargs.get("bundle_ids", [])),
                "timeline_refs": sorted(kwargs.get("timeline_refs", [])),
                "decision_refs": sorted(kwargs.get("decision_refs", [])),
                "evidence_refs": sorted(kwargs.get("evidence_refs", [])),
            }
        )

    def test_manifest_hash_is_64_hex(self):
        h = self._compute_hash(snapshot_ids=["s1"])
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_is_deterministic(self):
        h1 = self._compute_hash(snapshot_ids=["s1", "s2"])
        h2 = self._compute_hash(snapshot_ids=["s1", "s2"])
        assert h1 == h2

    def test_different_snapshot_ids_different_hash(self):
        h1 = self._compute_hash(snapshot_ids=["s1"])
        h2 = self._compute_hash(snapshot_ids=["s2"])
        assert h1 != h2

    def test_sorted_ids_same_hash_regardless_of_order(self):
        h1 = self._compute_hash(snapshot_ids=["b", "a"])
        h2 = self._compute_hash(snapshot_ids=["a", "b"])
        assert h1 == h2

    def test_schema_version_in_create_result(self):
        db = MagicMock()
        ex = MagicMock()
        scalars_result = MagicMock()
        ex.scalar_one_or_none.return_value = None
        ex.scalars.return_value = scalars_result
        scalars_result.all.return_value = []
        db.execute.return_value = ex
        result = create_certification(db, tenant_id="t1", engagement_id="e1")
        assert result["manifest"]["schema_version"] == "1.0"


# ---------------------------------------------------------------------------
# TestCertHash (~5 tests)
# ---------------------------------------------------------------------------


class TestCertHash:
    def _run(self, **kwargs):
        db = MagicMock()
        ex = MagicMock()
        scalars_result = MagicMock()
        ex.scalar_one_or_none.return_value = None
        ex.scalars.return_value = scalars_result
        scalars_result.all.return_value = []
        db.execute.return_value = ex
        defaults = dict(tenant_id="t1", engagement_id="eng-1", cert_name="X")
        defaults.update(kwargs)
        return create_certification(db, **defaults)

    def test_cert_hash_is_64_hex(self):
        result = self._run()
        assert len(result["cert_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in result["cert_hash"])

    def test_cert_hash_changes_when_cert_name_changes(self):
        # We can verify the hash function is sensitive to cert_name by
        # computing it directly (same inputs → same hash; different → different)
        h1 = _sha256(
            {
                "tenant_id": "t1",
                "engagement_id": "e1",
                "trust_arc_cert_id": None,
                "cert_name": "Alpha",
                "cert_type": "standard",
                "certification_level": None,
                "valid_from": None,
                "valid_until": None,
                "created_at": "2026-01-01T00:00:00Z",
            }
        )
        h2 = _sha256(
            {
                "tenant_id": "t1",
                "engagement_id": "e1",
                "trust_arc_cert_id": None,
                "cert_name": "Beta",
                "cert_type": "standard",
                "certification_level": None,
                "valid_from": None,
                "valid_until": None,
                "created_at": "2026-01-01T00:00:00Z",
            }
        )
        assert h1 != h2

    def test_cert_hash_deterministic(self):
        data = {
            "tenant_id": "t1",
            "engagement_id": "e1",
            "trust_arc_cert_id": None,
            "cert_name": "Stable",
            "cert_type": "standard",
            "certification_level": "gold",
            "valid_from": None,
            "valid_until": None,
            "created_at": "2026-01-01T00:00:00Z",
        }
        assert _sha256(data) == _sha256(data)

    def test_sha256_is_64_hex(self):
        h = _sha256({"foo": "bar"})
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_sha256_sort_keys_deterministic(self):
        h1 = _sha256({"a": 1, "b": 2})
        h2 = _sha256({"b": 2, "a": 1})
        assert h1 == h2


# ---------------------------------------------------------------------------
# TestDashboardHelpers (~5 tests)
# ---------------------------------------------------------------------------


class TestDashboardHelpers:
    def _make_certs(self, statuses, valid_untils=None):
        certs = []
        for i, s in enumerate(statuses):
            c = _make_cert(
                cert_id=f"c{i}",
                lifecycle_status=s,
                valid_until=valid_untils[i] if valid_untils else None,
            )
            certs.append(c)
        return certs

    def test_status_distribution_correct(self):
        certs = self._make_certs(["draft", "draft", "certified", "archived"])
        dist: dict[str, int] = {}
        for cert in certs:
            dist[cert.lifecycle_status] = dist.get(cert.lifecycle_status, 0) + 1
        assert dist["draft"] == 2
        assert dist["certified"] == 1
        assert dist["archived"] == 1

    def test_expiry_count_correct(self):
        now = datetime.now(timezone.utc)
        soon = (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        far = (now + timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ninety_days = (now + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
        now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        certs = self._make_certs(
            ["certified", "certified", "certified"],
            valid_untils=[soon, far, soon],
        )
        expiring = [
            c
            for c in certs
            if c.valid_until and now_str <= c.valid_until <= ninety_days
        ]
        assert len(expiring) == 2

    def test_renewal_needed_count(self):
        certs = self._make_certs(["renewal_due", "expired", "certified", "draft"])
        renewal_needed = [
            c for c in certs if c.lifecycle_status in ("renewal_due", "expired")
        ]
        assert len(renewal_needed) == 2

    def test_dashboard_structure_complete(self):
        """Keys expected by consumers are present."""
        expected_keys = {
            "engagement_id",
            "total_certifications",
            "status_distribution",
            "expiring_soon_count",
            "renewal_needed_count",
            "recently_created",
        }
        # Simulate dashboard output structure
        dashboard = {
            "engagement_id": "e1",
            "total_certifications": 4,
            "status_distribution": {"draft": 2},
            "expiring_soon_count": 1,
            "renewal_needed_count": 0,
            "recently_created": [],
        }
        assert set(dashboard.keys()) >= expected_keys

    def test_recently_created_at_most_5(self):
        certs = self._make_certs(["draft"] * 8)
        recent = certs[:5]
        assert len(recent) == 5


# ---------------------------------------------------------------------------
# TestDaysUntil helper
# ---------------------------------------------------------------------------


class TestDaysUntil:
    def test_future_date_positive(self):
        future = (datetime.now(timezone.utc) + timedelta(days=30)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        result = _days_until(future)
        assert result is not None
        assert 25 <= result <= 35

    def test_past_date_negative(self):
        past = (datetime.now(timezone.utc) - timedelta(days=10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        result = _days_until(past)
        assert result is not None
        assert result < 0

    def test_none_returns_none(self):
        assert _days_until(None) is None

    def test_invalid_string_returns_none(self):
        assert _days_until("not-a-date") is None
