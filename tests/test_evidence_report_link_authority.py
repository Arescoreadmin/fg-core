"""Tests for PR 1.4 — Evidence-to-Report Link Authority.

Covers:
  Link Creation:
    - valid link with all fields
    - deterministic event_hash for identical inputs
    - authority fields persisted when key configured
    - unsigned link when key absent (legacy-compatible)
    - schema_version 1.1 when signed, 1.0 when unsigned

  Verification (verify_report_link):
    - valid link passes
    - tampered report_hash → hash_mismatch
    - tampered report_signature → hash_mismatch
    - tampered evidence_id → hash_mismatch
    - tampered signing_key_id → signature_mismatch
    - legacy unsigned link → legacy_unsigned (not failure)
    - not_found → not_found reason

  verify_link_signature:
    - verified status on signed link
    - legacy_unsigned on unsigned link (schema 1.0)
    - partial_authority_fields when signing_key_id set but signature None
    - missing_signature when schema 1.1 but all auth fields None
    - signature_mismatch on corrupted signature

  Security:
    - cross-tenant verify returns not_found
    - cross-tenant list returns empty
    - authority fields not client-controllable (create_report_link signature check)
    - create_report_link validates tenant safety

  Replay Integration:
    - verify_full_provenance_chain exposes linked_reports, verified_report_links,
      invalid_report_links, report_link_status
    - valid link appears in verified_report_links
    - tampered link appears in invalid_report_links
    - chain with no links has report_link_status="unlinked"
    - not_found chain has report_link_status="unlinked"

  List operations:
    - list_report_links_for_evidence
    - list_report_links_for_report
    - list_report_links_for_engagement

  Compatibility:
    - chain with no links → report_link_status="unlinked"
    - legacy unsigned link participates in replay (warning, not failure)

  Performance:
    - 1000 link verifications in <2 seconds (verify_report_links_bulk)
"""

from __future__ import annotations

import base64
import inspect
import time

import pytest
import sqlalchemy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEvidenceReportLink
from services.field_assessment.report_link_authority import (
    LINK_AUTHORITY_VERSION,
    LINK_VERSION,
    build_canonical_report_link_event,
    compute_link_event_hash,
    create_report_link,
    list_report_links_for_engagement,
    list_report_links_for_evidence,
    list_report_links_for_report,
    verify_link_signature,
    verify_report_link,
    verify_report_links_bulk,
)
from services.field_assessment.trust_replay import verify_full_provenance_chain

# ---------------------------------------------------------------------------
# Test key pair
# ---------------------------------------------------------------------------

_TEST_SEED = b"\xab" * 32
_TEST_PRIV = Ed25519PrivateKey.from_private_bytes(_TEST_SEED)
_TEST_PUB_BYTES = _TEST_PRIV.public_key().public_bytes_raw()
_TEST_KEY_B64 = base64.b64encode(_TEST_SEED).decode()

TENANT_A = "tenant-link-auth-001"
TENANT_B = "tenant-link-auth-002"
ENG_A = "eng-link-auth-001"
ENG_B = "eng-link-auth-002"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def signing_env(monkeypatch):
    monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_KEY_B64)
    yield


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_provenance(
    db, *, engagement_id=ENG_A, tenant_id=TENANT_A, artifact_hash=None
):
    from services.field_assessment.evidence_provenance import create_evidence_provenance

    return create_evidence_provenance(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type="scan",
        collected_by_type="system",
        collection_method="automated",
        artifact_hash=artifact_hash,
    )


def _make_link(
    db,
    *,
    tenant_id=TENANT_A,
    engagement_id=ENG_A,
    evidence_id="ev-001",
    report_id="rep-001",
    report_hash=None,
    report_signature=None,
    provenance_record_id=None,
    linked_by=None,
):
    return create_report_link(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        evidence_id=evidence_id,
        report_id=report_id,
        report_hash=report_hash,
        report_signature=report_signature,
        provenance_record_id=provenance_record_id,
        linked_by=linked_by,
    )


# ---------------------------------------------------------------------------
# Link Creation
# ---------------------------------------------------------------------------


def test_create_report_link_valid(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        link = _make_link(
            db,
            report_hash="a" * 64,
            report_signature="b" * 128,
            linked_by="assessor@example.com",
        )
        db.commit()

        assert link.id is not None
        assert link.tenant_id == TENANT_A
        assert link.engagement_id == ENG_A
        assert link.evidence_id == "ev-001"
        assert link.report_id == "rep-001"
        assert link.report_hash == "a" * 64
        assert link.event_hash is not None
        assert len(link.event_hash) == 64
        assert link.authority_version == LINK_AUTHORITY_VERSION
        assert link.link_version == LINK_VERSION
        assert link.linked_at is not None
        assert link.created_at is not None


def test_create_report_link_authority_fields_set(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        link = _make_link(db, report_hash="c" * 64)
        db.commit()

        stored = db.get(FaEvidenceReportLink, link.id)
        assert stored.signature is not None
        assert len(stored.signature) == 128
        assert stored.signing_key_id is not None
        assert len(stored.signing_key_id) == 16
        assert stored.signed_at is not None
        assert stored.schema_version == "1.1"


def test_create_report_link_unsigned_without_key(build_app, monkeypatch):
    from api.db import get_engine

    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    build_app()
    with Session(get_engine()) as db:
        link = _make_link(db)
        db.commit()

        stored = db.get(FaEvidenceReportLink, link.id)
        assert stored.signature is None
        assert stored.signing_key_id is None
        assert stored.schema_version == "1.0"


def test_create_report_link_deterministic_event_hash(build_app, signing_env):
    """Same logical link fields → same event_hash (modulo linked_at/created_at which are timestamps)."""
    build_app()
    from services.field_assessment.report_link_authority import _link_hash_payload

    kwargs = dict(
        tenant_id=TENANT_A,
        engagement_id=ENG_A,
        evidence_id="ev-det-001",
        provenance_record_id=None,
        report_id="rep-det-001",
        report_hash="d" * 64,
        report_signature=None,
        linked_at="2024-01-01T00:00:00Z",
        linked_by="user@example.com",
        previous_hash=None,
        created_at="2024-01-01T00:00:00Z",
    )
    assert compute_link_event_hash(
        _link_hash_payload(**kwargs)
    ) == compute_link_event_hash(_link_hash_payload(**kwargs))


def test_canonical_event_has_required_fields(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        link = _make_link(db, report_hash="e" * 64)
        db.commit()

        event = build_canonical_report_link_event(link)
        assert "event_hash" in event
        assert "evidence_id" in event
        assert "report_id" in event
        assert "report_hash" in event
        assert "report_signature" in event
        assert "tenant_id" in event
        assert "engagement_id" in event
        assert "signing_key_id" in event
        assert "authority_version" in event
        assert "link_version" in event
        assert event["authority_version"] == LINK_AUTHORITY_VERSION
        assert event["link_version"] == LINK_VERSION


def test_canonical_event_is_deterministic(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        link = _make_link(db, report_hash="f" * 64)
        db.commit()

        e1 = build_canonical_report_link_event(link)
        e2 = build_canonical_report_link_event(link)
        assert e1 == e2


# ---------------------------------------------------------------------------
# verify_report_link — DB-based verification
# ---------------------------------------------------------------------------


def test_verify_valid_link(build_app, signing_env):
    from api.db import get_engine

    build_app()
    link_id = None
    with Session(get_engine()) as db:
        link = _make_link(db, report_hash="g" * 64)
        db.commit()
        link_id = link.id

    with Session(get_engine()) as db2:
        result = verify_report_link(db2, link_id=link_id, tenant_id=TENANT_A)
        assert result["valid"] is True
        assert result["reason"] == "ok"
        assert result["signature_status"] == "verified"
        assert result["evidence_id"] == "ev-001"
        assert result["report_id"] == "rep-001"


def test_verify_link_not_found_returns_safe_result(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        result = verify_report_link(db, link_id="nonexistent-id", tenant_id=TENANT_A)
        assert result["valid"] is False
        assert result["reason"] == "not_found"


def test_verify_link_wrong_tenant_returns_not_found(build_app, signing_env):
    from api.db import get_engine

    build_app()
    link_id = None
    with Session(get_engine()) as db:
        link = _make_link(db, report_hash="h" * 64)
        db.commit()
        link_id = link.id

    with Session(get_engine()) as db2:
        result = verify_report_link(db2, link_id=link_id, tenant_id=TENANT_B)
        assert result["valid"] is False
        assert result["reason"] == "not_found"


def test_verify_tampered_report_hash_fails(build_app, signing_env):
    from api.db import get_engine

    build_app()
    link_id = None
    with Session(get_engine()) as db:
        link = _make_link(db, report_hash="i" * 64)
        db.commit()
        link_id = link.id

        db.execute(
            sqlalchemy.text(
                "UPDATE fa_evidence_report_links SET report_hash = :h WHERE id = :rid"
            ),
            {"h": "0" * 64, "rid": link_id},
        )
        db.commit()
        db.expire_all()

        result = verify_report_link(db, link_id=link_id, tenant_id=TENANT_A)
        assert result["valid"] is False
        assert result["reason"] == "hash_mismatch"


def test_verify_tampered_report_signature_fails(build_app, signing_env):
    from api.db import get_engine

    build_app()
    link_id = None
    with Session(get_engine()) as db:
        link = _make_link(db, report_hash="j" * 64, report_signature="k" * 128)
        db.commit()
        link_id = link.id

        db.execute(
            sqlalchemy.text(
                "UPDATE fa_evidence_report_links SET report_signature = :s WHERE id = :rid"
            ),
            {"s": "00" * 64, "rid": link_id},
        )
        db.commit()
        db.expire_all()

        result = verify_report_link(db, link_id=link_id, tenant_id=TENANT_A)
        assert result["valid"] is False
        assert result["reason"] == "hash_mismatch"


def test_verify_tampered_evidence_id_fails(build_app, signing_env):
    from api.db import get_engine

    build_app()
    link_id = None
    with Session(get_engine()) as db:
        link = _make_link(db, report_hash="l" * 64)
        db.commit()
        link_id = link.id

        db.execute(
            sqlalchemy.text(
                "UPDATE fa_evidence_report_links SET evidence_id = :e WHERE id = :rid"
            ),
            {"e": "ev-tampered", "rid": link_id},
        )
        db.commit()
        db.expire_all()

        result = verify_report_link(db, link_id=link_id, tenant_id=TENANT_A)
        assert result["valid"] is False
        assert result["reason"] == "hash_mismatch"


def test_verify_tampered_signing_key_id_fails(build_app, signing_env):
    """Stripping or changing signing_key_id changes the canonical event → signature_mismatch."""
    from api.db import get_engine

    build_app()
    link_id = None
    with Session(get_engine()) as db:
        link = _make_link(db, report_hash="m" * 64)
        db.commit()
        link_id = link.id

    with Session(get_engine()) as db2:
        stored = db2.get(FaEvidenceReportLink, link_id)
        # Strip signing_key_id in-session (no flush — SQLite has no append-only trigger)
        stored.signing_key_id = None

        result = verify_link_signature(stored)
        # signing_key_id=None with signature present → canonical changes → mismatch
        assert result["valid"] is False
        assert result["status"] == "invalid"


def test_verify_tampered_authority_version_fails(build_app, signing_env):
    """Changing authority_version changes the canonical event → signature_mismatch (P1.2 fix)."""
    from api.db import get_engine

    build_app()
    link_id = None
    with Session(get_engine()) as db:
        link = _make_link(db, report_hash="n" * 64)
        db.commit()
        link_id = link.id

    with Session(get_engine()) as db2:
        stored = db2.get(FaEvidenceReportLink, link_id)
        stored.authority_version = "evidence-report-authority-v99"

        result = verify_link_signature(stored)
        assert result["valid"] is False
        assert result["status"] == "invalid"
        assert result["reason"] == "signature_mismatch"


def test_verify_tampered_link_version_fails(build_app, signing_env):
    """Changing link_version changes the canonical event → signature_mismatch (P1.2 fix)."""
    from api.db import get_engine

    build_app()
    link_id = None
    with Session(get_engine()) as db:
        link = _make_link(db, report_hash="o" * 64)
        db.commit()
        link_id = link.id

    with Session(get_engine()) as db2:
        stored = db2.get(FaEvidenceReportLink, link_id)
        stored.link_version = "report-link-v99"

        result = verify_link_signature(stored)
        assert result["valid"] is False
        assert result["status"] == "invalid"
        assert result["reason"] == "signature_mismatch"


# ---------------------------------------------------------------------------
# verify_link_signature — unit tests
# ---------------------------------------------------------------------------


def test_verify_link_signature_legacy_unsigned(build_app, monkeypatch):
    from api.db import get_engine

    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    build_app()
    with Session(get_engine()) as db:
        link = _make_link(db)
        db.commit()

        stored = db.get(FaEvidenceReportLink, link.id)
        result = verify_link_signature(stored)
        assert result["valid"] is None
        assert result["status"] == "legacy_unsigned"
        assert result["reason"] == "no_signature"


def test_verify_link_signature_partial_strip_returns_invalid(build_app, signing_env):
    """signing_key_id present but signature=None → partial_authority_fields."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        link = _make_link(db, report_hash="n" * 64)
        db.commit()

        stored = db.get(FaEvidenceReportLink, link.id)
        stored.signature = None  # strip signature only

        result = verify_link_signature(stored)
        assert result["valid"] is False
        assert result["status"] == "invalid"
        assert result["reason"] == "partial_authority_fields"


def test_verify_link_signature_full_strip_schema_v11_invalid(build_app, signing_env):
    """schema_version=1.1 with all auth fields None → missing_signature."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        link = _make_link(db, report_hash="o" * 64)
        db.commit()

        stored = db.get(FaEvidenceReportLink, link.id)
        assert stored.schema_version == "1.1"
        stored.signature = None
        stored.signing_key_id = None
        stored.signed_at = None

        result = verify_link_signature(stored)
        assert result["valid"] is False
        assert result["status"] == "invalid"
        assert result["reason"] == "missing_signature"


def test_verify_link_signature_corrupted_bytes(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        link = _make_link(db, report_hash="p" * 64)
        db.commit()

        stored = db.get(FaEvidenceReportLink, link.id)
        stored.signature = "not-hex!!!"

        result = verify_link_signature(stored)
        assert result["valid"] is False
        assert result["reason"] == "signature_encoding_error"


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


def test_cross_tenant_list_returns_empty(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        _make_link(db, report_hash="q" * 64)
        db.commit()

        results = list_report_links_for_evidence(
            db,
            tenant_id=TENANT_B,
            engagement_id=ENG_A,
            evidence_id="ev-001",
        )
        assert results == []


def test_authority_fields_not_client_controllable():
    """create_report_link does not expose authority fields as arguments."""
    sig = inspect.signature(create_report_link)
    forbidden = {"signature", "signing_key_id", "signed_at", "signature_version"}
    exposed = forbidden & sig.parameters.keys()
    assert not exposed, f"Authority fields must not be caller-controllable: {exposed}"


def test_list_by_evidence_returns_only_matching_tenant(build_app, signing_env):
    """Links from a different tenant do not appear in list queries."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        # Create link for TENANT_A
        _make_link(db, tenant_id=TENANT_A, report_hash="r" * 64)
        # Create link for TENANT_B with same evidence_id
        _make_link(db, tenant_id=TENANT_B, report_hash="s" * 64)
        db.commit()

        results_a = list_report_links_for_evidence(
            db, tenant_id=TENANT_A, engagement_id=ENG_A, evidence_id="ev-001"
        )
        results_b = list_report_links_for_evidence(
            db, tenant_id=TENANT_B, engagement_id=ENG_A, evidence_id="ev-001"
        )
        assert len(results_a) >= 1
        assert len(results_b) >= 1
        assert all(r.tenant_id == TENANT_A for r in results_a)
        assert all(r.tenant_id == TENANT_B for r in results_b)


# ---------------------------------------------------------------------------
# List operations
# ---------------------------------------------------------------------------


def test_list_report_links_for_evidence(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        _make_link(db, evidence_id="ev-list-001", report_id="rep-L1")
        _make_link(db, evidence_id="ev-list-001", report_id="rep-L2")
        _make_link(db, evidence_id="ev-other-001", report_id="rep-L3")
        db.commit()

        results = list_report_links_for_evidence(
            db,
            tenant_id=TENANT_A,
            engagement_id=ENG_A,
            evidence_id="ev-list-001",
        )
        assert len(results) == 2
        assert all(r.evidence_id == "ev-list-001" for r in results)


def test_list_report_links_for_report(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        _make_link(db, evidence_id="ev-rep-001", report_id="rep-list-001")
        _make_link(db, evidence_id="ev-rep-002", report_id="rep-list-001")
        _make_link(db, evidence_id="ev-rep-003", report_id="rep-list-other")
        db.commit()

        results = list_report_links_for_report(
            db,
            tenant_id=TENANT_A,
            engagement_id=ENG_A,
            report_id="rep-list-001",
        )
        assert len(results) == 2
        assert all(r.report_id == "rep-list-001" for r in results)


def test_list_report_links_for_engagement(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        _make_link(
            db, engagement_id="eng-list-all", evidence_id="ev-A", report_id="rep-1"
        )
        _make_link(
            db, engagement_id="eng-list-all", evidence_id="ev-B", report_id="rep-2"
        )
        _make_link(db, engagement_id="eng-other", evidence_id="ev-C", report_id="rep-3")
        db.commit()

        results = list_report_links_for_engagement(
            db, tenant_id=TENANT_A, engagement_id="eng-list-all"
        )
        assert len(results) == 2
        assert all(r.engagement_id == "eng-list-all" for r in results)


# ---------------------------------------------------------------------------
# Replay Integration
# ---------------------------------------------------------------------------


def test_verify_full_chain_exposes_link_fields(build_app, signing_env):
    """verify_full_provenance_chain result includes PR 1.4 report link fields."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        prov = _make_provenance(
            db, engagement_id="eng-replay-link-001", artifact_hash="A" * 64
        )
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=prov.id
        )
        assert "linked_reports" in result
        assert "verified_report_links" in result
        assert "invalid_report_links" in result
        assert "report_link_status" in result


def test_verify_full_chain_no_links_is_unlinked(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        prov = _make_provenance(
            db, engagement_id="eng-unlinked-001", artifact_hash="B" * 64
        )
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=prov.id
        )
        assert result["linked_reports"] == []
        assert result["verified_report_links"] == []
        assert result["invalid_report_links"] == []
        assert result["report_link_status"] == "unlinked"


def test_verify_full_chain_valid_link_in_verified(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        prov = _make_provenance(
            db, engagement_id="eng-chain-valid-link", artifact_hash="C" * 64
        )
        db.commit()
        _make_link(
            db,
            engagement_id="eng-chain-valid-link",
            evidence_id="ev-chain-001",
            report_id="rep-chain-001",
            report_hash="D" * 64,
        )
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=prov.id
        )
        assert len(result["verified_report_links"]) == 1
        assert result["invalid_report_links"] == []
        assert result["report_link_status"] == "verified"
        assert result["linked_reports"][0]["report_id"] == "rep-chain-001"
        assert result["linked_reports"][0]["verified_count"] == 1


def test_verify_full_chain_tampered_link_in_invalid(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        prov = _make_provenance(
            db, engagement_id="eng-chain-bad-link", artifact_hash="E" * 64
        )
        db.commit()
        link = _make_link(
            db,
            engagement_id="eng-chain-bad-link",
            evidence_id="ev-chain-bad",
            report_id="rep-chain-bad",
            report_hash="F" * 64,
        )
        db.commit()
        link_id = link.id

        db.execute(
            sqlalchemy.text(
                "UPDATE fa_evidence_report_links SET report_hash = :h WHERE id = :rid"
            ),
            {"h": "0" * 64, "rid": link_id},
        )
        db.commit()
        db.expire_all()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=prov.id
        )
        assert len(result["invalid_report_links"]) == 1
        assert result["verified_report_links"] == []
        assert result["report_link_status"] == "invalid"
        assert result["invalid_report_links"][0]["reason"] == "hash_mismatch"


def test_verify_full_chain_mixed_links_partially_verified(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        prov = _make_provenance(
            db, engagement_id="eng-chain-mixed-links", artifact_hash="G" * 64
        )
        db.commit()
        # Good link
        _make_link(
            db,
            engagement_id="eng-chain-mixed-links",
            evidence_id="ev-good",
            report_id="rep-good",
            report_hash="H" * 64,
        )
        # Bad link (will tamper)
        bad_link = _make_link(
            db,
            engagement_id="eng-chain-mixed-links",
            evidence_id="ev-bad",
            report_id="rep-bad",
            report_hash="I" * 64,
        )
        db.commit()
        bad_link_id = bad_link.id

        db.execute(
            sqlalchemy.text(
                "UPDATE fa_evidence_report_links SET report_hash = :h WHERE id = :rid"
            ),
            {"h": "0" * 64, "rid": bad_link_id},
        )
        db.commit()
        db.expire_all()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=prov.id
        )
        assert len(result["verified_report_links"]) == 1
        assert len(result["invalid_report_links"]) == 1
        assert result["report_link_status"] == "partially_verified"


def test_not_found_chain_has_empty_link_fields(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id="nonexistent-prov-id"
        )
        assert result["linked_reports"] == []
        assert result["verified_report_links"] == []
        assert result["invalid_report_links"] == []
        assert result["report_link_status"] == "unlinked"


# ---------------------------------------------------------------------------
# Compatibility
# ---------------------------------------------------------------------------


def test_legacy_unsigned_link_in_replay_is_warning_not_failure(build_app, monkeypatch):
    """Legacy unsigned link → appears in verified_report_links with signature_valid=None."""
    from api.db import get_engine

    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    build_app()
    with Session(get_engine()) as db:
        prov = _make_provenance(
            db, engagement_id="eng-compat-legacy-link", artifact_hash="J" * 64
        )
        db.commit()
        _make_link(
            db,
            engagement_id="eng-compat-legacy-link",
            evidence_id="ev-compat-001",
            report_id="rep-compat-001",
        )
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=prov.id
        )
        # Legacy unsigned link is not a hard failure — it's in verified_report_links
        # with signature_valid=None (legacy_unsigned warning, not invalid)
        assert len(result["invalid_report_links"]) == 0
        assert len(result["verified_report_links"]) == 1
        assert result["verified_report_links"][0]["signature_valid"] is None
        assert (
            result["verified_report_links"][0]["signature_status"] == "legacy_unsigned"
        )


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------


def test_1000_link_verifications_under_2s(build_app, signing_env):
    """Bulk verification of 1000 links completes in <2 seconds."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        links = []
        for i in range(1000):
            link = _make_link(
                db,
                engagement_id=f"eng-perf-{i // 100}",
                evidence_id=f"ev-perf-{i}",
                report_id=f"rep-perf-{i % 10}",
                report_hash=("a" * 63 + str(i % 10)),
            )
            links.append(link)
        db.commit()

        # Re-fetch to ensure clean ORM state
        for link in links:
            db.refresh(link)

        t0 = time.monotonic()
        verified, invalid = verify_report_links_bulk(links)
        elapsed_ms = (time.monotonic() - t0) * 1000

        assert len(verified) == 1000
        assert len(invalid) == 0
        assert elapsed_ms < 2000, (
            f"1000 link verifications took {elapsed_ms:.0f}ms, expected <2000ms"
        )
