"""Tests for PR 1.3 — Evidence Authority Foundation.

Covers:
  Authority Signing:
    - sign_provenance_event: returns required fields
    - verify_provenance_signature: valid record passes
    - build_canonical_provenance_event: deterministic payload
    - sign_new_provenance_event: pre-creation signing path

  Authority Failure:
    - tampered payload → signature_mismatch
    - tampered signature → signature_mismatch
    - wrong public key → key_id_mismatch
    - corrupted signature encoding → signature_encoding_error

  Persistence:
    - authority fields persisted on create_evidence_provenance
    - authority fields persisted on mark_provenance_reviewed
    - all 5 columns stored correctly

  Replay Integration:
    - signed node verified in verify_full_provenance_chain
    - legacy unsigned node → warning (not failure)
    - invalid signature → hard failure
    - SCORE_DEGRADED for all-legacy-unsigned chain
    - SCORE_BROKEN for any invalid signature
    - SCORE_PERFECT for all signed chain
    - signature info in verified_nodes per-node

  Security:
    - private key never in record
    - client cannot supply authority fields through create_evidence_provenance args
    - cross-tenant contamination already covered by hash chain tests

  Compatibility:
    - legacy records (no signature) work without errors
    - not_found path unaffected

  Performance:
    - 100-node signed chain verifies in <150ms
"""

from __future__ import annotations

import base64
import time

import pytest
import sqlalchemy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEvidenceProvenance
from services.field_assessment.evidence_authority import (
    AUTHORITY_VERSION,
    SIGNATURE_VERSION,
    EvidenceAuthorityError,
    build_canonical_provenance_event,
    get_signing_key_id,
    sign_new_provenance_event,
    sign_provenance_event,
    verify_provenance_signature,
)
from services.field_assessment.trust_replay import (
    SCORE_BROKEN,
    SCORE_DEGRADED,
    SCORE_PERFECT,
    SCORE_WARNINGS,
    compute_chain_replay_score,
    verify_full_provenance_chain,
)

# ---------------------------------------------------------------------------
# Test key pair — deterministic 32-byte seed for all tests
# ---------------------------------------------------------------------------

_TEST_SEED = b"\xab" * 32
_TEST_PRIV = Ed25519PrivateKey.from_private_bytes(_TEST_SEED)
_TEST_PUB_BYTES = _TEST_PRIV.public_key().public_bytes_raw()
_TEST_KEY_B64 = base64.b64encode(_TEST_SEED).decode()

# Different key for wrong-key tests
_ALT_SEED = b"\xcd" * 32
_ALT_KEY_B64 = base64.b64encode(_ALT_SEED).decode()

TENANT_A = "tenant-authority-001"
TENANT_B = "tenant-authority-002"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def signing_env(monkeypatch):
    """Set FG_EVIDENCE_SIGNING_KEY_B64 for the test."""
    monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_KEY_B64)
    yield


@pytest.fixture()
def alt_signing_env(monkeypatch):
    """Set the alternative (wrong) key."""
    monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _ALT_KEY_B64)
    yield


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_provenance(db, *, engagement_id, artifact_hash=None, tenant_id=TENANT_A):
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


def _extend_chain(db, prior, *, steps=1):
    from services.field_assessment.evidence_provenance import mark_provenance_reviewed

    current = prior
    for _ in range(steps):
        current = mark_provenance_reviewed(
            db,
            tenant_id=current.tenant_id,
            provenance_id=current.id,
            reviewed_by="analyst@example.com",
            new_status="approved",
        )
    return current


# ---------------------------------------------------------------------------
# build_canonical_provenance_event — determinism
# ---------------------------------------------------------------------------


def test_canonical_event_has_required_fields(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-canon-001")
        db.commit()

        event = build_canonical_provenance_event(record)
        assert "event_hash" in event
        assert "previous_hash" in event
        assert "tenant_id" in event
        assert "engagement_id" in event
        assert "evidence_id" in event
        assert "finding_id" in event
        assert "source_type" in event
        assert "collected_at" in event
        assert "authority_version" in event
        assert "signature_version" in event
        assert event["authority_version"] == AUTHORITY_VERSION
        assert event["signature_version"] == SIGNATURE_VERSION
        # P1.1: signing_key_id in canonical so stripping it invalidates the signature
        assert "signing_key_id" in event
        # P1.2: decision fields covered by signature
        assert "review_status" in event
        assert "reviewed_by" in event
        assert "trust_level" in event


def test_canonical_event_deterministic(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-canon-det-001")
        db.commit()

        e1 = build_canonical_provenance_event(record)
        e2 = build_canonical_provenance_event(record)
        assert e1 == e2


def test_canonical_event_excludes_ephemeral_fields(build_app, signing_env):
    """Timestamps, IDs, and report linkage must not appear in canonical event.

    Note: review_status, reviewed_by, trust_level ARE intentionally included
    (P1.2 fix — decision fields must be covered by signature to prevent tampering).
    """
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-canon-excl-001")
        db.commit()

        event = build_canonical_provenance_event(record)
        excluded_fields = {
            "reviewed_at",
            "used_in_report_ids",
            "id",
            "created_at",
            "schema_version",
        }
        assert not (excluded_fields & event.keys()), (
            f"Ephemeral fields must not appear in canonical event: {excluded_fields & event.keys()}"
        )


# ---------------------------------------------------------------------------
# sign_provenance_event — signing
# ---------------------------------------------------------------------------


def test_sign_provenance_event_returns_required_fields(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-sign-001")
        db.commit()

        result = sign_provenance_event(record)
        assert "signature" in result
        assert "signing_key_id" in result
        assert "signed_at" in result
        assert "signature_version" in result
        assert "authority_version" in result
        assert result["signature_version"] == SIGNATURE_VERSION
        assert result["authority_version"] == AUTHORITY_VERSION
        assert isinstance(result["signature"], str)
        assert len(result["signature"]) == 128  # 64 bytes hex


def test_sign_provenance_event_deterministic_signature(build_app, signing_env):
    """Two calls on the same record produce the same signature (Ed25519 is deterministic)."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-sign-det-001")
        db.commit()

        r1 = sign_provenance_event(record)
        r2 = sign_provenance_event(record)
        assert r1["signature"] == r2["signature"]
        assert r1["signing_key_id"] == r2["signing_key_id"]


def test_sign_provenance_event_raises_without_key(build_app, monkeypatch):
    from api.db import get_engine

    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-sign-nokey-001")
        db.commit()

        with pytest.raises(EvidenceAuthorityError):
            sign_provenance_event(record)


def test_sign_new_provenance_event_matches_sign_provenance_event(
    build_app, signing_env
):
    """sign_new_provenance_event and sign_provenance_event produce identical signatures."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-sign-new-001")
        db.commit()

        sig_from_record = sign_provenance_event(record)
        sig_from_fields = sign_new_provenance_event(
            event_hash=record.event_hash,
            previous_hash=record.previous_hash,
            tenant_id=record.tenant_id,
            engagement_id=record.engagement_id,
            evidence_id=record.evidence_id,
            finding_id=record.finding_id,
            source_type=record.source_type,
            collected_at=record.collected_at,
            review_status=record.review_status or "pending",
            reviewed_by=record.reviewed_by,
            trust_level=record.trust_level or "unverified",
        )
        assert sig_from_record["signature"] == sig_from_fields["signature"]
        assert sig_from_record["signing_key_id"] == sig_from_fields["signing_key_id"]


# ---------------------------------------------------------------------------
# verify_provenance_signature — verification
# ---------------------------------------------------------------------------


def test_verify_valid_signature(build_app, signing_env):
    """Record created with key set is auto-signed; verify_provenance_signature passes."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-verify-ok-001", artifact_hash="a" * 64
        )
        db.commit()

        # create_evidence_provenance auto-signed via signing_env fixture
        assert record.signature is not None
        result = verify_provenance_signature(record)
        assert result["valid"] is True
        assert result["status"] == "verified"
        assert result["reason"] == "ok"
        assert result["authority_version"] == AUTHORITY_VERSION


def test_verify_legacy_unsigned_returns_warning(build_app, monkeypatch):
    """Record with no signature → legacy_unsigned (warning, not failure)."""
    from api.db import get_engine

    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-legacy-001")
        db.commit()

        assert record.signature is None
        result = verify_provenance_signature(record)
        assert result["valid"] is None
        assert result["status"] == "legacy_unsigned"
        assert result["reason"] == "no_signature"


def test_verify_tampered_payload_fails(signing_env):
    """Changing a canonical field after signing invalidates the signature.

    Uses an in-memory record — no DB required for this unit test.
    """
    # Build a signed record in memory (no DB flush needed to test verify logic)
    record = FaEvidenceProvenance(
        id="test-id-tamper-payload",
        tenant_id=TENANT_A,
        engagement_id="eng-tamper-payload-001",
        source_type="scan",
        collected_at="2024-01-01T00:00:00Z",
        collection_method="automated",
        collected_by_type="system",
        event_hash="a" * 64,
        previous_hash=None,
        created_at="2024-01-01T00:00:00Z",
        schema_version="1.0",
        review_status="pending",
        trust_level="unverified",
        chain_status="active",
        used_in_report_ids=[],
        collection_context_json={},
    )
    sig_fields = sign_provenance_event(record)
    record.signature = sig_fields["signature"]
    record.signing_key_id = sig_fields["signing_key_id"]
    record.signature_version = sig_fields["signature_version"]
    record.authority_version = sig_fields["authority_version"]

    # Tamper a canonical field
    record.source_type = "tampered_source"

    result = verify_provenance_signature(record)
    assert result["valid"] is False
    assert result["status"] == "invalid"
    assert result["reason"] == "signature_mismatch"


def test_verify_tampered_signature_fails(signing_env):
    """Corrupting the signature bytes fails verification.

    Uses an in-memory record — no DB required for this unit test.
    """
    record = FaEvidenceProvenance(
        id="test-id-tamper-sig",
        tenant_id=TENANT_A,
        engagement_id="eng-tamper-sig-001",
        source_type="scan",
        collected_at="2024-01-01T00:00:00Z",
        collection_method="automated",
        collected_by_type="system",
        event_hash="b" * 64,
        previous_hash=None,
        created_at="2024-01-01T00:00:00Z",
        schema_version="1.0",
        review_status="pending",
        trust_level="unverified",
        chain_status="active",
        used_in_report_ids=[],
        collection_context_json={},
    )
    sig_fields = sign_provenance_event(record)
    corrupted = bytearray(bytes.fromhex(sig_fields["signature"]))
    corrupted[0] ^= 0xFF
    record.signature = corrupted.hex()
    record.signing_key_id = sig_fields["signing_key_id"]
    record.signature_version = sig_fields["signature_version"]
    record.authority_version = sig_fields["authority_version"]

    result = verify_provenance_signature(record)
    assert result["valid"] is False
    assert result["status"] == "invalid"
    assert result["reason"] == "signature_mismatch"


def test_verify_wrong_key_fails(build_app, signing_env, monkeypatch):
    """Signature created with key A cannot be verified with key B."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        # Record auto-signed with test key via signing_env
        record = _make_provenance(
            db, engagement_id="eng-wrong-key-001", artifact_hash="d" * 64
        )
        db.commit()

        # Verify still passes with original key
        assert verify_provenance_signature(record)["valid"] is True

        # Switch to alt key for verification — stored key_id won't match
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _ALT_KEY_B64)

        result = verify_provenance_signature(record)
        assert result["valid"] is False
        assert result["status"] == "invalid"


def test_verify_corrupted_signature_encoding_fails(build_app, signing_env):
    """Non-hex signature string returns encoding error, not crash."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-corrupt-enc-001")
        db.commit()

        # Corrupt signature in Python memory (no flush) — SQLite test DB has no
        # append-only trigger for fa_evidence_provenance (Postgres-only).
        # We modify the in-session object to avoid DetachedInstanceError.
        stored = db.get(FaEvidenceProvenance, record.id)
        stored.signature = "not-valid-hex!!!"
        # signing_key_id stays correct so code reaches the encoding check

        result = verify_provenance_signature(stored)
        assert result["valid"] is False
        assert result["reason"] == "signature_encoding_error"


# ---------------------------------------------------------------------------
# Persistence — authority fields stored in DB on creation
# ---------------------------------------------------------------------------


def test_authority_fields_persisted_on_create(build_app, signing_env):
    """All 5 authority columns are written by create_evidence_provenance."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-persist-001", artifact_hash="e" * 64
        )
        db.commit()

        stored = db.get(FaEvidenceProvenance, record.id)
        assert stored.signature is not None
        assert stored.signing_key_id is not None
        assert stored.signed_at is not None
        assert stored.signature_version == SIGNATURE_VERSION
        assert stored.authority_version == AUTHORITY_VERSION
        assert len(stored.signature) == 128  # 64-byte signature as hex


def test_authority_fields_verify_after_persist(build_app, signing_env):
    """Signature stored in DB passes verification after a round-trip."""
    from api.db import get_engine

    build_app()
    record_id = None
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-persist-verify-001", artifact_hash="f" * 64
        )
        db.commit()
        record_id = record.id  # capture before session closes

    with Session(get_engine()) as db2:
        stored = db2.get(FaEvidenceProvenance, record_id)
        result = verify_provenance_signature(stored)
        assert result["valid"] is True
        assert result["status"] == "verified"


def test_authority_fields_persisted_on_reviewed_record(build_app, signing_env):
    """mark_provenance_reviewed creates a new signed record."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        genesis = _make_provenance(
            db, engagement_id="eng-review-persist-001", artifact_hash="g" * 64
        )
        db.commit()
        reviewed = _extend_chain(db, genesis)
        db.commit()

        stored = db.get(FaEvidenceProvenance, reviewed.id)
        assert stored.signature is not None
        assert stored.signing_key_id is not None
        assert stored.authority_version == AUTHORITY_VERSION


def test_authority_key_id_is_public_key_fingerprint(build_app, signing_env):
    """signing_key_id == SHA256(public_key_bytes)[:16]."""
    import hashlib

    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-key-id-001", artifact_hash="h" * 64
        )
        db.commit()

        expected_key_id = hashlib.sha256(_TEST_PUB_BYTES).hexdigest()[:16]
        assert record.signing_key_id == expected_key_id


def test_authority_fields_absent_without_signing_key(build_app, monkeypatch):
    """Without signing key in dev/test, record is created unsigned (legacy-compatible)."""
    from api.db import get_engine

    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-no-key-001")
        db.commit()

        assert record.signature is None
        assert record.signing_key_id is None
        assert record.authority_version is None


# ---------------------------------------------------------------------------
# Replay Integration
# ---------------------------------------------------------------------------


def test_verify_full_chain_signed_node_verified(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-replay-signed-001", artifact_hash="i" * 64
        )
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        assert result["chain_valid"] is True
        assert len(result["verified_nodes"]) == 1
        node = result["verified_nodes"][0]
        assert node["signature_valid"] is True
        assert node["signature_status"] == "verified"
        assert node["authority_version"] == AUTHORITY_VERSION


def test_verify_full_chain_legacy_node_warning(build_app, monkeypatch):
    """Legacy unsigned node → warning, chain_valid=True, SCORE_DEGRADED."""
    from api.db import get_engine

    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-replay-legacy-001", artifact_hash="j" * 64
        )
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        assert result["chain_valid"] is True  # warning, not failure
        assert any("legacy_unsigned" in w for w in result["warnings"])
        assert result["chain_replay_score"] == SCORE_DEGRADED

        node = result["verified_nodes"][0]
        assert node["signature_valid"] is None
        assert node["signature_status"] == "legacy_unsigned"


def test_verify_full_chain_invalid_signature_failure(build_app, signing_env):
    """Tampered signature → hard failure, chain_valid=False, SCORE_BROKEN."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-replay-invalid-sig-001", artifact_hash="k" * 64
        )
        db.commit()

        record_id = record.id

        # Corrupt via SQL (SQLite test DB has no append-only trigger for this table)
        db.execute(
            sqlalchemy.text(
                "UPDATE fa_evidence_provenance SET signature = :bad WHERE id = :rid"
            ),
            {"bad": "00" * 64, "rid": record_id},
        )
        db.commit()
        db.expire_all()  # force reload so verify sees the corrupted value

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record_id
        )
        assert result["chain_valid"] is False
        assert result["chain_replay_score"] == SCORE_BROKEN
        assert any(f["reason"] == "invalid_signature" for f in result["failed_nodes"])


def test_verify_full_chain_mixed_signed_and_legacy(build_app, signing_env, monkeypatch):
    """Chain with a mix of signed and legacy nodes: all-legacy-unsigned → SCORE_DEGRADED."""
    from api.db import get_engine

    # Create genesis without key → legacy
    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    build_app()
    genesis_id = None
    with Session(get_engine()) as db:
        genesis = _make_provenance(
            db,
            engagement_id="eng-mixed-chain-001",
            artifact_hash="l" * 64,
        )
        db.commit()
        genesis_id = genesis.id  # capture before session closes

    # Extend with key → signed (load genesis fresh in new session)
    monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_KEY_B64)
    with Session(get_engine()) as db:
        genesis_in_session = db.get(FaEvidenceProvenance, genesis_id)
        latest = _extend_chain(db, genesis_in_session)
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=latest.id
        )
        # One signed, one legacy → not all-legacy, so SCORE_WARNINGS (or better)
        # The signed node passes; the legacy one gets a warning
        legacy_warnings = [w for w in result["warnings"] if "legacy_unsigned" in w]
        assert len(legacy_warnings) == 1
        # Mixed chain: has a legacy_unsigned warning AND possibly other warnings
        # Since only legacy_unsigned warning, SCORE_DEGRADED applies
        assert result["chain_replay_score"] == SCORE_DEGRADED


def test_verify_full_chain_all_signed_score_perfect(build_app, signing_env):
    """All signed nodes with artifact_hash → SCORE_PERFECT."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        genesis = _make_provenance(
            db, engagement_id="eng-all-signed-001", artifact_hash="m" * 64
        )
        db.commit()
        latest = _extend_chain(db, genesis, steps=2)
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=latest.id
        )
        assert result["chain_valid"] is True
        assert result["chain_replay_score"] == SCORE_PERFECT
        assert result["warnings"] == []
        for node in result["verified_nodes"]:
            assert node["signature_valid"] is True


def test_verify_full_chain_signed_no_artifact_hash_score_warnings(
    build_app, signing_env
):
    """Signed node with no artifact_hash → no_artifact_hash warning → SCORE_WARNINGS."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db,
            engagement_id="eng-signed-noartifact-001",
            # no artifact_hash → soft warning
        )
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        assert result["chain_valid"] is True
        assert result["chain_replay_score"] == SCORE_WARNINGS
        assert any("no_artifact_hash" in w for w in result["warnings"])


# ---------------------------------------------------------------------------
# compute_chain_replay_score — SCORE_DEGRADED activation
# ---------------------------------------------------------------------------


def test_score_degraded_when_only_legacy_unsigned_warnings():
    """SCORE_DEGRADED when all warnings are :legacy_unsigned."""
    node = {"node_id": "n1", "event_hash": "a" * 64, "previous_hash": None}
    warnings = ["node:n1:legacy_unsigned", "node:n2:legacy_unsigned"]
    assert compute_chain_replay_score([node], [], warnings) == SCORE_DEGRADED


def test_score_warnings_when_mixed_warnings():
    """SCORE_WARNINGS when warnings include non-legacy entries."""
    node = {"node_id": "n1", "event_hash": "a" * 64, "previous_hash": None}
    warnings = ["node:n1:legacy_unsigned", "node:n2:no_artifact_hash"]
    assert compute_chain_replay_score([node], [], warnings) == SCORE_WARNINGS


def test_score_perfect_when_signed_and_no_warnings():
    node = {"node_id": "n1", "event_hash": "a" * 64, "previous_hash": None}
    assert compute_chain_replay_score([node], [], []) == SCORE_PERFECT


def test_score_broken_when_failed_nodes():
    failed = [{"node_id": "n1", "reason": "invalid_signature"}]
    assert compute_chain_replay_score([], failed, []) == SCORE_BROKEN


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


def test_private_key_not_in_record(build_app, signing_env):
    """No signing key material in any record column."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-sec-privkey-001", artifact_hash="n" * 64
        )
        db.commit()

        stored = db.get(FaEvidenceProvenance, record.id)
        all_text = " ".join(
            str(v)
            for v in [
                stored.signature,
                stored.signing_key_id,
                stored.signed_at,
                stored.signature_version,
                stored.authority_version,
            ]
            if v is not None
        )
        assert _TEST_KEY_B64 not in all_text
        assert base64.b64decode(_TEST_KEY_B64).hex() not in all_text


def test_authority_metadata_cannot_be_client_supplied(build_app, signing_env):
    """create_evidence_provenance does not accept authority fields as arguments.

    Authority fields are set by the service — not by callers.
    This test verifies the function signature does not expose them.
    """
    import inspect

    from services.field_assessment.evidence_provenance import create_evidence_provenance

    sig = inspect.signature(create_evidence_provenance)
    authority_params = {
        "signature",
        "signing_key_id",
        "signed_at",
        "signature_version",
        "authority_version",
    }
    exposed = authority_params & sig.parameters.keys()
    assert not exposed, f"Authority fields must not be caller-controllable: {exposed}"


# ---------------------------------------------------------------------------
# Compatibility — legacy records
# ---------------------------------------------------------------------------


def test_legacy_record_verify_full_chain_works(build_app, monkeypatch):
    """Legacy record (no authority key) completes chain verification without error."""
    from api.db import get_engine

    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-compat-001", artifact_hash="o" * 64
        )
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        assert "chain_valid" in result
        assert "verified_nodes" in result
        assert "warnings" in result


def test_verify_provenance_signature_on_null_signature(build_app, monkeypatch):
    """verify_provenance_signature on a null-signature record never raises."""
    from api.db import get_engine

    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-null-sig-001")
        db.commit()

        result = verify_provenance_signature(record)
        assert result["status"] == "legacy_unsigned"
        assert result["valid"] is None


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------


def test_100_node_signed_chain_under_150ms(build_app, signing_env):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        genesis = _make_provenance(
            db, engagement_id="eng-perf-signed-001", artifact_hash="p" * 64
        )
        db.commit()
        latest = _extend_chain(db, genesis, steps=99)
        db.commit()

        t0 = time.monotonic()
        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=latest.id
        )
        elapsed_ms = (time.monotonic() - t0) * 1000

        assert result["chain_valid"] is True
        assert result["chain_depth"] == 100
        assert elapsed_ms < 150, (
            f"100-node signed chain took {elapsed_ms:.0f}ms, expected <150ms"
        )


# ---------------------------------------------------------------------------
# P1.1 — Signature stripping detection
# ---------------------------------------------------------------------------


def test_verify_partial_strip_signing_key_id_present_returns_invalid(
    build_app, signing_env
):
    """signing_key_id set but signature=None → invalid (partial_authority_fields).

    This detects the case where an attacker strips only the signature field.
    """
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-partial-strip-001", artifact_hash="q" * 64
        )
        db.commit()

        stored = db.get(FaEvidenceProvenance, record.id)
        stored.signature = None  # strip signature only

        result = verify_provenance_signature(stored)
        assert result["valid"] is False
        assert result["status"] == "invalid"
        assert result["reason"] == "partial_authority_fields"


def test_verify_full_strip_schema_v11_returns_invalid(build_app, signing_env):
    """schema_version=1.1 with all authority fields null → invalid (missing_signature).

    Detects full stripping of all authority fields from a signed record.
    """
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-full-strip-001", artifact_hash="r" * 64
        )
        db.commit()

        stored = db.get(FaEvidenceProvenance, record.id)
        # Strip all authority fields — simulate full strip attack
        stored.signature = None
        stored.signing_key_id = None
        stored.signed_at = None
        stored.signature_version = None
        stored.authority_version = None
        # schema_version stays at "1.1" (set by create_evidence_provenance with signing key)
        assert stored.schema_version == "1.1"

        result = verify_provenance_signature(stored)
        assert result["valid"] is False
        assert result["status"] == "invalid"
        assert result["reason"] == "missing_signature"


def test_schema_version_1_0_unsigned_is_legacy(build_app, monkeypatch):
    """schema_version=1.0 with null signature → legacy_unsigned (not invalid).

    Records created before PR 1.3 have schema_version=1.0 and are genuinely unsigned.
    """
    from api.db import get_engine

    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-legacy-schema-001")
        db.commit()

        stored = db.get(FaEvidenceProvenance, record.id)
        assert stored.schema_version == "1.0"
        result = verify_provenance_signature(stored)
        assert result["valid"] is None
        assert result["status"] == "legacy_unsigned"


def test_signed_record_has_schema_version_1_1(build_app, signing_env):
    """Records auto-signed via create_evidence_provenance get schema_version=1.1."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-schema-v11-001", artifact_hash="s" * 64
        )
        db.commit()

        stored = db.get(FaEvidenceProvenance, record.id)
        assert stored.schema_version == "1.1"


def test_stripping_signing_key_id_alone_fails_signature_mismatch(signing_env):
    """Stripping signing_key_id from a signed in-memory record → signature_mismatch.

    The canonical event includes signing_key_id, so changing it (to None) changes
    the digest → signature no longer matches.
    """
    record = FaEvidenceProvenance(
        id="test-id-strip-keyid",
        tenant_id=TENANT_A,
        engagement_id="eng-strip-keyid-001",
        source_type="scan",
        collected_at="2024-01-01T00:00:00Z",
        collection_method="automated",
        collected_by_type="system",
        event_hash="c" * 64,
        previous_hash=None,
        created_at="2024-01-01T00:00:00Z",
        schema_version="1.0",
        review_status="pending",
        trust_level="unverified",
        chain_status="active",
        used_in_report_ids=[],
        collection_context_json={},
    )
    sig_fields = sign_provenance_event(record)
    record.signature = sig_fields["signature"]
    record.signing_key_id = sig_fields["signing_key_id"]
    record.signature_version = sig_fields["signature_version"]
    record.authority_version = sig_fields["authority_version"]

    # Strip signing_key_id only — canonical event changes → mismatch
    record.signing_key_id = None

    result = verify_provenance_signature(record)
    # signing_key_id=None with signature present → key_id_mismatch check is skipped
    # (None is falsy), but canonical event now has signing_key_id=None vs signed value
    # → signature_mismatch
    assert result["valid"] is False
    assert result["status"] == "invalid"


# ---------------------------------------------------------------------------
# P1.2 — Decision field coverage
# ---------------------------------------------------------------------------


def test_canonical_event_includes_review_fields(build_app, signing_env):
    """review_status, reviewed_by, trust_level appear in the canonical event."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        genesis = _make_provenance(
            db, engagement_id="eng-review-canon-001", artifact_hash="t" * 64
        )
        db.commit()
        reviewed = _extend_chain(db, genesis)
        db.commit()

        event = build_canonical_provenance_event(reviewed)
        assert event["review_status"] == "approved"
        assert event["reviewed_by"] == "analyst@example.com"
        assert "trust_level" in event


def test_tampered_review_status_fails_signature(signing_env):
    """Tampering with review_status on a signed in-memory record → signature_mismatch."""
    record = FaEvidenceProvenance(
        id="test-id-tamper-decision",
        tenant_id=TENANT_A,
        engagement_id="eng-tamper-decision-001",
        source_type="scan",
        collected_at="2024-01-01T00:00:00Z",
        collection_method="automated",
        collected_by_type="system",
        event_hash="d" * 64,
        previous_hash=None,
        created_at="2024-01-01T00:00:00Z",
        schema_version="1.0",
        review_status="approved",
        reviewed_by="alice@example.com",
        trust_level="qa_approved",
        chain_status="active",
        used_in_report_ids=[],
        collection_context_json={},
    )
    sig_fields = sign_provenance_event(record)
    record.signature = sig_fields["signature"]
    record.signing_key_id = sig_fields["signing_key_id"]
    record.signature_version = sig_fields["signature_version"]
    record.authority_version = sig_fields["authority_version"]

    # Tamper the approval decision
    record.review_status = "rejected"

    result = verify_provenance_signature(record)
    assert result["valid"] is False
    assert result["status"] == "invalid"
    assert result["reason"] == "signature_mismatch"


# ---------------------------------------------------------------------------
# P1.3 — Public-key-only verification
# ---------------------------------------------------------------------------


def test_verify_with_public_key_only_env(build_app, signing_env, monkeypatch):
    """FG_EVIDENCE_VERIFY_KEY_B64 enables verification without the private key."""
    from api.db import get_engine

    build_app()
    record_id = None
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-pubkey-only-001", artifact_hash="u" * 64
        )
        db.commit()
        record_id = record.id

    # Switch to public-key-only mode: clear private key, set public key
    pub_b64 = base64.b64encode(_TEST_PUB_BYTES).decode()
    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    monkeypatch.setenv("FG_EVIDENCE_VERIFY_KEY_B64", pub_b64)

    with Session(get_engine()) as db2:
        stored = db2.get(FaEvidenceProvenance, record_id)
        result = verify_provenance_signature(stored)
        assert result["valid"] is True
        assert result["status"] == "verified"


def test_verify_key_env_invalid_base64_raises(monkeypatch):
    """FG_EVIDENCE_VERIFY_KEY_B64 with bad base64 raises EvidenceAuthorityError."""
    from services.field_assessment.evidence_authority import (
        _load_verification_public_key,
    )

    monkeypatch.setenv("FG_EVIDENCE_VERIFY_KEY_B64", "not-valid-base64!!!")
    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)

    with pytest.raises(EvidenceAuthorityError, match="valid base64"):
        _load_verification_public_key()


def test_get_signing_key_id_returns_fingerprint(signing_env):
    """get_signing_key_id() returns SHA256(pub_bytes)[:16]."""
    import hashlib

    expected = hashlib.sha256(_TEST_PUB_BYTES).hexdigest()[:16]
    assert get_signing_key_id() == expected


def test_get_signing_key_id_raises_without_key(monkeypatch):
    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    with pytest.raises(EvidenceAuthorityError):
        get_signing_key_id()
