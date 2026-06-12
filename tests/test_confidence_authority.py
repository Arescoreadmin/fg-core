"""Confidence Authority & Drift Intelligence tests — PR 1.7A.

Coverage matrix:
  Confidence Authority Version    constants, exception class
  Sign Confidence Manifest        signing behavior, required fields, determinism
  Verify Confidence Manifest      roundtrip, tamper, key failure, never raises
  Generate Confidence Snapshot    required fields, hash stability, timestamp exclusion
  Verify Confidence Snapshot      roundtrip, tamper, missing fields, key failure
  Confidence Drift                all 5 directions, all 5 velocities, boundaries
  Confidence Timeline             ordering, stability, large sets, determinism
  Explainability Graph            structure, sections, tree connectors
  Trust Policy                    dataclass, validation, extensibility
  Evaluate Trust Policy           allowed/blocked, all policies, future entities
  Replay Confidence Snapshot      locate, verify layers, fail-closed
  Anomaly Detection               all anomaly types, severity, single/multi snapshot
  Determinism                     all functions produce stable output
  Cross Tenant Isolation          snapshot isolation, hash isolation
  Cross Engagement Isolation      snapshot/hash isolation
  Tamper Detection                manifest, snapshot, signature, score inflation
  Performance                     signing, timeline, drift, policy, anomaly
  Future Node Compatibility       generic entities, extra fields tolerated
  AGI Governance Compatibility    agent policies, future subject types
  Security Invariants             fail-closed, no private key leakage, bounded
"""

from __future__ import annotations

import base64
import time
import uuid
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from services.field_assessment.confidence_authority import (
    CONFIDENCE_AUTHORITY_VERSION,
    ConfidenceAuthorityError,
    TrustPolicy,
    _ANOMALY_CORROBORATION_DROP,
    _ANOMALY_DROP_THRESHOLD,
    _ANOMALY_RISE_THRESHOLD,
    _RAPID_DRIFT_THRESHOLD,
    calculate_confidence_drift,
    detect_confidence_anomalies,
    evaluate_trust_policy,
    generate_confidence_explainability_graph,
    generate_confidence_snapshot,
    generate_confidence_timeline,
    replay_confidence_snapshot,
    sign_confidence_manifest,
    verify_confidence_manifest,
    verify_confidence_snapshot,
)

# ---------------------------------------------------------------------------
# Key fixtures
# ---------------------------------------------------------------------------


def _gen_keypair() -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()
    seed_b64 = base64.b64encode(
        private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode()
    pub_b64 = base64.b64encode(
        private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return seed_b64, pub_b64


_SEED_B64, _PUB_B64 = _gen_keypair()
_WRONG_SEED_B64, _WRONG_PUB_B64 = _gen_keypair()

TENANT = "tenant-ca-001"
ENG = "eng-ca-001"
TENANT_B = "tenant-ca-002"
ENG_B = "eng-ca-002"


@pytest.fixture
def signing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _SEED_B64)
    monkeypatch.setenv("FG_EVIDENCE_VERIFY_KEY_B64", _PUB_B64)


@pytest.fixture
def no_signing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
    monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)


@pytest.fixture
def wrong_signing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _WRONG_SEED_B64)
    monkeypatch.setenv("FG_EVIDENCE_VERIFY_KEY_B64", _WRONG_PUB_B64)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _manifest(
    confidence_score: int = 80,
    corroboration_score: int = 60,
    strength_score: int = 75,
    trust_quality_score: int = 70,
    manifest_hash: str = "deadbeef" * 8,
) -> dict[str, Any]:
    return {
        "confidence_version": "trust-confidence-v1",
        "confidence_score": confidence_score,
        "corroboration_score": corroboration_score,
        "strength_score": strength_score,
        "trust_quality_score": trust_quality_score,
        "generated_at": "2026-06-12T00:00:00Z",
        "manifest_hash": manifest_hash,
    }


def _snap(
    tenant: str = TENANT,
    eng: str = ENG,
    confidence_score: int = 80,
    confidence_level: str = "strong",
    manifest_hash: str = "deadbeef" * 8,
    signing_env_fixture: Any = None,
) -> dict[str, Any]:
    return generate_confidence_snapshot(
        tenant,
        eng,
        {"confidence_score": confidence_score, "confidence_level": confidence_level},
        {"manifest_hash": manifest_hash},
    )


def _confidence_result(score: int = 80) -> dict[str, Any]:
    return {
        "confidence_score": score,
        "confidence_level": "strong" if score >= 75 else "moderate",
        "confidence_factors": [
            {"factor": "evidence_present", "points": 10},
            {"factor": "all_evidence_signed", "points": 20},
            {"factor": "fresh_evidence", "points": 10},
        ],
        "negative_factors": [],
        "corroboration": {"corroboration_score": 40},
        "quality": {"trust_quality_score": 60},
        "explanation": "",
    }


# ---------------------------------------------------------------------------
# 1. Confidence Authority Version & Constants
# ---------------------------------------------------------------------------


class TestConfidenceAuthorityConstants:
    def test_version_string(self) -> None:
        assert CONFIDENCE_AUTHORITY_VERSION == "confidence-authority-v1"

    def test_exception_is_runtime_error_subclass(self) -> None:
        assert issubclass(ConfidenceAuthorityError, RuntimeError)

    def test_anomaly_drop_threshold(self) -> None:
        assert _ANOMALY_DROP_THRESHOLD == 15

    def test_anomaly_rise_threshold(self) -> None:
        assert _ANOMALY_RISE_THRESHOLD == 15

    def test_anomaly_corroboration_drop(self) -> None:
        assert _ANOMALY_CORROBORATION_DROP == 20

    def test_rapid_drift_threshold(self) -> None:
        assert _RAPID_DRIFT_THRESHOLD == 10


# ---------------------------------------------------------------------------
# 2. Sign Confidence Manifest
# ---------------------------------------------------------------------------


class TestSignConfidenceManifest:
    def test_raises_without_key(self, no_signing_env: Any) -> None:
        with pytest.raises(ConfidenceAuthorityError):
            sign_confidence_manifest(_manifest())

    def test_returns_required_fields(self, signing_env: Any) -> None:
        result = sign_confidence_manifest(_manifest())
        for key in ("event_hash", "signature", "signing_key_id", "authority_version"):
            assert key in result

    def test_event_hash_is_64_hex(self, signing_env: Any) -> None:
        result = sign_confidence_manifest(_manifest())
        assert len(result["event_hash"]) == 64
        bytes.fromhex(result["event_hash"])

    def test_signature_is_128_hex(self, signing_env: Any) -> None:
        result = sign_confidence_manifest(_manifest())
        assert len(result["signature"]) == 128
        bytes.fromhex(result["signature"])

    def test_signing_key_id_is_16_hex(self, signing_env: Any) -> None:
        result = sign_confidence_manifest(_manifest())
        assert len(result["signing_key_id"]) == 16
        bytes.fromhex(result["signing_key_id"])

    def test_authority_version_matches_constant(self, signing_env: Any) -> None:
        result = sign_confidence_manifest(_manifest())
        assert result["authority_version"] == CONFIDENCE_AUTHORITY_VERSION

    def test_same_manifest_same_event_hash(self, signing_env: Any) -> None:
        m = _manifest()
        r1 = sign_confidence_manifest(m)
        r2 = sign_confidence_manifest(m)
        assert r1["event_hash"] == r2["event_hash"]

    def test_different_score_different_hash(self, signing_env: Any) -> None:
        r1 = sign_confidence_manifest(_manifest(confidence_score=80))
        r2 = sign_confidence_manifest(_manifest(confidence_score=81))
        assert r1["event_hash"] != r2["event_hash"]

    def test_raises_missing_confidence_score(self, signing_env: Any) -> None:
        m = _manifest()
        del m["confidence_score"]
        with pytest.raises(ConfidenceAuthorityError):
            sign_confidence_manifest(m)

    def test_raises_missing_corroboration_score(self, signing_env: Any) -> None:
        m = _manifest()
        del m["corroboration_score"]
        with pytest.raises(ConfidenceAuthorityError):
            sign_confidence_manifest(m)

    def test_raises_missing_strength_score(self, signing_env: Any) -> None:
        m = _manifest()
        del m["strength_score"]
        with pytest.raises(ConfidenceAuthorityError):
            sign_confidence_manifest(m)

    def test_raises_missing_trust_quality_score(self, signing_env: Any) -> None:
        m = _manifest()
        del m["trust_quality_score"]
        with pytest.raises(ConfidenceAuthorityError):
            sign_confidence_manifest(m)

    def test_raises_missing_manifest_hash(self, signing_env: Any) -> None:
        m = _manifest()
        del m["manifest_hash"]
        with pytest.raises(ConfidenceAuthorityError):
            sign_confidence_manifest(m)

    def test_extra_fields_in_manifest_accepted(self, signing_env: Any) -> None:
        m = _manifest()
        m["future_field"] = "extended_trust_model"
        result = sign_confidence_manifest(m)
        assert result["event_hash"]


# ---------------------------------------------------------------------------
# 3. Verify Confidence Manifest
# ---------------------------------------------------------------------------


class TestVerifyConfidenceManifest:
    def test_valid_roundtrip(self, signing_env: Any) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is True
        assert result["reason"] is None

    def test_returns_valid_and_reason(self, signing_env: Any) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        result = verify_confidence_manifest(m, auth)
        assert "valid" in result
        assert "reason" in result

    def test_empty_authority_returns_missing(self, signing_env: Any) -> None:
        result = verify_confidence_manifest(_manifest(), {})
        assert result["valid"] is False
        assert result["reason"] == "missing_authority"

    def test_none_authority_returns_missing(self, signing_env: Any) -> None:
        result = verify_confidence_manifest(_manifest(), None)  # type: ignore[arg-type]
        assert result["valid"] is False

    def test_missing_event_hash_in_authority(self, signing_env: Any) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        del auth["event_hash"]
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is False
        assert "missing_authority_fields" in result["reason"]

    def test_wrong_authority_version(self, signing_env: Any) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        auth["authority_version"] = "confidence-authority-v0"
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is False
        assert "invalid_authority_version" in result["reason"]

    def test_missing_manifest_fields(self, signing_env: Any) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        del m["confidence_score"]
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is False
        assert "missing_manifest_fields" in result["reason"]

    def test_tampered_confidence_score(self, signing_env: Any) -> None:
        m = _manifest(confidence_score=80)
        auth = sign_confidence_manifest(m)
        m["confidence_score"] = 99
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is False
        assert result["reason"] == "event_hash_mismatch"

    def test_tampered_manifest_hash(self, signing_env: Any) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        m["manifest_hash"] = "00" * 32
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is False

    def test_wrong_key_returns_mismatch(
        self, signing_env: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        monkeypatch.setenv("FG_EVIDENCE_VERIFY_KEY_B64", _WRONG_PUB_B64)
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is False
        assert result["reason"] == "signature_mismatch"

    def test_no_key_returns_key_unavailable(self, no_signing_env: Any) -> None:
        m = _manifest()
        fake_auth = {
            "event_hash": "a" * 64,
            "signature": "b" * 128,
            "signing_key_id": "c" * 16,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        result = verify_confidence_manifest(m, fake_auth)
        assert result["valid"] is False
        assert result["reason"] == "key_unavailable"

    def test_never_raises_on_invalid_signature(self, signing_env: Any) -> None:
        m = _manifest()
        auth = {
            "event_hash": "not_hex",
            "signature": "also_not_hex",
            "signing_key_id": "x" * 16,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        result = verify_confidence_manifest(m, auth)
        assert isinstance(result, dict)
        assert result["valid"] is False

    def test_injected_field_in_authority_tolerated(self, signing_env: Any) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        auth["injected"] = "attack_payload"
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is True

    def test_deterministic_verification(self, signing_env: Any) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        r1 = verify_confidence_manifest(m, auth)
        r2 = verify_confidence_manifest(m, auth)
        assert r1 == r2

    def test_missing_corroboration_score_in_manifest(self, signing_env: Any) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        del m["corroboration_score"]
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is False

    def test_tampered_corroboration_score(self, signing_env: Any) -> None:
        m = _manifest(corroboration_score=40)
        auth = sign_confidence_manifest(m)
        m["corroboration_score"] = 100
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is False

    def test_malformed_verify_key_returns_key_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, signing_env: Any
    ) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        monkeypatch.setenv("FG_EVIDENCE_VERIFY_KEY_B64", "!!!not_valid_base64!!!")
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is False
        assert result["reason"] == "key_unavailable"

    def test_wrong_length_verify_key_returns_key_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, signing_env: Any
    ) -> None:
        import base64 as _b64

        m = _manifest()
        auth = sign_confidence_manifest(m)
        monkeypatch.setenv(
            "FG_EVIDENCE_VERIFY_KEY_B64", _b64.b64encode(b"short").decode()
        )
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is False
        assert result["reason"] == "key_unavailable"

    def test_forged_signing_key_id_rejected(self, signing_env: Any) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        auth["signing_key_id"] = "a" * 16
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is False
        assert result["reason"] == "signing_key_id_mismatch"

    def test_correct_signing_key_id_accepted(self, signing_env: Any) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is True

    def test_non_numeric_score_returns_invalid_manifest_values(
        self, signing_env: Any
    ) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        m["confidence_score"] = "not_a_number"
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is False
        assert result["reason"] == "invalid_manifest_values"


# ---------------------------------------------------------------------------
# 4. Generate Confidence Snapshot
# ---------------------------------------------------------------------------


class TestGenerateConfidenceSnapshot:
    def test_raises_without_key(self, no_signing_env: Any) -> None:
        with pytest.raises(ConfidenceAuthorityError):
            generate_confidence_snapshot(TENANT, ENG, _confidence_result(), _manifest())

    def test_raises_empty_tenant_id(self, signing_env: Any) -> None:
        with pytest.raises(ConfidenceAuthorityError):
            generate_confidence_snapshot("", ENG, _confidence_result(), _manifest())

    def test_raises_empty_engagement_id(self, signing_env: Any) -> None:
        with pytest.raises(ConfidenceAuthorityError):
            generate_confidence_snapshot(TENANT, "", _confidence_result(), _manifest())

    def test_returns_required_fields(self, signing_env: Any) -> None:
        snap = _snap()
        for key in (
            "snapshot_id",
            "tenant_id",
            "engagement_id",
            "confidence_score",
            "confidence_level",
            "manifest_hash",
            "snapshot_hash",
            "snapshot_signature",
            "signing_key_id",
            "authority_version",
            "created_at",
        ):
            assert key in snap, f"missing key: {key}"

    def test_snapshot_id_unique_per_call(self, signing_env: Any) -> None:
        s1 = _snap()
        s2 = _snap()
        assert s1["snapshot_id"] != s2["snapshot_id"]

    def test_snapshot_hash_stable_same_inputs(self, signing_env: Any) -> None:
        s1 = _snap()
        s2 = _snap()
        assert s1["snapshot_hash"] == s2["snapshot_hash"]

    def test_snapshot_hash_changes_with_score(self, signing_env: Any) -> None:
        s1 = _snap(confidence_score=80)
        s2 = _snap(confidence_score=81)
        assert s1["snapshot_hash"] != s2["snapshot_hash"]

    def test_snapshot_hash_changes_with_manifest_hash(self, signing_env: Any) -> None:
        s1 = _snap(manifest_hash="aa" * 32)
        s2 = _snap(manifest_hash="bb" * 32)
        assert s1["snapshot_hash"] != s2["snapshot_hash"]

    def test_snapshot_hash_excludes_snapshot_id(self, signing_env: Any) -> None:
        s1 = _snap()
        s2 = _snap()
        assert s1["snapshot_id"] != s2["snapshot_id"]
        assert s1["snapshot_hash"] == s2["snapshot_hash"]

    def test_snapshot_hash_excludes_created_at(self, signing_env: Any) -> None:
        s1 = _snap()
        s2 = _snap()
        assert s1["snapshot_hash"] == s2["snapshot_hash"]

    def test_authority_version_in_output(self, signing_env: Any) -> None:
        snap = _snap()
        assert snap["authority_version"] == CONFIDENCE_AUTHORITY_VERSION

    def test_signing_key_id_is_16_hex(self, signing_env: Any) -> None:
        snap = _snap()
        assert len(snap["signing_key_id"]) == 16
        bytes.fromhex(snap["signing_key_id"])

    def test_snapshot_signature_is_hex(self, signing_env: Any) -> None:
        snap = _snap()
        bytes.fromhex(snap["snapshot_signature"])

    def test_roundtrip_verifies_immediately(self, signing_env: Any) -> None:
        snap = _snap()
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is True


# ---------------------------------------------------------------------------
# 5. Verify Confidence Snapshot
# ---------------------------------------------------------------------------


class TestVerifyConfidenceSnapshot:
    def test_valid_roundtrip(self, signing_env: Any) -> None:
        snap = _snap()
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is True
        assert result["reason"] is None

    def test_empty_dict_returns_missing(self, signing_env: Any) -> None:
        result = verify_confidence_snapshot({})
        assert result["valid"] is False
        assert result["reason"] == "missing_snapshot"

    def test_none_returns_missing(self, signing_env: Any) -> None:
        result = verify_confidence_snapshot(None)  # type: ignore[arg-type]
        assert result["valid"] is False

    def test_missing_tenant_id(self, signing_env: Any) -> None:
        snap = _snap()
        del snap["tenant_id"]
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False
        assert "missing_fields" in result["reason"]

    def test_missing_snapshot_hash(self, signing_env: Any) -> None:
        snap = _snap()
        del snap["snapshot_hash"]
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False

    def test_missing_snapshot_signature(self, signing_env: Any) -> None:
        snap = _snap()
        del snap["snapshot_signature"]
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False

    def test_wrong_authority_version(self, signing_env: Any) -> None:
        snap = _snap()
        snap["authority_version"] = "confidence-authority-v0"
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False
        assert "invalid_authority_version" in result["reason"]

    def test_tampered_confidence_score(self, signing_env: Any) -> None:
        snap = _snap(confidence_score=80)
        snap["confidence_score"] = 99
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False
        assert result["reason"] == "tampered_snapshot_hash"

    def test_tampered_tenant_id(self, signing_env: Any) -> None:
        snap = _snap()
        snap["tenant_id"] = "evil-tenant"
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False
        assert result["reason"] == "tampered_snapshot_hash"

    def test_tampered_manifest_hash(self, signing_env: Any) -> None:
        snap = _snap()
        snap["manifest_hash"] = "00" * 32
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False

    def test_tampered_signature_rejected(self, signing_env: Any) -> None:
        snap = _snap()
        snap["snapshot_signature"] = "ff" * 64
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False
        assert result["reason"] == "signature_mismatch"

    def test_wrong_key_rejected(
        self, signing_env: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        snap = _snap()
        monkeypatch.setenv("FG_EVIDENCE_VERIFY_KEY_B64", _WRONG_PUB_B64)
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False

    def test_no_key_returns_key_unavailable(
        self, signing_env: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        snap = _snap()
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False
        assert result["reason"] == "key_unavailable"

    def test_never_raises(self, signing_env: Any) -> None:
        bad_inputs: list[Any] = [
            None,
            {},
            {"snapshot_id": "x"},
            {"snapshot_signature": "not_hex"},
        ]
        for bad in bad_inputs:
            result = verify_confidence_snapshot(bad)  # type: ignore[arg-type]
            assert isinstance(result, dict)

    def test_malformed_verify_key_returns_key_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, signing_env: Any
    ) -> None:
        snap = _snap()
        monkeypatch.setenv("FG_EVIDENCE_VERIFY_KEY_B64", "!!!not_valid_base64!!!")
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False
        assert result["reason"] == "key_unavailable"


# ---------------------------------------------------------------------------
# 6. Confidence Drift
# ---------------------------------------------------------------------------


class TestCalculateConfidenceDrift:
    def test_returns_required_fields(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 80}, {"confidence_score": 80}
        )
        for key in (
            "previous_score",
            "current_score",
            "delta",
            "direction",
            "velocity",
            "trend",
        ):
            assert key in result

    def test_delta_is_current_minus_previous(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 70}, {"confidence_score": 85}
        )
        assert result["delta"] == 15

    def test_zero_delta_is_stable_neutral(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 80}, {"confidence_score": 80}
        )
        assert result["direction"] == "stable"
        assert result["trend"] == "neutral"

    def test_small_positive_delta_is_improving(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 80}, {"confidence_score": 85}
        )
        assert result["direction"] == "improving"
        assert result["trend"] == "positive"

    def test_large_positive_delta_is_rapidly_improving(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 70}, {"confidence_score": 92}
        )
        assert result["direction"] == "rapidly_improving"
        assert result["trend"] == "positive"

    def test_small_negative_delta_is_degrading(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 85}, {"confidence_score": 80}
        )
        assert result["direction"] == "degrading"
        assert result["trend"] == "negative"

    def test_large_negative_delta_is_rapidly_degrading(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 90}, {"confidence_score": 65}
        )
        assert result["direction"] == "rapidly_degrading"
        assert result["trend"] == "negative"

    def test_velocity_minimal_at_delta_2(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 80}, {"confidence_score": 82}
        )
        assert result["velocity"] == "minimal"

    def test_velocity_low_at_delta_4(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 80}, {"confidence_score": 84}
        )
        assert result["velocity"] == "low"

    def test_velocity_moderate_at_delta_8(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 80}, {"confidence_score": 88}
        )
        assert result["velocity"] == "moderate"

    def test_velocity_significant_at_delta_15(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 70}, {"confidence_score": 85}
        )
        assert result["velocity"] == "significant"

    def test_velocity_rapid_at_delta_25(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 50}, {"confidence_score": 100}
        )
        assert result["velocity"] == "rapid"

    def test_deterministic(self) -> None:
        prev = {"confidence_score": 75}
        curr = {"confidence_score": 83}
        assert calculate_confidence_drift(prev, curr) == calculate_confidence_drift(
            prev, curr
        )

    def test_works_with_snapshot_dicts(self, signing_env: Any) -> None:
        s1 = _snap(confidence_score=70)
        s2 = _snap(confidence_score=82)
        result = calculate_confidence_drift(s1, s2)
        assert result["delta"] == 12

    def test_works_with_confidence_result_dicts(self) -> None:
        result = calculate_confidence_drift(
            _confidence_result(70), _confidence_result(80)
        )
        assert result["delta"] == 10

    def test_boundary_delta_10_is_improving(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 80}, {"confidence_score": 90}
        )
        assert result["direction"] == "rapidly_improving"

    def test_boundary_delta_neg_10_is_degrading(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 90}, {"confidence_score": 80}
        )
        assert result["direction"] == "rapidly_degrading"

    def test_delta_1_is_improving_not_rapid(self) -> None:
        result = calculate_confidence_drift(
            {"confidence_score": 80}, {"confidence_score": 81}
        )
        assert result["direction"] == "improving"


# ---------------------------------------------------------------------------
# 7. Confidence Timeline
# ---------------------------------------------------------------------------


class TestGenerateConfidenceTimeline:
    def test_empty_returns_empty(self) -> None:
        assert generate_confidence_timeline([]) == []

    def test_single_snapshot_single_entry(self, signing_env: Any) -> None:
        snap = _snap()
        timeline = generate_confidence_timeline([snap])
        assert len(timeline) == 1

    def test_returns_required_fields(self, signing_env: Any) -> None:
        snap = _snap()
        entry = generate_confidence_timeline([snap])[0]
        for key in ("timestamp", "confidence_score", "confidence_level", "snapshot_id"):
            assert key in entry

    def test_sorted_by_timestamp(self, signing_env: Any) -> None:
        snaps = [
            {
                "created_at": "2026-06-12T03:00:00Z",
                "confidence_score": 70,
                "confidence_level": "moderate",
                "snapshot_id": "c",
            },
            {
                "created_at": "2026-06-12T01:00:00Z",
                "confidence_score": 80,
                "confidence_level": "strong",
                "snapshot_id": "a",
            },
            {
                "created_at": "2026-06-12T02:00:00Z",
                "confidence_score": 75,
                "confidence_level": "strong",
                "snapshot_id": "b",
            },
        ]
        timeline = generate_confidence_timeline(snaps)
        scores = [e["confidence_score"] for e in timeline]
        assert scores == [80, 75, 70]

    def test_stable_sort_same_timestamp(self) -> None:
        snaps = [
            {
                "created_at": "2026-06-12T00:00:00Z",
                "confidence_score": 80,
                "confidence_level": "strong",
                "snapshot_id": "z",
            },
            {
                "created_at": "2026-06-12T00:00:00Z",
                "confidence_score": 75,
                "confidence_level": "strong",
                "snapshot_id": "a",
            },
        ]
        timeline = generate_confidence_timeline(snaps)
        assert timeline[0]["snapshot_id"] == "a"
        assert timeline[1]["snapshot_id"] == "z"

    def test_100_snapshots_ordered(self, signing_env: Any) -> None:
        snaps = [
            {
                "created_at": f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}Z",
                "confidence_score": 50 + i,
                "confidence_level": "moderate",
                "snapshot_id": uuid.uuid4().hex,
            }
            for i in range(100)
        ]
        import random

        shuffled = snaps[:]
        random.shuffle(shuffled)
        timeline = generate_confidence_timeline(shuffled)
        scores = [e["confidence_score"] for e in timeline]
        assert scores == sorted(scores)

    def test_1000_snapshots_performance(self) -> None:
        snaps = [
            {
                "created_at": f"2026-01-01T{i // 3600:02d}:{(i % 3600) // 60:02d}:{i % 60:02d}Z",
                "confidence_score": i % 100,
                "confidence_level": "moderate",
                "snapshot_id": uuid.uuid4().hex,
            }
            for i in range(1000)
        ]
        t0 = time.perf_counter()
        generate_confidence_timeline(snaps)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 250

    def test_deterministic(self, signing_env: Any) -> None:
        snap = _snap()
        t1 = generate_confidence_timeline([snap])
        t2 = generate_confidence_timeline([snap])
        assert t1 == t2

    def test_missing_created_at_uses_empty_string(self) -> None:
        snap = {
            "confidence_score": 75,
            "confidence_level": "strong",
            "snapshot_id": "x",
        }
        entry = generate_confidence_timeline([snap])[0]
        assert entry["timestamp"] == ""

    def test_missing_confidence_score_defaults_zero(self) -> None:
        snap = {
            "created_at": "2026-06-12T00:00:00Z",
            "confidence_level": "strong",
            "snapshot_id": "x",
        }
        entry = generate_confidence_timeline([snap])[0]
        assert entry["confidence_score"] == 0

    def test_missing_confidence_level_defaults_unknown(self) -> None:
        snap = {
            "created_at": "2026-06-12T00:00:00Z",
            "confidence_score": 75,
            "snapshot_id": "x",
        }
        entry = generate_confidence_timeline([snap])[0]
        assert entry["confidence_level"] == "unknown"

    def test_does_not_mutate_input(self) -> None:
        snaps = [
            {
                "created_at": "2026-06-12T00:00:00Z",
                "confidence_score": 80,
                "confidence_level": "strong",
                "snapshot_id": "x",
            }
        ]
        original = snaps[:]
        generate_confidence_timeline(snaps)
        assert snaps == original


# ---------------------------------------------------------------------------
# 8. Confidence Explainability Graph
# ---------------------------------------------------------------------------


class TestGenerateConfidenceExplainabilityGraph:
    def _result(
        self, pos: list[dict] | None = None, neg: list[dict] | None = None
    ) -> dict:
        return {
            "confidence_score": 87,
            "confidence_level": "strong",
            "confidence_factors": pos
            or [
                {"factor": "evidence_present", "points": 10},
                {"factor": "all_evidence_signed", "points": 20},
                {"factor": "fresh_evidence", "points": 10},
            ],
            "negative_factors": neg or [],
        }

    def test_returns_string(self) -> None:
        assert isinstance(generate_confidence_explainability_graph(self._result()), str)

    def test_contains_score(self) -> None:
        text = generate_confidence_explainability_graph(self._result())
        assert "87" in text

    def test_contains_level(self) -> None:
        text = generate_confidence_explainability_graph(self._result())
        assert "strong" in text

    def test_evidence_section_present(self) -> None:
        text = generate_confidence_explainability_graph(self._result())
        assert "Evidence Strength" in text

    def test_corroboration_section_present(self) -> None:
        result = self._result(
            pos=[{"factor": "independent_corroboration_2", "points": 8}]
        )
        text = generate_confidence_explainability_graph(result)
        assert "Corroboration" in text

    def test_replay_section_present(self) -> None:
        result = self._result(pos=[{"factor": "chain_replay_score_100", "points": 10}])
        text = generate_confidence_explainability_graph(result)
        assert "Chain Replay" in text

    def test_snapshot_section_present(self) -> None:
        result = self._result(pos=[{"factor": "snapshot_verified", "points": 10}])
        text = generate_confidence_explainability_graph(result)
        assert "Snapshot" in text

    def test_tree_connectors_present(self) -> None:
        text = generate_confidence_explainability_graph(self._result())
        assert "├─" in text or "└─" in text

    def test_deterministic(self) -> None:
        result = self._result()
        assert generate_confidence_explainability_graph(
            result
        ) == generate_confidence_explainability_graph(result)

    def test_stale_factor_appears_in_evidence_section(self) -> None:
        result = self._result(
            neg=[{"factor": "stale_evidence_critical", "points": -25}]
        )
        text = generate_confidence_explainability_graph(result)
        assert "Evidence Strength" in text

    def test_empty_factors_produces_minimal_output(self) -> None:
        result = {
            "confidence_score": 0,
            "confidence_level": "critical",
            "confidence_factors": [],
            "negative_factors": [],
        }
        text = generate_confidence_explainability_graph(result)
        assert "Confidence 0" in text

    def test_negative_factor_shown_with_negative_points(self) -> None:
        result = self._result(neg=[{"factor": "unsigned_evidence", "points": -15}])
        text = generate_confidence_explainability_graph(result)
        assert "-15" in text


# ---------------------------------------------------------------------------
# 9. Trust Policy
# ---------------------------------------------------------------------------


class TestTrustPolicy:
    def test_policy_name_stored(self) -> None:
        p = TrustPolicy("report_export", 80)
        assert p.policy_name == "report_export"

    def test_minimum_confidence_stored(self) -> None:
        p = TrustPolicy("report_export", 80)
        assert p.minimum_confidence == 80

    def test_subject_type_defaults_any(self) -> None:
        p = TrustPolicy("report_export", 80)
        assert p.subject_type == "any"

    def test_policy_version_defaults(self) -> None:
        p = TrustPolicy("report_export", 80)
        assert p.policy_version == "trust-policy-v1"

    def test_raises_negative_confidence(self) -> None:
        with pytest.raises(ValueError):
            TrustPolicy("report_export", -1)

    def test_raises_confidence_above_100(self) -> None:
        with pytest.raises(ValueError):
            TrustPolicy("report_export", 101)

    def test_zero_confidence_accepted(self) -> None:
        p = TrustPolicy("report_export", 0)
        assert p.minimum_confidence == 0

    def test_100_confidence_accepted(self) -> None:
        p = TrustPolicy("report_export", 100)
        assert p.minimum_confidence == 100

    def test_custom_subject_type_accepted(self) -> None:
        p = TrustPolicy("agent_approval", 90, subject_type="agi_governance")
        assert p.subject_type == "agi_governance"

    def test_evidence_approval_policy_name(self) -> None:
        p = TrustPolicy("evidence_approval", 70)
        assert p.policy_name == "evidence_approval"


# ---------------------------------------------------------------------------
# 10. Evaluate Trust Policy
# ---------------------------------------------------------------------------


class TestEvaluateTrustPolicy:
    def test_returns_required_fields(self) -> None:
        p = TrustPolicy("report_export", 80)
        result = evaluate_trust_policy(p, _confidence_result(85))
        for key in (
            "allowed",
            "policy_name",
            "subject_type",
            "required_confidence",
            "actual_confidence",
            "reason",
            "policy_version",
            "authority_version",
        ):
            assert key in result

    def test_allowed_when_actual_ge_required(self) -> None:
        p = TrustPolicy("report_export", 80)
        result = evaluate_trust_policy(p, _confidence_result(85))
        assert result["allowed"] is True

    def test_blocked_when_actual_lt_required(self) -> None:
        p = TrustPolicy("report_export", 80)
        result = evaluate_trust_policy(p, _confidence_result(75))
        assert result["allowed"] is False

    def test_reason_satisfied_when_allowed(self) -> None:
        p = TrustPolicy("report_export", 80)
        result = evaluate_trust_policy(p, _confidence_result(90))
        assert result["reason"] == "policy_satisfied"

    def test_reason_contains_shortfall_when_blocked(self) -> None:
        p = TrustPolicy("report_export", 80)
        result = evaluate_trust_policy(p, _confidence_result(65))
        assert "confidence_below_threshold" in result["reason"]
        assert "15" in result["reason"]

    def test_required_confidence_echoed(self) -> None:
        p = TrustPolicy("report_export", 75)
        result = evaluate_trust_policy(p, _confidence_result(80))
        assert result["required_confidence"] == 75

    def test_actual_confidence_from_result(self) -> None:
        p = TrustPolicy("report_export", 75)
        result = evaluate_trust_policy(p, _confidence_result(82))
        assert result["actual_confidence"] == 82

    def test_policy_name_echoed(self) -> None:
        p = TrustPolicy("qa_approval", 80)
        result = evaluate_trust_policy(p, _confidence_result(85))
        assert result["policy_name"] == "qa_approval"

    def test_subject_type_echoed(self) -> None:
        p = TrustPolicy("agent_approval", 80, subject_type="agent")
        result = evaluate_trust_policy(p, _confidence_result(85))
        assert result["subject_type"] == "agent"

    def test_authority_version_in_output(self) -> None:
        p = TrustPolicy("report_export", 80)
        result = evaluate_trust_policy(p, _confidence_result(85))
        assert result["authority_version"] == CONFIDENCE_AUTHORITY_VERSION

    def test_policy_version_in_output(self) -> None:
        p = TrustPolicy("report_export", 80)
        result = evaluate_trust_policy(p, _confidence_result(85))
        assert result["policy_version"] == "trust-policy-v1"

    def test_deterministic(self) -> None:
        p = TrustPolicy("report_export", 80)
        cr = _confidence_result(85)
        assert evaluate_trust_policy(p, cr) == evaluate_trust_policy(p, cr)

    def test_exact_boundary_allowed(self) -> None:
        p = TrustPolicy("report_export", 80)
        result = evaluate_trust_policy(p, _confidence_result(80))
        assert result["allowed"] is True

    def test_zero_score_blocked(self) -> None:
        p = TrustPolicy("report_export", 1)
        result = evaluate_trust_policy(p, _confidence_result(0))
        assert result["allowed"] is False

    def test_all_eight_policy_names(self) -> None:
        from services.field_assessment.confidence_authority import _VALID_POLICY_NAMES

        cr = _confidence_result(90)
        for name in _VALID_POLICY_NAMES:
            p = TrustPolicy(name, 80)
            result = evaluate_trust_policy(p, cr)
            assert result["allowed"] is True

    def test_future_subject_type_accepted(self) -> None:
        p = TrustPolicy("agent_autonomy", 95, subject_type="agi_governance")
        result = evaluate_trust_policy(p, _confidence_result(96))
        assert result["allowed"] is True


# ---------------------------------------------------------------------------
# 11. Replay Confidence Snapshot
# ---------------------------------------------------------------------------


class TestReplayConfidenceSnapshot:
    def test_returns_required_fields(self, signing_env: Any) -> None:
        snap = _snap()
        result = replay_confidence_snapshot(snap["snapshot_id"], [snap])
        for key in ("valid", "reason", "snapshot", "validations"):
            assert key in result

    def test_empty_snapshot_id_returns_missing(self, signing_env: Any) -> None:
        snap = _snap()
        result = replay_confidence_snapshot("", [snap])
        assert result["valid"] is False
        assert result["reason"] == "missing_snapshot_id"

    def test_not_found_returns_snapshot_not_found(self, signing_env: Any) -> None:
        snap = _snap()
        result = replay_confidence_snapshot("nonexistent_id", [snap])
        assert result["valid"] is False
        assert result["reason"] == "snapshot_not_found"

    def test_found_without_verify_returns_valid(self, signing_env: Any) -> None:
        snap = _snap()
        result = replay_confidence_snapshot(snap["snapshot_id"], [snap], verify=False)
        assert result["valid"] is True
        assert result["snapshot"] is snap

    def test_found_with_verify_validates_signature(self, signing_env: Any) -> None:
        snap = _snap()
        result = replay_confidence_snapshot(snap["snapshot_id"], [snap])
        assert result["valid"] is True
        assert "snapshot_authority" in result["validations"]

    def test_tampered_snapshot_fails(self, signing_env: Any) -> None:
        snap = _snap()
        snap["confidence_score"] = 99
        result = replay_confidence_snapshot(snap["snapshot_id"], [snap])
        assert result["valid"] is False

    def test_manifest_authority_failed_blocks(self, signing_env: Any) -> None:
        snap = _snap()
        manifest_auth = {"valid": False, "reason": "tampered"}
        result = replay_confidence_snapshot(
            snap["snapshot_id"], [snap], manifest_authority=manifest_auth
        )
        assert result["valid"] is False
        assert "manifest_authority_failed" in result["reason"]

    def test_manifest_authority_valid_passes(self, signing_env: Any) -> None:
        snap = _snap()
        manifest_auth = {"valid": True, "reason": None}
        result = replay_confidence_snapshot(
            snap["snapshot_id"], [snap], manifest_authority=manifest_auth
        )
        assert result["valid"] is True
        assert "manifest_authority" in result["validations"]

    def test_graph_hash_mismatch_blocks(self, signing_env: Any) -> None:
        snap = _snap(manifest_hash="aa" * 32)
        result = replay_confidence_snapshot(
            snap["snapshot_id"], [snap], graph_hash="bb" * 32
        )
        assert result["valid"] is False
        assert result["reason"] == "graph_hash_mismatch"

    def test_graph_hash_match_passes(self, signing_env: Any) -> None:
        h = "cc" * 32
        snap = _snap(manifest_hash=h)
        result = replay_confidence_snapshot(snap["snapshot_id"], [snap], graph_hash=h)
        assert result["valid"] is True
        assert "graph_authority" in result["validations"]

    def test_replay_chain_broken_blocks(self, signing_env: Any) -> None:
        snap = _snap()
        result = replay_confidence_snapshot(
            snap["snapshot_id"],
            [snap],
            replay_result={"chain_replay_score": 0},
        )
        assert result["valid"] is False
        assert result["reason"] == "replay_chain_broken"

    def test_replay_chain_valid_passes(self, signing_env: Any) -> None:
        snap = _snap()
        result = replay_confidence_snapshot(
            snap["snapshot_id"],
            [snap],
            replay_result={"chain_replay_score": 100},
        )
        assert result["valid"] is True
        assert "replay_authority" in result["validations"]

    def test_finds_correct_snapshot_among_multiple(self, signing_env: Any) -> None:
        s1 = _snap(confidence_score=70)
        s2 = _snap(confidence_score=80)
        s3 = _snap(confidence_score=90)
        result = replay_confidence_snapshot(s2["snapshot_id"], [s1, s2, s3])
        assert result["valid"] is True
        assert result["snapshot"]["confidence_score"] == 80

    def test_snapshot_authority_in_validations_when_pass(
        self, signing_env: Any
    ) -> None:
        snap = _snap()
        result = replay_confidence_snapshot(snap["snapshot_id"], [snap])
        assert "snapshot_authority" in result["validations"]

    def test_graph_hash_unbound_when_snapshot_has_empty_manifest_hash(
        self, signing_env: Any
    ) -> None:
        snap = _snap(manifest_hash="")
        result = replay_confidence_snapshot(
            snap["snapshot_id"], [snap], graph_hash="deadbeef" * 8
        )
        assert result["valid"] is False
        assert result["reason"] == "graph_hash_unbound"
        assert "graph_authority" not in result["validations"]

    def test_graph_hash_matching_manifest_hash_validates(
        self, signing_env: Any
    ) -> None:
        snap = _snap(manifest_hash="abcd1234" * 8)
        result = replay_confidence_snapshot(
            snap["snapshot_id"], [snap], graph_hash="abcd1234" * 8
        )
        assert "graph_authority" in result["validations"]


# ---------------------------------------------------------------------------
# 12. Anomaly Detection
# ---------------------------------------------------------------------------


class TestDetectConfidenceAnomalies:
    def test_empty_list_no_anomaly(self) -> None:
        result = detect_confidence_anomalies([])
        assert result["anomaly_detected"] is False
        assert result["reason"] == "no_snapshots"

    def test_single_no_signature_anomaly(self) -> None:
        snap = {
            "confidence_score": 80,
            "confidence_level": "strong",
            "snapshot_id": "x",
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
            "snapshot_signature": "",
        }
        result = detect_confidence_anomalies([snap])
        assert result["anomaly_detected"] is True
        assert any(a["type"] == "signature_loss" for a in result["anomalies"])

    def test_single_with_signature_no_anomaly(self) -> None:
        snap = {
            "confidence_score": 80,
            "confidence_level": "strong",
            "snapshot_id": "x",
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
            "snapshot_signature": "aa" * 64,
        }
        result = detect_confidence_anomalies([snap])
        assert result["anomaly_detected"] is False

    def test_two_snaps_no_change_no_anomaly(self, signing_env: Any) -> None:
        s1 = _snap(confidence_score=80)
        s2 = _snap(confidence_score=80)
        result = detect_confidence_anomalies([s1, s2])
        assert result["anomaly_detected"] is False

    def test_drop_15_points_is_high_collapse(self) -> None:
        s1 = {
            "confidence_score": 90,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 75,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        result = detect_confidence_anomalies([s1, s2])
        assert result["anomaly_detected"] is True
        collapse = next(
            a for a in result["anomalies"] if a["type"] == "confidence_collapse"
        )
        assert collapse["severity"] == "high"

    def test_drop_25_points_is_critical_collapse(self) -> None:
        s1 = {
            "confidence_score": 90,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 65,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        result = detect_confidence_anomalies([s1, s2])
        collapse = next(
            a for a in result["anomalies"] if a["type"] == "confidence_collapse"
        )
        assert collapse["severity"] == "critical"

    def test_drop_14_no_collapse(self) -> None:
        s1 = {
            "confidence_score": 90,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 76,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        result = detect_confidence_anomalies([s1, s2])
        assert not any(a["type"] == "confidence_collapse" for a in result["anomalies"])

    def test_rise_15_points_is_inflation(self) -> None:
        s1 = {
            "confidence_score": 60,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 75,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        result = detect_confidence_anomalies([s1, s2])
        assert any(a["type"] == "confidence_inflation" for a in result["anomalies"])

    def test_rise_14_no_inflation(self) -> None:
        s1 = {
            "confidence_score": 60,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 74,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        result = detect_confidence_anomalies([s1, s2])
        assert not any(a["type"] == "confidence_inflation" for a in result["anomalies"])

    def test_authority_downgrade_detected(self) -> None:
        s1 = {
            "confidence_score": 80,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 80,
            "snapshot_signature": "aa" * 64,
            "authority_version": "confidence-authority-v0",
        }
        result = detect_confidence_anomalies([s1, s2])
        assert any(a["type"] == "authority_downgrade" for a in result["anomalies"])
        assert result["severity"] == "critical"

    def test_corroboration_collapse_detected(self) -> None:
        s1 = {
            "confidence_score": 80,
            "corroboration_score": 75,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 80,
            "corroboration_score": 40,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        result = detect_confidence_anomalies([s1, s2])
        assert any(a["type"] == "corroboration_collapse" for a in result["anomalies"])

    def test_corroboration_drop_19_no_collapse(self) -> None:
        s1 = {
            "confidence_score": 80,
            "corroboration_score": 60,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 80,
            "corroboration_score": 41,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        result = detect_confidence_anomalies([s1, s2])
        assert not any(
            a["type"] == "corroboration_collapse" for a in result["anomalies"]
        )

    def test_replay_degradation_detected(self) -> None:
        s1 = {
            "confidence_score": 80,
            "chain_replay_score": 100,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 80,
            "chain_replay_score": 75,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        result = detect_confidence_anomalies([s1, s2])
        assert any(a["type"] == "replay_degradation" for a in result["anomalies"])
        replay = next(
            a for a in result["anomalies"] if a["type"] == "replay_degradation"
        )
        assert replay["severity"] == "medium"

    def test_missing_signature_on_latest(self) -> None:
        s1 = {
            "confidence_score": 80,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 80,
            "snapshot_signature": "",
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        result = detect_confidence_anomalies([s1, s2])
        assert any(a["type"] == "signature_loss" for a in result["anomalies"])
        assert result["severity"] == "critical"

    def test_multiple_anomalies_highest_severity_returned(self) -> None:
        s1 = {
            "confidence_score": 90,
            "corroboration_score": 80,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 65,
            "corroboration_score": 40,
            "snapshot_signature": "",
            "authority_version": "confidence-authority-v0",
        }
        result = detect_confidence_anomalies([s1, s2])
        assert result["anomaly_detected"] is True
        assert result["severity"] == "critical"

    def test_deterministic(self) -> None:
        s1 = {
            "confidence_score": 90,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 70,
            "snapshot_signature": "bb" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        r1 = detect_confidence_anomalies([s1, s2])
        r2 = detect_confidence_anomalies([s1, s2])
        assert r1 == r2

    def test_single_snapshot_wrong_version(self) -> None:
        snap = {
            "confidence_score": 80,
            "snapshot_signature": "aa" * 64,
            "authority_version": "confidence-authority-v0",
        }
        result = detect_confidence_anomalies([snap])
        assert result["anomaly_detected"] is True

    def test_no_anomalies_severity_none(self, signing_env: Any) -> None:
        s1 = _snap(confidence_score=80)
        s2 = _snap(confidence_score=82)
        result = detect_confidence_anomalies([s1, s2])
        if not result["anomaly_detected"]:
            assert result["severity"] == "none"


# ---------------------------------------------------------------------------
# 13. Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_sign_manifest_deterministic_hash(self, signing_env: Any) -> None:
        m = _manifest()
        r1 = sign_confidence_manifest(m)
        r2 = sign_confidence_manifest(m)
        assert r1["event_hash"] == r2["event_hash"]

    def test_verify_manifest_deterministic(self, signing_env: Any) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        r1 = verify_confidence_manifest(m, auth)
        r2 = verify_confidence_manifest(m, auth)
        assert r1 == r2

    def test_confidence_drift_deterministic(self) -> None:
        prev = {"confidence_score": 70}
        curr = {"confidence_score": 83}
        assert calculate_confidence_drift(prev, curr) == calculate_confidence_drift(
            prev, curr
        )

    def test_timeline_deterministic(self, signing_env: Any) -> None:
        snaps = [_snap(confidence_score=i * 10) for i in range(5, 10)]
        t1 = generate_confidence_timeline(snaps)
        t2 = generate_confidence_timeline(snaps)
        assert t1 == t2

    def test_explainability_graph_deterministic(self) -> None:
        cr = _confidence_result(85)
        cr["confidence_factors"] = [
            {"factor": "evidence_present", "points": 10},
            {"factor": "all_evidence_signed", "points": 20},
        ]
        cr["negative_factors"] = []
        g1 = generate_confidence_explainability_graph(cr)
        g2 = generate_confidence_explainability_graph(cr)
        assert g1 == g2

    def test_evaluate_policy_deterministic(self) -> None:
        p = TrustPolicy("report_export", 80)
        cr = _confidence_result(85)
        r1 = evaluate_trust_policy(p, cr)
        r2 = evaluate_trust_policy(p, cr)
        assert r1 == r2

    def test_detect_anomalies_deterministic(self) -> None:
        s1 = {
            "confidence_score": 90,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 70,
            "snapshot_signature": "bb" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        r1 = detect_confidence_anomalies([s1, s2])
        r2 = detect_confidence_anomalies([s1, s2])
        assert r1 == r2

    def test_snapshot_hash_deterministic_across_calls(self, signing_env: Any) -> None:
        s1 = _snap(confidence_score=85)
        s2 = _snap(confidence_score=85)
        assert s1["snapshot_hash"] == s2["snapshot_hash"]
        assert s1["snapshot_id"] != s2["snapshot_id"]


# ---------------------------------------------------------------------------
# 14. Cross Tenant Isolation
# ---------------------------------------------------------------------------


class TestCrossTenantIsolation:
    def test_different_tenants_produce_different_snapshot_hashes(
        self, signing_env: Any
    ) -> None:
        s_a = _snap(tenant=TENANT)
        s_b = _snap(tenant=TENANT_B)
        assert s_a["snapshot_hash"] != s_b["snapshot_hash"]

    def test_snapshot_tenant_b_fails_verify_with_tenant_a_data(
        self, signing_env: Any
    ) -> None:
        snap = _snap(tenant=TENANT)
        snap["tenant_id"] = TENANT_B
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False
        assert result["reason"] == "tampered_snapshot_hash"

    def test_replay_finds_only_correct_tenant(self, signing_env: Any) -> None:
        s_a = _snap(tenant=TENANT, confidence_score=80)
        s_b = _snap(tenant=TENANT_B, confidence_score=90)
        result = replay_confidence_snapshot(s_a["snapshot_id"], [s_a, s_b])
        assert result["valid"] is True
        assert result["snapshot"]["tenant_id"] == TENANT

    def test_timeline_preserves_tenant_context(self, signing_env: Any) -> None:
        s_a = _snap(tenant=TENANT)
        s_b = _snap(tenant=TENANT_B)
        timeline = generate_confidence_timeline([s_a, s_b])
        assert len(timeline) == 2

    def test_drift_cross_tenant_produces_delta(self, signing_env: Any) -> None:
        s_a = _snap(tenant=TENANT, confidence_score=70)
        s_b = _snap(tenant=TENANT_B, confidence_score=90)
        drift = calculate_confidence_drift(s_a, s_b)
        assert drift["delta"] == 20

    def test_policy_evaluation_independent_per_tenant(self) -> None:
        p = TrustPolicy("report_export", 80)
        cr_a = _confidence_result(85)
        cr_b = _confidence_result(75)
        r_a = evaluate_trust_policy(p, cr_a)
        r_b = evaluate_trust_policy(p, cr_b)
        assert r_a["allowed"] is True
        assert r_b["allowed"] is False


# ---------------------------------------------------------------------------
# 15. Cross Engagement Isolation
# ---------------------------------------------------------------------------


class TestCrossEngagementIsolation:
    def test_different_engagements_produce_different_hashes(
        self, signing_env: Any
    ) -> None:
        s1 = _snap(eng=ENG)
        s2 = _snap(eng=ENG_B)
        assert s1["snapshot_hash"] != s2["snapshot_hash"]

    def test_tampered_engagement_fails_verify(self, signing_env: Any) -> None:
        snap = _snap(eng=ENG)
        snap["engagement_id"] = ENG_B
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False
        assert result["reason"] == "tampered_snapshot_hash"

    def test_replay_finds_correct_engagement(self, signing_env: Any) -> None:
        s1 = _snap(eng=ENG, confidence_score=80)
        s2 = _snap(eng=ENG_B, confidence_score=90)
        result = replay_confidence_snapshot(s1["snapshot_id"], [s1, s2])
        assert result["snapshot"]["engagement_id"] == ENG

    def test_drift_across_engagements_computes_delta(self, signing_env: Any) -> None:
        s1 = _snap(eng=ENG, confidence_score=65)
        s2 = _snap(eng=ENG_B, confidence_score=85)
        drift = calculate_confidence_drift(s1, s2)
        assert drift["delta"] == 20


# ---------------------------------------------------------------------------
# 16. Tamper Detection
# ---------------------------------------------------------------------------


class TestTamperDetection:
    def test_tampered_score_in_manifest_changes_hash(self, signing_env: Any) -> None:
        m = _manifest(confidence_score=80)
        auth = sign_confidence_manifest(m)
        m["confidence_score"] = 99
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is False

    def test_tampered_manifest_hash_in_manifest(self, signing_env: Any) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        m["manifest_hash"] = "00" * 32
        result = verify_confidence_manifest(m, auth)
        assert result["valid"] is False

    def test_tampered_snapshot_confidence_score(self, signing_env: Any) -> None:
        snap = _snap(confidence_score=80)
        snap["confidence_score"] = 99
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False

    def test_tampered_snapshot_tenant_id(self, signing_env: Any) -> None:
        snap = _snap()
        snap["tenant_id"] = "attacker-tenant"
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False

    def test_tampered_snapshot_manifest_hash(self, signing_env: Any) -> None:
        snap = _snap()
        snap["manifest_hash"] = "00" * 32
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False

    def test_tampered_snapshot_signature(self, signing_env: Any) -> None:
        snap = _snap()
        snap["snapshot_signature"] = "ff" * 64
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False
        assert result["reason"] == "signature_mismatch"

    def test_injected_extra_field_in_snapshot_tolerated(self, signing_env: Any) -> None:
        snap = _snap()
        result_before = verify_confidence_snapshot(snap)
        snap["future_field"] = "extended_governance"
        result_after = verify_confidence_snapshot(snap)
        assert result_before["valid"] is True
        assert result_after["valid"] is True

    def test_cross_tenant_snapshot_fails_verify(self, signing_env: Any) -> None:
        snap = _snap(tenant=TENANT)
        snap["tenant_id"] = TENANT_B
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is False

    def test_score_inflation_detected_as_anomaly(self) -> None:
        s1 = {
            "confidence_score": 60,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 80,
            "snapshot_signature": "bb" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        result = detect_confidence_anomalies([s1, s2])
        assert result["anomaly_detected"] is True
        assert any(a["type"] == "confidence_inflation" for a in result["anomalies"])

    def test_authority_version_change_detected(self) -> None:
        s1 = {
            "confidence_score": 80,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 80,
            "snapshot_signature": "bb" * 64,
            "authority_version": "old-authority-v0",
        }
        result = detect_confidence_anomalies([s1, s2])
        assert any(a["type"] == "authority_downgrade" for a in result["anomalies"])

    def test_manifest_authority_mismatch_blocks_replay(self, signing_env: Any) -> None:
        snap = _snap()
        result = replay_confidence_snapshot(
            snap["snapshot_id"],
            [snap],
            manifest_authority={"valid": False, "reason": "tampered"},
        )
        assert result["valid"] is False

    def test_corroboration_manipulation_detected(self) -> None:
        s1 = {
            "confidence_score": 70,
            "corroboration_score": 80,
            "snapshot_signature": "aa" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        s2 = {
            "confidence_score": 85,
            "corroboration_score": 20,
            "snapshot_signature": "bb" * 64,
            "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        }
        result = detect_confidence_anomalies([s1, s2])
        assert result["anomaly_detected"] is True


# ---------------------------------------------------------------------------
# 17. Performance
# ---------------------------------------------------------------------------


class TestPerformance:
    def test_100_signatures_under_100ms(self, signing_env: Any) -> None:
        m = _manifest()
        t0 = time.perf_counter()
        for _ in range(100):
            sign_confidence_manifest(m)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 100, f"100 signatures took {elapsed_ms:.1f}ms"

    def test_1000_signatures_under_500ms(self, signing_env: Any) -> None:
        m = _manifest()
        t0 = time.perf_counter()
        for _ in range(1000):
            sign_confidence_manifest(m)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 500, f"1000 signatures took {elapsed_ms:.1f}ms"

    def test_1000_timeline_points_under_250ms(self) -> None:
        snaps = [
            {
                "created_at": f"2026-01-{(i % 28) + 1:02d}T00:00:00Z",
                "confidence_score": i % 100,
                "confidence_level": "moderate",
                "snapshot_id": uuid.uuid4().hex,
            }
            for i in range(1000)
        ]
        t0 = time.perf_counter()
        generate_confidence_timeline(snaps)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 250, f"1000 timeline points took {elapsed_ms:.1f}ms"

    def test_1000_drift_calculations_under_250ms(self) -> None:
        pairs = [
            ({"confidence_score": i % 100}, {"confidence_score": (i + 5) % 100})
            for i in range(1000)
        ]
        t0 = time.perf_counter()
        for prev, curr in pairs:
            calculate_confidence_drift(prev, curr)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 250, f"1000 drift calcs took {elapsed_ms:.1f}ms"

    def test_1000_policy_evaluations_under_100ms(self) -> None:
        p = TrustPolicy("report_export", 80)
        crs = [_confidence_result(i % 100) for i in range(1000)]
        t0 = time.perf_counter()
        for cr in crs:
            evaluate_trust_policy(p, cr)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 100, f"1000 policy evals took {elapsed_ms:.1f}ms"

    def test_100_snapshot_verifications_under_100ms(self, signing_env: Any) -> None:
        snap = _snap()
        t0 = time.perf_counter()
        for _ in range(100):
            verify_confidence_snapshot(snap)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 100, f"100 snapshot verifications took {elapsed_ms:.1f}ms"

    def test_10000_timeline_points_under_500ms(self) -> None:
        snaps = [
            {
                "created_at": f"2026-01-01T00:00:{i % 60:02d}Z",
                "confidence_score": i % 100,
                "confidence_level": "moderate",
                "snapshot_id": uuid.uuid4().hex,
            }
            for i in range(10000)
        ]
        t0 = time.perf_counter()
        generate_confidence_timeline(snaps)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 500, f"10000 timeline points took {elapsed_ms:.1f}ms"

    def test_1000_anomaly_detections_under_250ms(self) -> None:
        snap_pairs = [
            [
                {
                    "confidence_score": 80,
                    "snapshot_signature": "aa" * 64,
                    "authority_version": CONFIDENCE_AUTHORITY_VERSION,
                },
                {
                    "confidence_score": 78,
                    "snapshot_signature": "bb" * 64,
                    "authority_version": CONFIDENCE_AUTHORITY_VERSION,
                },
            ]
            for _ in range(1000)
        ]
        t0 = time.perf_counter()
        for pair in snap_pairs:
            detect_confidence_anomalies(pair)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 250, f"1000 anomaly detections took {elapsed_ms:.1f}ms"


# ---------------------------------------------------------------------------
# 18. Future Node Compatibility
# ---------------------------------------------------------------------------


class TestFutureNodeCompatibility:
    def test_manifest_with_future_fields_accepted(self, signing_env: Any) -> None:
        m = _manifest()
        m["future_model_registry_hash"] = "abc"
        m["agi_governance_anchor"] = "xyz"
        result = sign_confidence_manifest(m)
        assert result["event_hash"]

    def test_snapshot_with_extra_fields_verifies(self, signing_env: Any) -> None:
        snap = _snap()
        snap["agent_decision_hash"] = "future-field"
        snap["model_deployment_id"] = "model-001"
        result = verify_confidence_snapshot(snap)
        assert result["valid"] is True

    def test_trust_policy_future_subject_type(self) -> None:
        for st in (
            "identity",
            "agent",
            "agi_governance",
            "model_deployment",
            "autonomous_system",
        ):
            p = TrustPolicy("agent_approval", 80, subject_type=st)
            result = evaluate_trust_policy(p, _confidence_result(85))
            assert result["allowed"] is True

    def test_policy_future_name_accepted(self) -> None:
        p = TrustPolicy("model_evaluation_gate", 90)
        result = evaluate_trust_policy(p, _confidence_result(95))
        assert result["allowed"] is True

    def test_timeline_extra_fields_ignored(self) -> None:
        snaps = [
            {
                "created_at": "2026-06-12T00:00:00Z",
                "confidence_score": 80,
                "confidence_level": "strong",
                "snapshot_id": "x",
                "future_field": "agent_trust_score_v2",
            }
        ]
        timeline = generate_confidence_timeline(snaps)
        assert len(timeline) == 1

    def test_drift_extra_fields_in_snapshots_ignored(self) -> None:
        s1 = {"confidence_score": 70, "future_field": "model_reliability_v3"}
        s2 = {"confidence_score": 85, "future_field": "agent_delegation_depth"}
        result = calculate_confidence_drift(s1, s2)
        assert result["delta"] == 15


# ---------------------------------------------------------------------------
# 19. AGI Governance Compatibility
# ---------------------------------------------------------------------------


class TestAGIGovernanceCompatibility:
    def test_agent_approval_policy_evaluates(self) -> None:
        p = TrustPolicy("agent_approval", 85, subject_type="agent")
        result = evaluate_trust_policy(p, _confidence_result(90))
        assert result["allowed"] is True

    def test_agent_autonomy_blocks_low_confidence(self) -> None:
        p = TrustPolicy("agent_autonomy", 95, subject_type="autonomous_system")
        result = evaluate_trust_policy(p, _confidence_result(88))
        assert result["allowed"] is False
        assert "7" in result["reason"]

    def test_agi_governance_subject_type_in_output(self) -> None:
        p = TrustPolicy("agent_execution", 80, subject_type="agi_governance")
        result = evaluate_trust_policy(p, _confidence_result(85))
        assert result["subject_type"] == "agi_governance"
        assert result["authority_version"] == CONFIDENCE_AUTHORITY_VERSION

    def test_future_policy_name_model_deployment(self) -> None:
        p = TrustPolicy("model_deployment", 92)
        result = evaluate_trust_policy(p, _confidence_result(94))
        assert result["allowed"] is True

    def test_agi_snapshot_carries_authority_version(self, signing_env: Any) -> None:
        snap = generate_confidence_snapshot(
            TENANT,
            ENG,
            {
                "confidence_score": 91,
                "confidence_level": "high_assurance",
                "agent_type": "autonomous_decision_engine",
            },
            {"manifest_hash": "cc" * 32},
        )
        assert snap["authority_version"] == CONFIDENCE_AUTHORITY_VERSION

    def test_agent_drift_timeline_works(self, signing_env: Any) -> None:
        snaps = []
        for i, score in enumerate([60, 70, 75, 82, 89]):
            snap = generate_confidence_snapshot(
                TENANT,
                ENG,
                {
                    "confidence_score": score,
                    "confidence_level": "moderate",
                    "agent_type": "llm_agent",
                },
                {"manifest_hash": f"{i:02x}" * 32},
            )
            snaps.append(snap)
        timeline = generate_confidence_timeline(snaps)
        assert len(timeline) == 5
        drift = calculate_confidence_drift(snaps[0], snaps[-1])
        assert drift["direction"] == "rapidly_improving"


# ---------------------------------------------------------------------------
# 20. Security Invariants
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    def test_confidence_authority_error_is_runtime_error(self) -> None:
        assert issubclass(ConfidenceAuthorityError, RuntimeError)

    def test_no_private_key_in_sign_manifest_output(self, signing_env: Any) -> None:
        m = _manifest()
        auth = sign_confidence_manifest(m)
        output_str = str(auth)
        assert _SEED_B64 not in output_str
        assert _SEED_B64[:10] not in output_str

    def test_no_private_key_in_snapshot_output(self, signing_env: Any) -> None:
        snap = _snap()
        snap_str = str(snap)
        assert _SEED_B64 not in snap_str

    def test_verify_functions_never_raise(self, signing_env: Any) -> None:
        bad_inputs2: list[Any] = [None, {}, {"event_hash": "x"}, 42, []]
        for bad in bad_inputs2:
            r = verify_confidence_manifest(bad, bad)  # type: ignore[arg-type]
            assert isinstance(r, dict)
        r2 = verify_confidence_snapshot(None)  # type: ignore[arg-type]
        assert isinstance(r2, dict)

    def test_detect_anomalies_never_raises(self) -> None:
        bad_inputs: list[Any] = [[], [None], [{}], [{"confidence_score": "not_int"}]]
        for bad in bad_inputs:
            try:
                detect_confidence_anomalies(bad)
            except Exception as e:
                pytest.fail(f"detect_confidence_anomalies raised: {e}")

    def test_replay_never_raises(self, signing_env: Any) -> None:
        arg_sets: list[tuple[str, list[Any]]] = [
            ("", []),
            ("missing", []),
            ("x", [{"snapshot_id": "y"}]),
        ]
        for args in arg_sets:
            result = replay_confidence_snapshot(*args)
            assert isinstance(result, dict)

    def test_empty_key_raises_confidence_authority_error(
        self, no_signing_env: Any
    ) -> None:
        with pytest.raises(ConfidenceAuthorityError):
            sign_confidence_manifest(_manifest())

    def test_invalid_base64_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", "NOT_VALID_BASE64!!!")
        with pytest.raises(ConfidenceAuthorityError):
            sign_confidence_manifest(_manifest())

    def test_wrong_length_seed_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        short_seed = base64.b64encode(b"tooshort").decode()
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", short_seed)
        with pytest.raises(ConfidenceAuthorityError):
            sign_confidence_manifest(_manifest())

    def test_policy_minimum_confidence_bounded(self) -> None:
        with pytest.raises(ValueError):
            TrustPolicy("report_export", -1)
        with pytest.raises(ValueError):
            TrustPolicy("report_export", 101)
        p = TrustPolicy("report_export", 0)
        result = evaluate_trust_policy(p, _confidence_result(0))
        assert result["allowed"] is True
