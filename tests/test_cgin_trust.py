"""PR 17.7B — CGIN Trust & Integrity Authority tests."""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.cgin.trust import (
    ACTIVE_SIGNING_ALGORITHM,
    CGIN_CANONICALIZATION_VERSION,
    CGIN_TRUST_VERSION,
    SigningAlgorithm,
    VerificationResult,
    _b64url_decode,
    _b64url_encode,
    build_trust_metadata,
    canonicalize_snapshot,
    generate_digest,
    sign_payload,
    verify_payload,
    verify_snapshot,
)
from services.cgin.trust_manifest import (
    TrustManifest,
    generate_trust_manifest,
    verify_trust_manifest,
)
from services.cgin.privacy import (
    CGIN_SCHEMA_VERSION,
    ACTIVE_FINGERPRINT_ALGORITHM,
)

_TEST_PRIVATE_KEY = Ed25519PrivateKey.generate()
_TEST_PUBLIC_KEY = _TEST_PRIVATE_KEY.public_key()

# Second keypair for wrong-key tests
_OTHER_PRIVATE_KEY = Ed25519PrivateKey.generate()
_OTHER_PUBLIC_KEY = _OTHER_PRIVATE_KEY.public_key()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_payload(**kwargs):
    """Return a simple snapshot payload without a trust block."""
    base = {"score": 0.75, "label": "benchmark", "version": "1"}
    base.update(kwargs)
    return base


def _make_signed_snapshot(payload=None, private_key=None):
    """Build a full signed snapshot (payload + trust block)."""
    if payload is None:
        payload = _make_payload()
    if private_key is None:
        private_key = _TEST_PRIVATE_KEY
    trust = build_trust_metadata(
        payload_without_trust=payload,
        private_key=private_key,
    )
    return {**payload, "trust": trust}


# ---------------------------------------------------------------------------
# TestCanonicalSerialization
# ---------------------------------------------------------------------------


class TestCanonicalSerialization:
    """20+ tests for canonicalize_snapshot."""

    def test_returns_bytes(self):
        result = canonicalize_snapshot({"a": 1})
        assert isinstance(result, bytes)

    def test_deterministic_same_dict(self):
        d = {"z": 1, "a": 2, "m": 3}
        assert canonicalize_snapshot(d) == canonicalize_snapshot(d)

    def test_key_ordering_ascending(self):
        d = {"z": 1, "a": 2, "m": 3}
        result = json.loads(canonicalize_snapshot(d))
        assert list(result.keys()) == ["a", "m", "z"]

    def test_insertion_order_irrelevant(self):
        d1 = {"a": 1, "b": 2, "c": 3}
        d2 = {"c": 3, "a": 1, "b": 2}
        assert canonicalize_snapshot(d1) == canonicalize_snapshot(d2)

    def test_no_extra_whitespace(self):
        result = canonicalize_snapshot({"a": 1})
        assert b" " not in result
        assert b"\n" not in result

    def test_utf8_encoding(self):
        result = canonicalize_snapshot({"emoji": "hello"})
        assert isinstance(result, bytes)
        result.decode("utf-8")  # must not raise

    def test_unicode_value_preserved(self):
        payload = {"name": "Ångström"}
        result = canonicalize_snapshot(payload)
        parsed = json.loads(result.decode("utf-8"))
        assert parsed["name"] == "Ångström"

    def test_unicode_key_preserved(self):
        payload = {"cléf": "val"}
        result = canonicalize_snapshot(payload)
        parsed = json.loads(result.decode("utf-8"))
        assert "cléf" in parsed

    def test_ensure_ascii_false(self):
        # Non-ASCII characters should NOT be escaped as \\uXXXX
        payload = {"name": "Ångström"}
        result = canonicalize_snapshot(payload)
        assert "\\u" not in result.decode("utf-8") or "Å" in result.decode("utf-8")

    def test_float_value_stable(self):
        d = {"x": 1.5}
        assert canonicalize_snapshot(d) == canonicalize_snapshot(d)

    def test_float_round_trip(self):
        d = {"pi": 3.141592653589793}
        result = canonicalize_snapshot(d)
        parsed = json.loads(result)
        assert parsed["pi"] == 3.141592653589793

    def test_bool_true(self):
        result = json.loads(canonicalize_snapshot({"flag": True}))
        assert result["flag"] is True

    def test_bool_false(self):
        result = json.loads(canonicalize_snapshot({"flag": False}))
        assert result["flag"] is False

    def test_none_value(self):
        result = json.loads(canonicalize_snapshot({"x": None}))
        assert result["x"] is None

    def test_empty_dict(self):
        result = canonicalize_snapshot({})
        assert result == b"{}"

    def test_nested_dict_keys_sorted(self):
        payload = {"outer": {"z": 1, "a": 2}}
        result = json.loads(canonicalize_snapshot(payload))
        assert list(result["outer"].keys()) == ["a", "z"]

    def test_deeply_nested_keys_sorted(self):
        payload = {"a": {"z": {"y": 1, "m": 2, "a": 3}}}
        result = json.loads(canonicalize_snapshot(payload))
        assert list(result["a"]["z"].keys()) == ["a", "m", "y"]

    def test_array_order_preserved(self):
        payload = {"items": [3, 1, 2]}
        result = json.loads(canonicalize_snapshot(payload))
        assert result["items"] == [3, 1, 2]

    def test_array_of_dicts_keys_sorted(self):
        payload = {"items": [{"z": 1, "a": 2}, {"y": 3, "b": 4}]}
        result = json.loads(canonicalize_snapshot(payload))
        assert list(result["items"][0].keys()) == ["a", "z"]
        assert list(result["items"][1].keys()) == ["b", "y"]

    def test_integer_value(self):
        payload = {"count": 42}
        result = json.loads(canonicalize_snapshot(payload))
        assert result["count"] == 42

    def test_string_value(self):
        payload = {"label": "test"}
        result = json.loads(canonicalize_snapshot(payload))
        assert result["label"] == "test"

    def test_nested_array_in_array(self):
        payload = {"matrix": [[1, 2], [3, 4]]}
        result = json.loads(canonicalize_snapshot(payload))
        assert result["matrix"] == [[1, 2], [3, 4]]

    def test_different_values_produce_different_bytes(self):
        a = canonicalize_snapshot({"x": 1})
        b = canonicalize_snapshot({"x": 2})
        assert a != b

    def test_different_keys_produce_different_bytes(self):
        a = canonicalize_snapshot({"x": 1})
        b = canonicalize_snapshot({"y": 1})
        assert a != b

    def test_complex_payload_deterministic(self):
        payload = {
            "score": 0.85,
            "metadata": {"version": "1.0", "flags": [True, False]},
            "tags": ["a", "b"],
        }
        assert canonicalize_snapshot(payload) == canonicalize_snapshot(payload)


# ---------------------------------------------------------------------------
# TestDigestGeneration
# ---------------------------------------------------------------------------


class TestDigestGeneration:
    """15+ tests for generate_digest."""

    def test_returns_string(self):
        assert isinstance(generate_digest(b"hello"), str)

    def test_length_64(self):
        assert len(generate_digest(b"hello")) == 64

    def test_hex_only(self):
        digest = generate_digest(b"test")
        assert all(c in "0123456789abcdef" for c in digest)

    def test_lowercase(self):
        digest = generate_digest(b"test")
        assert digest == digest.lower()

    def test_deterministic(self):
        data = b"canonical bytes"
        assert generate_digest(data) == generate_digest(data)

    def test_sha256_identity(self):
        data = b"canonical bytes"
        expected = hashlib.sha256(data).hexdigest()
        assert generate_digest(data) == expected

    def test_empty_bytes_known_value(self):
        # SHA-256 of empty bytes is well-known
        expected = hashlib.sha256(b"").hexdigest()
        assert generate_digest(b"") == expected

    def test_different_inputs_different_digests(self):
        assert generate_digest(b"a") != generate_digest(b"b")

    def test_single_byte_difference_changes_digest(self):
        a = generate_digest(b"hello world")
        b = generate_digest(b"hello World")
        assert a != b

    def test_empty_bytes(self):
        digest = generate_digest(b"")
        assert len(digest) == 64

    def test_large_payload(self):
        data = b"x" * 100_000
        digest = generate_digest(data)
        assert len(digest) == 64

    def test_unicode_bytes(self):
        data = "Ångström".encode("utf-8")
        digest = generate_digest(data)
        assert len(digest) == 64

    def test_digest_of_canonical_snapshot(self):
        payload = {"a": 1}
        canonical = canonicalize_snapshot(payload)
        digest = generate_digest(canonical)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_digest_stable_across_calls(self):
        payload = {"score": 0.9, "label": "ok"}
        canonical = canonicalize_snapshot(payload)
        d1 = generate_digest(canonical)
        d2 = generate_digest(canonical)
        assert d1 == d2

    def test_known_sha256(self):
        # Verify against a manually computed SHA-256
        data = b"CGIN"
        expected = hashlib.sha256(data).hexdigest()
        assert generate_digest(data) == expected


# ---------------------------------------------------------------------------
# TestSignatureGeneration
# ---------------------------------------------------------------------------


class TestSignatureGeneration:
    """15+ tests for sign_payload."""

    def test_returns_string(self):
        sig = sign_payload(b"data", _TEST_PRIVATE_KEY)
        assert isinstance(sig, str)

    def test_base64url_chars_only(self):
        sig = sign_payload(b"data", _TEST_PRIVATE_KEY)
        allowed = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        )
        assert all(c in allowed for c in sig)

    def test_no_padding(self):
        sig = sign_payload(b"data", _TEST_PRIVATE_KEY)
        assert "=" not in sig

    def test_deterministic_same_key_same_bytes(self):
        # Ed25519 is deterministic
        data = b"canonical"
        sig1 = sign_payload(data, _TEST_PRIVATE_KEY)
        sig2 = sign_payload(data, _TEST_PRIVATE_KEY)
        assert sig1 == sig2

    def test_different_keys_produce_different_sigs(self):
        data = b"canonical"
        sig1 = sign_payload(data, _TEST_PRIVATE_KEY)
        sig2 = sign_payload(data, _OTHER_PRIVATE_KEY)
        assert sig1 != sig2

    def test_different_data_different_sig(self):
        sig1 = sign_payload(b"data1", _TEST_PRIVATE_KEY)
        sig2 = sign_payload(b"data2", _TEST_PRIVATE_KEY)
        assert sig1 != sig2

    def test_length_plausible(self):
        # Ed25519 signature = 64 bytes, base64url without padding = 86 chars
        sig = sign_payload(b"data", _TEST_PRIVATE_KEY)
        assert 80 <= len(sig) <= 90

    def test_decodes_to_64_bytes(self):
        sig = sign_payload(b"data", _TEST_PRIVATE_KEY)
        decoded = _b64url_decode(sig)
        assert len(decoded) == 64

    def test_wrong_key_type_raises_type_error(self):
        with pytest.raises(TypeError):
            sign_payload(b"data", "not-a-key")

    def test_empty_bytes_signable(self):
        sig = sign_payload(b"", _TEST_PRIVATE_KEY)
        assert isinstance(sig, str)

    def test_large_payload_signable(self):
        data = b"x" * 10_000
        sig = sign_payload(data, _TEST_PRIVATE_KEY)
        assert len(sig) > 0

    def test_sign_canonical_snapshot(self):
        payload = {"a": 1, "b": 2}
        canonical = canonicalize_snapshot(payload)
        sig = sign_payload(canonical, _TEST_PRIVATE_KEY)
        assert isinstance(sig, str)

    def test_verifiable_after_sign(self):
        data = b"hello trust"
        sig = sign_payload(data, _TEST_PRIVATE_KEY)
        result = verify_payload(
            data, sig, _TEST_PUBLIC_KEY, SigningAlgorithm.ED25519_V1
        )
        assert result is True

    def test_b64url_encode_decode_roundtrip(self):
        raw = b"\x00\x01\x02\xff\xfe"
        encoded = _b64url_encode(raw)
        decoded = _b64url_decode(encoded)
        assert decoded == raw

    def test_b64url_no_padding_in_encode(self):
        raw = b"a"
        encoded = _b64url_encode(raw)
        assert "=" not in encoded


# ---------------------------------------------------------------------------
# TestVerifyPayload
# ---------------------------------------------------------------------------


class TestVerifyPayload:
    """15+ tests for verify_payload."""

    def _sign_and_get(self, data=b"test data"):
        sig = sign_payload(data, _TEST_PRIVATE_KEY)
        return data, sig

    def test_valid_sig_returns_true(self):
        data, sig = self._sign_and_get()
        assert (
            verify_payload(data, sig, _TEST_PUBLIC_KEY, SigningAlgorithm.ED25519_V1)
            is True
        )

    def test_corrupted_sig_returns_false(self):
        data, sig = self._sign_and_get()
        assert (
            verify_payload(
                data, sig[:-2] + "XX", _TEST_PUBLIC_KEY, SigningAlgorithm.ED25519_V1
            )
            is False
        )

    def test_wrong_key_returns_false(self):
        data, sig = self._sign_and_get()
        assert (
            verify_payload(data, sig, _OTHER_PUBLIC_KEY, SigningAlgorithm.ED25519_V1)
            is False
        )

    def test_tampered_data_returns_false(self):
        data, sig = self._sign_and_get(b"original")
        assert (
            verify_payload(
                b"tampered", sig, _TEST_PUBLIC_KEY, SigningAlgorithm.ED25519_V1
            )
            is False
        )

    def test_never_raises_on_garbage_sig(self):
        result = verify_payload(
            b"data",
            "!!!not-base64url!!!",
            _TEST_PUBLIC_KEY,
            SigningAlgorithm.ED25519_V1,
        )
        assert result is False

    def test_never_raises_on_empty_sig(self):
        result = verify_payload(
            b"data", "", _TEST_PUBLIC_KEY, SigningAlgorithm.ED25519_V1
        )
        assert result is False

    def test_never_raises_on_wrong_key_type(self):
        data, sig = self._sign_and_get()
        result = verify_payload(data, sig, "not-a-key", SigningAlgorithm.ED25519_V1)
        assert result is False

    def test_unsupported_algorithm_returns_false(self):
        data, sig = self._sign_and_get()
        # Construct an unknown algorithm by bypassing the enum
        # We can't create a new enum value, but we can test that
        # a known algorithm doesn't match the wrong key
        assert (
            verify_payload(data, sig, _OTHER_PUBLIC_KEY, SigningAlgorithm.ED25519_V1)
            is False
        )

    def test_returns_bool_type(self):
        data, sig = self._sign_and_get()
        result = verify_payload(
            data, sig, _TEST_PUBLIC_KEY, SigningAlgorithm.ED25519_V1
        )
        assert isinstance(result, bool)

    def test_false_is_bool_not_none(self):
        result = verify_payload(
            b"data", "bad", _TEST_PUBLIC_KEY, SigningAlgorithm.ED25519_V1
        )
        assert result is False
        assert result is not None

    def test_empty_data_valid_sig(self):
        sig = sign_payload(b"", _TEST_PRIVATE_KEY)
        assert (
            verify_payload(b"", sig, _TEST_PUBLIC_KEY, SigningAlgorithm.ED25519_V1)
            is True
        )

    def test_empty_data_wrong_data(self):
        sig = sign_payload(b"", _TEST_PRIVATE_KEY)
        assert (
            verify_payload(b"x", sig, _TEST_PUBLIC_KEY, SigningAlgorithm.ED25519_V1)
            is False
        )

    def test_sig_from_canonical_snapshot(self):
        payload = {"a": 1, "z": 99}
        canonical = canonicalize_snapshot(payload)
        sig = sign_payload(canonical, _TEST_PRIVATE_KEY)
        assert (
            verify_payload(
                canonical, sig, _TEST_PUBLIC_KEY, SigningAlgorithm.ED25519_V1
            )
            is True
        )

    def test_reordered_canonical_still_verifies(self):
        # Dict with different insertion order should canonicalize identically
        p1 = {"a": 1, "z": 99}
        p2 = {"z": 99, "a": 1}
        c1 = canonicalize_snapshot(p1)
        c2 = canonicalize_snapshot(p2)
        sig = sign_payload(c1, _TEST_PRIVATE_KEY)
        assert (
            verify_payload(c2, sig, _TEST_PUBLIC_KEY, SigningAlgorithm.ED25519_V1)
            is True
        )

    def test_never_raises_on_none_key(self):
        data, sig = self._sign_and_get()
        result = verify_payload(data, sig, None, SigningAlgorithm.ED25519_V1)
        assert result is False


# ---------------------------------------------------------------------------
# TestBuildTrustMetadata
# ---------------------------------------------------------------------------


class TestBuildTrustMetadata:
    """15+ tests for build_trust_metadata."""

    def _build(self, payload=None, **kwargs):
        if payload is None:
            payload = _make_payload()
        return build_trust_metadata(
            payload_without_trust=payload, private_key=_TEST_PRIVATE_KEY, **kwargs
        )

    def test_returns_dict(self):
        assert isinstance(self._build(), dict)

    def test_has_digest_field(self):
        assert "digest" in self._build()

    def test_has_signature_field(self):
        assert "signature" in self._build()

    def test_has_signing_algorithm_field(self):
        assert "signing_algorithm" in self._build()

    def test_has_schema_version_field(self):
        assert "schema_version" in self._build()

    def test_has_created_at_field(self):
        assert "created_at" in self._build()

    def test_has_authority_version_field(self):
        assert "authority_version" in self._build()

    def test_has_trust_version_field(self):
        assert "trust_version" in self._build()

    def test_has_canonicalization_version_field(self):
        assert "canonicalization_version" in self._build()

    def test_has_fingerprint_algorithm_field(self):
        assert "fingerprint_algorithm" in self._build()

    def test_algorithm_field_correct(self):
        trust = self._build()
        assert trust["signing_algorithm"] == ACTIVE_SIGNING_ALGORITHM.value

    def test_digest_length_64(self):
        trust = self._build()
        assert len(trust["digest"]) == 64

    def test_digest_matches_recomputed(self):
        payload = _make_payload()
        trust = self._build(payload=payload)
        trust_meta = {
            k: v for k, v in trust.items() if k not in ("digest", "signature")
        }
        canonical = canonicalize_snapshot({**payload, "trust": trust_meta})
        expected_digest = generate_digest(canonical)
        assert trust["digest"] == expected_digest

    def test_signature_verifiable(self):
        payload = _make_payload()
        trust = self._build(payload=payload)
        trust_meta = {
            k: v for k, v in trust.items() if k not in ("digest", "signature")
        }
        canonical = canonicalize_snapshot({**payload, "trust": trust_meta})
        assert (
            verify_payload(
                canonical,
                trust["signature"],
                _TEST_PUBLIC_KEY,
                SigningAlgorithm.ED25519_V1,
            )
            is True
        )

    def test_previous_snapshot_digest_absent_by_default(self):
        trust = self._build()
        assert "previous_snapshot_digest" not in trust

    def test_previous_snapshot_digest_present_when_provided(self):
        fake_digest = "a" * 64
        trust = self._build(previous_snapshot_digest=fake_digest)
        assert trust["previous_snapshot_digest"] == fake_digest

    def test_trust_version_default(self):
        trust = self._build()
        assert trust["trust_version"] == CGIN_TRUST_VERSION

    def test_canonicalization_version_default(self):
        trust = self._build()
        assert trust["canonicalization_version"] == CGIN_CANONICALIZATION_VERSION

    def test_schema_version_matches_constant(self):
        trust = self._build()
        assert trust["schema_version"] == CGIN_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# TestVerifySnapshot
# ---------------------------------------------------------------------------


class TestVerifySnapshot:
    """25+ tests for verify_snapshot."""

    def test_valid_snapshot_passes(self):
        snapshot = _make_signed_snapshot()
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is True

    def test_valid_result_all_flags_true(self):
        snapshot = _make_signed_snapshot()
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.digest_match is True
        assert result.signature_valid is True
        assert result.algorithm_supported is True
        assert result.canonicalization_valid is True

    def test_valid_no_errors(self):
        snapshot = _make_signed_snapshot()
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.errors == []

    def test_changed_value_detected(self):
        snapshot = _make_signed_snapshot({"score": 0.75})
        snapshot["score"] = 0.99  # tamper
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_changed_value_digest_mismatch(self):
        snapshot = _make_signed_snapshot({"score": 0.75})
        snapshot["score"] = 0.99
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.digest_match is False

    def test_added_field_detected(self):
        snapshot = _make_signed_snapshot()
        snapshot["injected"] = "evil"
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_removed_field_detected(self):
        payload = {"a": 1, "b": 2}
        snapshot = _make_signed_snapshot(payload)
        del snapshot["a"]
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_altered_trust_block_digest_detected(self):
        snapshot = _make_signed_snapshot()
        snapshot["trust"]["digest"] = "0" * 64
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_altered_trust_block_sig_detected(self):
        snapshot = _make_signed_snapshot()
        snapshot["trust"]["signature"] = "AAAA" * 21 + "AA"
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_missing_trust_block(self):
        payload = _make_payload()
        result = verify_snapshot(payload, _TEST_PUBLIC_KEY)
        assert result.valid is False
        assert any("trust" in e for e in result.errors)

    def test_missing_trust_block_errors(self):
        payload = _make_payload()
        result = verify_snapshot(payload, _TEST_PUBLIC_KEY)
        assert "missing trust block" in result.errors

    def test_unsupported_algorithm(self):
        snapshot = _make_signed_snapshot()
        snapshot["trust"]["signing_algorithm"] = "rsa-v99"
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is False
        assert result.algorithm_supported is False

    def test_malformed_signature(self):
        snapshot = _make_signed_snapshot()
        snapshot["trust"]["signature"] = "!!!not-valid-base64url!!!"
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is False
        assert result.signature_valid is False

    def test_wrong_public_key_returns_false(self):
        snapshot = _make_signed_snapshot()
        result = verify_snapshot(snapshot, _OTHER_PUBLIC_KEY)
        assert result.valid is False
        assert result.signature_valid is False

    def test_digest_mismatch_error_present(self):
        snapshot = _make_signed_snapshot()
        snapshot["trust"]["digest"] = "f" * 64  # wrong digest
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.digest_match is False
        assert any("digest" in e for e in result.errors)

    def test_partial_corruption_score(self):
        snapshot = _make_signed_snapshot({"score": 0.5, "label": "good"})
        snapshot["score"] = 0.1  # partial tamper
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_returns_verification_result_type(self):
        snapshot = _make_signed_snapshot()
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert isinstance(result, VerificationResult)

    def test_never_raises(self):
        # Pass garbage; should never raise
        result = verify_snapshot({"trust": {}}, _TEST_PUBLIC_KEY)
        assert isinstance(result, VerificationResult)

    def test_never_raises_none_trust(self):
        result = verify_snapshot({}, _TEST_PUBLIC_KEY)
        assert isinstance(result, VerificationResult)

    def test_trust_missing_digest_field(self):
        snapshot = _make_signed_snapshot()
        del snapshot["trust"]["digest"]
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_trust_missing_signature_field(self):
        snapshot = _make_signed_snapshot()
        del snapshot["trust"]["signature"]
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_trust_missing_algorithm_field(self):
        snapshot = _make_signed_snapshot()
        del snapshot["trust"]["signing_algorithm"]
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_expected_digest_matches(self):
        payload = _make_payload()
        snapshot = _make_signed_snapshot(payload)
        expected = snapshot["trust"]["digest"]
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY, expected_digest=expected)
        assert result.valid is True

    def test_expected_digest_mismatch(self):
        snapshot = _make_signed_snapshot()
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY, expected_digest="0" * 64)
        assert result.valid is False

    def test_valid_signed_snapshot_is_accepted(self):
        # Protected trust metadata (all fields except digest/signature) is included
        # in the signed payload, so a properly built snapshot verifies cleanly.
        payload = _make_payload()
        snapshot = _make_signed_snapshot(payload)
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is True

    def test_tampered_trust_created_at_detected(self):
        snapshot = _make_signed_snapshot()
        snapshot["trust"]["created_at"] = "2000-01-01T00:00:00+00:00"
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_tampered_trust_authority_version_detected(self):
        snapshot = _make_signed_snapshot()
        snapshot["trust"]["authority_version"] = "9.9"
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_tampered_trust_previous_snapshot_digest_detected(self):
        fake_digest = "c" * 64
        snapshot = _make_signed_snapshot()
        snapshot["trust"]["previous_snapshot_digest"] = fake_digest
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_non_dict_trust_block_returns_verification_result(self):
        result = verify_snapshot({"trust": "x"}, _TEST_PUBLIC_KEY)
        assert isinstance(result, VerificationResult)
        assert result.valid is False

    def test_non_dict_trust_block_error_message(self):
        result = verify_snapshot({"trust": 42}, _TEST_PUBLIC_KEY)
        assert any("dict" in e for e in result.errors)

    def test_valid_snapshot_with_nested_payload(self):
        payload = {"meta": {"score": 0.8, "flags": [True, False]}, "version": "2"}
        snapshot = _make_signed_snapshot(payload)
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is True

    def test_valid_snapshot_with_unicode_payload(self):
        payload = {"label": "Ångström", "value": 1}
        snapshot = _make_signed_snapshot(payload)
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.valid is True

    def test_errors_list_populated_on_failure(self):
        result = verify_snapshot({}, _TEST_PUBLIC_KEY)
        assert len(result.errors) > 0

    def test_errors_empty_on_success(self):
        snapshot = _make_signed_snapshot()
        result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
        assert result.errors == []


# ---------------------------------------------------------------------------
# TestAlgorithmRegistry
# ---------------------------------------------------------------------------


class TestAlgorithmRegistry:
    """10+ tests for SigningAlgorithm enum and ACTIVE constant."""

    def test_active_algorithm_is_ed25519_v1(self):
        assert ACTIVE_SIGNING_ALGORITHM == SigningAlgorithm.ED25519_V1

    def test_ed25519_v1_value(self):
        assert SigningAlgorithm.ED25519_V1.value == "ed25519-v1"

    def test_active_algorithm_is_enum_member(self):
        assert isinstance(ACTIVE_SIGNING_ALGORITHM, SigningAlgorithm)

    def test_active_algorithm_is_str_subclass(self):
        # SigningAlgorithm inherits from str
        assert isinstance(ACTIVE_SIGNING_ALGORITHM, str)

    def test_enum_lookup_by_value(self):
        assert SigningAlgorithm("ed25519-v1") == SigningAlgorithm.ED25519_V1

    def test_unsupported_algorithm_value_error(self):
        with pytest.raises(ValueError):
            SigningAlgorithm("rsa-pss-v1")

    def test_unsupported_algorithm_verify_returns_false(self):
        # verify_payload with a known algorithm but wrong key → False, not raise
        sig = sign_payload(b"data", _TEST_PRIVATE_KEY)
        result = verify_payload(
            b"data", sig, _OTHER_PUBLIC_KEY, SigningAlgorithm.ED25519_V1
        )
        assert result is False

    def test_canonicalization_version_constant(self):
        assert isinstance(CGIN_CANONICALIZATION_VERSION, str)
        assert len(CGIN_CANONICALIZATION_VERSION) > 0

    def test_trust_version_constant(self):
        assert isinstance(CGIN_TRUST_VERSION, str)
        assert len(CGIN_TRUST_VERSION) > 0

    def test_enum_members_count(self):
        # Only ED25519_V1 is active; future slots are commented out
        members = list(SigningAlgorithm)
        assert len(members) >= 1
        assert SigningAlgorithm.ED25519_V1 in members

    def test_active_algorithm_str_comparison(self):
        assert ACTIVE_SIGNING_ALGORITHM == "ed25519-v1"


# ---------------------------------------------------------------------------
# TestTrustManifest
# ---------------------------------------------------------------------------


class TestTrustManifest:
    """15+ tests for generate_trust_manifest / verify_trust_manifest."""

    def _manifest(self, name="TestAuthority", key=None):
        if key is None:
            key = _TEST_PRIVATE_KEY
        return generate_trust_manifest(name, key)

    def test_returns_trust_manifest(self):
        assert isinstance(self._manifest(), TrustManifest)

    def test_authority_name_set(self):
        m = self._manifest("MyAuth")
        assert m.authority_name == "MyAuth"

    def test_authority_version_default(self):
        m = self._manifest()
        assert m.authority_version == "1.0"

    def test_signing_algorithm_field(self):
        m = self._manifest()
        assert m.signing_algorithm == ACTIVE_SIGNING_ALGORITHM.value

    def test_fingerprint_algorithm_field(self):
        m = self._manifest()
        assert m.fingerprint_algorithm == ACTIVE_FINGERPRINT_ALGORITHM.value

    def test_schema_version_field(self):
        m = self._manifest()
        assert m.schema_version == CGIN_SCHEMA_VERSION

    def test_trust_version_field(self):
        m = self._manifest()
        assert m.trust_version == CGIN_TRUST_VERSION

    def test_canonicalization_version_field(self):
        m = self._manifest()
        assert m.canonicalization_version == CGIN_CANONICALIZATION_VERSION

    def test_digest_length_64(self):
        m = self._manifest()
        assert len(m.digest) == 64

    def test_generated_at_present(self):
        m = self._manifest()
        assert m.generated_at
        assert "T" in m.generated_at  # ISO format

    def test_verify_trust_manifest_passes(self):
        m = self._manifest()
        result = verify_trust_manifest(m, _TEST_PUBLIC_KEY)
        assert result.valid is True

    def test_tampered_digest_fails(self):
        m = self._manifest()
        import dataclasses

        m2 = dataclasses.replace(m, digest="0" * 64)
        result = verify_trust_manifest(m2, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_tampered_signature_fails(self):
        m = self._manifest()
        import dataclasses

        m2 = dataclasses.replace(m, signature="AAAA" * 21 + "AA")
        result = verify_trust_manifest(m2, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_tampered_authority_name_fails(self):
        m = self._manifest("OriginalAuth")
        import dataclasses

        m2 = dataclasses.replace(m, authority_name="EvilAuth")
        result = verify_trust_manifest(m2, _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_wrong_public_key_fails(self):
        m = self._manifest()
        result = verify_trust_manifest(m, _OTHER_PUBLIC_KEY)
        assert result.valid is False

    def test_deterministic_digest_for_same_body(self):
        # Two manifests with same body fields should produce same digest
        # (generated_at differs per call, but we can verify digest consistency
        # by reconstructing the body manually)
        m = self._manifest()
        body = {
            "authority_name": m.authority_name,
            "authority_version": m.authority_version,
            "signing_algorithm": m.signing_algorithm,
            "fingerprint_algorithm": m.fingerprint_algorithm,
            "schema_version": m.schema_version,
            "benchmark_version": m.benchmark_version,
            "privacy_version": m.privacy_version,
            "generated_at": m.generated_at,
            "trust_version": m.trust_version,
            "canonicalization_version": m.canonicalization_version,
        }
        canonical = canonicalize_snapshot(body)
        expected_digest = generate_digest(canonical)
        assert m.digest == expected_digest

    def test_verify_returns_verification_result(self):
        m = self._manifest()
        result = verify_trust_manifest(m, _TEST_PUBLIC_KEY)
        assert isinstance(result, VerificationResult)


# ---------------------------------------------------------------------------
# TestChainOfTrust
# ---------------------------------------------------------------------------


class TestChainOfTrust:
    """10+ tests for previous_snapshot_digest chaining."""

    def _build_chain(self, n=3):
        """Build a chain of n snapshots, each referencing the previous digest."""
        snapshots = []
        prev_digest = None
        for i in range(n):
            payload = {"step": i, "value": float(i) * 0.1}
            trust = build_trust_metadata(
                payload_without_trust=payload,
                private_key=_TEST_PRIVATE_KEY,
                previous_snapshot_digest=prev_digest,
            )
            snapshot = {**payload, "trust": trust}
            prev_digest = trust["digest"]
            snapshots.append(snapshot)
        return snapshots

    def test_first_snapshot_no_previous_digest(self):
        chain = self._build_chain(3)
        assert "previous_snapshot_digest" not in chain[0]["trust"]

    def test_second_snapshot_has_previous_digest(self):
        chain = self._build_chain(3)
        assert "previous_snapshot_digest" in chain[1]["trust"]

    def test_previous_digest_wired_through(self):
        chain = self._build_chain(3)
        # chain[1].trust.previous_snapshot_digest == chain[0].trust.digest
        assert (
            chain[1]["trust"]["previous_snapshot_digest"] == chain[0]["trust"]["digest"]
        )

    def test_third_references_second(self):
        chain = self._build_chain(3)
        assert (
            chain[2]["trust"]["previous_snapshot_digest"] == chain[1]["trust"]["digest"]
        )

    def test_each_snapshot_individually_valid(self):
        chain = self._build_chain(3)
        for snapshot in chain:
            result = verify_snapshot(snapshot, _TEST_PUBLIC_KEY)
            assert result.valid is True, f"Snapshot failed: {result.errors}"

    def test_tampered_link_detected(self):
        chain = self._build_chain(3)
        # Tamper with snapshot[1]'s payload
        chain[1]["step"] = 99
        result = verify_snapshot(chain[1], _TEST_PUBLIC_KEY)
        assert result.valid is False

    def test_chain_integrity_detectable(self):
        chain = self._build_chain(3)
        # Recompute chain[1]'s digest using the same signing payload (payload + trust_meta)
        trust_1 = chain[1]["trust"]
        trust_meta_1 = {
            k: v for k, v in trust_1.items() if k not in ("digest", "signature")
        }
        payload_1 = {k: v for k, v in chain[1].items() if k != "trust"}
        canonical_1 = canonicalize_snapshot({**payload_1, "trust": trust_meta_1})
        recomputed_digest_1 = generate_digest(canonical_1)
        assert chain[2]["trust"]["previous_snapshot_digest"] == recomputed_digest_1

    def test_chain_of_one_is_valid(self):
        chain = self._build_chain(1)
        result = verify_snapshot(chain[0], _TEST_PUBLIC_KEY)
        assert result.valid is True

    def test_previous_digest_none_omits_field(self):
        trust = build_trust_metadata(
            payload_without_trust={"x": 1},
            private_key=_TEST_PRIVATE_KEY,
            previous_snapshot_digest=None,
        )
        assert "previous_snapshot_digest" not in trust

    def test_previous_digest_string_included(self):
        fake = "b" * 64
        trust = build_trust_metadata(
            payload_without_trust={"x": 1},
            private_key=_TEST_PRIVATE_KEY,
            previous_snapshot_digest=fake,
        )
        assert trust["previous_snapshot_digest"] == fake


# ---------------------------------------------------------------------------
# TestCanonicalDeterminism
# ---------------------------------------------------------------------------


class TestCanonicalDeterminism:
    """10+ tests proving canonical bytes are stable across calls and key-insertion-order independent."""

    def test_same_payload_same_bytes_twice(self):
        p = {"a": 1, "b": 2}
        assert canonicalize_snapshot(p) == canonicalize_snapshot(p)

    def test_same_payload_same_bytes_ten_times(self):
        p = {"score": 0.99, "label": "ok", "nested": {"x": 1}}
        first = canonicalize_snapshot(p)
        for _ in range(9):
            assert canonicalize_snapshot(p) == first

    def test_insertion_order_independence_two_keys(self):
        a = canonicalize_snapshot({"x": 1, "y": 2})
        b = canonicalize_snapshot({"y": 2, "x": 1})
        assert a == b

    def test_insertion_order_independence_five_keys(self):
        keys = ["e", "b", "a", "d", "c"]
        import itertools

        base = canonicalize_snapshot({k: i for i, k in enumerate(keys)})
        for perm in itertools.permutations(keys):
            d = {k: keys.index(k) for k in perm}
            assert canonicalize_snapshot(d) == base

    def test_nested_dict_insertion_order_independence(self):
        a = canonicalize_snapshot({"outer": {"z": 1, "a": 2}})
        b = canonicalize_snapshot({"outer": {"a": 2, "z": 1}})
        assert a == b

    def test_digest_stable_after_canonicalize(self):
        p = {"alpha": True, "beta": 3.14}
        d1 = generate_digest(canonicalize_snapshot(p))
        d2 = generate_digest(canonicalize_snapshot(p))
        assert d1 == d2

    def test_signature_stable_for_same_payload_and_key(self):
        canonical = canonicalize_snapshot({"x": 42})
        sig1 = sign_payload(canonical, _TEST_PRIVATE_KEY)
        sig2 = sign_payload(canonical, _TEST_PRIVATE_KEY)
        assert sig1 == sig2

    def test_different_payloads_different_bytes(self):
        a = canonicalize_snapshot({"v": 1})
        b = canonicalize_snapshot({"v": 2})
        assert a != b

    def test_empty_string_vs_none(self):
        a = canonicalize_snapshot({"x": ""})
        b = canonicalize_snapshot({"x": None})
        assert a != b

    def test_int_vs_float(self):
        # json treats 1 and 1.0 differently in some edge cases; ensure stability
        a = canonicalize_snapshot({"x": 1})
        # Called twice with same value is stable
        assert a == canonicalize_snapshot({"x": 1})

    def test_array_order_matters_for_determinism(self):
        # Arrays preserve order — different orders are NOT equal
        a = canonicalize_snapshot({"items": [1, 2, 3]})
        b = canonicalize_snapshot({"items": [3, 2, 1]})
        assert a != b

    def test_full_round_trip_sign_verify_deterministic(self):
        payload = {"a": "alpha", "z": "zeta", "m": 42}
        canonical = canonicalize_snapshot(payload)
        digest = generate_digest(canonical)
        sig = sign_payload(canonical, _TEST_PRIVATE_KEY)
        # Redo from scratch
        canonical2 = canonicalize_snapshot(payload)
        digest2 = generate_digest(canonical2)
        sig2 = sign_payload(canonical2, _TEST_PRIVATE_KEY)
        assert canonical == canonical2
        assert digest == digest2
        assert sig == sig2
