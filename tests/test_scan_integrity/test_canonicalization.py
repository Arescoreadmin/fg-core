"""
Tests for deterministic payload canonicalization.

L14-SCAN-INTEGRITY-001 — test_canonicalization.py

Verifies:
- Equivalent dicts produce the same digest
- Different dicts produce different digests
- Key-order variation produces the same digest
- Unicode NFC normalization
- Null field handling
- Schema version scope (1.0 vs 1.1 produce different digests)
- Timestamp ISO8601 UTC stability
- Large payload (1000-key dict) completes without error
"""

import hashlib

import pytest

from services.field_assessment.evidence_integrity import (
    canonicalize_payload,
    compute_payload_digest,
)


class TestCanonicalizePayload:
    """Unit tests for canonicalize_payload()."""

    def test_equivalent_dicts_same_digest(self):
        """Two structurally equivalent dicts must produce the same digest."""
        a = {"host": "example.com", "port": 443, "open": True}
        b = {"host": "example.com", "port": 443, "open": True}
        assert canonicalize_payload(a) == canonicalize_payload(b)

    def test_different_dicts_different_digest(self):
        """Dicts with different values must produce different digests."""
        a = {"host": "example.com", "port": 443}
        b = {"host": "example.com", "port": 80}
        assert canonicalize_payload(a) != canonicalize_payload(b)

    def test_key_order_invariant(self):
        """Key order must not affect the digest."""
        # Python 3.7+ dicts maintain insertion order, but canonicalization
        # must sort keys deterministically regardless.
        a = {"z": 1, "a": 2, "m": 3}
        b = {"a": 2, "m": 3, "z": 1}
        assert canonicalize_payload(a) == canonicalize_payload(b)

    def test_nested_key_order_invariant(self):
        """Nested key order must not affect the digest."""
        a = {"outer": {"z": 1, "a": 2}}
        b = {"outer": {"a": 2, "z": 1}}
        assert canonicalize_payload(a) == canonicalize_payload(b)

    def test_unicode_nfc_normalization(self):
        """Unicode NFC normalization — combining characters must canonicalize to NFC."""
        # "é" can be encoded as U+00E9 (precomposed) or U+0065 + U+0301 (decomposed)
        nfc_e = "é"  # precomposed é
        nfd_e = "é"  # decomposed e + combining acute accent
        a = {"key": nfc_e}
        b = {"key": nfd_e}
        # After NFC normalization both are equal
        assert canonicalize_payload(a) == canonicalize_payload(b)

    def test_null_fields_retained(self):
        """Null fields must be retained, not stripped."""
        with_null = {"host": "example.com", "extra": None}
        without_null = {"host": "example.com"}
        # They are different — nulls are NOT stripped
        assert canonicalize_payload(with_null) != canonicalize_payload(without_null)

    def test_null_null_equivalent(self):
        """Two dicts with matching null values must be equal."""
        a = {"host": None, "port": None}
        b = {"host": None, "port": None}
        assert canonicalize_payload(a) == canonicalize_payload(b)

    def test_schema_version_scoping_10_vs_11(self):
        """schema_version 1.0 and 1.1 must produce different digests for the same payload."""
        payload = {"host": "example.com", "port": 443}
        v10 = canonicalize_payload(payload, schema_version="1.0")
        v11 = canonicalize_payload(payload, schema_version="1.1")
        assert v10 != v11

    def test_schema_version_same_produces_same(self):
        """Same schema_version and same payload must produce the same bytes."""
        payload = {"host": "example.com", "port": 443}
        v10a = canonicalize_payload(payload, schema_version="1.0")
        v10b = canonicalize_payload(payload, schema_version="1.0")
        assert v10a == v10b

    def test_timestamp_iso8601_stable(self):
        """ISO8601 UTC timestamp in payload must produce a stable digest."""
        ts = "2026-11-06T14:30:00+00:00"
        payload = {"scan_id": "abc123", "collected_at": ts}
        a = canonicalize_payload(payload)
        b = canonicalize_payload(payload)
        assert a == b

    def test_large_payload_completes(self):
        """A 1000-key dict must canonicalize without error."""
        large = {f"key_{i:04d}": f"value_{i}" for i in range(1000)}
        result = canonicalize_payload(large)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_returns_utf8_bytes(self):
        """canonicalize_payload must return bytes (UTF-8 encoded JSON)."""
        payload = {"host": "example.com"}
        result = canonicalize_payload(payload)
        assert isinstance(result, bytes)

    def test_non_dict_raises(self):
        """Passing a non-dict to canonicalize_payload must raise TypeError."""
        with pytest.raises(TypeError):
            canonicalize_payload(["not", "a", "dict"])  # type: ignore[arg-type]

    def test_unicode_in_key(self):
        """Unicode characters in keys must be preserved after NFC normalization."""
        # Combining key character — NFC-normalized to precomposed form
        nfc_key = "école"  # école (precomposed)
        nfd_key = "école"  # e + combining accent + cole (decomposed)
        a = {nfc_key: "value"}
        b = {nfd_key: "value"}
        assert canonicalize_payload(a) == canonicalize_payload(b)


class TestComputePayloadDigest:
    """Unit tests for compute_payload_digest()."""

    def test_digest_format(self):
        """Digest must be 'sha256:<hex>' format."""
        payload = {"host": "example.com"}
        digest = compute_payload_digest(payload)
        assert digest.startswith("sha256:")
        hex_part = digest[len("sha256:") :]
        assert len(hex_part) == 64  # SHA-256 is 256 bits = 64 hex chars
        assert all(c in "0123456789abcdef" for c in hex_part)

    def test_digest_deterministic(self):
        """Same payload + schema_version must always produce the same digest."""
        payload = {"host": "example.com", "port": 443, "findings": ["TLS_WEAK"]}
        d1 = compute_payload_digest(payload)
        d2 = compute_payload_digest(payload)
        assert d1 == d2

    def test_digest_matches_manual_sha256(self):
        """The digest must match a manual SHA-256 of the canonical bytes."""
        payload = {"host": "example.com", "port": 443}
        raw = canonicalize_payload(payload, schema_version="1.0")
        expected_hex = hashlib.sha256(raw).hexdigest()
        digest = compute_payload_digest(payload, schema_version="1.0")
        assert digest == f"sha256:{expected_hex}"

    def test_digest_changes_on_mutation(self):
        """Mutating the payload must change the digest."""
        original = {"host": "example.com", "port": 443}
        mutated = {"host": "example.com", "port": 444}
        assert compute_payload_digest(original) != compute_payload_digest(mutated)

    def test_key_order_invariant_in_digest(self):
        """Key ordering must not affect the digest."""
        a = {"b": 2, "a": 1}
        b = {"a": 1, "b": 2}
        assert compute_payload_digest(a) == compute_payload_digest(b)

    def test_schema_version_1_0_vs_1_1(self):
        """Different schema_version must produce different digests."""
        payload = {"host": "example.com"}
        d10 = compute_payload_digest(payload, schema_version="1.0")
        d11 = compute_payload_digest(payload, schema_version="1.1")
        assert d10 != d11
