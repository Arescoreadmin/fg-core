"""
PR 17.7A — CGIN Privacy Hardening tests.

Covers:
- services/cgin/privacy.py helpers
- All 6 fixed authority CGIN snapshots use tenant_fingerprint, not tenant_id
- Schema validation
- Already-correct authorities not broken
- Integration with actual engine classes using in-memory SQLite
"""

from __future__ import annotations

import hashlib
import uuid

import pytest
from sqlalchemy.orm import Session

from services.cgin.privacy import (
    ACTIVE_FINGERPRINT_ALGORITHM,
    CGIN_BENCHMARK_VERSION,
    CGIN_FINGERPRINT_NAMESPACE,
    CGIN_FINGERPRINT_VERSION,
    CGIN_FORBIDDEN_FIELDS,
    CGIN_NAMESPACE,
    CGIN_PRIVACY_VERSION,
    CGIN_SCHEMA_VERSION,
    FingerprintAlgorithm,
    _check_value,
    assert_snapshot_safe,
    build_cgin_metadata,
    fingerprint_tenant,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _uid() -> str:
    return uuid.uuid4().hex[:8]


# ---------------------------------------------------------------------------
# 1. fingerprint_tenant — basic properties
# ---------------------------------------------------------------------------


class TestFingerprintTenantBasic:
    """Tests 1–20: basic properties of fingerprint_tenant."""

    def test_returns_string(self):
        assert isinstance(fingerprint_tenant("tenant-abc"), str)

    def test_length_is_32(self):
        assert len(fingerprint_tenant("tenant-abc")) == 32

    def test_hex_chars_only(self):
        fp = fingerprint_tenant("tenant-abc")
        assert all(c in "0123456789abcdef" for c in fp)

    def test_deterministic_same_input(self):
        tid = "tenant-xyz"
        assert fingerprint_tenant(tid) == fingerprint_tenant(tid)

    def test_deterministic_third_call(self):
        tid = "tenant-repeat"
        fp1 = fingerprint_tenant(tid)
        fp2 = fingerprint_tenant(tid)
        fp3 = fingerprint_tenant(tid)
        assert fp1 == fp2 == fp3

    def test_different_tenants_different_fingerprints(self):
        assert fingerprint_tenant("tenant-a") != fingerprint_tenant("tenant-b")

    def test_empty_string_produces_result(self):
        fp = fingerprint_tenant("")
        assert isinstance(fp, str)
        assert len(fp) == 32

    def test_uuid_style_tenant(self):
        fp = fingerprint_tenant("550e8400-e29b-41d4-a716-446655440000")
        assert len(fp) == 32

    def test_short_tenant(self):
        assert len(fingerprint_tenant("x")) == 32

    def test_long_tenant(self):
        long_id = "t-" + "a" * 200
        assert len(fingerprint_tenant(long_id)) == 32

    def test_special_chars_in_tenant(self):
        fp = fingerprint_tenant("tenant/with:special@chars")
        assert len(fp) == 32

    def test_numeric_tenant(self):
        assert len(fingerprint_tenant("12345")) == 32

    def test_fingerprint_is_lowercase_hex(self):
        fp = fingerprint_tenant("some-tenant")
        assert fp == fp.lower()

    def test_matches_manual_sha256(self):
        tid = "test-tenant-manual"
        expected = hashlib.sha256(f"cgin:v1:{tid}".encode()).hexdigest()[:32]
        assert fingerprint_tenant(tid) == expected

    def test_prefix_in_hash_input(self):
        # "cgin:v1:" prefix must be used — different from raw sha256
        tid = "my-tenant"
        raw_hash = hashlib.sha256(tid.encode()).hexdigest()[:32]
        with_prefix = fingerprint_tenant(tid)
        assert raw_hash != with_prefix

    def test_version_tag_used(self):
        # Verify the version constant is reflected in the hash
        tid = "tenant-version-check"
        fp = fingerprint_tenant(tid)
        expected = hashlib.sha256(
            f"cgin:{CGIN_FINGERPRINT_VERSION}:{tid}".encode()
        ).hexdigest()[:32]
        assert fp == expected

    def test_two_similar_tenants_differ(self):
        a = fingerprint_tenant("tenant-001")
        b = fingerprint_tenant("tenant-001x")
        assert a != b

    def test_case_sensitive(self):
        assert fingerprint_tenant("TENANT") != fingerprint_tenant("tenant")

    def test_stable_known_value(self):
        # Regression guard: this value must never change
        expected = hashlib.sha256(b"cgin:v1:acme-corp").hexdigest()[:32]
        assert fingerprint_tenant("acme-corp") == expected

    def test_constants_defined(self):
        assert CGIN_FINGERPRINT_VERSION == "v1"
        assert CGIN_SCHEMA_VERSION == "2"
        assert CGIN_PRIVACY_VERSION == "1.0"


# ---------------------------------------------------------------------------
# 2. fingerprint_tenant — irreversibility
# ---------------------------------------------------------------------------


class TestFingerprintIrreversibility:
    """Tests 21–35: cannot recover tenant_id from fingerprint."""

    def test_fingerprint_does_not_contain_tenant_id(self):
        tid = "acme-corporation"
        fp = fingerprint_tenant(tid)
        assert tid not in fp

    def test_fingerprint_does_not_contain_partial_tenant(self):
        tid = "acme-12345"
        fp = fingerprint_tenant(tid)
        assert "acme" not in fp
        assert "12345" not in fp

    def test_fingerprint_not_base64_of_tenant(self):
        import base64

        tid = "reverse-me"
        fp = fingerprint_tenant(tid)
        try:
            decoded = base64.b64decode(fp + "==").decode("utf-8", errors="replace")
        except Exception:
            decoded = ""
        assert tid not in decoded

    def test_fingerprint_length_hides_tenant_length(self):
        # All fingerprints are 32 chars regardless of input length
        fps = [fingerprint_tenant(f"t-{'x' * i}") for i in range(1, 20)]
        assert all(len(fp) == 32 for fp in fps)

    def test_no_common_prefix_with_tenant(self):
        tid = "acme"
        fp = fingerprint_tenant(tid)
        # fingerprint shouldn't start with anything that looks like tenant
        assert not fp.startswith(tid[:2])

    def test_collision_resistance_sample(self):
        """100 distinct tenants should produce 100 distinct fingerprints."""
        tids = [f"tenant-{i:04d}" for i in range(100)]
        fps = [fingerprint_tenant(t) for t in tids]
        assert len(set(fps)) == 100

    def test_uuid_tenants_unique(self):
        uuids = [str(uuid.uuid4()) for _ in range(20)]
        fps = [fingerprint_tenant(u) for u in uuids]
        assert len(set(fps)) == 20

    def test_numeric_sequence_unique(self):
        fps = [fingerprint_tenant(str(i)) for i in range(50)]
        assert len(set(fps)) == 50

    def test_adjacent_strings_differ(self):
        for i in range(10):
            assert fingerprint_tenant(f"t-{i}") != fingerprint_tenant(f"t-{i + 1}")

    def test_fingerprint_not_in_any_known_word_list(self):
        words = ["tenant", "acme", "corp", "admin", "root", "user"]
        for w in words:
            fp = fingerprint_tenant(w)
            assert w not in fp

    def test_fingerprint_stable_across_python_restarts(self):
        # sha256 is deterministic; this test verifies no randomness
        tid = "stable-tenant-seed"
        expected = hashlib.sha256(f"cgin:v1:{tid}".encode()).hexdigest()[:32]
        for _ in range(5):
            assert fingerprint_tenant(tid) == expected

    def test_fingerprint_not_md5(self):
        tid = "check-not-md5"
        md5_hex = hashlib.md5(tid.encode()).hexdigest()[:32]
        assert fingerprint_tenant(tid) != md5_hex

    def test_fingerprint_not_sha1(self):
        tid = "check-not-sha1"
        sha1_hex = hashlib.sha1(tid.encode()).hexdigest()[:32]
        assert fingerprint_tenant(tid) != sha1_hex

    def test_single_char_tenants_all_unique(self):
        chars = "abcdefghijklmnopqrstuvwxyz"
        fps = [fingerprint_tenant(c) for c in chars]
        assert len(set(fps)) == len(chars)

    def test_whitespace_variants_differ(self):
        a = fingerprint_tenant("tenant-a")
        b = fingerprint_tenant("tenant-a ")  # trailing space
        c = fingerprint_tenant(" tenant-a")  # leading space
        assert a != b
        assert a != c
        assert b != c


# ---------------------------------------------------------------------------
# 3. assert_snapshot_safe — forbidden fields
# ---------------------------------------------------------------------------


class TestAssertSnapshotSafeForbiddenKeys:
    """Tests 36–55: assert_snapshot_safe catches forbidden keys."""

    def test_empty_dict_is_safe(self):
        assert_snapshot_safe({}, "any-tenant")

    def test_safe_snapshot_passes(self):
        snap = {
            "tenant_fingerprint": "abc123",
            "total": 5,
            "generated_at": "2026-01-01T00:00:00Z",
        }
        assert_snapshot_safe(snap, "some-tenant")

    def test_tenant_id_key_raises(self):
        with pytest.raises(ValueError, match="tenant_id"):
            assert_snapshot_safe({"tenant_id": "acme"}, "acme")

    def test_organization_name_raises(self):
        with pytest.raises(ValueError, match="organization_name"):
            assert_snapshot_safe({"organization_name": "Acme Corp"}, "t-1")

    def test_customer_name_raises(self):
        with pytest.raises(ValueError, match="customer_name"):
            assert_snapshot_safe({"customer_name": "Bob"}, "t-1")

    def test_tenant_slug_raises(self):
        with pytest.raises(ValueError, match="tenant_slug"):
            assert_snapshot_safe({"tenant_slug": "acme"}, "t-1")

    def test_multiple_forbidden_keys_raises(self):
        with pytest.raises(ValueError):
            assert_snapshot_safe({"tenant_id": "x", "organization_name": "y"}, "t-1")

    def test_tenant_fingerprint_allowed(self):
        # tenant_fingerprint is NOT a forbidden key
        snap = {"tenant_fingerprint": fingerprint_tenant("t-abc")}
        assert_snapshot_safe(snap, "t-abc")  # no raise

    def test_arbitrary_keys_allowed(self):
        snap = {"score": 95.0, "count": 10, "label": "EFFECTIVE"}
        assert_snapshot_safe(snap, "t-any")

    def test_none_tenant_id_skips_value_check(self):
        # When tenant_id is empty string, value check is skipped
        snap = {"tenant_fingerprint": "abcdef0123456789abcdef0123456789"}
        assert_snapshot_safe(snap, "")

    def test_forbidden_key_error_message(self):
        with pytest.raises(ValueError) as exc_info:
            assert_snapshot_safe({"tenant_id": "x"}, "t-1")
        assert "forbidden" in str(exc_info.value).lower()

    def test_nested_safe_passes(self):
        snap = {
            "tenant_fingerprint": "abc",
            "items": [{"score": 1}, {"score": 2}],
            "meta": {"version": "1.0"},
        }
        assert_snapshot_safe(snap, "t-nested")

    def test_number_values_ignored(self):
        snap = {"score": 99, "count": 1}
        assert_snapshot_safe(snap, "some-tenant")

    def test_none_values_ignored(self):
        snap = {"score": None, "delta": None}
        assert_snapshot_safe(snap, "t-none")

    def test_bool_values_ignored(self):
        snap = {"active": True, "expired": False}
        assert_snapshot_safe(snap, "t-bool")

    def test_list_value_without_tenant_id(self):
        snap = {"items": ["apple", "banana", "cherry"]}
        assert_snapshot_safe(snap, "no-match")

    def test_tuple_value_without_tenant_id(self):
        snap = {"pair": (1, 2)}
        assert_snapshot_safe(snap, "t-tuple")

    def test_returns_none_on_success(self):
        result = assert_snapshot_safe({"safe_field": "value"}, "t-1")
        assert result is None

    def test_dict_in_list_without_tenant_id(self):
        snap = {"items": [{"score": 1, "name": "ctrl-1"}]}
        assert_snapshot_safe(snap, "t-no-match")

    def test_deeply_nested_safe(self):
        snap = {"a": {"b": {"c": {"d": "value"}}}}
        assert_snapshot_safe(snap, "t-deep")


# ---------------------------------------------------------------------------
# 4. assert_snapshot_safe — value containment
# ---------------------------------------------------------------------------


class TestAssertSnapshotSafeValues:
    """Tests 56–70: assert_snapshot_safe catches raw tenant_id in values."""

    def test_raw_tenant_in_string_value_raises(self):
        tid = "acme-corp-123"
        snap = {"description": f"Data for {tid}"}
        with pytest.raises(ValueError, match="raw tenant_id"):
            assert_snapshot_safe(snap, tid)

    def test_raw_tenant_in_nested_dict_value_raises(self):
        tid = "secret-tenant"
        snap = {"meta": {"info": tid}}
        with pytest.raises(ValueError, match="raw tenant_id"):
            assert_snapshot_safe(snap, tid)

    def test_raw_tenant_in_list_value_raises(self):
        tid = "exposed-tenant"
        snap = {"items": [tid, "other"]}
        with pytest.raises(ValueError, match="raw tenant_id"):
            assert_snapshot_safe(snap, tid)

    def test_raw_tenant_in_nested_list_raises(self):
        tid = "deep-tenant"
        snap = {"outer": [{"inner": [tid]}]}
        with pytest.raises(ValueError, match="raw tenant_id"):
            assert_snapshot_safe(snap, tid)

    def test_partial_match_raises(self):
        tid = "acme"
        snap = {"label": "prefix-acme-suffix"}
        with pytest.raises(ValueError, match="raw tenant_id"):
            assert_snapshot_safe(snap, tid)

    def test_fingerprint_value_does_not_contain_tenant(self):
        tid = "my-real-tenant"
        fp = fingerprint_tenant(tid)
        snap = {"tenant_fingerprint": fp}
        # fingerprint should NOT contain raw tenant_id
        assert_snapshot_safe(snap, tid)

    def test_empty_tenant_id_skips_value_check(self):
        snap = {"label": "some-data"}
        # empty tenant_id → value check skipped → no raise
        assert_snapshot_safe(snap, "")

    def test_number_equal_to_tenant_not_checked(self):
        # Numbers can't "contain" a string tenant_id
        snap = {"count": 42}
        assert_snapshot_safe(snap, "42")  # should not raise (int, not str)

    def test_check_value_dict(self):
        with pytest.raises(ValueError):
            _check_value({"key": "tenant-xyz"}, "tenant-xyz")

    def test_check_value_list(self):
        with pytest.raises(ValueError):
            _check_value(["safe", "tenant-xyz", "ok"], "tenant-xyz")

    def test_check_value_tuple(self):
        with pytest.raises(ValueError):
            _check_value(("safe", "tenant-xyz"), "tenant-xyz")

    def test_check_value_safe_string(self):
        _check_value("safe-string", "different-tenant")

    def test_check_value_empty_tenant_skips(self):
        _check_value("any-value", "")

    def test_check_value_none_tenant(self):
        _check_value("any-value", "")

    def test_multiple_levels_all_clean(self):
        snap = {
            "tenant_fingerprint": fingerprint_tenant("t-abc"),
            "nested": {"count": 5, "items": ["ctrl-1", "ctrl-2"]},
            "meta": {"version": "2", "privacy_version": "1.0"},
        }
        assert_snapshot_safe(snap, "t-abc")


# ---------------------------------------------------------------------------
# 5. Engine integration tests (in-memory SQLite via build_app)
# ---------------------------------------------------------------------------


class TestControlEffectivenessPrivacy:
    """Tests 71–80: control_effectiveness CGIN snapshot uses tenant_fingerprint."""

    def test_snapshot_has_tenant_fingerprint_field(self, db):
        from services.control_effectiveness.engine import ControlEffectivenessEngine

        eng = ControlEffectivenessEngine(db, tenant_id="t-ce-priv-01")
        snap = eng.get_cgin_snapshot()
        assert hasattr(snap, "tenant_fingerprint")

    def test_snapshot_no_tenant_id_field(self, db):
        from services.control_effectiveness.engine import ControlEffectivenessEngine

        eng = ControlEffectivenessEngine(db, tenant_id="t-ce-priv-02")
        snap = eng.get_cgin_snapshot()
        assert not hasattr(snap, "tenant_id")

    def test_fingerprint_is_correct_hash(self, db):
        from services.control_effectiveness.engine import ControlEffectivenessEngine

        tid = "t-ce-hash-01"
        eng = ControlEffectivenessEngine(db, tenant_id=tid)
        snap = eng.get_cgin_snapshot()
        expected = hashlib.sha256(f"cgin:v1:{tid}".encode()).hexdigest()[:32]
        assert snap.tenant_fingerprint == expected

    def test_fingerprint_length(self, db):
        from services.control_effectiveness.engine import ControlEffectivenessEngine

        eng = ControlEffectivenessEngine(db, tenant_id="t-ce-len-01")
        snap = eng.get_cgin_snapshot()
        assert len(snap.tenant_fingerprint) == 32

    def test_different_tenants_different_fingerprints(self, db):
        from services.control_effectiveness.engine import ControlEffectivenessEngine

        snap_a = ControlEffectivenessEngine(db, tenant_id="t-ce-a").get_cgin_snapshot()
        snap_b = ControlEffectivenessEngine(db, tenant_id="t-ce-b").get_cgin_snapshot()
        assert snap_a.tenant_fingerprint != snap_b.tenant_fingerprint

    def test_snapshot_safe_assertion(self, db):
        from services.control_effectiveness.engine import ControlEffectivenessEngine

        tid = "t-ce-safe-01"
        eng = ControlEffectivenessEngine(db, tenant_id=tid)
        snap = eng.get_cgin_snapshot()
        assert_snapshot_safe(snap.model_dump(), tid)

    def test_empty_db_fingerprint_correct(self, db):
        from services.control_effectiveness.engine import ControlEffectivenessEngine

        tid = "t-ce-empty-01"
        eng = ControlEffectivenessEngine(db, tenant_id=tid)
        snap = eng.get_cgin_snapshot()
        assert snap.total_controls == 0
        expected = fingerprint_tenant(tid)
        assert snap.tenant_fingerprint == expected

    def test_fingerprint_deterministic_across_calls(self, db):
        from services.control_effectiveness.engine import ControlEffectivenessEngine

        tid = "t-ce-det-01"
        eng = ControlEffectivenessEngine(db, tenant_id=tid)
        snap1 = eng.get_cgin_snapshot()
        snap2 = eng.get_cgin_snapshot()
        assert snap1.tenant_fingerprint == snap2.tenant_fingerprint

    def test_tenant_fingerprint_not_in_schema_extra(self, db):
        from services.control_effectiveness.engine import ControlEffectivenessEngine
        from services.control_effectiveness.schemas import CGINEffectivenessSnapshot

        eng = ControlEffectivenessEngine(db, tenant_id="t-ce-schema")
        snap = eng.get_cgin_snapshot()
        assert isinstance(snap, CGINEffectivenessSnapshot)
        d = snap.model_dump()
        assert "tenant_fingerprint" in d
        assert "tenant_id" not in d

    def test_model_dump_no_forbidden_keys(self, db):
        from services.control_effectiveness.engine import ControlEffectivenessEngine

        tid = "t-ce-dump-01"
        eng = ControlEffectivenessEngine(db, tenant_id=tid)
        snap = eng.get_cgin_snapshot()
        d = snap.model_dump()
        forbidden = {"tenant_id", "organization_name", "customer_name", "tenant_slug"}
        assert not (forbidden & set(d.keys()))


class TestEvidenceFreshnessPrivacy:
    """Tests 81–90: evidence_freshness_authority CGIN snapshot."""

    def test_snapshot_has_tenant_fingerprint(self, db):
        from services.evidence_freshness_authority.engine import EvidenceFreshnessEngine

        eng = EvidenceFreshnessEngine(db, tenant_id="t-ef-priv-01")
        snap = eng.get_cgin_snapshot()
        assert hasattr(snap, "tenant_fingerprint")

    def test_snapshot_no_tenant_id(self, db):
        from services.evidence_freshness_authority.engine import EvidenceFreshnessEngine

        eng = EvidenceFreshnessEngine(db, tenant_id="t-ef-priv-02")
        snap = eng.get_cgin_snapshot()
        assert not hasattr(snap, "tenant_id")

    def test_fingerprint_is_correct(self, db):
        from services.evidence_freshness_authority.engine import EvidenceFreshnessEngine

        tid = "t-ef-hash-01"
        snap = EvidenceFreshnessEngine(db, tenant_id=tid).get_cgin_snapshot()
        assert snap.tenant_fingerprint == fingerprint_tenant(tid)

    def test_fingerprint_length(self, db):
        from services.evidence_freshness_authority.engine import EvidenceFreshnessEngine

        snap = EvidenceFreshnessEngine(db, tenant_id="t-ef-len").get_cgin_snapshot()
        assert len(snap.tenant_fingerprint) == 32

    def test_safe_assertion(self, db):
        from services.evidence_freshness_authority.engine import EvidenceFreshnessEngine

        tid = "t-ef-safe-01"
        snap = EvidenceFreshnessEngine(db, tenant_id=tid).get_cgin_snapshot()
        assert_snapshot_safe(snap.model_dump(), tid)

    def test_different_tenants_differ(self, db):
        from services.evidence_freshness_authority.engine import EvidenceFreshnessEngine

        snap_a = EvidenceFreshnessEngine(db, tenant_id="t-ef-aa").get_cgin_snapshot()
        snap_b = EvidenceFreshnessEngine(db, tenant_id="t-ef-bb").get_cgin_snapshot()
        assert snap_a.tenant_fingerprint != snap_b.tenant_fingerprint

    def test_no_forbidden_keys_in_dump(self, db):
        from services.evidence_freshness_authority.engine import EvidenceFreshnessEngine

        tid = "t-ef-dump-01"
        d = EvidenceFreshnessEngine(db, tenant_id=tid).get_cgin_snapshot().model_dump()
        forbidden = {"tenant_id", "organization_name", "customer_name"}
        assert not (forbidden & set(d.keys()))

    def test_schema_class_has_fingerprint_field(self):
        from services.evidence_freshness_authority.schemas import FreshnessCGINSnapshot

        fields = FreshnessCGINSnapshot.model_fields
        assert "tenant_fingerprint" in fields
        assert "tenant_id" not in fields

    def test_deterministic(self, db):
        from services.evidence_freshness_authority.engine import EvidenceFreshnessEngine

        tid = "t-ef-det-01"
        eng = EvidenceFreshnessEngine(db, tenant_id=tid)
        snap1 = eng.get_cgin_snapshot()
        snap2 = eng.get_cgin_snapshot()
        assert snap1.tenant_fingerprint == snap2.tenant_fingerprint

    def test_model_config_extra_forbid(self):
        from services.evidence_freshness_authority.schemas import FreshnessCGINSnapshot

        config = FreshnessCGINSnapshot.model_config
        assert config.get("extra") == "forbid"


class TestRemediationEffectivenessPrivacy:
    """Tests 91–100: remediation_effectiveness CGIN snapshot."""

    def test_snapshot_has_tenant_fingerprint(self, db):
        from services.remediation_effectiveness.engine import (
            RemediationEffectivenessEngine,
        )

        eng = RemediationEffectivenessEngine(db, tenant_id="t-re-priv-01")
        snap = eng.cgin_snapshot()
        assert hasattr(snap, "tenant_fingerprint")

    def test_snapshot_no_tenant_id(self, db):
        from services.remediation_effectiveness.engine import (
            RemediationEffectivenessEngine,
        )

        snap = RemediationEffectivenessEngine(
            db, tenant_id="t-re-priv-02"
        ).cgin_snapshot()
        assert not hasattr(snap, "tenant_id")

    def test_fingerprint_correct(self, db):
        from services.remediation_effectiveness.engine import (
            RemediationEffectivenessEngine,
        )

        tid = "t-re-hash-01"
        snap = RemediationEffectivenessEngine(db, tenant_id=tid).cgin_snapshot()
        assert snap.tenant_fingerprint == fingerprint_tenant(tid)

    def test_fingerprint_length(self, db):
        from services.remediation_effectiveness.engine import (
            RemediationEffectivenessEngine,
        )

        snap = RemediationEffectivenessEngine(db, tenant_id="t-re-len").cgin_snapshot()
        assert len(snap.tenant_fingerprint) == 32

    def test_safe_assertion(self, db):
        from services.remediation_effectiveness.engine import (
            RemediationEffectivenessEngine,
        )

        tid = "t-re-safe-01"
        snap = RemediationEffectivenessEngine(db, tenant_id=tid).cgin_snapshot()
        assert_snapshot_safe(snap.model_dump(), tid)

    def test_different_tenants_differ(self, db):
        from services.remediation_effectiveness.engine import (
            RemediationEffectivenessEngine,
        )

        snap_a = RemediationEffectivenessEngine(db, tenant_id="t-re-aa").cgin_snapshot()
        snap_b = RemediationEffectivenessEngine(db, tenant_id="t-re-bb").cgin_snapshot()
        assert snap_a.tenant_fingerprint != snap_b.tenant_fingerprint

    def test_no_forbidden_keys_in_dump(self, db):
        from services.remediation_effectiveness.engine import (
            RemediationEffectivenessEngine,
        )

        d = (
            RemediationEffectivenessEngine(db, tenant_id="t-re-dump")
            .cgin_snapshot()
            .model_dump()
        )
        forbidden = {"tenant_id", "organization_name", "customer_name"}
        assert not (forbidden & set(d.keys()))

    def test_schema_class(self):
        from services.remediation_effectiveness.schemas import CGINRemediationSnapshot

        fields = CGINRemediationSnapshot.model_fields
        assert "tenant_fingerprint" in fields
        assert "tenant_id" not in fields

    def test_deterministic(self, db):
        from services.remediation_effectiveness.engine import (
            RemediationEffectivenessEngine,
        )

        tid = "t-re-det-01"
        eng = RemediationEffectivenessEngine(db, tenant_id=tid)
        assert (
            eng.cgin_snapshot().tenant_fingerprint
            == eng.cgin_snapshot().tenant_fingerprint
        )

    def test_schema_model_config_extra_forbid(self):
        from services.remediation_effectiveness.schemas import CGINRemediationSnapshot

        assert CGINRemediationSnapshot.model_config.get("extra") == "forbid"


class TestVerificationAuthorityPrivacy:
    """Tests 101–110: verification_authority CGIN snapshot."""

    def test_snapshot_has_tenant_fingerprint(self, db):
        from services.verification_authority.engine import VerificationAuthorityEngine

        snap = VerificationAuthorityEngine(
            db, tenant_id="t-va-priv-01"
        ).get_cgin_snapshot()
        assert hasattr(snap, "tenant_fingerprint")

    def test_snapshot_no_tenant_id(self, db):
        from services.verification_authority.engine import VerificationAuthorityEngine

        snap = VerificationAuthorityEngine(
            db, tenant_id="t-va-priv-02"
        ).get_cgin_snapshot()
        assert not hasattr(snap, "tenant_id")

    def test_fingerprint_correct(self, db):
        from services.verification_authority.engine import VerificationAuthorityEngine

        tid = "t-va-hash-01"
        snap = VerificationAuthorityEngine(db, tenant_id=tid).get_cgin_snapshot()
        assert snap.tenant_fingerprint == fingerprint_tenant(tid)

    def test_fingerprint_length(self, db):
        from services.verification_authority.engine import VerificationAuthorityEngine

        snap = VerificationAuthorityEngine(db, tenant_id="t-va-len").get_cgin_snapshot()
        assert len(snap.tenant_fingerprint) == 32

    def test_safe_assertion(self, db):
        from services.verification_authority.engine import VerificationAuthorityEngine

        tid = "t-va-safe-01"
        snap = VerificationAuthorityEngine(db, tenant_id=tid).get_cgin_snapshot()
        assert_snapshot_safe(snap.model_dump(), tid)

    def test_different_tenants_differ(self, db):
        from services.verification_authority.engine import VerificationAuthorityEngine

        snap_a = VerificationAuthorityEngine(
            db, tenant_id="t-va-aa"
        ).get_cgin_snapshot()
        snap_b = VerificationAuthorityEngine(
            db, tenant_id="t-va-bb"
        ).get_cgin_snapshot()
        assert snap_a.tenant_fingerprint != snap_b.tenant_fingerprint

    def test_no_forbidden_keys_in_dump(self, db):
        from services.verification_authority.engine import VerificationAuthorityEngine

        d = (
            VerificationAuthorityEngine(db, tenant_id="t-va-dump")
            .get_cgin_snapshot()
            .model_dump()
        )
        forbidden = {"tenant_id", "organization_name", "customer_name"}
        assert not (forbidden & set(d.keys()))

    def test_schema_class(self):
        from services.verification_authority.schemas import WorkflowCginSnapshot

        fields = WorkflowCginSnapshot.model_fields
        assert "tenant_fingerprint" in fields
        assert "tenant_id" not in fields

    def test_schema_model_config_extra_forbid(self):
        from services.verification_authority.schemas import WorkflowCginSnapshot

        assert WorkflowCginSnapshot.model_config.get("extra") == "forbid"

    def test_deterministic(self, db):
        from services.verification_authority.engine import VerificationAuthorityEngine

        tid = "t-va-det-01"
        eng = VerificationAuthorityEngine(db, tenant_id=tid)
        snap1 = eng.get_cgin_snapshot()
        snap2 = eng.get_cgin_snapshot()
        assert snap1.tenant_fingerprint == snap2.tenant_fingerprint


class TestFreshnessScoreHistoryPrivacy:
    """Tests 111–120: freshness_score_history CGIN snapshot."""

    def test_snapshot_has_tenant_fingerprint(self, db):
        from services.freshness_score_history.engine import FreshnessScoreHistoryEngine

        snap = FreshnessScoreHistoryEngine(
            db, tenant_id="t-fsh-priv-01"
        ).get_cgin_trends()
        assert hasattr(snap, "tenant_fingerprint")

    def test_snapshot_no_tenant_id(self, db):
        from services.freshness_score_history.engine import FreshnessScoreHistoryEngine

        snap = FreshnessScoreHistoryEngine(
            db, tenant_id="t-fsh-priv-02"
        ).get_cgin_trends()
        assert not hasattr(snap, "tenant_id")

    def test_fingerprint_correct(self, db):
        from services.freshness_score_history.engine import FreshnessScoreHistoryEngine

        tid = "t-fsh-hash-01"
        snap = FreshnessScoreHistoryEngine(db, tenant_id=tid).get_cgin_trends()
        assert snap.tenant_fingerprint == fingerprint_tenant(tid)

    def test_fingerprint_length(self, db):
        from services.freshness_score_history.engine import FreshnessScoreHistoryEngine

        snap = FreshnessScoreHistoryEngine(db, tenant_id="t-fsh-len").get_cgin_trends()
        assert len(snap.tenant_fingerprint) == 32

    def test_safe_assertion(self, db):
        from services.freshness_score_history.engine import FreshnessScoreHistoryEngine

        tid = "t-fsh-safe-01"
        snap = FreshnessScoreHistoryEngine(db, tenant_id=tid).get_cgin_trends()
        assert_snapshot_safe(snap.model_dump(), tid)

    def test_different_tenants_differ(self, db):
        from services.freshness_score_history.engine import FreshnessScoreHistoryEngine

        snap_a = FreshnessScoreHistoryEngine(db, tenant_id="t-fsh-aa").get_cgin_trends()
        snap_b = FreshnessScoreHistoryEngine(db, tenant_id="t-fsh-bb").get_cgin_trends()
        assert snap_a.tenant_fingerprint != snap_b.tenant_fingerprint

    def test_no_forbidden_keys(self, db):
        from services.freshness_score_history.engine import FreshnessScoreHistoryEngine

        d = (
            FreshnessScoreHistoryEngine(db, tenant_id="t-fsh-dump")
            .get_cgin_trends()
            .model_dump()
        )
        forbidden = {"tenant_id", "organization_name"}
        assert not (forbidden & set(d.keys()))

    def test_schema_class(self):
        from services.freshness_score_history.schemas import FreshnessCGINTrendSnapshot

        fields = FreshnessCGINTrendSnapshot.model_fields
        assert "tenant_fingerprint" in fields
        assert "tenant_id" not in fields

    def test_schema_model_config_extra_forbid(self):
        from services.freshness_score_history.schemas import FreshnessCGINTrendSnapshot

        assert FreshnessCGINTrendSnapshot.model_config.get("extra") == "forbid"

    def test_deterministic(self, db):
        from services.freshness_score_history.engine import FreshnessScoreHistoryEngine

        tid = "t-fsh-det-01"
        eng = FreshnessScoreHistoryEngine(db, tenant_id=tid)
        snap1 = eng.get_cgin_trends()
        snap2 = eng.get_cgin_trends()
        assert snap1.tenant_fingerprint == snap2.tenant_fingerprint


# ---------------------------------------------------------------------------
# 6. Evidence authority CGIN bundle
# ---------------------------------------------------------------------------


class TestEvidenceAuthorityPrivacy:
    """Tests 121–130: evidence_authority CGIN bundle schema fields."""

    def test_bundle_schema_no_tenant_id(self):
        from services.evidence_authority.schemas import CGINSnapshotBundle

        fields = CGINSnapshotBundle.model_fields
        assert "tenant_fingerprint" in fields
        assert "tenant_id" not in fields

    def test_evidence_status_snapshot_no_tenant_id(self):
        from services.evidence_authority.schemas import EvidenceStatusSnapshot

        fields = EvidenceStatusSnapshot.model_fields
        assert "tenant_fingerprint" in fields
        assert "tenant_id" not in fields

    def test_verification_snapshot_no_tenant_id(self):
        from services.evidence_authority.schemas import VerificationSnapshot

        fields = VerificationSnapshot.model_fields
        assert "tenant_fingerprint" in fields
        assert "tenant_id" not in fields

    def test_coverage_snapshot_no_tenant_id(self):
        from services.evidence_authority.schemas import CoverageSnapshot

        fields = CoverageSnapshot.model_fields
        assert "tenant_fingerprint" in fields
        assert "tenant_id" not in fields

    def test_health_snapshot_no_tenant_id(self):
        from services.evidence_authority.schemas import HealthSnapshot

        fields = HealthSnapshot.model_fields
        assert "tenant_fingerprint" in fields
        assert "tenant_id" not in fields

    def test_bundle_extra_forbid(self):
        from services.evidence_authority.schemas import CGINSnapshotBundle

        assert CGINSnapshotBundle.model_config.get("extra") == "forbid"

    def test_evidence_status_extra_forbid(self):
        from services.evidence_authority.schemas import EvidenceStatusSnapshot

        assert EvidenceStatusSnapshot.model_config.get("extra") == "forbid"

    def test_verification_snapshot_extra_forbid(self):
        from services.evidence_authority.schemas import VerificationSnapshot

        assert VerificationSnapshot.model_config.get("extra") == "forbid"

    def test_coverage_snapshot_extra_forbid(self):
        from services.evidence_authority.schemas import CoverageSnapshot

        assert CoverageSnapshot.model_config.get("extra") == "forbid"

    def test_health_snapshot_extra_forbid(self):
        from services.evidence_authority.schemas import HealthSnapshot

        assert HealthSnapshot.model_config.get("extra") == "forbid"


# ---------------------------------------------------------------------------
# 7. Already-correct authorities still work (do not regress)
# ---------------------------------------------------------------------------


class TestAlreadyCorrectAuthoritiesUnchanged:
    """Tests 131–140: governance_chain and friends still emit tenant_fingerprint."""

    def test_governance_chain_schema_has_fingerprint(self):
        try:
            from services.governance_chain.schemas import CGINChainSnapshotBundle
        except ImportError:
            pytest.skip("governance_chain schema unavailable")
        fields = CGINChainSnapshotBundle.model_fields
        assert "tenant_fingerprint" in fields

    def test_governance_chain_fingerprint_algo(self, db):
        try:
            from services.governance_chain.engine import GovernanceChainEngine
        except ImportError:
            pytest.skip("governance_chain engine unavailable")
        tid = "t-gc-algo-01"
        eng = GovernanceChainEngine(db, tenant_id=tid)
        snap = eng.get_cgin_snapshot()
        expected = fingerprint_tenant(tid)
        assert snap.tenant_fingerprint == expected

    def test_governance_chain_no_raw_tenant_id_in_dump(self, db):
        try:
            from services.governance_chain.engine import GovernanceChainEngine
        except ImportError:
            pytest.skip("governance_chain engine unavailable")
        tid = "t-gc-safe-01"
        snap = GovernanceChainEngine(db, tenant_id=tid).get_cgin_snapshot()
        d = snap.model_dump()
        assert "tenant_id" not in d

    def test_privacy_module_importable(self):
        from services.cgin import privacy  # noqa: F401

        assert privacy.fingerprint_tenant is not None

    def test_fingerprint_tenant_importable_from_cgin(self):
        from services.cgin.privacy import fingerprint_tenant as ft

        assert callable(ft)

    def test_assert_snapshot_safe_importable(self):
        from services.cgin.privacy import assert_snapshot_safe as ssa

        assert callable(ssa)

    def test_all_six_schema_classes_have_fingerprint(self):
        from services.control_effectiveness.schemas import CGINEffectivenessSnapshot
        from services.evidence_authority.schemas import CGINSnapshotBundle
        from services.evidence_freshness_authority.schemas import FreshnessCGINSnapshot
        from services.freshness_score_history.schemas import FreshnessCGINTrendSnapshot
        from services.remediation_effectiveness.schemas import CGINRemediationSnapshot
        from services.verification_authority.schemas import WorkflowCginSnapshot

        for cls in [
            CGINEffectivenessSnapshot,
            CGINSnapshotBundle,
            FreshnessCGINSnapshot,
            FreshnessCGINTrendSnapshot,
            CGINRemediationSnapshot,
            WorkflowCginSnapshot,
        ]:
            assert "tenant_fingerprint" in cls.model_fields, (
                f"{cls.__name__} missing tenant_fingerprint"
            )
            assert "tenant_id" not in cls.model_fields, (
                f"{cls.__name__} still has tenant_id"
            )

    def test_all_six_schema_classes_no_tenant_id(self):
        from services.control_effectiveness.schemas import CGINEffectivenessSnapshot
        from services.evidence_authority.schemas import CGINSnapshotBundle
        from services.evidence_freshness_authority.schemas import FreshnessCGINSnapshot
        from services.freshness_score_history.schemas import FreshnessCGINTrendSnapshot
        from services.remediation_effectiveness.schemas import CGINRemediationSnapshot
        from services.verification_authority.schemas import WorkflowCginSnapshot

        for cls in [
            CGINEffectivenessSnapshot,
            CGINSnapshotBundle,
            FreshnessCGINSnapshot,
            FreshnessCGINTrendSnapshot,
            CGINRemediationSnapshot,
            WorkflowCginSnapshot,
        ]:
            assert "tenant_id" not in cls.model_fields

    def test_fingerprint_tenant_uses_same_algo_as_governance_chain(self, db):
        try:
            from services.governance_chain.engine import GovernanceChainEngine
        except ImportError:
            pytest.skip("governance_chain engine unavailable")
        from services.control_effectiveness.engine import ControlEffectivenessEngine

        tid = "t-algo-cross-01"
        gc_snap = GovernanceChainEngine(db, tenant_id=tid).get_cgin_snapshot()
        ce_snap = ControlEffectivenessEngine(db, tenant_id=tid).get_cgin_snapshot()
        assert gc_snap.tenant_fingerprint == ce_snap.tenant_fingerprint

    def test_health_signals_response_still_has_tenant_id(self):
        """HealthSignalsResponse (non-CGIN API schema) must NOT be changed."""
        from services.evidence_authority.schemas import HealthSignalsResponse

        fields = HealthSignalsResponse.model_fields
        assert "tenant_id" in fields


# ---------------------------------------------------------------------------
# FingerprintAlgorithm enum + namespace constants (items 1+2)
# ---------------------------------------------------------------------------


class TestFingerprintAlgorithm:
    def test_active_algorithm_is_sha256_cgin_v1(self):
        assert ACTIVE_FINGERPRINT_ALGORITHM is FingerprintAlgorithm.SHA256_CGIN_V1

    def test_algorithm_value_string(self):
        assert FingerprintAlgorithm.SHA256_CGIN_V1.value == "sha256-cgin-v1"

    def test_namespace_constant_format(self):
        assert CGIN_NAMESPACE == "cgin"
        assert CGIN_FINGERPRINT_VERSION == "v1"
        assert CGIN_FINGERPRINT_NAMESPACE == "cgin:v1"

    def test_fingerprint_uses_namespace_constant(self):
        tid = "t-ns-test-01"
        expected = hashlib.sha256(f"cgin:v1:{tid}".encode()).hexdigest()[:32]
        assert fingerprint_tenant(tid) == expected

    def test_fingerprint_explicit_algorithm_matches_active(self):
        tid = "t-algo-explicit-01"
        assert fingerprint_tenant(tid) == fingerprint_tenant(
            tid, FingerprintAlgorithm.SHA256_CGIN_V1
        )

    def test_unsupported_algorithm_raises(self):
        # Verify the guard in fingerprint_tenant raises for unknown algorithms.
        class FakeAlg:
            value = "unknown-alg"

        with pytest.raises(NotImplementedError):
            fingerprint_tenant("tid", FakeAlg())  # type: ignore[arg-type]

    def test_forbidden_fields_constant_includes_required_keys(self):
        assert "tenant_id" in CGIN_FORBIDDEN_FIELDS
        assert "organization_name" in CGIN_FORBIDDEN_FIELDS
        assert "customer_name" in CGIN_FORBIDDEN_FIELDS
        assert "tenant_slug" in CGIN_FORBIDDEN_FIELDS
        assert "account_id" in CGIN_FORBIDDEN_FIELDS

    def test_benchmark_version_constant_exists(self):
        assert CGIN_BENCHMARK_VERSION == "1.0"

    def test_privacy_version_constant_exists(self):
        assert CGIN_PRIVACY_VERSION == "1.0"

    def test_schema_version_constant_exists(self):
        assert CGIN_SCHEMA_VERSION == "2"


# ---------------------------------------------------------------------------
# build_cgin_metadata() helper (item 3)
# ---------------------------------------------------------------------------


class TestBuildCGINMetadata:
    def test_returns_dict_with_required_keys(self):
        meta = build_cgin_metadata(tenant_id="t-meta-01", authority_name="test_auth")
        required = {
            "tenant_fingerprint",
            "schema_version",
            "privacy_version",
            "benchmark_version",
            "fingerprint_algorithm",
            "authority_name",
            "authority_version",
            "generated_at",
        }
        assert required <= set(meta.keys())

    def test_tenant_fingerprint_matches_direct_call(self):
        tid = "t-meta-fp-01"
        meta = build_cgin_metadata(tenant_id=tid, authority_name="auth")
        assert meta["tenant_fingerprint"] == fingerprint_tenant(tid)

    def test_no_raw_tenant_id_in_output(self):
        tid = "t-meta-noleak-01"
        meta = build_cgin_metadata(tenant_id=tid, authority_name="auth")
        assert "tenant_id" not in meta
        assert tid not in str(meta)

    def test_authority_name_propagated(self):
        meta = build_cgin_metadata(tenant_id="t-x", authority_name="my_authority")
        assert meta["authority_name"] == "my_authority"

    def test_authority_version_default(self):
        meta = build_cgin_metadata(tenant_id="t-x", authority_name="auth")
        assert meta["authority_version"] == "1.0"

    def test_authority_version_custom(self):
        meta = build_cgin_metadata(
            tenant_id="t-x", authority_name="auth", authority_version="2.3"
        )
        assert meta["authority_version"] == "2.3"

    def test_schema_version_is_canonical(self):
        meta = build_cgin_metadata(tenant_id="t-x", authority_name="auth")
        assert meta["schema_version"] == CGIN_SCHEMA_VERSION

    def test_privacy_version_is_canonical(self):
        meta = build_cgin_metadata(tenant_id="t-x", authority_name="auth")
        assert meta["privacy_version"] == CGIN_PRIVACY_VERSION

    def test_fingerprint_algorithm_matches_active(self):
        meta = build_cgin_metadata(tenant_id="t-x", authority_name="auth")
        assert meta["fingerprint_algorithm"] == ACTIVE_FINGERPRINT_ALGORITHM.value

    def test_generated_at_is_iso_string(self):
        meta = build_cgin_metadata(tenant_id="t-x", authority_name="auth")
        from datetime import datetime

        # Must be parseable as ISO datetime
        dt = datetime.fromisoformat(meta["generated_at"])
        assert dt is not None

    def test_deterministic_fingerprint_across_calls(self):
        tid = "t-meta-det-01"
        meta1 = build_cgin_metadata(tenant_id=tid, authority_name="auth")
        meta2 = build_cgin_metadata(tenant_id=tid, authority_name="auth")
        assert meta1["tenant_fingerprint"] == meta2["tenant_fingerprint"]

    def test_different_tenants_different_fingerprints(self):
        meta1 = build_cgin_metadata(tenant_id="t-meta-a", authority_name="auth")
        meta2 = build_cgin_metadata(tenant_id="t-meta-b", authority_name="auth")
        assert meta1["tenant_fingerprint"] != meta2["tenant_fingerprint"]

    def test_assert_snapshot_safe_passes_on_metadata(self):
        tid = "t-meta-safe-01"
        meta = build_cgin_metadata(tenant_id=tid, authority_name="auth")
        # Should not raise — metadata itself is safe
        assert_snapshot_safe(meta, tid)


# ---------------------------------------------------------------------------
# Fuzz / property-based regression suite (item 6)
# ---------------------------------------------------------------------------


class TestFuzzAssertSnapshotSafe:
    """Property tests: assert_snapshot_safe must catch any leaked identifier
    regardless of nesting depth, key type, or value structure.
    """

    def _make_deeply_nested(self, tenant_id: str, depth: int) -> dict:
        obj: dict = {"leaf": tenant_id}
        for _ in range(depth):
            obj = {"nested": obj}
        return obj

    def test_fuzz_flat_forbidden_key(self):
        for key in CGIN_FORBIDDEN_FIELDS:
            with pytest.raises(ValueError, match="forbidden"):
                assert_snapshot_safe({key: "some_value"}, "t-fuzz-001")

    def test_fuzz_mixed_safe_and_forbidden(self):
        for key in CGIN_FORBIDDEN_FIELDS:
            with pytest.raises(ValueError):
                assert_snapshot_safe(
                    {"safe_key": "safe_value", key: "val", "other": 123},
                    "t-fuzz-002",
                )

    def test_fuzz_raw_tenant_id_in_list(self):
        tid = "t-fuzz-list-001"
        with pytest.raises(ValueError, match="raw tenant_id"):
            assert_snapshot_safe({"scores": [1, 2, tid, 3]}, tid)

    def test_fuzz_raw_tenant_id_in_nested_list(self):
        tid = "t-fuzz-nested-list-001"
        with pytest.raises(ValueError, match="raw tenant_id"):
            assert_snapshot_safe({"data": {"inner": [{"v": tid}]}}, tid)

    def test_fuzz_tenant_id_nested_depth_2(self):
        tid = "t-fuzz-d2-001"
        with pytest.raises(ValueError):
            assert_snapshot_safe(self._make_deeply_nested(tid, 2), tid)

    def test_fuzz_tenant_id_nested_depth_5(self):
        tid = "t-fuzz-d5-001"
        with pytest.raises(ValueError):
            assert_snapshot_safe(self._make_deeply_nested(tid, 5), tid)

    def test_fuzz_tenant_id_nested_depth_10(self):
        tid = "t-fuzz-d10-001"
        with pytest.raises(ValueError):
            assert_snapshot_safe(self._make_deeply_nested(tid, 10), tid)

    def test_fuzz_safe_payload_no_raise(self):
        tid = "t-fuzz-safe-001"
        fingerprint = fingerprint_tenant(tid)
        safe = {
            "tenant_fingerprint": fingerprint,
            "scores": [1.0, 2.0, 3.0],
            "distribution": {"A": 5, "B": 3},
            "metadata": {"version": "1.0"},
        }
        assert_snapshot_safe(safe, tid)  # must not raise

    def test_fuzz_empty_payload_safe(self):
        assert_snapshot_safe({}, "t-fuzz-empty-001")  # must not raise

    def test_fuzz_numeric_values_ignored(self):
        tid = "t-fuzz-nums-001"
        safe = {"score": 42.5, "count": 100, "flag": True}
        assert_snapshot_safe(safe, tid)  # numbers are safe

    def test_fuzz_none_values_ignored(self):
        tid = "t-fuzz-none-001"
        safe = {"score": None, "other": None}
        assert_snapshot_safe(safe, tid)  # None is safe

    def test_fuzz_multiple_forbidden_keys_reports_them(self):
        with pytest.raises(ValueError, match="forbidden"):
            assert_snapshot_safe(
                {"tenant_id": "x", "organization_name": "y"}, "t-fuzz-multi-001"
            )

    def test_fuzz_substring_not_leaked(self):
        """Partial tenant_id substrings in unrelated values should not trigger."""
        tid = "t-fuzz-sub-001"
        partial = tid[:5]  # "t-fuz" — a prefix of tenant_id, not the full thing
        safe = {"safe_field": partial, "score": 1.0}
        # partial does not equal full tid, so no leak
        assert_snapshot_safe(safe, tid)  # must not raise

    def test_fuzz_fingerprint_value_is_safe(self):
        """The fingerprint itself should never trigger the raw-tenant-id check."""
        tid = "t-fuzz-fp-safe-001"
        fingerprint = fingerprint_tenant(tid)
        safe = {"tenant_fingerprint": fingerprint}
        assert_snapshot_safe(safe, tid)  # fingerprint ≠ tenant_id → no raise

    def test_fuzz_many_random_safe_tenants(self):
        """20 randomly-generated tenants, all safe payloads — none should raise."""
        import random
        import string

        rng = random.Random(42)
        for _ in range(20):
            tid = "t-" + "".join(
                rng.choices(string.ascii_lowercase + string.digits, k=12)
            )
            fp = fingerprint_tenant(tid)
            payload = {
                "tenant_fingerprint": fp,
                "score": rng.random() * 100,
                "count": rng.randint(0, 1000),
            }
            assert_snapshot_safe(payload, tid)  # must not raise

    def test_fuzz_many_random_unsafe_tenants_caught(self):
        """20 randomly-generated tenants, all with leaked tenant_id — all should raise."""
        import random
        import string

        rng = random.Random(99)
        for _ in range(20):
            tid = "t-" + "".join(
                rng.choices(string.ascii_lowercase + string.digits, k=12)
            )
            payload = {"tenant_id": tid, "score": 1.0}
            with pytest.raises(ValueError):
                assert_snapshot_safe(payload, tid)


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(build_app):
    from api.db import get_engine

    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session
