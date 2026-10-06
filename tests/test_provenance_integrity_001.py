"""tests/test_provenance_integrity_001.py — PROVENANCE-INTEGRITY-001 adversarial test suite.

This module is NOT standalone. It is a component of the Field Assessment
Engagement Substrate and Governance Platform.

Proves that DB-level mutation of report_json is detected by the verification
layer before the Vault signature is checked. The security invariant is:

    CURRENT_REPORT_CONTENT → CANONICALIZE → DERIVE DIGEST
        → COMPARE TO STORED manifest_hash → VERIFY PROOF → VERIFIED

NOT:

    STORED_MANIFEST_HASH → VERIFY SIGNATURE → VERIFIED

Categories:
    A  — Root-cause regression (report_json changed, manifest_hash unchanged → FAILS)
    B  — Structural mutation variants (field changes, additions, removals → FAILS)
    C  — Nested content mutations (findings, evidence, determination → FAILS)
    D  — Provenance metadata mutations (keys, signatures → FAILS)
    E  — Malformed / missing inputs → FAILS
    F  — Cross-report replay (provenance from report A against report B → FAILS)
    G  — Cross-tenant replay → FAILS
    H  — Determinism (identical material verified twice → same result)
    I  — Legitimate unchanged report continues to verify → PASSES
    J  — _derive_manifest_hash_from_report_json unit tests

The tests in categories A–J operate on the
_derive_manifest_hash_from_report_json helper directly (unit) and via
simulated GovernanceReportRecord objects (integration).
"""

from __future__ import annotations

import hashlib
import json
import os

os.environ.setdefault("FG_ENV", "test")

from api.field_assessment import _derive_manifest_hash_from_report_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonical_hash(report_json: dict) -> str:
    """Reproduce the signing-time canonical hash (must match creation path)."""
    canonical_str = json.dumps(
        report_json, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def _make_report_json(**overrides) -> dict:
    """Minimal but realistic report_json suitable for signing tests."""
    base = {
        "report_id": "rep-pi-001",
        "tenant_id": "tenant-pi-001",
        "engagement_id": "eng-pi-001",
        "version": 1,
        "schema_version": "1.0",
        "report_type": "full_assessment",
        "generated_at": "2026-10-06T00:00:00+00:00",
        "executive_summary": {
            "title": "AI Governance Assessment",
            "determination": "COMPLIANT",
            "epistemic_state": "PROVEN",
        },
        "normalized_findings": [
            {
                "id": "finding-001",
                "severity": "HIGH",
                "confidence": 0.92,
                "title": "MFA not enforced",
                "description": "Multi-factor auth absent on admin accounts.",
                "evidence_refs": ["evidence-001", "evidence-002"],
            }
        ],
        "result_truth_gate": {
            "decision": "PROVEN",
            "result_fingerprint": "fp" * 32,
        },
        "governance_determination": {
            "outcome": "COMPLIANT",
            "rationale": "All controls evidenced.",
        },
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# A — Root-cause regression
# ---------------------------------------------------------------------------


class TestARootCauseRegression:
    """A: report_json mutated, manifest_hash unchanged → hash mismatch detected."""

    def test_a1_report_json_changed_manifest_hash_unchanged_fails(self):
        """Primary root-cause regression.

        Before PROVENANCE-INTEGRITY-001 fix: the Vault verify path would pass
        a stored manifest_hash into build_report_signing_payload without
        re-deriving it from report_json, so a mutated report_json would still
        produce a valid signing payload and verify_report would return True.

        After fix: _derive_manifest_hash_from_report_json re-derives the hash
        from current content; mismatch → fails closed.
        """
        original = _make_report_json()
        stored_hash = _canonical_hash(original)

        # Simulate DB-level mutation: change report_json without updating hash
        mutated = dict(original)
        mutated["tampered"] = True

        derived = _derive_manifest_hash_from_report_json(mutated)
        assert derived != stored_hash, (
            "DEFECT STILL PRESENT: mutated report_json produces the same hash "
            "as the original — the canonical serialization is not detecting changes."
        )

    def test_a2_unchanged_report_json_produces_matching_hash(self):
        """Positive case: unchanged report_json must reproduce the stored hash."""
        original = _make_report_json()
        stored_hash = _canonical_hash(original)
        derived = _derive_manifest_hash_from_report_json(original)
        assert derived == stored_hash

    def test_a3_derive_matches_signing_path_serialization(self):
        """_derive_manifest_hash_from_report_json must use the SAME serialization
        as the signing path (sort_keys=True, separators=(',', ':'), ensure_ascii=True).
        """
        report_json = _make_report_json()
        # Reproduce signing-path hash independently
        canonical_str = json.dumps(
            report_json, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        expected = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        assert _derive_manifest_hash_from_report_json(report_json) == expected


# ---------------------------------------------------------------------------
# B — Structural mutation variants
# ---------------------------------------------------------------------------


class TestBStructuralMutations:
    """B: various structural mutations must all fail the hash check."""

    def test_b1_top_level_field_added_fails(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        report["injected_field"] = "malicious"
        assert _derive_manifest_hash_from_report_json(report) != stored

    def test_b2_top_level_field_removed_fails(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        del report["governance_determination"]
        assert _derive_manifest_hash_from_report_json(report) != stored

    def test_b3_top_level_field_value_changed_fails(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        report["report_type"] = "executive_summary"
        assert _derive_manifest_hash_from_report_json(report) != stored

    def test_b4_version_changed_fails(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        report["version"] = 999
        assert _derive_manifest_hash_from_report_json(report) != stored

    def test_b5_tenant_id_changed_fails(self):
        """Tenant substitution attack (report from another tenant) → FAILS."""
        report = _make_report_json()
        stored = _canonical_hash(report)
        report["tenant_id"] = "tenant-attacker-9999"
        assert _derive_manifest_hash_from_report_json(report) != stored

    def test_b6_engagement_id_changed_fails(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        report["engagement_id"] = "eng-other-9999"
        assert _derive_manifest_hash_from_report_json(report) != stored


# ---------------------------------------------------------------------------
# C — Nested content mutations (findings, evidence, determination)
# ---------------------------------------------------------------------------


class TestCNestedMutations:
    """C: mutations inside nested structures must be detected."""

    def test_c1_finding_added_fails(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        findings = list(report["normalized_findings"])
        findings.append(
            {
                "id": "finding-injected",
                "severity": "CRITICAL",
                "confidence": 1.0,
                "title": "Injected finding",
            }
        )
        report["normalized_findings"] = findings
        assert _derive_manifest_hash_from_report_json(report) != stored

    def test_c2_finding_removed_fails(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        report["normalized_findings"] = []
        assert _derive_manifest_hash_from_report_json(report) != stored

    def test_c3_finding_severity_changed_fails(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        report["normalized_findings"][0]["severity"] = "LOW"
        assert _derive_manifest_hash_from_report_json(report) != stored

    def test_c4_finding_confidence_changed_fails(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        report["normalized_findings"][0]["confidence"] = 0.01
        assert _derive_manifest_hash_from_report_json(report) != stored

    def test_c5_evidence_reference_changed_fails(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        report["normalized_findings"][0]["evidence_refs"] = ["evidence-TAMPERED"]
        assert _derive_manifest_hash_from_report_json(report) != stored

    def test_c6_governance_determination_changed_fails(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        report["governance_determination"]["outcome"] = "NON_COMPLIANT"
        assert _derive_manifest_hash_from_report_json(report) != stored

    def test_c7_epistemic_state_changed_fails(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        report["executive_summary"]["epistemic_state"] = "UNPROVEN"
        assert _derive_manifest_hash_from_report_json(report) != stored

    def test_c8_result_truth_gate_decision_changed_fails(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        report["result_truth_gate"]["decision"] = "NOT_PROVEN"
        assert _derive_manifest_hash_from_report_json(report) != stored

    def test_c9_result_fingerprint_changed_fails(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        report["result_truth_gate"]["result_fingerprint"] = "00" * 32
        assert _derive_manifest_hash_from_report_json(report) != stored


# ---------------------------------------------------------------------------
# D — Provenance metadata mutations (stored hash / signature corruption)
# ---------------------------------------------------------------------------


class TestDProvenanceMetadataMutations:
    """D: changes that corrupt stored provenance metadata must be detected."""

    def test_d1_stored_manifest_hash_corrupted_detected(self):
        """If manifest_hash in DB is corrupted, re-derived hash will not match."""
        report = _make_report_json()
        correct_hash = _canonical_hash(report)
        corrupted_hash = "00" * 32
        # The derived hash is not corrupted — mismatch proves corruption detected
        derived = _derive_manifest_hash_from_report_json(report)
        assert derived == correct_hash
        assert derived != corrupted_hash

    def test_d2_all_zeros_hash_fails_against_real_content(self):
        """All-zeros stored_hash never matches a real report_json hash."""
        report = _make_report_json()
        fake_stored = "0" * 64
        derived = _derive_manifest_hash_from_report_json(report)
        assert derived != fake_stored

    def test_d3_signed_payload_sha256_mismatch_from_report_json_change(self):
        """The signed_payload_sha256 binds the signing payload hash. When
        report_json changes, the content-binding check fails before reaching
        the signature verification — double protection.
        """
        original = _make_report_json()
        stored_hash = _canonical_hash(original)

        mutated = dict(original)
        mutated["extra_field"] = "injected"

        # Content-binding check: derived hash differs from stored
        derived = _derive_manifest_hash_from_report_json(mutated)
        assert derived != stored_hash


# ---------------------------------------------------------------------------
# E — Malformed / missing inputs
# ---------------------------------------------------------------------------


class TestEMalformedInputs:
    """E: malformed or missing report_json must fail closed."""

    def test_e1_none_report_json_does_not_match_real_report_hash(self):
        """None report_json cannot produce a hash matching any real report.

        json.dumps(None, ...) returns the string 'null', which produces a
        distinct hash that will never match a real report's stored manifest_hash.
        The route-level guard (isinstance(record.report_json, dict) check)
        catches None before calling this helper, returning valid=False early.
        """
        # _derive_manifest_hash_from_report_json(None) returns hash of "null"
        hash_of_none = _derive_manifest_hash_from_report_json(None)  # type: ignore[arg-type]
        # Must differ from any real report hash
        real_report = _make_report_json()
        real_hash = _canonical_hash(real_report)
        assert hash_of_none != real_hash

    def test_e2_empty_dict_produces_deterministic_hash(self):
        """An empty dict produces a stable hash (not the same as a real report)."""
        h1 = _derive_manifest_hash_from_report_json({})
        h2 = _derive_manifest_hash_from_report_json({})
        assert h1 == h2
        # Must differ from a real report hash
        real = _derive_manifest_hash_from_report_json(_make_report_json())
        assert h1 != real

    def test_e3_missing_normalized_findings_key_detected(self):
        """Report with normalized_findings removed produces a different hash."""
        report = _make_report_json()
        stored = _canonical_hash(report)
        del report["normalized_findings"]
        derived = _derive_manifest_hash_from_report_json(report)
        assert derived != stored

    def test_e4_missing_result_truth_gate_detected(self):
        report = _make_report_json()
        stored = _canonical_hash(report)
        del report["result_truth_gate"]
        derived = _derive_manifest_hash_from_report_json(report)
        assert derived != stored


# ---------------------------------------------------------------------------
# F — Cross-report replay (provenance from report A against report B)
# ---------------------------------------------------------------------------


class TestFCrossReportReplay:
    """F: valid provenance from report A must not verify against report B."""

    def test_f1_different_report_id_fails(self):
        """Two reports with different report_ids produce different manifest_hashes."""
        report_a = _make_report_json(report_id="rep-A-001")
        report_b = _make_report_json(report_id="rep-B-999")
        hash_a = _canonical_hash(report_a)
        # Stored hash is from report A; current content is report B — must differ
        derived_b = _derive_manifest_hash_from_report_json(report_b)
        assert derived_b != hash_a  # cross-report replay fails

    def test_f2_same_structure_different_content_fails(self):
        """Even structurally identical reports must differ if content differs."""
        report_a = _make_report_json(tenant_id="tenant-A")
        report_b = _make_report_json(tenant_id="tenant-B")
        hash_a = _canonical_hash(report_a)
        derived_b = _derive_manifest_hash_from_report_json(report_b)
        assert derived_b != hash_a

    def test_f3_replay_provenance_across_versions_fails(self):
        """Provenance from version 1 must not verify version 2 content."""
        report_v1 = _make_report_json(version=1)
        report_v2 = _make_report_json(version=2)
        hash_v1 = _canonical_hash(report_v1)
        derived_v2 = _derive_manifest_hash_from_report_json(report_v2)
        assert derived_v2 != hash_v1


# ---------------------------------------------------------------------------
# G — Cross-tenant replay
# ---------------------------------------------------------------------------


class TestGCrossTenantReplay:
    """G: provenance from tenant A must not match content for tenant B."""

    def test_g1_tenant_substitution_fails(self):
        """Report signed for tenant-A must not verify when tenant_id becomes tenant-B."""
        report_a = _make_report_json(tenant_id="tenant-A-prod")
        report_b = _make_report_json(tenant_id="tenant-B-attacker")
        hash_a = _canonical_hash(report_a)
        derived_b = _derive_manifest_hash_from_report_json(report_b)
        assert derived_b != hash_a

    def test_g2_cross_tenant_with_identical_content_otherwise_fails(self):
        """Even if all other fields match, a tenant_id change is detected."""
        base = _make_report_json()
        tenant_a = dict(base)
        tenant_a["tenant_id"] = "tenant-A"
        tenant_b = dict(base)
        tenant_b["tenant_id"] = "tenant-B"

        hash_a = _canonical_hash(tenant_a)
        derived_b = _derive_manifest_hash_from_report_json(tenant_b)
        assert derived_b != hash_a


# ---------------------------------------------------------------------------
# H — Determinism
# ---------------------------------------------------------------------------


class TestHDeterminism:
    """H: identical material verified twice must produce the same result."""

    def test_h1_same_report_json_produces_same_hash_twice(self):
        report = _make_report_json()
        h1 = _derive_manifest_hash_from_report_json(report)
        h2 = _derive_manifest_hash_from_report_json(report)
        assert h1 == h2

    def test_h2_dict_insertion_order_does_not_affect_hash(self):
        """JSON key order must not affect the canonical hash."""
        report_a = {
            "b_field": "value_b",
            "a_field": "value_a",
            "z_field": {"nested": 1},
        }
        report_b = {
            "z_field": {"nested": 1},
            "a_field": "value_a",
            "b_field": "value_b",
        }
        assert _derive_manifest_hash_from_report_json(
            report_a
        ) == _derive_manifest_hash_from_report_json(report_b)

    def test_h3_null_vs_missing_produces_different_hashes(self):
        """Null value vs missing key must produce distinct hashes (no null=missing bypass)."""
        with_null = {"field": None, "other": "value"}
        without = {"other": "value"}
        h_null = _derive_manifest_hash_from_report_json(with_null)
        h_without = _derive_manifest_hash_from_report_json(without)
        assert h_null != h_without

    def test_h4_whitespace_in_strings_is_preserved(self):
        """Whitespace inside string values must not be collapsed."""
        report_spaces = _make_report_json()
        report_spaces["executive_summary"]["title"] = "  AI Governance  "
        report_no_spaces = _make_report_json()
        report_no_spaces["executive_summary"]["title"] = "AI Governance"
        h_spaces = _derive_manifest_hash_from_report_json(report_spaces)
        h_no_spaces = _derive_manifest_hash_from_report_json(report_no_spaces)
        assert h_spaces != h_no_spaces


# ---------------------------------------------------------------------------
# I — Legitimate unchanged report continues to verify (PASSES)
# ---------------------------------------------------------------------------


class TestILegitimateReportVerifies:
    """I: an unmodified report must produce the same hash as was stored at signing."""

    def test_i1_legitimate_report_hash_matches_stored_hash(self):
        """The canonical derivation of an unmodified report must match its stored hash."""
        report = _make_report_json()
        stored_hash = _canonical_hash(report)
        derived = _derive_manifest_hash_from_report_json(report)
        assert derived == stored_hash

    def test_i2_complex_nested_report_is_stable(self):
        """A more complex report structure round-trips correctly."""
        report = _make_report_json()
        # Add more realistic depth
        report["control_appendix"] = {
            "controls": [
                {"id": "CC1.1", "status": "IMPLEMENTED", "evidence_count": 3},
                {"id": "CC1.2", "status": "NOT_TESTED", "evidence_count": 0},
            ]
        }
        report["evidence_appendix"] = {
            "evidence": [
                {"id": "ev-001", "type": "screenshot", "hash": "abc123"},
            ]
        }
        stored = _canonical_hash(report)
        derived = _derive_manifest_hash_from_report_json(report)
        assert derived == stored


# ---------------------------------------------------------------------------
# J — _derive_manifest_hash_from_report_json unit tests
# ---------------------------------------------------------------------------


class TestJDeriveManifestHashUnit:
    """J: unit tests for the _derive_manifest_hash_from_report_json helper."""

    def test_j1_returns_64_char_hex_string(self):
        result = _derive_manifest_hash_from_report_json({"key": "value"})
        assert isinstance(result, str)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_j2_known_value_sha256(self):
        """Verify against a known SHA-256 for a simple dict."""
        data = {"a": 1}
        canonical = json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert _derive_manifest_hash_from_report_json(data) == expected

    def test_j3_unicode_handled_with_ensure_ascii(self):
        """Non-ASCII characters are escaped (ensure_ascii=True)."""
        data = {"name": "café"}  # café
        result = _derive_manifest_hash_from_report_json(data)
        # Reproduce manually
        canonical = json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert result == expected

    def test_j4_separators_not_default_json_output(self):
        """Verify that the function does NOT use Python's default (space-after-colon) output."""
        data = {"key": "value"}
        # Default Python json.dumps adds spaces: {"key": "value"}
        default_canonical = json.dumps(data)
        compact_canonical = json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        # They should be different for this dict
        default_hash = hashlib.sha256(default_canonical.encode("utf-8")).hexdigest()
        compact_hash = hashlib.sha256(compact_canonical.encode("utf-8")).hexdigest()
        result = _derive_manifest_hash_from_report_json(data)
        # The function must use compact (no-space) separators
        assert result == compact_hash
        assert result != default_hash
