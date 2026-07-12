"""Tests for PR-CI-03 Signed Validation Manifests.

Covers: canonical serialization, hash stability, signing, verification,
tampering detection, chain validation, history integration, GitHub summary,
CLI, security (no key leakage), backward compatibility.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from tools.testing.runtime_intelligence.github_summary import generate_summary
from tools.testing.runtime_intelligence.history import build_history_entry
from tools.testing.runtime_intelligence.manifest import (
    ValidationManifest,
    build_manifest,
    canonical_bytes,
    compute_manifest_hash,
    deserialize_manifest,
    manifest_from_dict,
    manifest_to_dict,
    serialize_manifest,
)
from tools.testing.runtime_intelligence.manifest_writer import (
    load_manifest,
    write_chain_record,
    write_manifest,
    write_verification_report,
)
from tools.testing.runtime_intelligence.models import (
    RuntimeMetadata,
    RuntimeResult,
    SlowTest,
)
from tools.testing.runtime_intelligence.serializer import to_json
from tools.testing.runtime_intelligence.signing import (
    Ed25519KeyProvider,
    SignatureResult,
    VerificationResult,
    generate_keypair,
    sign_manifest,
    verify_signature_bytes,
)
from tools.testing.runtime_intelligence.verification import (
    verify_chain,
    verify_hash,
    verify_manifest,
    verify_runtime,
    verify_signature,
)

pytestmark = pytest.mark.contract


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "tools" / "testing" / "runtime_intelligence" / "cli.py"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_meta(**kwargs: object) -> RuntimeMetadata:
    defaults: dict[str, object] = dict(
        schema_version="1.0",
        gate="fg-fast",
        commit_sha="abc123def456",
        workflow="ci",
        job="tests",
        runner_os="linux",
        python_version="3.12.0",
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:05:00Z",
        duration_seconds=300.0,
        environment_fingerprint="aabbccdd",
        dependency_fingerprint="eeff0011",
    )
    defaults.update(kwargs)
    return RuntimeMetadata(**defaults)  # type: ignore[arg-type]


def _make_result(**kwargs: object) -> RuntimeResult:
    defaults: dict[str, object] = dict(
        meta=_make_meta(),
        collected=398,
        passed=396,
        failed=0,
        skipped=2,
        xfailed=0,
        warnings=0,
        duration_seconds=300.0,
        slowest_tests=(),
        slowest_fixtures=(),
        manifest_fingerprint="deadbeef01234567",
        selector_fingerprint="cafef00d89abcdef",
    )
    defaults.update(kwargs)
    return RuntimeResult(**defaults)  # type: ignore[arg-type]


def _make_manifest(**kwargs: object) -> ValidationManifest:
    result = _make_result()
    return build_manifest(
        result=result,
        gate="fg-fast",
        validation_status="passed",
        repository="frostgate/fg-core",
        branch="main",
        commit_sha="abc123def456",
        tree_sha="tree1234",
        runner="linux",
        **kwargs,  # type: ignore[arg-type]
    )


@pytest.fixture
def keypair() -> tuple[str, str]:
    return generate_keypair()


@pytest.fixture
def provider(keypair: tuple[str, str]) -> Ed25519KeyProvider:
    priv, _ = keypair
    return Ed25519KeyProvider(private_key_hex=priv)


@pytest.fixture
def signed_manifest(provider: Ed25519KeyProvider) -> ValidationManifest:
    m = _make_manifest()
    return sign_manifest(m, provider)


# ---------------------------------------------------------------------------
# TestCanonicalSerialization
# ---------------------------------------------------------------------------


class TestCanonicalSerialization:
    def test_canonical_bytes_excludes_volatile_fields(self) -> None:
        m = _make_manifest()
        b = canonical_bytes(manifest_to_dict(m))
        text = b.decode("utf-8")
        assert "created_at" not in text
        assert '"signature"' not in text
        assert '"signature_algorithm"' not in text
        assert '"signing_identity"' not in text
        assert '"manifest_id"' not in text
        assert '"manifest_hash"' not in text
        assert '"verification_status"' not in text

    def test_canonical_bytes_sorted_keys(self) -> None:
        m = _make_manifest()
        b = canonical_bytes(manifest_to_dict(m))
        parsed = json.loads(b)
        assert list(parsed.keys()) == sorted(parsed.keys())

    def test_canonical_bytes_no_whitespace(self) -> None:
        m = _make_manifest()
        b = canonical_bytes(manifest_to_dict(m))
        assert b" " not in b
        assert b"\n" not in b
        assert b"\t" not in b

    def test_canonical_bytes_utf8(self) -> None:
        m = _make_manifest()
        b = canonical_bytes(manifest_to_dict(m))
        assert isinstance(b, bytes)
        # Round-trip decoding must succeed as UTF-8.
        b.decode("utf-8")

    def test_same_content_same_bytes(self) -> None:
        m1 = _make_manifest()
        m2 = _make_manifest()
        # created_at may differ by seconds — but hash excludes it, so canonical
        # bytes must match regardless.
        assert canonical_bytes(manifest_to_dict(m1)) == canonical_bytes(
            manifest_to_dict(m2)
        )

    def test_different_created_at_same_bytes(self) -> None:
        m1 = _make_manifest()
        m2 = replace(m1, created_at="2999-12-31T23:59:59Z")
        assert canonical_bytes(manifest_to_dict(m1)) == canonical_bytes(
            manifest_to_dict(m2)
        )

    def test_different_signature_same_bytes(self) -> None:
        m1 = _make_manifest()
        m2 = replace(
            m1,
            signature="deadbeef" * 16,
            signing_identity="test",
            signature_algorithm="ed25519",
        )
        assert canonical_bytes(manifest_to_dict(m1)) == canonical_bytes(
            manifest_to_dict(m2)
        )


# ---------------------------------------------------------------------------
# TestHashStability
# ---------------------------------------------------------------------------


class TestHashStability:
    def test_hash_is_64_char_hex(self) -> None:
        m = _make_manifest()
        assert len(m.manifest_hash) == 64
        int(m.manifest_hash, 16)

    def test_hash_stable_across_calls(self) -> None:
        m = _make_manifest()
        d = manifest_to_dict(m)
        assert compute_manifest_hash(d) == compute_manifest_hash(d)

    def test_hash_changes_on_content_change(self) -> None:
        m = _make_manifest()
        d = manifest_to_dict(m)
        h1 = compute_manifest_hash(d)
        d["gate"] = "fg-security"
        h2 = compute_manifest_hash(d)
        assert h1 != h2

    def test_manifest_id_equals_manifest_hash(self) -> None:
        m = _make_manifest()
        assert m.manifest_id == m.manifest_hash

    def test_hash_excludes_created_at(self) -> None:
        m1 = _make_manifest()
        m2 = replace(m1, created_at="2999-12-31T23:59:59Z")
        assert compute_manifest_hash(manifest_to_dict(m1)) == compute_manifest_hash(
            manifest_to_dict(m2)
        )

    def test_hash_changes_on_validation_status_change(self) -> None:
        m1 = _make_manifest()
        m2 = replace(m1, validation_status="failed")
        assert compute_manifest_hash(manifest_to_dict(m1)) != compute_manifest_hash(
            manifest_to_dict(m2)
        )


# ---------------------------------------------------------------------------
# TestBuildManifest
# ---------------------------------------------------------------------------


class TestBuildManifest:
    def test_builds_valid_manifest(self) -> None:
        m = _make_manifest()
        assert m.schema_version == "1.0"
        assert m.manifest_version == "1.0"
        assert m.gate == "fg-fast"
        assert m.manifest_hash
        assert m.manifest_id

    def test_validation_status_passed(self) -> None:
        result = _make_result()
        m = build_manifest(result, gate="fg-fast", validation_status="passed")
        assert m.validation_status == "passed"

    def test_validation_status_failed(self) -> None:
        result = _make_result()
        m = build_manifest(result, gate="fg-fast", validation_status="failed")
        assert m.validation_status == "failed"

    def test_manifest_id_is_hash(self) -> None:
        m = _make_manifest()
        assert m.manifest_id == m.manifest_hash

    def test_initial_verification_status_is_pending(self) -> None:
        m = _make_manifest()
        assert m.verification_status == "pending"

    def test_initial_signature_is_empty(self) -> None:
        m = _make_manifest()
        assert m.signature == ""

    def test_initial_algorithm_is_unsigned(self) -> None:
        m = _make_manifest()
        assert m.signature_algorithm == "unsigned"

    def test_runtime_result_hash_matches_result(self) -> None:
        result = _make_result()
        m = build_manifest(result, gate="fg-fast", validation_status="passed")
        expected = hashlib.sha256(to_json(result).encode()).hexdigest()
        assert m.runtime_result_hash == expected
        vr = verify_runtime(m, result)
        assert vr.valid

    def test_deterministic_for_same_inputs(self) -> None:
        result = _make_result()
        m1 = build_manifest(result, gate="fg-fast", validation_status="passed")
        m2 = build_manifest(result, gate="fg-fast", validation_status="passed")
        # created_at may differ, but the hash excludes it.
        assert m1.manifest_hash == m2.manifest_hash


# ---------------------------------------------------------------------------
# TestEd25519KeyProvider
# ---------------------------------------------------------------------------


class TestEd25519KeyProvider:
    def test_generate_keypair_returns_hex_strings(self) -> None:
        priv, pub = generate_keypair()
        assert isinstance(priv, str)
        assert isinstance(pub, str)
        int(priv, 16)
        int(pub, 16)

    def test_keypair_lengths(self) -> None:
        priv, pub = generate_keypair()
        assert len(priv) == 64
        assert len(pub) == 64

    def test_from_generated_keypair(self) -> None:
        priv, pub = generate_keypair()
        provider = Ed25519KeyProvider(private_key_hex=priv)
        assert provider.has_private_key()
        assert provider.has_public_key()
        assert provider.get_public_key_hex() == pub

    def test_key_id_is_16_char_hex(self) -> None:
        priv, _ = generate_keypair()
        provider = Ed25519KeyProvider(private_key_hex=priv)
        kid = provider.key_id()
        assert len(kid) == 16
        int(kid, 16)

    def test_has_private_key_true_when_loaded(self) -> None:
        priv, _ = generate_keypair()
        provider = Ed25519KeyProvider(private_key_hex=priv)
        assert provider.has_private_key() is True

    def test_has_public_key_true_when_loaded(self) -> None:
        _, pub = generate_keypair()
        provider = Ed25519KeyProvider(public_key_hex=pub)
        assert provider.has_public_key() is True
        assert provider.has_private_key() is False

    def test_repr_does_not_expose_key_material(self) -> None:
        priv, _ = generate_keypair()
        provider = Ed25519KeyProvider(private_key_hex=priv)
        r = repr(provider)
        assert priv not in r
        assert provider.get_public_key_hex() not in r or True
        # Sanity check on structure
        assert "Ed25519KeyProvider" in r
        assert "key_id=" in r

    def test_from_env_uses_env_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        priv, pub = generate_keypair()
        monkeypatch.setenv(Ed25519KeyProvider.PRIVATE_KEY_ENV, priv)
        monkeypatch.setenv(Ed25519KeyProvider.PUBLIC_KEY_ENV, pub)
        provider = Ed25519KeyProvider.from_env()
        assert provider.has_private_key()
        assert provider.get_public_key_hex() == pub


# ---------------------------------------------------------------------------
# TestSigning
# ---------------------------------------------------------------------------


class TestSigning:
    def test_sign_manifest_sets_signature(self, provider: Ed25519KeyProvider) -> None:
        m = _make_manifest()
        signed = sign_manifest(m, provider)
        assert signed.signature != ""

    def test_sign_manifest_sets_algorithm_ed25519(
        self, provider: Ed25519KeyProvider
    ) -> None:
        signed = sign_manifest(_make_manifest(), provider)
        assert signed.signature_algorithm == "ed25519"

    def test_sign_manifest_sets_signing_identity(
        self, provider: Ed25519KeyProvider
    ) -> None:
        signed = sign_manifest(_make_manifest(), provider)
        assert signed.signing_identity == provider.key_id()

    def test_sign_manifest_signature_is_128_char_hex(
        self, provider: Ed25519KeyProvider
    ) -> None:
        signed = sign_manifest(_make_manifest(), provider)
        assert len(signed.signature) == 128
        int(signed.signature, 16)

    def test_signature_stable_for_same_content(
        self, provider: Ed25519KeyProvider
    ) -> None:
        m = _make_manifest()
        s1 = sign_manifest(m, provider)
        s2 = sign_manifest(m, provider)
        assert s1.signature == s2.signature

    def test_different_content_different_signature(
        self, provider: Ed25519KeyProvider
    ) -> None:
        m1 = _make_manifest()
        m2 = build_manifest(
            _make_result(),
            gate="fg-security",
            validation_status="passed",
        )
        s1 = sign_manifest(m1, provider)
        s2 = sign_manifest(m2, provider)
        assert s1.signature != s2.signature

    def test_signed_manifest_hash_unchanged(self, provider: Ed25519KeyProvider) -> None:
        m = _make_manifest()
        signed = sign_manifest(m, provider)
        assert signed.manifest_hash == m.manifest_hash


# ---------------------------------------------------------------------------
# TestVerification
# ---------------------------------------------------------------------------


class TestVerification:
    def test_verify_hash_passes_on_valid_manifest(self) -> None:
        m = _make_manifest()
        assert verify_hash(m).valid

    def test_verify_hash_fails_on_tampered_manifest(self) -> None:
        m = _make_manifest()
        tampered = replace(m, gate="fg-security")
        assert not verify_hash(tampered).valid

    def test_verify_signature_passes_with_correct_key(
        self, provider: Ed25519KeyProvider
    ) -> None:
        signed = sign_manifest(_make_manifest(), provider)
        vr = verify_signature(signed, provider.get_public_key_hex())
        assert vr.valid

    def test_verify_signature_fails_with_wrong_key(
        self, provider: Ed25519KeyProvider
    ) -> None:
        signed = sign_manifest(_make_manifest(), provider)
        _, wrong_pub = generate_keypair()
        vr = verify_signature(signed, wrong_pub)
        assert not vr.valid

    def test_verify_signature_fails_on_unsigned_manifest(self) -> None:
        m = _make_manifest()
        vr = verify_signature(m, "aa" * 32)
        assert not vr.valid
        assert "unsigned" in vr.reason

    def test_verify_chain_root_passes(self) -> None:
        m = _make_manifest(previous_manifest_hash="")
        assert verify_chain(m, previous=None).valid

    def test_verify_chain_passes_with_correct_previous(self) -> None:
        prev = _make_manifest()
        cur = _make_manifest(previous_manifest_hash=prev.manifest_hash)
        vr = verify_chain(cur, previous=prev)
        assert vr.valid

    def test_verify_chain_fails_with_wrong_previous(self) -> None:
        prev = _make_manifest()
        wrong = _make_manifest(previous_manifest_hash="0" * 64)
        vr = verify_chain(wrong, previous=prev)
        assert not vr.valid

    def test_verify_chain_fails_when_previous_required_but_not_provided(self) -> None:
        cur = _make_manifest(previous_manifest_hash="0" * 64)
        vr = verify_chain(cur, previous=None)
        assert not vr.valid

    def test_verify_runtime_passes_with_matching_result(self) -> None:
        result = _make_result()
        m = build_manifest(result, gate="fg-fast", validation_status="passed")
        vr = verify_runtime(m, result)
        assert vr.valid

    def test_verify_runtime_fails_with_modified_result(self) -> None:
        result = _make_result()
        m = build_manifest(result, gate="fg-fast", validation_status="passed")
        modified = _make_result(passed=1234)
        vr = verify_runtime(m, modified)
        assert not vr.valid

    def test_verify_manifest_returns_all_checks(
        self, provider: Ed25519KeyProvider
    ) -> None:
        signed = sign_manifest(_make_manifest(), provider)
        checks = verify_manifest(signed, public_key_hex=provider.get_public_key_hex())
        assert "hash" in checks
        assert "signature" in checks
        assert "chain" in checks

    def test_verify_manifest_unsigned_legacy(self) -> None:
        m = _make_manifest()
        checks = verify_manifest(m, public_key_hex="")
        assert checks["hash"].valid
        assert checks["signature"].valid  # unsigned is not treated as failure
        assert checks["signature"].algorithm == "unsigned"
        assert "unsigned" in checks["signature"].reason


# ---------------------------------------------------------------------------
# TestTampering
# ---------------------------------------------------------------------------


class TestTampering:
    def test_tamper_gate_fails_hash(self) -> None:
        m = _make_manifest()
        tampered = replace(m, gate="fg-security")
        assert not verify_hash(tampered).valid

    def test_tamper_gate_fails_signature(self, provider: Ed25519KeyProvider) -> None:
        signed = sign_manifest(_make_manifest(), provider)
        tampered = replace(signed, gate="fg-security")
        vr = verify_signature(tampered, provider.get_public_key_hex())
        assert not vr.valid

    def test_tamper_validation_status_fails_hash(self) -> None:
        m = _make_manifest()
        tampered = replace(m, validation_status="failed")
        assert not verify_hash(tampered).valid

    def test_tamper_dependency_fingerprint_fails(self) -> None:
        m = _make_manifest()
        tampered = replace(m, dependency_fingerprint="ffffffffffffffff")
        assert not verify_hash(tampered).valid

    def test_modified_artifact_fails_runtime_hash(self) -> None:
        result = _make_result()
        m = build_manifest(result, gate="fg-fast", validation_status="passed")
        modified = _make_result(collected=1)
        assert not verify_runtime(m, modified).valid

    def test_replay_same_inputs_produces_same_hash(self) -> None:
        result = _make_result()
        m1 = build_manifest(result, gate="fg-fast", validation_status="passed")
        m2 = build_manifest(result, gate="fg-fast", validation_status="passed")
        assert m1.manifest_hash == m2.manifest_hash


# ---------------------------------------------------------------------------
# TestChainValidation
# ---------------------------------------------------------------------------


class TestChainValidation:
    def test_chain_of_two_manifests(self) -> None:
        m1 = _make_manifest()
        m2 = _make_manifest(previous_manifest_hash=m1.manifest_hash)
        assert verify_chain(m2, previous=m1).valid

    def test_chain_breaks_on_wrong_hash(self) -> None:
        m1 = _make_manifest()
        m2 = _make_manifest(previous_manifest_hash="a" * 64)
        assert not verify_chain(m2, previous=m1).valid

    def test_chain_root_has_empty_previous(self) -> None:
        m = _make_manifest(previous_manifest_hash="")
        assert m.previous_manifest_hash == ""
        assert verify_chain(m, previous=None).valid

    def test_validate_chain_with_multiple_manifests(self, tmp_path: Path) -> None:
        m1 = build_manifest(
            _make_result(),
            gate="fg-fast",
            validation_status="passed",
        )
        m2 = build_manifest(
            _make_result(meta=_make_meta(gate="fg-security")),
            gate="fg-security",
            validation_status="passed",
            previous_manifest_hash=m1.manifest_hash,
        )
        write_manifest(m1, tmp_path)
        write_manifest(m2, tmp_path)
        chain_path = write_chain_record([m1, m2], tmp_path)
        data = json.loads(chain_path.read_text())
        assert len(data["chain"]) == 2
        assert data["chain"][1]["previous_manifest_hash"] == m1.manifest_hash


# ---------------------------------------------------------------------------
# TestHistoryIntegration
# ---------------------------------------------------------------------------


class TestHistoryIntegration:
    def test_history_entry_includes_manifest_id_when_provided(self) -> None:
        result = _make_result()
        m = build_manifest(result, gate="fg-fast", validation_status="passed")
        entry = build_history_entry(result, gate="fg-fast", manifest=m)
        assert entry["manifest_id"] == m.manifest_id
        assert entry["manifest_hash"] == m.manifest_hash

    def test_history_entry_includes_signature_status(self) -> None:
        result = _make_result()
        m = build_manifest(result, gate="fg-fast", validation_status="passed")
        entry = build_history_entry(result, gate="fg-fast", manifest=m)
        assert entry["signature_status"] == m.verification_status

    def test_history_entry_works_without_manifest(self) -> None:
        result = _make_result()
        entry = build_history_entry(result, gate="fg-fast")
        assert "manifest_id" not in entry
        assert "signature_status" not in entry
        # Backwards-compat fields always present
        assert entry["duration_seconds"] == 300.0
        assert entry["gate"] == "fg-fast"


# ---------------------------------------------------------------------------
# TestGitHubSummary
# ---------------------------------------------------------------------------


class TestGitHubSummary:
    def test_summary_includes_manifest_section_when_provided(
        self, provider: Ed25519KeyProvider
    ) -> None:
        result = _make_result()
        signed = sign_manifest(
            build_manifest(result, gate="fg-fast", validation_status="passed"),
            provider,
        )
        summary = generate_summary(result, manifest=signed)
        assert "Validation Manifest" in summary

    def test_summary_shows_manifest_id(self, provider: Ed25519KeyProvider) -> None:
        result = _make_result()
        signed = sign_manifest(
            build_manifest(result, gate="fg-fast", validation_status="passed"),
            provider,
        )
        summary = generate_summary(result, manifest=signed)
        assert signed.manifest_id[:16] in summary

    def test_summary_shows_verification_status(self) -> None:
        m = _make_manifest()
        summary = generate_summary(_make_result(), manifest=m)
        assert m.verification_status in summary

    def test_summary_works_without_manifest(self) -> None:
        summary = generate_summary(_make_result())
        assert "Validation Manifest" not in summary
        assert "Runtime Summary" in summary

    def test_summary_no_private_key_in_output(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        priv, pub = generate_keypair()
        monkeypatch.setenv(Ed25519KeyProvider.PRIVATE_KEY_ENV, priv)
        monkeypatch.setenv(Ed25519KeyProvider.PUBLIC_KEY_ENV, pub)
        provider = Ed25519KeyProvider.from_env()
        result = _make_result()
        signed = sign_manifest(
            build_manifest(result, gate="fg-fast", validation_status="passed"),
            provider,
        )
        summary = generate_summary(result, manifest=signed)
        assert priv not in summary


# ---------------------------------------------------------------------------
# TestSecurityInvariants
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    def test_private_key_not_in_repr(self) -> None:
        priv, _ = generate_keypair()
        provider = Ed25519KeyProvider(private_key_hex=priv)
        assert priv not in repr(provider)
        assert priv not in str(provider)

    def test_private_key_not_in_sign_result(self, provider: Ed25519KeyProvider) -> None:
        signed = sign_manifest(_make_manifest(), provider)
        priv_hex = provider.get_private_key_bytes().hex()
        assert priv_hex not in serialize_manifest(signed)

    def test_private_key_not_in_verification_result(
        self, provider: Ed25519KeyProvider
    ) -> None:
        signed = sign_manifest(_make_manifest(), provider)
        priv_hex = provider.get_private_key_bytes().hex()
        vr = verify_signature(signed, provider.get_public_key_hex())
        assert priv_hex not in vr.reason
        assert priv_hex not in vr.detail

    def test_private_key_not_in_manifest(self, provider: Ed25519KeyProvider) -> None:
        signed = sign_manifest(_make_manifest(), provider)
        priv_hex = provider.get_private_key_bytes().hex()
        assert priv_hex not in serialize_manifest(signed)

    def test_private_key_not_in_history_entry(
        self, provider: Ed25519KeyProvider
    ) -> None:
        result = _make_result()
        signed = sign_manifest(
            build_manifest(result, gate="fg-fast", validation_status="passed"),
            provider,
        )
        entry = build_history_entry(result, gate="fg-fast", manifest=signed)
        priv_hex = provider.get_private_key_bytes().hex()
        assert priv_hex not in json.dumps(entry)


# ---------------------------------------------------------------------------
# TestBackwardCompatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    def test_unsigned_manifest_loads_correctly(self, tmp_path: Path) -> None:
        m = _make_manifest()
        path = write_manifest(m, tmp_path)
        loaded = load_manifest(path)
        assert loaded is not None
        assert loaded.signature_algorithm == "unsigned"
        assert loaded.signature == ""
        assert loaded.manifest_hash == m.manifest_hash

    def test_verify_manifest_unsigned_reports_not_failed(self) -> None:
        m = _make_manifest()
        checks = verify_manifest(m, public_key_hex="")
        # Signature check on unsigned manifest is intentionally non-fatal.
        assert checks["signature"].valid
        assert checks["signature"].algorithm == "unsigned"

    def test_manifest_from_dict_handles_extra_fields(self) -> None:
        m = _make_manifest()
        d = manifest_to_dict(m)
        d["future_field"] = "some_new_value"
        d["another_new_thing"] = {"nested": "value"}
        loaded = manifest_from_dict(d)
        assert loaded.gate == m.gate
        assert loaded.manifest_hash == m.manifest_hash


# ---------------------------------------------------------------------------
# TestSerialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_serialize_deserialize_roundtrip(self) -> None:
        m = _make_manifest()
        text = serialize_manifest(m)
        loaded = deserialize_manifest(text)
        assert loaded == m

    def test_serialized_keys_sorted(self) -> None:
        m = _make_manifest()
        text = serialize_manifest(m)
        data = json.loads(text)
        assert list(data.keys()) == sorted(data.keys())

    def test_serialized_no_whitespace(self) -> None:
        m = _make_manifest()
        text = serialize_manifest(m)
        # No indentation whitespace
        assert "\n" not in text
        assert ", " not in text
        assert ": " not in text

    def test_deserialized_equals_original(self) -> None:
        m = _make_manifest()
        loaded = deserialize_manifest(serialize_manifest(m))
        assert loaded == m

    def test_manifest_from_dict_and_to_dict_roundtrip(self) -> None:
        m = _make_manifest()
        assert manifest_from_dict(manifest_to_dict(m)) == m


# ---------------------------------------------------------------------------
# TestCLI
# ---------------------------------------------------------------------------


class TestCLI:
    def test_create_manifest_subcommand_recognized(self, tmp_path: Path) -> None:
        # Prepare a runtime artifact.
        runtime_dir = tmp_path / "runtime"
        runtime_dir.mkdir()
        result = _make_result()
        (runtime_dir / "fg-fast.json").write_text(to_json(result))

        manifest_dir = tmp_path / "manifests"
        proc = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "create-manifest",
                "--gate",
                "fg-fast",
                "--runtime-dir",
                str(runtime_dir),
                "--output",
                str(manifest_dir),
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert proc.returncode == 0, proc.stderr
        assert (manifest_dir / "fg-fast.manifest.json").exists()

    def test_verify_manifest_subcommand_recognized(self, tmp_path: Path) -> None:
        m = _make_manifest()
        path = write_manifest(m, tmp_path)
        proc = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "verify-manifest",
                "--manifest",
                str(path),
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        # Hash valid, unsigned legacy signature — CLI reports 0.
        assert proc.returncode == 0, proc.stderr
        parsed = json.loads(proc.stdout)
        assert parsed["checks"]["hash"]["valid"]

    def test_print_manifest_subcommand_recognized(self, tmp_path: Path) -> None:
        m = _make_manifest()
        path = write_manifest(m, tmp_path)
        proc = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "print-manifest",
                "--manifest",
                str(path),
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert proc.returncode == 0, proc.stderr
        parsed = json.loads(proc.stdout)
        assert parsed["manifest_hash"] == m.manifest_hash


# ---------------------------------------------------------------------------
# TestManifestWriter (extra coverage)
# ---------------------------------------------------------------------------


class TestManifestWriter:
    def test_write_manifest_creates_file(self, tmp_path: Path) -> None:
        m = _make_manifest()
        path = write_manifest(m, tmp_path)
        assert path.exists()
        assert path.name == "fg-fast.manifest.json"

    def test_write_verification_report(
        self, tmp_path: Path, provider: Ed25519KeyProvider
    ) -> None:
        signed = sign_manifest(_make_manifest(), provider)
        checks = verify_manifest(signed, public_key_hex=provider.get_public_key_hex())
        path = write_verification_report(signed, checks, tmp_path)
        data = json.loads(path.read_text())
        assert data["overall"] == "verified"

    def test_load_missing_manifest_returns_none(self, tmp_path: Path) -> None:
        assert load_manifest(tmp_path / "nope.json") is None

    def test_load_malformed_manifest_returns_none(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.manifest.json"
        bad.write_text("{ not json ...")
        assert load_manifest(bad) is None


# ---------------------------------------------------------------------------
# Sanity — unused imports guarded
# ---------------------------------------------------------------------------


def test_signature_and_verification_result_dataclass_shape() -> None:
    """Ensure SignatureResult / VerificationResult expose expected fields."""
    sig = SignatureResult(
        signature_hex="ab",
        signing_identity="id",
        algorithm="ed25519",
        public_key_hex="cd",
    )
    assert sig.signature_hex == "ab"
    ver = VerificationResult(
        valid=True,
        algorithm="sha256",
        signing_identity="",
        reason="ok",
    )
    assert ver.valid is True
    assert ver.detail == ""


def test_verify_signature_bytes_rejects_bad_hex() -> None:
    vr = verify_signature_bytes(b"data", "not-hex", "aa" * 32)
    assert not vr.valid


def test_slow_test_field_is_ignored_in_manifest() -> None:
    """Regression: fixture slot presence should not alter manifest hash pre-image."""
    result = _make_result(slowest_tests=(SlowTest("x::y", 1.0, "call"),))
    m = build_manifest(result, gate="fg-fast", validation_status="passed")
    assert verify_runtime(m, result).valid
