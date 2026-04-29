"""
tests/agent/test_release_signing_deployment_guide.py

Tests for task 18.6 — Release artifact signing and deployment guide.

Coverage:
  1. Signing contract — SigningPlan model, plan generation, secret guards
  2. Release manifest — ReleaseManifest model, serialization, validation
  3. Hash verification — verify_artifact_hashes() with real temp files
  4. Production readiness — validate_release_ready() paths
  5. Deployment guide — structure, required sections, placeholder checks
  6. Security regression — no secrets, no unsigned production, no localhost
  7. Plan YAML cross-reference

Tests are deterministic and offline-safe.
No live code-signing certificate required.
No Windows CI required.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
import pytest
import yaml

from agent.app.installer.release_signing import (
    ArtifactType,
    ReleaseArtifact,
    ReleaseManifest,
    ReleaseManifestError,
    SigningPlan,
    SigningToolchainError,
    UnsignedProductionArtifactError,
    build_release_manifest,
    build_signing_plan,
    execute_live_signing,
    validate_release_ready,
    verify_artifact_hashes,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PRODUCT = "FrostGate Agent"
_VERSION = "1.2.3"
_COMMIT = "abc123def456" * 3  # 36 chars
_BUILD_TIME = "2026-04-29T00:00:00Z"
_BUILD_ENV = "github-actions"
_THUMBPRINT_REF = "$env:FG_SIGNING_THUMBPRINT"
_ARTIFACT_PATH = r"C:\Build\FrostGateAgent-1.2.3.msi"
_SHA256 = "a" * 64  # valid-length hex string


def _make_artifact(
    *,
    signing_status: str = "signed",
    sha256: str | None = _SHA256,
    artifact_type: ArtifactType = "msi",
) -> ReleaseArtifact:
    return ReleaseArtifact(
        name=f"FrostGateAgent-{_VERSION}.msi",
        path=_ARTIFACT_PATH,
        artifact_type=artifact_type,
        signing_status=signing_status,  # type: ignore[arg-type]
        sha256=sha256,
        size_bytes=10_485_760,
    )


def _make_manifest(
    *,
    artifacts: list[ReleaseArtifact] | None = None,
    sha256_manifest_path: str | None = r"C:\Build\manifest.sha256",
) -> ReleaseManifest:
    return build_release_manifest(
        product=_PRODUCT,
        version=_VERSION,
        commit=_COMMIT,
        build_time=_BUILD_TIME,
        build_environment=_BUILD_ENV,
        artifacts=artifacts or [_make_artifact()],
        sha256_manifest_path=sha256_manifest_path,
    )


# ===========================================================================
# 1. Signing contract
# ===========================================================================


def test_signing_plan_exists() -> None:
    plan = build_signing_plan(
        artifact_path=_ARTIFACT_PATH,
        artifact_type="msi",
        cert_thumbprint_ref=_THUMBPRINT_REF,
    )
    assert isinstance(plan, SigningPlan)


def test_signing_plan_includes_signtool_sign() -> None:
    plan = build_signing_plan(
        artifact_path=_ARTIFACT_PATH,
        artifact_type="msi",
        cert_thumbprint_ref=_THUMBPRINT_REF,
    )
    assert "signtool.exe" in plan.sign_args
    assert "sign" in plan.sign_args


def test_signing_plan_includes_verify_step() -> None:
    plan = build_signing_plan(
        artifact_path=_ARTIFACT_PATH,
        artifact_type="msi",
        cert_thumbprint_ref=_THUMBPRINT_REF,
    )
    assert "signtool.exe" in plan.verify_args
    assert "verify" in plan.verify_args


def test_signing_plan_uses_sha256_digest() -> None:
    plan = build_signing_plan(
        artifact_path=_ARTIFACT_PATH,
        artifact_type="msi",
        cert_thumbprint_ref=_THUMBPRINT_REF,
    )
    combined = " ".join(plan.sign_args)
    assert "sha256" in combined.lower()


def test_signing_plan_includes_timestamp_url() -> None:
    plan = build_signing_plan(
        artifact_path=_ARTIFACT_PATH,
        artifact_type="msi",
        cert_thumbprint_ref=_THUMBPRINT_REF,
        timestamp_url="http://timestamp.digicert.com",
    )
    assert "http://timestamp.digicert.com" in plan.sign_args


def test_signing_plan_is_deterministic() -> None:
    kwargs = dict(
        artifact_path=_ARTIFACT_PATH,
        artifact_type="msi",
        cert_thumbprint_ref=_THUMBPRINT_REF,
    )
    plan_a = build_signing_plan(**kwargs)  # type: ignore[arg-type]
    plan_b = build_signing_plan(**kwargs)  # type: ignore[arg-type]
    assert plan_a.sign_args == plan_b.sign_args
    assert plan_a.verify_args == plan_b.verify_args


def test_signing_plan_does_not_contain_pfx_password() -> None:
    plan = build_signing_plan(
        artifact_path=_ARTIFACT_PATH,
        artifact_type="msi",
        cert_thumbprint_ref=_THUMBPRINT_REF,
    )
    combined = " ".join(plan.sign_args + plan.verify_args).lower()
    assert "pfx_password" not in combined
    assert "private_key" not in combined
    assert "-----" not in combined


def test_signing_plan_rejects_secret_in_thumbprint_ref() -> None:
    with pytest.raises(ReleaseManifestError, match="[Ss]ecret"):
        build_signing_plan(
            artifact_path=_ARTIFACT_PATH,
            artifact_type="msi",
            cert_thumbprint_ref="pfx_password=abc123",
        )


def test_signing_plan_rejects_empty_artifact_path() -> None:
    with pytest.raises(ReleaseManifestError, match="artifact_path"):
        build_signing_plan(
            artifact_path="",
            artifact_type="msi",
            cert_thumbprint_ref=_THUMBPRINT_REF,
        )


def test_execute_live_signing_raises_on_non_windows() -> None:
    """execute_live_signing() must raise SigningToolchainError on Linux."""
    import sys

    if sys.platform == "win32":
        pytest.skip("only meaningful on non-Windows")
    plan = build_signing_plan(
        artifact_path=_ARTIFACT_PATH,
        artifact_type="msi",
        cert_thumbprint_ref=_THUMBPRINT_REF,
    )
    with pytest.raises(SigningToolchainError, match="win32|Windows"):
        execute_live_signing(plan)


def test_signing_plan_cert_thumbprint_ref_is_env_reference() -> None:
    """cert_thumbprint_ref must be an env var reference, not a raw thumbprint value."""
    plan = build_signing_plan(
        artifact_path=_ARTIFACT_PATH,
        artifact_type="msi",
        cert_thumbprint_ref=_THUMBPRINT_REF,
    )
    assert plan.cert_thumbprint_ref == _THUMBPRINT_REF


def test_execute_live_signing_raises_when_env_var_unset() -> None:
    """execute_live_signing() must raise when $env: reference resolves to empty/missing."""
    import sys

    if sys.platform != "win32":
        pytest.skip("env-var resolution path only reached on Windows")
    import os
    import unittest.mock

    plan = build_signing_plan(
        artifact_path=_ARTIFACT_PATH,
        artifact_type="msi",
        cert_thumbprint_ref="$env:FG_SIGNING_THUMBPRINT_UNSET_TEST",
    )
    env = {
        k: v for k, v in os.environ.items() if k != "FG_SIGNING_THUMBPRINT_UNSET_TEST"
    }
    with unittest.mock.patch.dict(os.environ, env, clear=True):
        with pytest.raises(
            SigningToolchainError, match="FG_SIGNING_THUMBPRINT_UNSET_TEST"
        ):
            execute_live_signing(plan)


def test_sign_args_contain_thumbprint_ref_not_expanded() -> None:
    """sign_args store the env var reference literally — not the resolved value.

    Resolution happens at execute_live_signing() time so plans are portable
    across environments and never embed the actual thumbprint at build time.
    """
    plan = build_signing_plan(
        artifact_path=_ARTIFACT_PATH,
        artifact_type="msi",
        cert_thumbprint_ref=_THUMBPRINT_REF,
    )
    assert _THUMBPRINT_REF in plan.sign_args
    assert plan.cert_thumbprint_ref == _THUMBPRINT_REF


# ===========================================================================
# 2. Release manifest
# ===========================================================================


def test_release_manifest_exists() -> None:
    manifest = _make_manifest()
    assert isinstance(manifest, ReleaseManifest)


def test_release_manifest_includes_required_fields() -> None:
    manifest = _make_manifest()
    assert manifest.product == _PRODUCT
    assert manifest.version == _VERSION
    assert manifest.commit == _COMMIT
    assert manifest.build_time == _BUILD_TIME
    assert manifest.build_environment == _BUILD_ENV


def test_release_manifest_includes_signing_status() -> None:
    manifest = _make_manifest()
    assert manifest.signing_status in ("signed", "unsigned", "partial")


def test_release_manifest_production_ready_true_when_signed_and_hashed() -> None:
    manifest = _make_manifest(
        artifacts=[_make_artifact(signing_status="signed", sha256=_SHA256)],
        sha256_manifest_path=r"C:\Build\manifest.sha256",
    )
    assert manifest.production_ready is True


def test_release_manifest_production_ready_false_when_unsigned() -> None:
    manifest = _make_manifest(
        artifacts=[_make_artifact(signing_status="unsigned")],
    )
    assert manifest.production_ready is False


def test_release_manifest_production_ready_false_when_missing_sha256() -> None:
    manifest = _make_manifest(
        artifacts=[_make_artifact(sha256=None)],
    )
    assert manifest.production_ready is False


def test_release_manifest_production_ready_false_when_no_sha256_manifest() -> None:
    manifest = _make_manifest(sha256_manifest_path=None)
    assert manifest.production_ready is False


def test_release_manifest_production_ready_false_when_empty_sha256_manifest_path() -> (
    None
):
    manifest = _make_manifest(sha256_manifest_path="")
    assert manifest.production_ready is False


def test_release_manifest_production_ready_false_when_whitespace_sha256_manifest_path() -> (
    None
):
    manifest = _make_manifest(sha256_manifest_path="   ")
    assert manifest.production_ready is False


def test_release_manifest_serialization_is_deterministic() -> None:
    manifest = _make_manifest()
    json_a = manifest.as_json()
    json_b = manifest.as_json()
    assert json_a == json_b
    # Must be valid JSON
    parsed = json.loads(json_a)
    assert parsed["product"] == _PRODUCT
    assert parsed["version"] == _VERSION


def test_release_manifest_as_dict_has_all_required_keys() -> None:
    manifest = _make_manifest()
    d = manifest.as_dict()
    required_keys = {
        "product",
        "version",
        "commit",
        "build_time",
        "architecture",
        "signing_status",
        "production_ready",
        "sha256_manifest_path",
        "artifacts",
    }
    for key in required_keys:
        assert key in d, f"Missing key '{key}' in manifest dict"


def test_release_manifest_rejects_secret_in_product_name() -> None:
    with pytest.raises(ReleaseManifestError, match="[Ss]ecret"):
        build_release_manifest(
            product="FrostGate pfx_password",
            version=_VERSION,
            commit=_COMMIT,
            build_time=_BUILD_TIME,
            build_environment=_BUILD_ENV,
            artifacts=[_make_artifact()],
        )


def test_release_manifest_rejects_enrollment_token_in_metadata() -> None:
    with pytest.raises(ReleaseManifestError, match="[Ss]ecret"):
        build_release_manifest(
            product=_PRODUCT,
            version=_VERSION,
            commit=_COMMIT,
            build_time=_BUILD_TIME,
            build_environment="github-actions enrollment_token=abc",
            artifacts=[_make_artifact()],
        )


def test_release_manifest_rejects_empty_version() -> None:
    with pytest.raises(ReleaseManifestError, match="version"):
        build_release_manifest(
            product=_PRODUCT,
            version="",
            commit=_COMMIT,
            build_time=_BUILD_TIME,
            build_environment=_BUILD_ENV,
            artifacts=[_make_artifact()],
        )


def test_release_manifest_signing_status_partial_for_mixed_artifacts() -> None:
    artifacts = [
        _make_artifact(signing_status="signed", artifact_type="msi"),
        ReleaseArtifact(
            name="FrostGateAgent.exe",
            path=r"C:\Build\FrostGateAgent.exe",
            artifact_type="exe",
            signing_status="unsigned",
            sha256=_SHA256,
        ),
    ]
    manifest = build_release_manifest(
        product=_PRODUCT,
        version=_VERSION,
        commit=_COMMIT,
        build_time=_BUILD_TIME,
        build_environment=_BUILD_ENV,
        artifacts=artifacts,
        sha256_manifest_path=r"C:\Build\manifest.sha256",
    )
    assert manifest.signing_status == "partial"
    assert manifest.production_ready is False


# ===========================================================================
# 3. Hash verification
# ===========================================================================


def test_verify_artifact_hashes_matches_real_file() -> None:
    content = b"FrostGate agent binary content for hash test"
    expected_sha256 = hashlib.sha256(content).hexdigest()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".msi") as f:
        f.write(content)
        tmp_path = f.name

    artifact = ReleaseArtifact(
        name="test_artifact.msi",
        path=tmp_path,
        artifact_type="msi",
        signing_status="unsigned",
        sha256=expected_sha256,
    )
    results = verify_artifact_hashes([artifact])
    assert len(results) == 1
    assert results[0].matches is True
    assert results[0].error is None
    Path(tmp_path).unlink(missing_ok=True)


def test_verify_artifact_hashes_detects_mismatch() -> None:
    content = b"original content"
    wrong_sha256 = "b" * 64  # wrong hash

    with tempfile.NamedTemporaryFile(delete=False, suffix=".msi") as f:
        f.write(content)
        tmp_path = f.name

    artifact = ReleaseArtifact(
        name="test_artifact.msi",
        path=tmp_path,
        artifact_type="msi",
        signing_status="unsigned",
        sha256=wrong_sha256,
    )
    results = verify_artifact_hashes([artifact])
    assert results[0].matches is False
    assert results[0].error is None
    Path(tmp_path).unlink(missing_ok=True)


def test_verify_artifact_hashes_file_not_found() -> None:
    artifact = ReleaseArtifact(
        name="missing.msi",
        path="/nonexistent/path/missing.msi",
        artifact_type="msi",
        signing_status="unsigned",
        sha256=_SHA256,
    )
    results = verify_artifact_hashes([artifact])
    assert results[0].error == "file_not_found"
    assert results[0].matches is False


def test_verify_artifact_hashes_missing_expected_hash() -> None:
    artifact = ReleaseArtifact(
        name="no_hash.msi",
        path=_ARTIFACT_PATH,
        artifact_type="msi",
        signing_status="unsigned",
        sha256=None,
    )
    results = verify_artifact_hashes([artifact])
    assert results[0].error == "hash_missing"
    assert results[0].matches is False


def test_verify_artifact_hashes_returns_result_per_artifact() -> None:
    content = b"test content"
    sha = hashlib.sha256(content).hexdigest()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".msi") as f:
        f.write(content)
        tmp = f.name

    artifacts = [
        ReleaseArtifact(name="a.msi", path=tmp, artifact_type="msi", sha256=sha),
        ReleaseArtifact(
            name="b.exe", path="/missing.exe", artifact_type="exe", sha256=sha
        ),
    ]
    results = verify_artifact_hashes(artifacts)
    assert len(results) == 2
    assert results[0].matches is True
    assert results[1].error == "file_not_found"
    Path(tmp).unlink(missing_ok=True)


# ===========================================================================
# 4. Production readiness
# ===========================================================================


def test_validate_release_ready_passes_signed_manifest() -> None:
    manifest = _make_manifest(
        artifacts=[_make_artifact(signing_status="signed", sha256=_SHA256)],
        sha256_manifest_path=r"C:\Build\manifest.sha256",
    )
    validate_release_ready(manifest)  # must not raise


def test_validate_release_ready_rejects_unsigned_production_artifact() -> None:
    manifest = _make_manifest(
        artifacts=[_make_artifact(signing_status="unsigned")],
        sha256_manifest_path=r"C:\Build\manifest.sha256",
    )
    with pytest.raises(UnsignedProductionArtifactError, match="[Uu]nsigned"):
        validate_release_ready(manifest, require_production=True)


def test_validate_release_ready_unsigned_ok_when_not_production() -> None:
    manifest = _make_manifest(
        artifacts=[_make_artifact(signing_status="unsigned")],
        sha256_manifest_path=r"C:\Build\manifest.sha256",
    )
    validate_release_ready(manifest, require_production=False)  # must not raise


def test_validate_release_ready_rejects_missing_sha256_manifest() -> None:
    manifest = _make_manifest(sha256_manifest_path=None)
    with pytest.raises(ReleaseManifestError, match="sha256_manifest_path"):
        validate_release_ready(manifest, require_production=False)


def test_validate_release_ready_rejects_empty_sha256_manifest_path() -> None:
    manifest = _make_manifest(sha256_manifest_path="")
    with pytest.raises(ReleaseManifestError, match="sha256_manifest_path"):
        validate_release_ready(manifest, require_production=False)


def test_validate_release_ready_rejects_whitespace_sha256_manifest_path() -> None:
    manifest = _make_manifest(sha256_manifest_path="   ")
    with pytest.raises(ReleaseManifestError, match="sha256_manifest_path"):
        validate_release_ready(manifest, require_production=False)


def test_validate_release_ready_rejects_missing_artifact_hash() -> None:
    manifest = _make_manifest(
        artifacts=[_make_artifact(sha256=None)],
        sha256_manifest_path=r"C:\Build\manifest.sha256",
    )
    with pytest.raises(ReleaseManifestError, match="[Ss]HA256|hash"):
        validate_release_ready(manifest, require_production=False)


def test_validate_release_ready_rejects_empty_version() -> None:
    # Build manually to bypass builder validation
    manifest = ReleaseManifest(
        product=_PRODUCT,
        version="",
        commit=_COMMIT,
        build_time=_BUILD_TIME,
        architecture="x64",
        target_os="Windows 10+",
        build_environment=_BUILD_ENV,
        signing_status="signed",
        production_ready=False,
        sha256_manifest_path=r"C:\Build\manifest.sha256",
        artifacts=[_make_artifact()],
    )
    with pytest.raises(ReleaseManifestError, match="version"):
        validate_release_ready(manifest, require_production=False)


def test_validate_release_ready_rejects_localhost_in_build_env() -> None:
    manifest = ReleaseManifest(
        product=_PRODUCT,
        version=_VERSION,
        commit=_COMMIT,
        build_time=_BUILD_TIME,
        architecture="x64",
        target_os="Windows 10+",
        build_environment="localhost-dev-build",
        signing_status="signed",
        production_ready=False,
        sha256_manifest_path=r"C:\Build\manifest.sha256",
        artifacts=[_make_artifact()],
    )
    with pytest.raises(ReleaseManifestError, match="[Ll]ocalhost|[Ff]orbidden"):
        validate_release_ready(manifest, require_production=False)


def test_production_ready_false_for_unsigned_artifact() -> None:
    manifest = _make_manifest(
        artifacts=[_make_artifact(signing_status="unsigned")],
    )
    assert manifest.production_ready is False, (
        "REGRESSION: production_ready must be False for unsigned artifact"
    )


# ===========================================================================
# 5. Deployment guide
# ===========================================================================

_GUIDE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "docs"
    / "agent"
    / "windows_enterprise_deployment.md"
)


def _guide_content() -> str:
    assert _GUIDE_PATH.exists(), f"Deployment guide not found at {_GUIDE_PATH}"
    return _GUIDE_PATH.read_text(encoding="utf-8")


def test_deployment_guide_exists() -> None:
    assert _GUIDE_PATH.exists(), "Enterprise deployment guide must exist"


def test_deployment_guide_includes_silent_install_example() -> None:
    content = _guide_content()
    assert "msiexec" in content
    assert "/qn" in content
    assert "TENANT_ID" in content


def test_deployment_guide_includes_intune_section() -> None:
    content = _guide_content()
    assert "Intune" in content or "intune" in content


def test_deployment_guide_includes_gpo_section() -> None:
    content = _guide_content()
    assert "GPO" in content or "Group Policy" in content


def test_deployment_guide_includes_rmm_section() -> None:
    content = _guide_content()
    assert "RMM" in content


def test_deployment_guide_includes_signature_verification_steps() -> None:
    content = _guide_content()
    assert (
        "signtool" in content
        or "Get-FileHash" in content
        or "verify" in content.lower()
    )


def test_deployment_guide_includes_enrollment_parameter_description() -> None:
    content = _guide_content()
    assert "ENROLLMENT_TOKEN" in content
    assert "TENANT_ID" in content
    assert "FROSTGATE_ENDPOINT" in content


def test_deployment_guide_includes_upgrade_section() -> None:
    content = _guide_content()
    assert "Upgrade" in content or "upgrade" in content


def test_deployment_guide_includes_uninstall_section() -> None:
    content = _guide_content()
    assert "Uninstall" in content or "uninstall" in content


def test_deployment_guide_includes_purge_section() -> None:
    content = _guide_content()
    assert "Purge" in content or "purge" in content or "PURGE_DATA" in content


def test_deployment_guide_includes_credential_storage_guarantee() -> None:
    content = _guide_content()
    assert "Credential Manager" in content or "credential" in content.lower()
    assert "DPAPI" in content or "encrypted" in content.lower()


def test_deployment_guide_uses_placeholders_not_real_secrets() -> None:
    content = _guide_content()
    assert "<TENANT_ID>" in content
    assert "<FROSTGATE_ENDPOINT>" in content
    assert "<ENROLLMENT_TOKEN>" in content


def test_deployment_guide_has_no_localhost_in_production_example() -> None:
    content = _guide_content()
    lines = content.splitlines()
    for line in lines:
        if "msiexec" in line and ("localhost" in line or "127.0.0.1" in line):
            pytest.fail(
                f"Deployment guide contains localhost in msiexec example: {line!r}"
            )


def test_deployment_guide_has_no_raw_real_looking_secrets() -> None:
    content = _guide_content()
    forbidden_patterns = [
        "sk-",  # OpenAI-style key
        "ghp_",  # GitHub personal access token
        "enrollment_token=abc",  # real-looking token assignment
        "bearer abc",  # real-looking bearer
    ]
    lower = content.lower()
    for pattern in forbidden_patterns:
        assert pattern not in lower, (
            f"Deployment guide contains real-looking secret pattern: '{pattern}'"
        )


def test_deployment_guide_states_unsigned_not_for_production() -> None:
    content = _guide_content()
    assert (
        "NOT FOR PRODUCTION" in content
        or "unsigned artifact" in content.lower()
        or ("Unsigned" in content and "production" in content)
    )


def test_deployment_guide_documents_token_not_persisted() -> None:
    content = _guide_content()
    assert (
        "discarded" in content.lower()
        or "never persisted" in content.lower()
        or ("not persisted" in content.lower())
    )


# ===========================================================================
# 6. Security regression
# ===========================================================================


def test_regression_unsigned_production_artifact_rejected() -> None:
    manifest = _make_manifest(
        artifacts=[_make_artifact(signing_status="unsigned")],
        sha256_manifest_path=r"C:\Build\manifest.sha256",
    )
    with pytest.raises(UnsignedProductionArtifactError):
        validate_release_ready(manifest, require_production=True)


def test_regression_signing_command_never_includes_pfx_or_private_key() -> None:
    plan = build_signing_plan(
        artifact_path=_ARTIFACT_PATH,
        artifact_type="msi",
        cert_thumbprint_ref=_THUMBPRINT_REF,
    )
    all_args = plan.sign_args + plan.verify_args
    combined = " ".join(all_args).lower()
    forbidden = ("pfx", "private_key", "password", "secret", "-----begin")
    for pattern in forbidden:
        assert pattern not in combined, (
            f"REGRESSION: Forbidden pattern '{pattern}' found in signing args"
        )


def test_regression_manifest_never_contains_token() -> None:
    manifest = _make_manifest()
    json_str = manifest.as_json()
    forbidden = ("enrollment_token", "bootstrap_token", "api_key", "bearer")
    lower = json_str.lower()
    for pattern in forbidden:
        assert pattern not in lower, (
            f"REGRESSION: Token pattern '{pattern}' found in release manifest JSON"
        )


def test_regression_guide_does_not_remove_enterprise_deployment_instructions() -> None:
    content = _guide_content()
    required_sections = [
        "Intune",
        "GPO",
        "RMM",
        "Silent",
        "Upgrade",
        "Uninstall",
        "Purge",
    ]
    for section in required_sections:
        assert section in content, (
            f"REGRESSION: Required deployment section '{section}' missing from guide"
        )


def test_regression_guide_no_raw_token_persistence() -> None:
    content = _guide_content()
    # The guide must not instruct users to write tokens to config files or logs
    assert "write_token_to_file" not in content.lower()
    assert "save_token" not in content.lower()
    assert "token.txt" not in content.lower()


def test_regression_plan_18_6_requires_dedicated_test_file() -> None:
    """Task 18.6 must not be completable from make fg-fast alone."""
    plan_path = (
        Path(__file__).resolve().parent.parent.parent
        / "plans"
        / "30_day_repo_blitz.yaml"
    )
    assert plan_path.exists()
    with plan_path.open() as f:
        plan = yaml.safe_load(f)

    task_186: dict | None = None
    for phase in plan.get("phases", []):
        for module in phase.get("modules", []):
            for task in module.get("tasks", []):
                if str(task.get("id")) == "18.6":
                    task_186 = task
                    break

    assert task_186 is not None, "Task 18.6 not found in plan YAML"
    cmds = task_186.get("validation_commands", [])
    has_pytest = any("test_release_signing_deployment_guide" in c for c in cmds)
    has_fg_fast = any("fg-fast" in c for c in cmds)
    assert has_pytest, f"Task 18.6 must have pytest validation_command. Got: {cmds}"
    assert has_fg_fast, f"Task 18.6 must still include make fg-fast. Got: {cmds}"
    assert len(cmds) >= 2, "Task 18.6 must have at least 2 validation_commands"


# ===========================================================================
# 7. Plan YAML cross-reference
# ===========================================================================


def test_plan_validation_command_targets_this_test_file() -> None:
    """Task 18.6 validation_commands must include this test file."""
    plan_path = (
        Path(__file__).resolve().parent.parent.parent
        / "plans"
        / "30_day_repo_blitz.yaml"
    )
    assert plan_path.exists(), f"Plan YAML not found at {plan_path}"
    with plan_path.open() as f:
        plan = yaml.safe_load(f)

    task_186: dict | None = None
    for phase in plan.get("phases", []):
        for module in phase.get("modules", []):
            for task in module.get("tasks", []):
                if str(task.get("id")) == "18.6":
                    task_186 = task
                    break

    assert task_186 is not None, "Task 18.6 not found in plan YAML"
    cmds = task_186.get("validation_commands", [])
    found = any("test_release_signing_deployment_guide" in cmd for cmd in cmds)
    assert found, (
        f"Task 18.6 validation_commands do not reference "
        f"'test_release_signing_deployment_guide'. Got: {cmds}"
    )
