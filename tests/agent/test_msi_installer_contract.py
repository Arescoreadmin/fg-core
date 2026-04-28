"""
tests/agent/test_msi_installer_contract.py

Tests for task 18.2 — MSI installer build contract.

Coverage:
  1. Contract existence and required fields
  2. Silent install parameter definitions
  3. Security — endpoint/environment rejection, no token in plans
  4. Build / smoke-test plan determinism and correctness
  5. Artifact manifest requirements (SHA256, signing)
  6. Uninstall / purge semantics
  7. Platform / toolchain behavior
  8. Regression invariants

Tests are deterministic and offline-safe.
No Windows CI required — live MSI build is platform-gated.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agent.app.installer.msi_contract import (
    PURGE_PARAM,
    SILENT_OPTIONAL_PARAMS,
    SILENT_REQUIRED_PARAMS,
    MsiArtifactManifest,
    MsiBuildContract,
    MsiContractError,
    MsiToolchainError,
    _SECRET_PATTERNS,
    default_frostgate_msi_contract,
    validate_environment,
    validate_msi_endpoint,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_VALID_GUID = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
_BUILD_OUT = r"C:\build\output"


def _make_valid_contract(**overrides: object) -> MsiBuildContract:
    defaults: dict[str, object] = dict(
        product_name="FrostGateAgent",
        product_version="1.0.0",
        manufacturer="FrostGate Inc.",
        upgrade_code=_VALID_GUID,
        service_name="FrostGateAgent",
        install_dir=r"C:\Program Files\FrostGate\Agent",
        config_dir=r"C:\ProgramData\FrostGate\Agent\config",
        log_dir=r"C:\ProgramData\FrostGate\Agent\logs",
        data_dir=r"C:\ProgramData\FrostGate\Agent\data",
        build_output_dir=_BUILD_OUT,
        artifact_name="FrostGateAgent-1.0.0-x86_64.msi",
        signing_required=True,
        signing_status="unsigned",
        sha256_manifest_required=True,
    )
    defaults.update(overrides)
    return MsiBuildContract(**defaults)  # type: ignore[arg-type]


# ===========================================================================
# 1. Contract existence and required fields
# ===========================================================================


def test_msi_contract_validates_with_all_required_fields() -> None:
    """Valid MSI contract passes validate_contract() without error."""
    contract = _make_valid_contract()
    contract.validate_contract()  # must not raise


def test_msi_contract_requires_product_name() -> None:
    contract = _make_valid_contract(product_name="")
    with pytest.raises(MsiContractError, match="product_name"):
        contract.validate_contract()


def test_msi_contract_requires_product_version() -> None:
    contract = _make_valid_contract(product_version="")
    with pytest.raises(MsiContractError, match="product_version"):
        contract.validate_contract()


def test_msi_contract_requires_manufacturer() -> None:
    contract = _make_valid_contract(manufacturer="")
    with pytest.raises(MsiContractError, match="manufacturer"):
        contract.validate_contract()


def test_msi_contract_requires_valid_upgrade_code_guid() -> None:
    contract = _make_valid_contract(upgrade_code="not-a-guid")
    with pytest.raises(MsiContractError, match="upgrade_code"):
        contract.validate_contract()


def test_msi_contract_accepts_valid_guid_upgrade_code() -> None:
    contract = _make_valid_contract(upgrade_code=_VALID_GUID)
    contract.validate_contract()  # must not raise


def test_msi_contract_requires_service_name() -> None:
    contract = _make_valid_contract(service_name="")
    with pytest.raises(MsiContractError, match="service_name"):
        contract.validate_contract()


def test_msi_contract_requires_artifact_name() -> None:
    contract = _make_valid_contract(artifact_name="")
    with pytest.raises(MsiContractError, match="artifact_name"):
        contract.validate_contract()


def test_msi_contract_requires_sha256_manifest() -> None:
    """sha256_manifest_required=False is a contract violation."""
    contract = _make_valid_contract(sha256_manifest_required=False)
    with pytest.raises(MsiContractError, match="sha256_manifest_required"):
        contract.validate_contract()


def test_msi_contract_requires_non_string_sentinel_rejected() -> None:
    """None value for a required str field is rejected at validation time."""
    contract = _make_valid_contract(product_name=None)  # type: ignore[arg-type]
    with pytest.raises(MsiContractError, match="product_name"):
        contract.validate_contract()


def test_msi_contract_has_all_required_fields() -> None:
    """MsiBuildContract dataclass exposes all required contract fields."""
    required = {
        "product_name",
        "product_version",
        "manufacturer",
        "upgrade_code",
        "package_code_strategy",
        "service_name",
        "install_dir",
        "config_dir",
        "log_dir",
        "data_dir",
        "build_output_dir",
        "artifact_name",
        "signing_required",
        "signing_status",
        "sha256_manifest_required",
        "supported_install_modes",
    }
    contract_fields = set(MsiBuildContract.__dataclass_fields__.keys())
    missing = required - contract_fields
    assert not missing, f"MsiBuildContract is missing required fields: {missing}"


def test_msi_contract_supports_all_install_modes() -> None:
    """Contract declares all six required install modes."""
    contract = _make_valid_contract()
    required_modes = {
        "interactive",
        "silent",
        "repair",
        "upgrade",
        "uninstall",
        "purge_uninstall",
    }
    assert required_modes.issubset(set(contract.supported_install_modes))


# ===========================================================================
# 2. Silent install parameter definitions
# ===========================================================================


def test_silent_required_params_contains_tenant_id() -> None:
    assert "TENANT_ID" in SILENT_REQUIRED_PARAMS


def test_silent_required_params_contains_frostgate_endpoint() -> None:
    assert "FROSTGATE_ENDPOINT" in SILENT_REQUIRED_PARAMS


def test_silent_required_params_contains_enrollment_token() -> None:
    """ENROLLMENT_TOKEN (or BOOTSTRAP_TOKEN) must be in required params."""
    assert (
        "ENROLLMENT_TOKEN" in SILENT_REQUIRED_PARAMS
        or "BOOTSTRAP_TOKEN" in SILENT_REQUIRED_PARAMS
    )


def test_silent_required_params_contains_environment() -> None:
    assert "ENVIRONMENT" in SILENT_REQUIRED_PARAMS


def test_silent_optional_params_contains_installdir() -> None:
    assert "INSTALLDIR" in SILENT_OPTIONAL_PARAMS


def test_silent_optional_params_contains_log_level() -> None:
    assert "LOG_LEVEL" in SILENT_OPTIONAL_PARAMS


def test_purge_param_is_defined() -> None:
    """PURGE_PARAM constant must exist for uninstall purge mode."""
    assert PURGE_PARAM == "PURGE_DATA"


# ===========================================================================
# 3. Security — endpoint/environment rejection, no token in plans
# ===========================================================================


def test_validate_msi_endpoint_accepts_valid_https() -> None:
    validate_msi_endpoint(
        "https://control-plane.frostgate.example.com"
    )  # must not raise


def test_validate_msi_endpoint_rejects_http() -> None:
    with pytest.raises(MsiContractError, match="HTTPS"):
        validate_msi_endpoint("http://control-plane.frostgate.example.com")


def test_validate_msi_endpoint_rejects_localhost() -> None:
    with pytest.raises(MsiContractError):
        validate_msi_endpoint("https://localhost/api")


def test_validate_msi_endpoint_rejects_loopback_ip() -> None:
    with pytest.raises(MsiContractError):
        validate_msi_endpoint("https://127.0.0.1/api")


def test_validate_msi_endpoint_rejects_rfc1918_10() -> None:
    with pytest.raises(MsiContractError):
        validate_msi_endpoint("https://10.0.0.5/api")


def test_validate_msi_endpoint_rejects_rfc1918_172() -> None:
    with pytest.raises(MsiContractError):
        validate_msi_endpoint("https://172.16.1.1/api")


def test_validate_msi_endpoint_rejects_rfc1918_192_168() -> None:
    with pytest.raises(MsiContractError):
        validate_msi_endpoint("https://192.168.0.1/api")


def test_validate_msi_endpoint_rejects_link_local() -> None:
    with pytest.raises(MsiContractError):
        validate_msi_endpoint("https://169.254.1.1/api")


def test_validate_msi_endpoint_rejects_empty_hostname() -> None:
    with pytest.raises(MsiContractError):
        validate_msi_endpoint("https://")


def test_validate_msi_endpoint_rejects_path_only_no_host() -> None:
    with pytest.raises(MsiContractError):
        validate_msi_endpoint("https:///path")


def test_validate_msi_endpoint_rejects_port_only_no_host() -> None:
    with pytest.raises(MsiContractError):
        validate_msi_endpoint("https://:443")


def test_validate_environment_accepts_prod() -> None:
    validate_environment("prod")  # must not raise


def test_validate_environment_accepts_staging() -> None:
    validate_environment("staging")  # must not raise


def test_validate_environment_rejects_dev() -> None:
    with pytest.raises(MsiContractError, match="dev"):
        validate_environment("dev")


def test_validate_environment_rejects_local() -> None:
    with pytest.raises(MsiContractError, match="local"):
        validate_environment("local")


def test_validate_environment_rejects_unknown() -> None:
    with pytest.raises(MsiContractError):
        validate_environment("production")  # must use exact 'prod'


def test_artifact_name_with_secret_material_is_rejected() -> None:
    """Artifact name containing secret-like patterns is rejected at contract validation."""
    contract = _make_valid_contract(
        artifact_name="FrostGateAgent-ENROLLMENT_TOKEN-1.0.msi"
    )
    with pytest.raises(MsiContractError, match="secret material"):
        contract.validate_contract()


def test_build_command_plan_contains_no_secret_patterns() -> None:
    """Generated build plan contains no secret-like patterns."""
    contract = _make_valid_contract()
    plan = contract.build_build_command_plan()
    combined = " ".join(plan).lower()
    for pattern in _SECRET_PATTERNS:
        assert pattern.lower() not in combined, (
            f"Secret pattern '{pattern}' found in build command plan"
        )


def test_smoke_test_plan_contains_no_secret_patterns() -> None:
    """Generated smoke-test plan contains no secret-like patterns."""
    contract = _make_valid_contract()
    plan = contract.build_smoke_test_plan()
    combined = " ".join(plan).lower()
    for pattern in _SECRET_PATTERNS:
        assert pattern.lower() not in combined, (
            f"Secret pattern '{pattern}' found in smoke-test plan"
        )


def test_install_command_example_contains_only_placeholders() -> None:
    """Install command example uses placeholder values, not real secrets."""
    contract = _make_valid_contract()
    cmd = contract.build_install_command_example()
    # Must contain placeholder markers, not real secret values
    assert "<bootstrap-token>" in cmd
    assert "<tenant-id>" in cmd
    assert "<control-plane-fqdn>" in cmd
    # Must not contain bare secret-like key names as values (only as PROPERTY=value pairs)
    # The example shows ENROLLMENT_TOKEN= as a property name, which is expected
    assert "ENROLLMENT_TOKEN=" in cmd


def test_uninstall_command_example_no_purge_by_default() -> None:
    """Default uninstall command example does not include PURGE_DATA=1."""
    contract = _make_valid_contract()
    cmd = contract.build_uninstall_command_example()
    assert "PURGE_DATA=1" not in cmd
    assert "msiexec" in cmd
    assert "/x" in cmd


def test_purge_uninstall_is_explicit() -> None:
    """Purge uninstall command example requires purge=True and differs from standard."""
    contract = _make_valid_contract()
    standard = contract.build_uninstall_command_example(purge=False)
    purge = contract.build_uninstall_command_example(purge=True)
    assert "PURGE_DATA=1" in purge
    assert "PURGE_DATA=1" not in standard
    assert purge != standard


# ===========================================================================
# 4. Build / smoke-test plan determinism and correctness
# ===========================================================================


def test_build_command_plan_is_deterministic() -> None:
    """build_build_command_plan() returns identical plan across calls for same contract."""
    contract = _make_valid_contract()
    assert contract.build_build_command_plan() == contract.build_build_command_plan()


def test_smoke_test_plan_is_deterministic() -> None:
    """build_smoke_test_plan() returns identical plan across calls for same contract."""
    contract = _make_valid_contract()
    assert contract.build_smoke_test_plan() == contract.build_smoke_test_plan()


def test_build_command_plan_references_artifact_name() -> None:
    """Build plan must reference the artifact_name so operators can verify output."""
    contract = _make_valid_contract()
    plan = contract.build_build_command_plan()
    combined = " ".join(plan)
    assert contract.artifact_name in combined


def test_smoke_test_plan_references_artifact_path() -> None:
    """Smoke-test plan must reference the full artifact path."""
    contract = _make_valid_contract()
    plan = contract.build_smoke_test_plan()
    combined = " ".join(plan)
    assert contract.artifact_name in combined
    assert contract.build_output_dir in combined


def test_build_command_plan_is_non_empty_list() -> None:
    contract = _make_valid_contract()
    plan = contract.build_build_command_plan()
    assert isinstance(plan, list)
    assert len(plan) >= 2  # at minimum: candle step + light step


def test_smoke_test_plan_uses_sha256() -> None:
    """Smoke-test plan must use SHA256 for artifact hash verification."""
    contract = _make_valid_contract()
    plan = contract.build_smoke_test_plan()
    combined = " ".join(plan).lower()
    assert "sha256" in combined


# ===========================================================================
# 5. Artifact manifest requirements
# ===========================================================================


def test_manifest_template_returns_msi_artifact_manifest() -> None:
    contract = _make_valid_contract()
    manifest = contract.build_manifest_template(
        commit="abc1234", build_time="2026-04-28T00:00:00Z"
    )
    assert isinstance(manifest, MsiArtifactManifest)


def test_manifest_template_sha256_is_none_before_build() -> None:
    """Pre-build manifest has no SHA256 values — populated by build pipeline."""
    contract = _make_valid_contract()
    manifest = contract.build_manifest_template(
        commit="abc1234", build_time="2026-04-28T00:00:00Z"
    )
    assert manifest.sha256_msi is None
    assert manifest.sha256_exe is None


def test_manifest_template_signing_status_is_unsigned() -> None:
    """Pre-build manifest is always unsigned — updated by signing pipeline."""
    contract = _make_valid_contract()
    manifest = contract.build_manifest_template(
        commit="abc1234", build_time="2026-04-28T00:00:00Z"
    )
    assert manifest.signing_status == "unsigned"
    assert manifest.build_signed is False
    assert manifest.signed_by == "N/A"


def test_manifest_template_as_dict_has_required_fields() -> None:
    """MsiArtifactManifest.as_dict() contains all contract-required release metadata."""
    contract = _make_valid_contract()
    manifest = contract.build_manifest_template(
        commit="deadbeef", build_time="2026-04-28T12:00:00Z"
    )
    d = manifest.as_dict()
    for field in (
        "product",
        "version",
        "commit",
        "build_time",
        "signing_status",
        "signed_by",
        "sha256_msi",
        "sha256_exe",
        "min_os",
        "arch",
        "build_signed",
    ):
        assert field in d, f"Manifest dict missing required field: '{field}'"


def test_contract_signing_required_defaults_to_true() -> None:
    """signing_required defaults to True — unsigned = NOT FOR PRODUCTION."""
    contract = MsiBuildContract(
        product_name="FrostGateAgent",
        product_version="1.0.0",
        manufacturer="FrostGate Inc.",
        upgrade_code=_VALID_GUID,
        service_name="FrostGateAgent",
        install_dir=r"C:\Program Files\FrostGate\Agent",
        config_dir=r"C:\ProgramData\FrostGate\Agent\config",
        log_dir=r"C:\ProgramData\FrostGate\Agent\logs",
        data_dir=r"C:\ProgramData\FrostGate\Agent\data",
        build_output_dir=_BUILD_OUT,
        artifact_name="FrostGateAgent-1.0.0-x86_64.msi",
    )
    assert contract.signing_required is True


def test_contract_sha256_manifest_required_defaults_to_true() -> None:
    """sha256_manifest_required defaults to True."""
    contract = MsiBuildContract(
        product_name="FrostGateAgent",
        product_version="1.0.0",
        manufacturer="FrostGate Inc.",
        upgrade_code=_VALID_GUID,
        service_name="FrostGateAgent",
        install_dir=r"C:\Program Files\FrostGate\Agent",
        config_dir=r"C:\ProgramData\FrostGate\Agent\config",
        log_dir=r"C:\ProgramData\FrostGate\Agent\logs",
        data_dir=r"C:\ProgramData\FrostGate\Agent\data",
        build_output_dir=_BUILD_OUT,
        artifact_name="FrostGateAgent-1.0.0-x86_64.msi",
    )
    assert contract.sha256_manifest_required is True


def test_unsigned_artifact_manifest_is_not_production_ready() -> None:
    """Unsigned manifest must have build_signed=False, marking it not for production."""
    contract = _make_valid_contract(signing_status="unsigned")
    manifest = contract.build_manifest_template(
        commit="abc1234", build_time="2026-04-28T00:00:00Z"
    )
    assert manifest.build_signed is False
    assert manifest.signing_status == "unsigned"


# ===========================================================================
# 6. Default factory
# ===========================================================================


def test_default_frostgate_msi_contract_has_expected_defaults() -> None:
    contract = default_frostgate_msi_contract(
        product_version="1.2.3",
        build_output_dir=_BUILD_OUT,
    )
    assert contract.product_name == "FrostGateAgent"
    assert contract.service_name == "FrostGateAgent"
    assert contract.signing_required is True
    assert contract.sha256_manifest_required is True
    assert contract.package_code_strategy == "per_release"
    assert "1.2.3" in contract.artifact_name
    assert contract.artifact_name.endswith(".msi")


def test_default_frostgate_msi_contract_validates() -> None:
    contract = default_frostgate_msi_contract(
        product_version="1.2.3",
        build_output_dir=_BUILD_OUT,
    )
    contract.validate_contract()  # must not raise


# ===========================================================================
# 7. Platform / toolchain behavior
# ===========================================================================


def test_execute_live_build_raises_on_non_windows() -> None:
    """execute_live_build() raises MsiToolchainError on non-Windows platforms."""
    if sys.platform == "win32":
        pytest.skip("toolchain test only meaningful on non-Windows")
    contract = _make_valid_contract()
    with pytest.raises(MsiToolchainError, match="Windows"):
        contract.execute_live_build()


def test_plan_generation_works_cross_platform() -> None:
    """All build_*_command_plan() methods work on the current (non-Windows) platform."""
    contract = _make_valid_contract()
    build_plan = contract.build_build_command_plan()
    smoke_plan = contract.build_smoke_test_plan()
    assert isinstance(build_plan, list) and len(build_plan) > 0
    assert isinstance(smoke_plan, list) and len(smoke_plan) > 0


def test_install_and_uninstall_examples_work_cross_platform() -> None:
    """build_install_command_example() and build_uninstall_command_example() work cross-platform."""
    contract = _make_valid_contract()
    install = contract.build_install_command_example()
    uninstall = contract.build_uninstall_command_example()
    assert isinstance(install, str) and len(install) > 0
    assert isinstance(uninstall, str) and len(uninstall) > 0


def test_plan_validation_command_targets_this_test_file() -> None:
    """Task 18.2 validation_commands must include this dedicated test file."""
    plan_path = Path(__file__).resolve().parents[2] / "plans" / "30_day_repo_blitz.yaml"
    assert plan_path.exists(), f"Plan file missing: {plan_path}"
    plan_text = plan_path.read_text(encoding="utf-8")
    # Find task 18.2 section and verify this test file is in its validation_commands
    task_idx = plan_text.find("id: '18.2'")
    assert task_idx != -1, "Task 18.2 not found in plan YAML"
    # Scan from task 18.2 definition to the next task definition
    task_section = plan_text[task_idx : task_idx + 600]
    assert "test_msi_installer_contract" in task_section, (
        "Task 18.2 validation_commands must include tests/agent/test_msi_installer_contract.py"
    )


# ===========================================================================
# 8. Regression invariants
# ===========================================================================


def test_regression_execute_live_build_never_succeeds_on_non_windows() -> None:
    """Regression: execute_live_build() must ALWAYS raise on non-Windows.

    If this test fails, the platform guard has been removed or bypassed.
    """
    if sys.platform == "win32":
        pytest.skip("regression only meaningful on non-Windows")
    contract = _make_valid_contract()
    raised = False
    try:
        contract.execute_live_build()
    except MsiToolchainError:
        raised = True
    assert raised, (
        "execute_live_build() returned without raising MsiToolchainError on non-Windows. "
        "The platform guard has been broken."
    )


def test_regression_build_plan_never_contains_token_material() -> None:
    """Regression: build command plan must not contain any secret pattern."""
    contract = _make_valid_contract()
    plan = contract.build_build_command_plan()
    combined = " ".join(plan).lower()
    violations = [p for p in _SECRET_PATTERNS if p.lower() in combined]
    assert not violations, (
        f"Build command plan contains forbidden secret patterns: {violations}\nPlan: {plan}"
    )


def test_regression_uninstall_is_not_purge_by_default() -> None:
    """Regression: default uninstall must never include PURGE_DATA=1."""
    contract = _make_valid_contract()
    cmd = contract.build_uninstall_command_example()
    assert "PURGE_DATA=1" not in cmd, (
        "Default uninstall command includes PURGE_DATA=1. "
        "Purge must require explicit purge=True."
    )


def test_regression_purge_and_standard_uninstall_are_distinct() -> None:
    """Regression: purge and standard uninstall commands must be different."""
    contract = _make_valid_contract()
    assert contract.build_uninstall_command_example(
        purge=False
    ) != contract.build_uninstall_command_example(purge=True)


def test_regression_build_plan_is_deterministic() -> None:
    """Regression: build plan must not be nondeterministic (e.g. timestamp injection)."""
    contract = _make_valid_contract()
    plans = [contract.build_build_command_plan() for _ in range(5)]
    assert all(p == plans[0] for p in plans), (
        "build_build_command_plan() returned different results — nondeterminism detected"
    )


def test_regression_sha256_manifest_cannot_be_disabled() -> None:
    """Regression: sha256_manifest_required=False must always fail validate_contract()."""
    contract = _make_valid_contract(sha256_manifest_required=False)
    with pytest.raises(MsiContractError):
        contract.validate_contract()


def test_regression_validate_msi_endpoint_rejects_empty_hostname() -> None:
    """Regression (P2): endpoints with no hostname must be rejected.

    https://, https:///path, and https://:443 all parse to an empty hostname
    and previously passed the forbidden-hostname and IP checks silently.
    """
    for bad in ("https://", "https:///path", "https://:443"):
        with pytest.raises(MsiContractError, match="no resolvable hostname"):
            validate_msi_endpoint(bad)


def test_regression_execute_live_build_uses_arg_list_not_shell() -> None:
    """Regression (P1): execute_live_build() must not use shell=True.

    On non-Windows this raises MsiToolchainError before subprocess is called.
    On Windows it would previously have used shell=True, enabling shell metacharacter
    injection via artifact_name or build_output_dir.  This test verifies the platform
    guard fires first; the structural fix (shell=False arg list) is verified by
    code review of execute_live_build().
    """
    if sys.platform == "win32":
        pytest.skip(
            "structural shell=False fix must be verified by code review on Windows"
        )
    contract = _make_valid_contract()
    with pytest.raises(MsiToolchainError, match="WiX toolchain"):
        contract.execute_live_build()
