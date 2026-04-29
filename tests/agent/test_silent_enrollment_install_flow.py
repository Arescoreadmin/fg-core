"""
tests/agent/test_silent_enrollment_install_flow.py

Tests for task 18.3 — Silent enrollment install flow contract.

Coverage:
  1. Required enrollment parameter definitions
  2. Parameter validation — required fields, mutual exclusivity, env/endpoint guards
  3. Command plan — /qn mode, required MSI properties, determinism
  4. Token safety — log-safe redaction, no token in logged output
  5. Service credential gate invariant
  6. Platform / toolchain behavior
  7. Plan YAML cross-reference
  8. Regression invariants

Tests are deterministic and offline-safe.
No Windows CI required — live MSI enrollment is platform-gated.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

from agent.app.installer.msi_contract import SILENT_REQUIRED_PARAMS
from agent.app.service.wrapper import WindowsServiceConfig
from agent.app.installer.silent_enrollment import (
    MSI_PROP_ENDPOINT,
    MSI_PROP_ENVIRONMENT,
    MSI_PROP_TENANT_ID,
    MSI_PROP_TOKEN,
    PLACEHOLDER_ENDPOINT,
    PLACEHOLDER_TOKEN,
    SERVICE_CREDENTIAL_GATE_REQUIRED,
    TOKEN_REDACTED,
    EnrollmentToolchainError,
    EnrollmentValidationError,
    SilentEnrollmentParams,
    placeholder_enrollment_params,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ARTIFACT = r"C:\build\FrostGateAgent-1.0.0-x86_64.msi"
_VALID_ENDPOINT = "https://control-plane.frostgate.example.com"
_VALID_TENANT = "tenant-abc123"
_VALID_TOKEN = "enroll-token-abc123"


def _make_params(**overrides: object) -> SilentEnrollmentParams:
    defaults: dict[str, object] = dict(
        tenant_id=_VALID_TENANT,
        control_plane_url=_VALID_ENDPOINT,
        environment="prod",
        bootstrap_token=_VALID_TOKEN,
    )
    defaults.update(overrides)
    return SilentEnrollmentParams(**defaults)  # type: ignore[arg-type]


# ===========================================================================
# 1. Required enrollment parameter definitions
# ===========================================================================


def test_silent_required_params_contains_tenant_id() -> None:
    assert "TENANT_ID" in SILENT_REQUIRED_PARAMS


def test_silent_required_params_contains_frostgate_endpoint() -> None:
    assert "FROSTGATE_ENDPOINT" in SILENT_REQUIRED_PARAMS


def test_silent_required_params_contains_enrollment_token() -> None:
    assert (
        "ENROLLMENT_TOKEN" in SILENT_REQUIRED_PARAMS
        or "BOOTSTRAP_TOKEN" in SILENT_REQUIRED_PARAMS
    )


def test_silent_required_params_contains_environment() -> None:
    assert "ENVIRONMENT" in SILENT_REQUIRED_PARAMS


def test_service_credential_gate_required_is_true() -> None:
    """SERVICE_CREDENTIAL_GATE_REQUIRED must be True — never weakened."""
    assert SERVICE_CREDENTIAL_GATE_REQUIRED is True


def test_silent_enrollment_params_has_required_fields() -> None:
    required = {
        "tenant_id",
        "control_plane_url",
        "environment",
        "enrollment_token",
        "bootstrap_token",
    }
    fields = set(SilentEnrollmentParams.__dataclass_fields__.keys())
    missing = required - fields
    assert not missing, f"SilentEnrollmentParams missing fields: {missing}"


# ===========================================================================
# 2. Parameter validation
# ===========================================================================


def test_validate_passes_with_valid_params() -> None:
    _make_params().validate()  # must not raise


def test_validate_passes_with_enrollment_token() -> None:
    _make_params(bootstrap_token=None, enrollment_token=_VALID_TOKEN).validate()


def test_validate_passes_with_bootstrap_token() -> None:
    _make_params(enrollment_token=None, bootstrap_token=_VALID_TOKEN).validate()


def test_validate_rejects_missing_tenant_id() -> None:
    with pytest.raises(EnrollmentValidationError, match="tenant_id"):
        _make_params(tenant_id="").validate()


def test_validate_rejects_none_tenant_id() -> None:
    with pytest.raises(EnrollmentValidationError, match="tenant_id"):
        _make_params(tenant_id=None).validate()  # type: ignore[arg-type]


def test_validate_rejects_missing_endpoint() -> None:
    with pytest.raises(EnrollmentValidationError):
        _make_params(control_plane_url="").validate()


def test_validate_rejects_both_tokens_set() -> None:
    with pytest.raises(EnrollmentValidationError, match="mutually exclusive"):
        _make_params(
            enrollment_token=_VALID_TOKEN, bootstrap_token=_VALID_TOKEN
        ).validate()


def test_validate_rejects_no_token_supplied() -> None:
    with pytest.raises(EnrollmentValidationError, match="exactly one"):
        _make_params(enrollment_token=None, bootstrap_token=None).validate()


def test_validate_rejects_empty_enrollment_token_and_no_bootstrap() -> None:
    with pytest.raises(EnrollmentValidationError, match="exactly one"):
        _make_params(enrollment_token="", bootstrap_token=None).validate()


def test_validate_rejects_dev_environment() -> None:
    with pytest.raises(EnrollmentValidationError, match="dev"):
        _make_params(environment="dev").validate()


def test_validate_rejects_local_environment() -> None:
    with pytest.raises(EnrollmentValidationError, match="local"):
        _make_params(environment="local").validate()


def test_validate_rejects_unknown_environment() -> None:
    with pytest.raises(EnrollmentValidationError):
        _make_params(environment="test").validate()


def test_validate_accepts_prod_environment() -> None:
    _make_params(environment="prod").validate()  # must not raise


def test_validate_accepts_staging_environment() -> None:
    _make_params(environment="staging").validate()  # must not raise


def test_validate_rejects_http_endpoint() -> None:
    with pytest.raises(EnrollmentValidationError):
        _make_params(
            control_plane_url="http://control-plane.frostgate.example.com"
        ).validate()


def test_validate_rejects_localhost_endpoint() -> None:
    with pytest.raises(EnrollmentValidationError):
        _make_params(control_plane_url="https://localhost/api").validate()


def test_validate_rejects_loopback_ip_endpoint() -> None:
    with pytest.raises(EnrollmentValidationError):
        _make_params(control_plane_url="https://127.0.0.1/api").validate()


def test_validate_rejects_rfc1918_10_block() -> None:
    with pytest.raises(EnrollmentValidationError):
        _make_params(control_plane_url="https://10.0.0.1/api").validate()


def test_validate_rejects_rfc1918_172_block() -> None:
    with pytest.raises(EnrollmentValidationError):
        _make_params(control_plane_url="https://172.16.0.1/api").validate()


def test_validate_rejects_rfc1918_192_168_block() -> None:
    with pytest.raises(EnrollmentValidationError):
        _make_params(control_plane_url="https://192.168.1.1/api").validate()


def test_validate_rejects_link_local_endpoint() -> None:
    with pytest.raises(EnrollmentValidationError):
        _make_params(control_plane_url="https://169.254.1.1/api").validate()


def test_validate_rejects_empty_hostname_endpoint() -> None:
    with pytest.raises(EnrollmentValidationError):
        _make_params(control_plane_url="https://").validate()


def test_validate_accepts_valid_https_fqdn() -> None:
    _make_params(
        control_plane_url="https://control-plane.frostgate.example.com"
    ).validate()  # must not raise


# ===========================================================================
# 3. Command plan — /qn mode, required MSI properties, determinism
# ===========================================================================


def test_command_uses_qn_silent_mode() -> None:
    args = _make_params().build_msiexec_args(_ARTIFACT)
    assert "/qn" in args, f"Expected /qn in args: {args}"


def test_command_does_not_use_interactive_flags() -> None:
    args = _make_params().build_msiexec_args(_ARTIFACT)
    combined = " ".join(args)
    for interactive_flag in ("/qb", "/qf", "/qr", "/qb+", "/qb-"):
        assert interactive_flag not in combined, (
            f"Interactive UI flag '{interactive_flag}' found in command: {args}"
        )


def test_command_uses_msiexec() -> None:
    args = _make_params().build_msiexec_args(_ARTIFACT)
    assert args[0] == "msiexec"


def test_command_uses_i_flag() -> None:
    args = _make_params().build_msiexec_args(_ARTIFACT)
    assert "/i" in args


def test_command_includes_tenant_id_property() -> None:
    params = _make_params(tenant_id="my-tenant")
    args = params.build_msiexec_args(_ARTIFACT)
    assert any(a.startswith(f"{MSI_PROP_TENANT_ID}=") for a in args), (
        f"Expected {MSI_PROP_TENANT_ID}= in args: {args}"
    )


def test_command_includes_frostgate_endpoint_property() -> None:
    args = _make_params().build_msiexec_args(_ARTIFACT)
    assert any(a.startswith(f"{MSI_PROP_ENDPOINT}=") for a in args), (
        f"Expected {MSI_PROP_ENDPOINT}= in args: {args}"
    )


def test_command_includes_environment_property() -> None:
    args = _make_params().build_msiexec_args(_ARTIFACT)
    assert any(a.startswith(f"{MSI_PROP_ENVIRONMENT}=") for a in args), (
        f"Expected {MSI_PROP_ENVIRONMENT}= in args: {args}"
    )


def test_command_includes_token_property() -> None:
    args = _make_params().build_msiexec_args(_ARTIFACT)
    assert any(a.startswith(f"{MSI_PROP_TOKEN}=") for a in args), (
        f"Expected {MSI_PROP_TOKEN}= in args: {args}"
    )


def test_command_includes_optional_installdir_when_set() -> None:
    args = _make_params(install_dir=r"C:\Custom\FrostGate").build_msiexec_args(
        _ARTIFACT
    )
    assert any("INSTALLDIR=" in a for a in args)


def test_command_omits_installdir_when_not_set() -> None:
    args = _make_params(install_dir=None).build_msiexec_args(_ARTIFACT)
    assert not any("INSTALLDIR=" in a for a in args)


def test_command_includes_log_level_when_set() -> None:
    args = _make_params(log_level="DEBUG").build_msiexec_args(_ARTIFACT)
    assert any("LOG_LEVEL=DEBUG" in a for a in args)


def test_command_ordering_is_deterministic() -> None:
    params = _make_params()
    calls = [params.build_msiexec_args(_ARTIFACT) for _ in range(5)]
    assert all(c == calls[0] for c in calls), (
        "build_msiexec_args() is non-deterministic across calls"
    )


def test_log_safe_ordering_matches_redacted_build() -> None:
    params = _make_params()
    log_safe = params.build_log_safe_args(_ARTIFACT)
    redacted = params.build_msiexec_args(_ARTIFACT, redact_token=True)
    assert log_safe == redacted


def test_placeholder_params_build_command_plan() -> None:
    params = placeholder_enrollment_params()
    args = params.build_msiexec_args(_ARTIFACT)
    assert "/qn" in args
    assert any(f"{MSI_PROP_TENANT_ID}=" in a for a in args)
    assert any(f"{MSI_PROP_ENDPOINT}=" in a for a in args)


# ===========================================================================
# 4. Token safety — log-safe redaction, no token in logged output
# ===========================================================================


def test_log_safe_args_redact_token() -> None:
    real_token = "super-secret-enroll-token-xyz"
    params = _make_params(bootstrap_token=real_token, enrollment_token=None)
    log_safe = params.build_log_safe_args(_ARTIFACT)
    combined = " ".join(log_safe)
    assert real_token not in combined, (
        f"Real token '{real_token}' found in log-safe output: {log_safe}"
    )
    assert TOKEN_REDACTED in combined, (
        f"Expected TOKEN_REDACTED sentinel in log-safe output: {log_safe}"
    )


def test_log_safe_args_contain_redacted_sentinel() -> None:
    args = _make_params().build_log_safe_args(_ARTIFACT)
    assert any(TOKEN_REDACTED in a for a in args)


def test_execution_args_contain_real_token() -> None:
    real_token = "real-bootstrap-token-abc"
    params = _make_params(bootstrap_token=real_token, enrollment_token=None)
    args = params.build_msiexec_args(_ARTIFACT, redact_token=False)
    assert any(real_token in a for a in args)


def test_execution_args_with_enrollment_token() -> None:
    real_token = "real-enrollment-token-def"
    params = _make_params(enrollment_token=real_token, bootstrap_token=None)
    args = params.build_msiexec_args(_ARTIFACT, redact_token=False)
    assert any(real_token in a for a in args)


def test_silent_enrollment_params_has_no_to_config_method() -> None:
    """SilentEnrollmentParams must not expose a method that serialises the token
    into a plain config dict (which could be written to disk)."""
    params = _make_params()
    for method_name in ("to_config", "to_config_dict", "as_config", "as_dict"):
        assert not hasattr(params, method_name), (
            f"SilentEnrollmentParams has method '{method_name}' "
            "that could expose token in a config serialisation path"
        )


def test_placeholder_token_is_not_a_real_secret() -> None:
    assert "<" not in _VALID_TOKEN, "test helper token should not be a placeholder"
    assert PLACEHOLDER_TOKEN != _VALID_TOKEN


def test_placeholder_endpoint_is_not_production() -> None:
    assert "example.com" in PLACEHOLDER_ENDPOINT
    assert PLACEHOLDER_ENDPOINT != _VALID_ENDPOINT


# ===========================================================================
# 5. Service credential gate invariant
# ===========================================================================


def test_service_credential_gate_required_constant_exists() -> None:
    assert isinstance(SERVICE_CREDENTIAL_GATE_REQUIRED, bool)


def test_service_credential_gate_required_is_not_false() -> None:
    """Regression: weakening this to False would allow service start before credential."""
    assert SERVICE_CREDENTIAL_GATE_REQUIRED is True, (
        "SERVICE_CREDENTIAL_GATE_REQUIRED must be True. "
        "Changing this allows service start before device credential exists."
    )


def _make_service_config() -> WindowsServiceConfig:
    from agent.app.service.wrapper import default_frostgate_service_config

    return default_frostgate_service_config(
        executable_path=r"C:\Program Files\FrostGate\Agent\FrostGateAgent.exe",
        working_directory=r"C:\Program Files\FrostGate\Agent",
        config_path=r"C:\ProgramData\FrostGate\Agent\config\agent.toml",
        log_directory=r"C:\ProgramData\FrostGate\Agent\logs",
        data_directory=r"C:\ProgramData\FrostGate\Agent\data",
    )


def test_wrapper_build_start_plan_requires_device_credential_exists() -> None:
    """The WindowsServiceConfig service start plan must reject device_credential_exists=False."""
    from agent.app.service.wrapper import ServiceConfigError

    config = _make_service_config()
    with pytest.raises(ServiceConfigError, match="device credential"):
        config.build_start_command_plan(
            config_path_exists=True,
            device_credential_exists=False,
        )


def test_wrapper_build_start_plan_requires_config_path_exists() -> None:
    from agent.app.service.wrapper import ServiceConfigError

    config = _make_service_config()
    with pytest.raises(ServiceConfigError):
        config.build_start_command_plan(
            config_path_exists=False,
            device_credential_exists=True,
        )


# ===========================================================================
# 6. Platform / toolchain behavior
# ===========================================================================


def test_execute_live_enrollment_raises_on_non_windows() -> None:
    if sys.platform == "win32":
        pytest.skip("platform guard only meaningful on non-Windows")
    params = _make_params()
    with pytest.raises(EnrollmentToolchainError, match="msiexec"):
        params.execute_live_enrollment(_ARTIFACT)


def test_build_msiexec_args_is_cross_platform() -> None:
    """Command plan generation must work on Linux (no platform guard)."""
    params = _make_params()
    args = params.build_msiexec_args(_ARTIFACT)
    assert isinstance(args, list)
    assert len(args) > 0


def test_build_log_safe_args_is_cross_platform() -> None:
    params = _make_params()
    args = params.build_log_safe_args(_ARTIFACT)
    assert isinstance(args, list)
    assert len(args) > 0


def test_placeholder_enrollment_params_is_cross_platform() -> None:
    params = placeholder_enrollment_params()
    assert isinstance(params, SilentEnrollmentParams)
    args = params.build_msiexec_args(_ARTIFACT)
    assert len(args) > 0


# ===========================================================================
# 7. Plan YAML cross-reference
# ===========================================================================


def test_plan_validation_command_targets_this_test_file() -> None:
    """Task 18.3 validation_commands must include this test file."""
    plan_path = (
        Path(__file__).resolve().parent.parent.parent
        / "plans"
        / "30_day_repo_blitz.yaml"
    )
    assert plan_path.exists(), f"Plan YAML not found at {plan_path}"
    with plan_path.open() as f:
        plan = yaml.safe_load(f)

    task_183: dict | None = None
    for phase in plan.get("phases", []):
        for module in phase.get("modules", []):
            for task in module.get("tasks", []):
                if str(task.get("id")) == "18.3":
                    task_183 = task
                    break

    assert task_183 is not None, "Task 18.3 not found in plan YAML"
    validation_commands = task_183.get("validation_commands", [])
    found = any(
        "test_silent_enrollment_install_flow" in cmd for cmd in validation_commands
    )
    assert found, (
        f"Task 18.3 validation_commands do not reference "
        f"'test_silent_enrollment_install_flow'. Got: {validation_commands}"
    )


# ===========================================================================
# 8. Regression invariants
# ===========================================================================


def test_regression_log_safe_never_contains_real_token() -> None:
    """Regression: log-safe output must NEVER contain real token values."""
    real_token = "very-secret-enrollment-token-regression"
    params = _make_params(bootstrap_token=real_token, enrollment_token=None)
    log_args = params.build_log_safe_args(_ARTIFACT)
    combined = " ".join(log_args)
    assert real_token not in combined, (
        f"REGRESSION: real token '{real_token}' leaked into log-safe output. "
        f"Output: {log_args}"
    )


def test_regression_no_interactive_ui_flag_in_command() -> None:
    """Regression: silent install must never use interactive UI mode flags."""
    args = _make_params().build_msiexec_args(_ARTIFACT)
    combined = " ".join(args)
    for bad_flag in ("/qb", "/qf", "/qr", "/qb+", "/qb-"):
        assert bad_flag not in combined, (
            f"REGRESSION: interactive flag '{bad_flag}' found in command plan. "
            f"Silent enrollment must always use /qn."
        )


def test_regression_production_endpoint_not_localhost() -> None:
    """Regression: production endpoint must never default to localhost."""
    assert "localhost" not in PLACEHOLDER_ENDPOINT
    assert "127." not in PLACEHOLDER_ENDPOINT
    with pytest.raises(EnrollmentValidationError):
        _make_params(control_plane_url="https://localhost/api").validate()


def test_regression_service_cannot_start_without_credential() -> None:
    """Regression: service start plan must reject device_credential_exists=False."""
    from agent.app.service.wrapper import ServiceConfigError

    config = _make_service_config()
    with pytest.raises(ServiceConfigError):
        config.build_start_command_plan(
            config_path_exists=True,
            device_credential_exists=False,
        )


def test_regression_command_plan_is_deterministic() -> None:
    """Regression: command plan must not be nondeterministic (e.g. timestamps)."""
    params = _make_params()
    plans = [params.build_msiexec_args(_ARTIFACT) for _ in range(5)]
    assert all(p == plans[0] for p in plans), (
        "REGRESSION: build_msiexec_args() returned different results — nondeterminism detected"
    )


def test_regression_execute_live_enrollment_never_succeeds_on_non_windows() -> None:
    """Regression: execute_live_enrollment() must ALWAYS raise on non-Windows."""
    if sys.platform == "win32":
        pytest.skip("regression only meaningful on non-Windows")
    params = _make_params()
    raised = False
    try:
        params.execute_live_enrollment(_ARTIFACT)
    except EnrollmentToolchainError:
        raised = True
    assert raised, (
        "REGRESSION: execute_live_enrollment() returned without raising "
        "EnrollmentToolchainError on non-Windows. Platform guard broken."
    )


def test_regression_p1_whitespace_enrollment_token_uses_bootstrap() -> None:
    """Regression (P1): whitespace enrollment_token must not win over valid bootstrap_token.

    validate() treats '   ' as absent (strip() is empty), so bootstrap_token
    should be used. _active_token() previously returned the whitespace string
    because non-empty whitespace is truthy, making build_msiexec_args() emit
    ENROLLMENT_TOKEN=   instead of the valid bootstrap token.
    """
    real_bootstrap = "valid-bootstrap-token-xyz"
    params = _make_params(enrollment_token="   ", bootstrap_token=real_bootstrap)
    # Validation must pass (whitespace enrollment_token treated as absent)
    params.validate()
    # build_msiexec_args must use bootstrap_token, not whitespace
    args = params.build_msiexec_args(_ARTIFACT, redact_token=False)
    token_arg = next((a for a in args if a.startswith(f"{MSI_PROP_TOKEN}=")), None)
    assert token_arg is not None, f"No {MSI_PROP_TOKEN}= in args: {args}"
    assert token_arg == f"{MSI_PROP_TOKEN}={real_bootstrap}", (
        f"REGRESSION (P1): whitespace enrollment_token used instead of bootstrap_token. "
        f"Got: '{token_arg}', expected ENROLLMENT_TOKEN={real_bootstrap}"
    )


def test_regression_p2_non_string_token_raises_enrollment_validation_error() -> None:
    """Regression (P2): non-string token values must raise EnrollmentValidationError.

    validate() called .strip() directly without isinstance check, so integer or
    other non-string tokens raised AttributeError instead of EnrollmentValidationError,
    bypassing callers that only handle EnrollmentValidationError.
    """
    params = _make_params(
        enrollment_token=None,
        bootstrap_token=12345,  # type: ignore[arg-type]
    )
    with pytest.raises(EnrollmentValidationError):
        params.validate()


def test_regression_p2_non_string_enrollment_token_raises_validation_error() -> None:
    """Regression (P2): non-string enrollment_token must raise EnrollmentValidationError."""
    params = _make_params(
        enrollment_token=True,  # type: ignore[arg-type]
        bootstrap_token=None,
    )
    with pytest.raises(EnrollmentValidationError):
        params.validate()
