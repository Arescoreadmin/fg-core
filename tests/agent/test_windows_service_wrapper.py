"""
tests/agent/test_windows_service_wrapper.py

Tests for task 18.1 — Windows service wrapper foundation.

Coverage:
  1. Config / command plan  — validate, install, start, stop, uninstall, purge
  2. Security               — forbidden accounts, no token material, endpoint rejection
  3. Platform behavior      — live ops fail on non-Windows; plan mode is cross-platform
  4. Lifecycle compatibility — no bypass of device credential or agent config contract
  5. Regression             — invariants that must hold or tests must fail

Tests are deterministic and offline-safe.
No Windows CI required — live service execution is platform-gated.
"""

from __future__ import annotations

import sys

import pytest

from agent.app.service.wrapper import (
    ServiceConfigError,
    UnsupportedPlatformError,
    WindowsServiceConfig,
    _SECRET_PATTERNS,
    default_frostgate_service_config,
    validate_production_endpoint,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_EXEC_PATH = r"C:\Program Files\FrostGate\Agent\FrostGateAgent.exe"
_WORK_DIR = r"C:\ProgramData\FrostGate\Agent"
_CONFIG_PATH = r"C:\ProgramData\FrostGate\Agent\config\agent.toml"
_LOG_DIR = r"C:\ProgramData\FrostGate\Agent\logs"
_DATA_DIR = r"C:\ProgramData\FrostGate\Agent\data"


def _make_valid_config(**overrides: object) -> WindowsServiceConfig:
    """Return a valid WindowsServiceConfig, optionally overriding fields."""
    defaults: dict[str, object] = dict(
        service_name="FrostGateAgent",
        display_name="FrostGate Agent",
        description="FrostGate endpoint telemetry agent",
        executable_path=_EXEC_PATH,
        working_directory=_WORK_DIR,
        config_path=_CONFIG_PATH,
        log_directory=_LOG_DIR,
        data_directory=_DATA_DIR,
        service_account="NT SERVICE\\FrostGateAgent",
        start_type="auto",
        restart_policy="always",
        stop_timeout_seconds=30,
    )
    defaults.update(overrides)
    return WindowsServiceConfig(**defaults)  # type: ignore[arg-type]


# ===========================================================================
# 1. Config / command plan
# ===========================================================================


def test_service_config_validates_with_expected_fields() -> None:
    """Valid service config passes validation without error."""
    config = _make_valid_config()
    config.validate_service_config()  # must not raise


def test_install_command_plan_contains_service_name() -> None:
    config = _make_valid_config()
    plan = config.build_install_command_plan()
    assert config.service_name in plan


def test_install_command_plan_contains_executable_path() -> None:
    config = _make_valid_config()
    plan = config.build_install_command_plan()
    assert config.executable_path in plan


def test_install_command_plan_contains_service_account() -> None:
    config = _make_valid_config()
    plan = config.build_install_command_plan()
    assert config.service_account in plan


def test_install_command_plan_contains_sc_create() -> None:
    config = _make_valid_config()
    plan = config.build_install_command_plan()
    assert plan[0] == "sc"
    assert plan[1] == "create"


def test_start_command_plan_succeeds_with_all_preconditions() -> None:
    """Start plan is generated when config and credential are both present."""
    config = _make_valid_config()
    plan = config.build_start_command_plan(
        config_path_exists=True,
        device_credential_exists=True,
    )
    assert plan == ["sc", "start", config.service_name]


def test_start_command_plan_requires_config_path() -> None:
    """Start plan fails closed when config path is absent."""
    config = _make_valid_config()
    with pytest.raises(ServiceConfigError, match="config path"):
        config.build_start_command_plan(
            config_path_exists=False,
            device_credential_exists=True,
        )


def test_start_command_plan_requires_device_credential() -> None:
    """Start plan fails closed when device credential is absent."""
    config = _make_valid_config()
    with pytest.raises(ServiceConfigError, match="device credential"):
        config.build_start_command_plan(
            config_path_exists=True,
            device_credential_exists=False,
        )


def test_start_command_plan_fails_when_both_absent() -> None:
    """Start plan fails closed when both config and credential are absent."""
    config = _make_valid_config()
    with pytest.raises(ServiceConfigError):
        config.build_start_command_plan(
            config_path_exists=False,
            device_credential_exists=False,
        )


def test_stop_command_plan_is_deterministic() -> None:
    """Stop plan is identical across multiple calls for the same config."""
    config = _make_valid_config()
    plan_a = config.build_stop_command_plan()
    plan_b = config.build_stop_command_plan()
    assert plan_a == plan_b
    assert plan_a == ["sc", "stop", config.service_name]


def test_uninstall_command_plan_does_not_purge_by_default() -> None:
    """Default uninstall does not include purge signal."""
    config = _make_valid_config()
    plan = config.build_uninstall_command_plan()
    assert "--purge-data" not in plan
    assert "sc" in plan
    assert "delete" in plan
    assert config.service_name in plan


def test_purge_uninstall_is_explicit() -> None:
    """Purge uninstall requires purge=True and differs from standard uninstall."""
    config = _make_valid_config()
    standard = config.build_uninstall_command_plan(purge=False)
    purge = config.build_uninstall_command_plan(purge=True)
    assert "--purge-data" in purge
    assert "--purge-data" not in standard
    assert purge != standard


def test_uninstall_purge_and_standard_are_distinct_plans() -> None:
    """Standard uninstall and purge uninstall must produce different command plans."""
    config = _make_valid_config()
    assert config.build_uninstall_command_plan(
        purge=False
    ) != config.build_uninstall_command_plan(purge=True)


# ===========================================================================
# 2. Security
# ===========================================================================


def test_localsystem_is_forbidden() -> None:
    """LocalSystem account is explicitly rejected by validate_service_config."""
    config = _make_valid_config(service_account="LocalSystem")
    with pytest.raises(ServiceConfigError, match="forbidden"):
        config.validate_service_config()


def test_nt_authority_system_is_forbidden() -> None:
    """NT AUTHORITY\\SYSTEM account is explicitly rejected."""
    config = _make_valid_config(service_account="NT AUTHORITY\\SYSTEM")
    with pytest.raises(ServiceConfigError, match="forbidden"):
        config.validate_service_config()


def test_system_account_is_forbidden() -> None:
    """'SYSTEM' account shorthand is rejected."""
    config = _make_valid_config(service_account="SYSTEM")
    with pytest.raises(ServiceConfigError, match="forbidden"):
        config.validate_service_config()


def test_default_service_account_is_non_privileged() -> None:
    """Default service account is NT SERVICE\\FrostGateAgent (non-privileged)."""
    config = WindowsServiceConfig(
        service_name="FrostGateAgent",
        display_name="FrostGate Agent",
        description="desc",
        executable_path=_EXEC_PATH,
        working_directory=_WORK_DIR,
        config_path=_CONFIG_PATH,
        log_directory=_LOG_DIR,
        data_directory=_DATA_DIR,
    )
    assert config.service_account == "NT SERVICE\\FrostGateAgent"
    assert config.service_account.lower() not in {"localsystem", "system"}


def test_enrollment_token_in_config_path_is_rejected() -> None:
    """config_path containing secret-like material is rejected."""
    config = _make_valid_config(config_path=r"C:\tmp\ENROLLMENT_TOKEN_file.toml")
    with pytest.raises(ServiceConfigError, match="secret material"):
        config.validate_service_config()


def test_bootstrap_token_in_config_path_is_rejected() -> None:
    """config_path containing BOOTSTRAP_TOKEN is rejected."""
    config = _make_valid_config(config_path=r"C:\tmp\BOOTSTRAP_TOKEN.conf")
    with pytest.raises(ServiceConfigError, match="secret material"):
        config.validate_service_config()


def test_install_command_plan_contains_no_secret_patterns() -> None:
    """Generated install plan contains no secret-like patterns."""
    config = _make_valid_config()
    plan = config.build_install_command_plan()
    combined = " ".join(plan).lower()
    for pattern in _SECRET_PATTERNS:
        assert pattern.lower() not in combined, (
            f"Secret pattern '{pattern}' found in install command plan: {plan}"
        )


def test_stop_command_plan_contains_no_secret_patterns() -> None:
    """Generated stop plan contains no secret-like patterns."""
    config = _make_valid_config()
    plan = config.build_stop_command_plan()
    combined = " ".join(plan).lower()
    for pattern in _SECRET_PATTERNS:
        assert pattern.lower() not in combined


def test_validate_production_endpoint_accepts_valid_https() -> None:
    """Valid HTTPS production endpoint passes validation."""
    validate_production_endpoint("https://control-plane.frostgate.example.com")


def test_validate_production_endpoint_rejects_localhost() -> None:
    """localhost endpoint is rejected as a production endpoint."""
    with pytest.raises(ServiceConfigError, match="local"):
        validate_production_endpoint("https://localhost/api")


def test_validate_production_endpoint_rejects_127_0_0_1() -> None:
    """127.0.0.1 endpoint is rejected as a production endpoint."""
    with pytest.raises(ServiceConfigError, match="local"):
        validate_production_endpoint("https://127.0.0.1:8443/api")


def test_validate_production_endpoint_rejects_ipv6_loopback() -> None:
    """::1 (IPv6 loopback) is rejected as a production endpoint."""
    with pytest.raises(ServiceConfigError, match="local"):
        validate_production_endpoint("https://[::1]:8443/api")


def test_validate_production_endpoint_rejects_http() -> None:
    """HTTP (non-TLS) endpoint is rejected for production."""
    with pytest.raises(ServiceConfigError, match="HTTPS"):
        validate_production_endpoint("http://control-plane.frostgate.example.com")


def test_service_cannot_start_without_device_credential_even_with_config() -> None:
    """Device credential is independently required; config alone is not sufficient."""
    config = _make_valid_config()
    with pytest.raises(ServiceConfigError, match="device credential"):
        config.build_start_command_plan(
            config_path_exists=True,
            device_credential_exists=False,
        )


def test_service_cannot_start_without_config_even_with_credential() -> None:
    """Config path is independently required; credential alone is not sufficient."""
    config = _make_valid_config()
    with pytest.raises(ServiceConfigError, match="config path"):
        config.build_start_command_plan(
            config_path_exists=False,
            device_credential_exists=True,
        )


# ===========================================================================
# 3. Platform behavior
# ===========================================================================


def test_execute_live_raises_on_non_windows() -> None:
    """execute_live() raises UnsupportedPlatformError on non-Windows platforms."""
    if sys.platform == "win32":
        pytest.skip("live execution test only meaningful on non-Windows")
    config = _make_valid_config()
    plan = config.build_stop_command_plan()
    with pytest.raises(UnsupportedPlatformError, match="Windows"):
        config.execute_live(plan)


def test_plan_mode_works_cross_platform() -> None:
    """All build_*_command_plan() methods work on the current (non-Windows) platform."""
    config = _make_valid_config()
    install = config.build_install_command_plan()
    start = config.build_start_command_plan(
        config_path_exists=True,
        device_credential_exists=True,
    )
    stop = config.build_stop_command_plan()
    uninstall = config.build_uninstall_command_plan()
    assert all(isinstance(p, list) for p in [install, start, stop, uninstall])
    assert all(len(p) > 0 for p in [install, start, stop, uninstall])


def test_install_command_plan_is_deterministic() -> None:
    """build_install_command_plan() is deterministic for the same config."""
    config = _make_valid_config()
    assert config.build_install_command_plan() == config.build_install_command_plan()


def test_stop_plan_is_deterministic_across_instances() -> None:
    """build_stop_command_plan() is deterministic across equal configs."""
    config_a = _make_valid_config()
    config_b = _make_valid_config()
    assert config_a.build_stop_command_plan() == config_b.build_stop_command_plan()


def test_uninstall_plan_is_deterministic() -> None:
    """build_uninstall_command_plan() is deterministic for same config and purge flag."""
    config = _make_valid_config()
    assert (
        config.build_uninstall_command_plan() == config.build_uninstall_command_plan()
    )
    assert config.build_uninstall_command_plan(
        purge=True
    ) == config.build_uninstall_command_plan(purge=True)


# ===========================================================================
# 4. Lifecycle compatibility
# ===========================================================================


def test_wrapper_start_plan_requires_device_credential_no_bypass() -> None:
    """No code path allows the service to start without a device credential check.

    This validates that the 17.4 lifecycle contract is not bypassed:
    a revoked or un-enrolled device would have no valid credential in protected
    storage, so device_credential_exists=False forces the start plan to fail.
    """
    config = _make_valid_config()
    with pytest.raises(ServiceConfigError):
        config.build_start_command_plan(
            config_path_exists=True,
            device_credential_exists=False,
        )


def test_wrapper_config_path_references_canonical_agent_config() -> None:
    """config_path uses the canonical FrostGate agent config location, not a parallel auth."""
    config = default_frostgate_service_config(
        executable_path=_EXEC_PATH,
        working_directory=_WORK_DIR,
        config_path=_CONFIG_PATH,
        log_directory=_LOG_DIR,
        data_directory=_DATA_DIR,
    )
    config.validate_service_config()
    assert "FrostGate" in config.config_path
    assert "agent" in config.config_path.lower()


def test_wrapper_does_not_introduce_parallel_auth_mechanism() -> None:
    """Service config references existing config path; no new auth field is introduced."""
    config = _make_valid_config()
    fields = set(config.__dataclass_fields__.keys())
    # These would indicate a parallel auth mechanism was introduced — must be absent.
    forbidden_fields = {
        "enrollment_token",
        "bootstrap_token",
        "api_key",
        "bearer_token",
        "auth_token",
        "signing_secret",
    }
    assert not (fields & forbidden_fields), (
        f"Service config must not introduce parallel auth fields: {fields & forbidden_fields}"
    )


def test_default_frostgate_config_uses_non_privileged_account() -> None:
    """default_frostgate_service_config returns NT SERVICE\\FrostGateAgent account."""
    config = default_frostgate_service_config(
        executable_path=_EXEC_PATH,
        working_directory=_WORK_DIR,
        config_path=_CONFIG_PATH,
        log_directory=_LOG_DIR,
        data_directory=_DATA_DIR,
    )
    assert config.service_account == "NT SERVICE\\FrostGateAgent"
    config.validate_service_config()  # must pass without LocalSystem error


def test_default_frostgate_config_has_expected_service_name() -> None:
    """default_frostgate_service_config uses canonical FrostGateAgent service name."""
    config = default_frostgate_service_config(
        executable_path=_EXEC_PATH,
        working_directory=_WORK_DIR,
        config_path=_CONFIG_PATH,
        log_directory=_LOG_DIR,
        data_directory=_DATA_DIR,
    )
    assert config.service_name == "FrostGateAgent"
    assert config.display_name == "FrostGate Agent"


# ===========================================================================
# 5. Regression
# ===========================================================================


def test_regression_execute_live_must_never_succeed_on_non_windows() -> None:
    """Regression: execute_live() must ALWAYS raise on non-Windows.

    If this test fails, the platform guard has been removed or bypassed.
    """
    if sys.platform == "win32":
        pytest.skip("regression only meaningful on non-Windows")
    config = _make_valid_config()
    plan = config.build_stop_command_plan()
    raised = False
    try:
        config.execute_live(plan)
    except UnsupportedPlatformError:
        raised = True
    assert raised, (
        "execute_live() returned without raising UnsupportedPlatformError on a non-Windows "
        "platform. The platform guard has been broken."
    )


def test_regression_install_plan_must_never_contain_token_material() -> None:
    """Regression: install command plan must not contain any secret pattern.

    If this test fails, a secret pattern was introduced into the command plan.
    """
    config = _make_valid_config()
    plan = config.build_install_command_plan()
    combined = " ".join(plan).lower()
    violations = [p for p in _SECRET_PATTERNS if p.lower() in combined]
    assert not violations, (
        f"Install command plan contains forbidden secret patterns: {violations}\n"
        f"Plan: {plan}"
    )


def test_regression_service_account_default_is_not_localsystem() -> None:
    """Regression: default service_account must never be LocalSystem.

    If this test fails, the default account was changed to a privileged identity.
    """
    config = WindowsServiceConfig(
        service_name="FrostGateAgent",
        display_name="FrostGate Agent",
        description="desc",
        executable_path=_EXEC_PATH,
        working_directory=_WORK_DIR,
        config_path=_CONFIG_PATH,
        log_directory=_LOG_DIR,
        data_directory=_DATA_DIR,
    )
    assert config.service_account.lower() not in {
        "localsystem",
        "nt authority\\system",
        "system",
    }, (
        f"Default service_account is a forbidden privileged identity: '{config.service_account}'"
    )


def test_regression_validate_raises_on_empty_required_fields() -> None:
    """Regression: validation must reject configs with empty required fields."""
    config = _make_valid_config(executable_path="")
    with pytest.raises(ServiceConfigError, match="executable_path"):
        config.validate_service_config()


def test_regression_stop_plan_always_deterministic() -> None:
    """Regression: stop plan must not be nondeterministic (e.g. timestamp injection)."""
    config = _make_valid_config()
    plans = [config.build_stop_command_plan() for _ in range(5)]
    assert all(p == plans[0] for p in plans), (
        "build_stop_command_plan() returned different results across calls — nondeterminism detected"
    )


def test_regression_purge_uninstall_is_not_default() -> None:
    """Regression: purge=True must be explicitly passed; default must be non-purge."""
    config = _make_valid_config()
    default_plan = config.build_uninstall_command_plan()
    assert "--purge-data" not in default_plan, (
        "Default uninstall plan includes --purge-data. Purge must require explicit purge=True."
    )
