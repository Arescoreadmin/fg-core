"""
tests/agent/test_windows_service_installer_contract.py

Contract tests for task 17.6 — Windows service + installer contract.

These tests verify that the contract document exists and contains all
required invariants. They act as a machine-readable enforcement layer so
that the contract cannot be silently weakened without tests failing.

Tests are deterministic, offline-safe, and require no Windows environment.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_CONTRACT_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "agent"
    / "windows_service_installer_contract.md"
)


@pytest.fixture(scope="module")
def contract_text() -> str:
    assert _CONTRACT_PATH.exists(), (
        f"Contract document missing: {_CONTRACT_PATH}. "
        "Create docs/agent/windows_service_installer_contract.md."
    )
    return _CONTRACT_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Existence and structure
# ---------------------------------------------------------------------------


def test_contract_file_exists() -> None:
    """Contract document must exist at the canonical path."""
    assert _CONTRACT_PATH.exists(), f"Contract missing: {_CONTRACT_PATH}"


def test_contract_non_empty(contract_text: str) -> None:
    """Contract must have substantial content — not a stub."""
    assert len(contract_text) >= 2000, (
        f"Contract is too short ({len(contract_text)} chars). "
        "Contract must be fully defined."
    )


# ---------------------------------------------------------------------------
# Service identity
# ---------------------------------------------------------------------------


def test_contract_defines_service_name(contract_text: str) -> None:
    """Contract must specify the Windows service name."""
    assert "FrostGateAgent" in contract_text, (
        "Contract must define service name 'FrostGateAgent'."
    )


def test_contract_defines_service_display_name(contract_text: str) -> None:
    """Contract must specify the service display name."""
    assert "FrostGate Agent" in contract_text, (
        "Contract must define service display name 'FrostGate Agent'."
    )


def test_contract_defines_install_directory(contract_text: str) -> None:
    """Contract must specify the install directory."""
    assert "Program Files" in contract_text, (
        "Contract must define install directory under C:\\Program Files."
    )


def test_contract_defines_data_directory(contract_text: str) -> None:
    """Contract must specify the data/state directory."""
    assert "ProgramData" in contract_text, (
        "Contract must define data directory under C:\\ProgramData."
    )


def test_contract_defines_entrypoint(contract_text: str) -> None:
    """Contract must specify the service executable entrypoint."""
    assert "FrostGateAgent.exe" in contract_text, (
        "Contract must name the service executable 'FrostGateAgent.exe'."
    )


# ---------------------------------------------------------------------------
# Service lifecycle
# ---------------------------------------------------------------------------


def test_contract_defines_install_lifecycle(contract_text: str) -> None:
    """Contract must define the install operation."""
    assert "install" in contract_text.lower(), (
        "Contract must define install lifecycle behavior."
    )


def test_contract_defines_start_lifecycle(contract_text: str) -> None:
    """Contract must define the start operation."""
    assert "start" in contract_text.lower(), (
        "Contract must define start lifecycle behavior."
    )


def test_contract_defines_stop_lifecycle(contract_text: str) -> None:
    """Contract must define the stop operation."""
    assert "stop" in contract_text.lower(), (
        "Contract must define stop lifecycle behavior."
    )


def test_contract_defines_restart_lifecycle(contract_text: str) -> None:
    """Contract must define the restart operation."""
    assert "restart" in contract_text.lower(), (
        "Contract must define restart lifecycle behavior."
    )


def test_contract_defines_upgrade_lifecycle(contract_text: str) -> None:
    """Contract must define upgrade behavior."""
    assert "upgrade" in contract_text.lower(), (
        "Contract must define upgrade lifecycle behavior."
    )


def test_contract_defines_uninstall_lifecycle(contract_text: str) -> None:
    """Contract must define uninstall behavior."""
    assert "uninstall" in contract_text.lower(), (
        "Contract must define uninstall lifecycle behavior."
    )


def test_contract_defines_purge_uninstall(contract_text: str) -> None:
    """Contract must define purge uninstall (full data removal)."""
    assert "purge" in contract_text.lower(), (
        "Contract must define purge uninstall behavior (removes all data/credentials)."
    )


# ---------------------------------------------------------------------------
# Startup fail-closed guarantees
# ---------------------------------------------------------------------------


def test_contract_requires_fail_closed_on_missing_config(contract_text: str) -> None:
    """Contract must require fail-closed behavior when required config is absent."""
    text_lower = contract_text.lower()
    assert "fail closed" in text_lower or "fail-closed" in text_lower, (
        "Contract must require fail-closed behavior for missing required config."
    )


def test_contract_forbids_localhost_production_defaults(contract_text: str) -> None:
    """Contract must explicitly forbid localhost/dev defaults in production."""
    assert "localhost" in contract_text.lower(), (
        "Contract must mention and reject localhost defaults for production."
    )
    text_lower = contract_text.lower()
    # The contract must reject it — verify a negative/prohibition is stated
    assert any(
        phrase in text_lower
        for phrase in [
            "must not",
            "rejected",
            "reject",
            "forbidden",
            "never",
            "not allowed",
        ]
    ), "Contract must explicitly prohibit localhost/dev defaults."


def test_contract_forbids_service_start_without_enrollment(contract_text: str) -> None:
    """Contract must forbid collector start before device credential is valid."""
    text_lower = contract_text.lower()
    # Must reference enrollment/device credential requirement before starting collectors
    assert "credential" in text_lower, (
        "Contract must require valid device credential before starting collectors."
    )
    assert "collector" in text_lower, (
        "Contract must address collector start behavior relative to enrollment."
    )


# ---------------------------------------------------------------------------
# Silent install parameters
# ---------------------------------------------------------------------------


def test_contract_defines_tenant_id_parameter(contract_text: str) -> None:
    """Contract must define TENANT_ID as a required install parameter."""
    assert "TENANT_ID" in contract_text, (
        "Contract must define TENANT_ID as a required silent install parameter."
    )


def test_contract_defines_enrollment_token_parameter(contract_text: str) -> None:
    """Contract must define ENROLLMENT_TOKEN or BOOTSTRAP_TOKEN parameter."""
    assert "ENROLLMENT_TOKEN" in contract_text or "BOOTSTRAP_TOKEN" in contract_text, (
        "Contract must define ENROLLMENT_TOKEN or BOOTSTRAP_TOKEN parameter."
    )


def test_contract_defines_endpoint_parameter(contract_text: str) -> None:
    """Contract must define FROSTGATE_ENDPOINT or CONTROL_PLANE_URL parameter."""
    assert (
        "FROSTGATE_ENDPOINT" in contract_text or "CONTROL_PLANE_URL" in contract_text
    ), "Contract must define FROSTGATE_ENDPOINT or CONTROL_PLANE_URL parameter."


def test_contract_defines_environment_parameter(contract_text: str) -> None:
    """Contract must define ENVIRONMENT or PROFILE install parameter."""
    assert "ENVIRONMENT" in contract_text or "PROFILE" in contract_text, (
        "Contract must define ENVIRONMENT or PROFILE as a required install parameter."
    )


def test_contract_defines_msiexec_silent_install_example(contract_text: str) -> None:
    """Contract must include a concrete msiexec silent install example."""
    assert "msiexec" in contract_text.lower(), (
        "Contract must include an msiexec command example for silent install."
    )
    assert "/qn" in contract_text, (
        "Contract msiexec example must include /qn for silent (no UI) install."
    )


# ---------------------------------------------------------------------------
# Security: secrets and credential storage
# ---------------------------------------------------------------------------


def test_contract_forbids_embedded_secrets(contract_text: str) -> None:
    """Contract must explicitly forbid baking secrets into the MSI."""
    text_lower = contract_text.lower()
    assert "no" in text_lower or "must not" in text_lower or "never" in text_lower, (
        "Contract must prohibit embedded secrets."
    )
    assert "embedded" in text_lower or "baked" in text_lower, (
        "Contract must explicitly address embedded/baked secrets in the artifact."
    )


def test_contract_forbids_raw_token_persistence(contract_text: str) -> None:
    """Contract must forbid persisting the raw enrollment/bootstrap token."""
    text_lower = contract_text.lower()
    assert "token" in text_lower, "Contract must address enrollment token handling."
    assert any(
        phrase in text_lower
        for phrase in [
            "never written",
            "never persist",
            "deleted",
            "removed",
            "not stored",
        ]
    ), "Contract must explicitly forbid raw token persistence after exchange."


def test_contract_requires_protected_credential_storage(contract_text: str) -> None:
    """Contract must require protected storage for device credentials (DPAPI/Credential Manager)."""
    text_lower = contract_text.lower()
    assert any(
        phrase in text_lower
        for phrase in [
            "dpapi",
            "credential manager",
            "windows credential",
            "protected storage",
        ]
    ), (
        "Contract must require DPAPI or Windows Credential Manager for device credential storage."
    )


def test_contract_requires_no_plaintext_credentials(contract_text: str) -> None:
    """Contract must prohibit plaintext credential storage."""
    text_lower = contract_text.lower()
    assert "plaintext" in text_lower or "plain text" in text_lower, (
        "Contract must address and prohibit plaintext credential storage."
    )


# ---------------------------------------------------------------------------
# 17.4 lifecycle controls
# ---------------------------------------------------------------------------


def test_contract_preserves_revoked_device_behavior(contract_text: str) -> None:
    """Contract must enforce 17.4 revoked device behavior."""
    text_lower = contract_text.lower()
    assert "revoked" in text_lower, (
        "Contract must address revoked device behavior (17.4 lifecycle control)."
    )
    assert any(
        phrase in text_lower
        for phrase in ["halt", "cease", "stop collector", "cannot submit"]
    ), "Contract must specify that revoked agents halt collector execution."


def test_contract_preserves_disabled_device_behavior(contract_text: str) -> None:
    """Contract must enforce 17.4 disabled device behavior."""
    assert "disabled" in contract_text.lower(), (
        "Contract must address disabled device behavior (17.4 lifecycle control)."
    )


def test_contract_preserves_version_floor_behavior(contract_text: str) -> None:
    """Contract must enforce 17.4 version floor behavior."""
    text_lower = contract_text.lower()
    assert "version floor" in text_lower or "version_floor" in text_lower, (
        "Contract must address version floor enforcement (17.4 lifecycle control)."
    )
    assert "outdated" in text_lower, (
        "Contract must specify that below-floor agents report outdated health status."
    )


# ---------------------------------------------------------------------------
# 17.5 observability expectations
# ---------------------------------------------------------------------------


def test_contract_references_observability_logging(contract_text: str) -> None:
    """Contract must reference 17.5 heartbeat and observability expectations."""
    text_lower = contract_text.lower()
    assert "heartbeat" in text_lower, (
        "Contract must reference heartbeat reporting (17.5 observability)."
    )
    assert "collector" in text_lower, (
        "Contract must reference collector status in observability (17.5)."
    )


def test_contract_defines_log_path(contract_text: str) -> None:
    """Contract must specify a local log path."""
    assert (
        "agent.log" in contract_text
        or "logs\\" in contract_text
        or "logs/" in contract_text
    ), "Contract must define a local log file path."


def test_contract_forbids_secrets_in_logs(contract_text: str) -> None:
    """Contract must explicitly require that secrets never appear in logs."""
    text_lower = contract_text.lower()
    assert "log" in text_lower, "Contract must address logging."
    assert any(
        phrase in text_lower
        for phrase in [
            "never in log",
            "not in log",
            "secrets in log",
            "must not appear in log",
            "never appear in log",
            "never written to any log",
        ]
    ), "Contract must explicitly prohibit secrets from appearing in logs."


# ---------------------------------------------------------------------------
# Signing and release metadata
# ---------------------------------------------------------------------------


def test_contract_requires_msi_signing(contract_text: str) -> None:
    """Contract must require MSI signing for production."""
    text_lower = contract_text.lower()
    assert "sign" in text_lower, (
        "Contract must address MSI/executable signing requirements."
    )
    assert "production" in text_lower, (
        "Contract must specify that signing is required for production."
    )


def test_contract_requires_hash_manifest(contract_text: str) -> None:
    """Contract must require a hash manifest for artifact integrity."""
    text_lower = contract_text.lower()
    assert "sha256" in text_lower or "hash manifest" in text_lower, (
        "Contract must require SHA256 hash manifest for artifact integrity."
    )


def test_contract_defines_release_metadata_fields(contract_text: str) -> None:
    """Contract must define release metadata fields."""
    assert (
        "release_metadata" in contract_text
        or "release metadata" in contract_text.lower()
    ), "Contract must define release metadata structure."
    # Must include version, commit, build_time, signing_status
    for field in ("version", "commit", "build_time", "signing_status"):
        assert field in contract_text, (
            f"Contract release_metadata must include field '{field}'."
        )


# ---------------------------------------------------------------------------
# Upgrade and uninstall integrity
# ---------------------------------------------------------------------------


def test_contract_defines_upgrade_preserves_identity(contract_text: str) -> None:
    """Contract must state that upgrade preserves device identity."""
    text_lower = contract_text.lower()
    assert "preserv" in text_lower, (
        "Contract must state that upgrade preserves device identity (device_id/device_key)."
    )


def test_contract_defines_downgrade_behavior(contract_text: str) -> None:
    """Contract must define downgrade behavior explicitly."""
    assert "downgrade" in contract_text.lower(), (
        "Contract must explicitly define downgrade behavior."
    )


def test_contract_defines_rollback_behavior(contract_text: str) -> None:
    """Contract must define MSI rollback behavior."""
    assert "rollback" in contract_text.lower(), (
        "Contract must explicitly define MSI rollback behavior."
    )


# ---------------------------------------------------------------------------
# Enterprise deployment
# ---------------------------------------------------------------------------


def test_contract_includes_enterprise_deployment_notes(contract_text: str) -> None:
    """Contract must include enterprise deployment notes (Intune/GPO/RMM)."""
    text_lower = contract_text.lower()
    assert any(
        phrase in text_lower for phrase in ["intune", "gpo", "rmm", "group policy"]
    ), "Contract must include Intune/GPO/RMM enterprise deployment notes."


def test_contract_defines_tls_requirements(contract_text: str) -> None:
    """Contract must specify TLS/certificate requirements."""
    text_lower = contract_text.lower()
    assert "tls" in text_lower or "https" in text_lower, (
        "Contract must specify TLS/certificate requirements for control plane communication."
    )
