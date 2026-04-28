"""
agent/app/service/wrapper.py

Windows service wrapper contract module for task 18.1.

Provides a typed, reviewable service configuration dataclass and deterministic
command plan generators for Windows SCM operations (install / start / stop /
uninstall).  All live SCM execution is platform-gated: on non-Windows hosts
execute_live() raises UnsupportedPlatformError.  Command plan generation is
cross-platform and safe to call in Linux CI.

Security invariants enforced by this module:
- LocalSystem and NT AUTHORITY\\SYSTEM are forbidden as service accounts.
- No enrollment/bootstrap token material may appear in command args.
- Service start plan fails closed if config path or device credential is absent.
- Production endpoints must use HTTPS and cannot be localhost/private addresses.
- Uninstall never purges credentials unless purge=True is explicitly passed.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Literal

StartType = Literal["auto", "demand", "disabled", "delayed-auto"]
RestartPolicy = Literal["always", "on-failure", "never"]

# Forbidden service accounts (normalized to lowercase for comparison).
# These accounts grant unrestricted host access and are not permitted.
_FORBIDDEN_ACCOUNTS: frozenset[str] = frozenset(
    {"localsystem", "nt authority\\system", "system"}
)

# Secret-like key names that must never appear in service command arguments.
_SECRET_PATTERNS: tuple[str, ...] = (
    "ENROLLMENT_TOKEN",
    "BOOTSTRAP_TOKEN",
    "api_key",
    "bearer",
    "hmac_secret",
    "signing_secret",
    "FG_SIGNING_SECRET",
    "FG_INTERNAL_AUTH_SECRET",
    "FG_AGENT_KEY",
    "FG_API_KEY",
)

# Hosts that are forbidden in production service endpoint configuration.
_FORBIDDEN_PROD_HOSTS: tuple[str, ...] = ("localhost", "127.0.0.1", "::1")


class ServiceConfigError(ValueError):
    """Raised for invalid service configuration or violated precondition."""


class UnsupportedPlatformError(RuntimeError):
    """Raised when live SCM operations are attempted on a non-Windows platform."""


@dataclass(frozen=True)
class WindowsServiceConfig:
    """Typed, reviewable Windows service wrapper configuration.

    service_account defaults to NT SERVICE\\FrostGateAgent — a non-privileged
    Windows virtual service account with no interactive logon rights and no
    admin access.  LocalSystem and NT AUTHORITY\\SYSTEM are explicitly forbidden.

    All path fields must be supplied by the caller; no silent path defaults
    are applied.
    """

    service_name: str
    display_name: str
    description: str
    executable_path: str
    working_directory: str
    config_path: str
    log_directory: str
    data_directory: str
    service_account: str = "NT SERVICE\\FrostGateAgent"
    start_type: StartType = "auto"
    restart_policy: RestartPolicy = "always"
    stop_timeout_seconds: int = 30

    def validate_service_config(self) -> None:
        """Validate all required fields and enforce security invariants.

        Raises ServiceConfigError listing all violations found.
        """
        errors: list[str] = []

        for attr in (
            "service_name",
            "display_name",
            "description",
            "executable_path",
            "working_directory",
            "config_path",
            "log_directory",
            "data_directory",
        ):
            if not str(getattr(self, attr, "")).strip():
                errors.append(f"'{attr}' must be non-empty")

        if self.service_account.lower().strip() in _FORBIDDEN_ACCOUNTS:
            errors.append(
                f"service_account '{self.service_account}' is forbidden. "
                "LocalSystem and NT AUTHORITY\\SYSTEM grant unrestricted host access. "
                "Use 'NT SERVICE\\FrostGateAgent' or a documented least-privilege account."
            )

        if self.stop_timeout_seconds <= 0:
            errors.append("'stop_timeout_seconds' must be a positive integer")

        for pattern in _SECRET_PATTERNS:
            if pattern.lower() in self.config_path.lower():
                errors.append(
                    f"'config_path' must not reference secret material (matched: '{pattern}'). "
                    "Config paths must point to non-secret configuration files only."
                )

        if errors:
            raise ServiceConfigError("; ".join(errors))

    def build_install_command_plan(self) -> list[str]:
        """Generate a deterministic sc.exe create command plan.

        Returns a list of tokens suitable for subprocess.run() on Windows or
        for operator review on any platform.  No enrollment/bootstrap token
        material may appear in the returned plan.
        """
        self.validate_service_config()
        plan: list[str] = [
            "sc",
            "create",
            self.service_name,
            "binPath=",
            self.executable_path,
            "DisplayName=",
            self.display_name,
            "start=",
            _map_start_type(self.start_type),
            "obj=",
            self.service_account,
        ]
        _assert_no_secret_material("install", plan)
        return plan

    def build_start_command_plan(
        self,
        *,
        config_path_exists: bool,
        device_credential_exists: bool,
    ) -> list[str]:
        """Generate a deterministic sc.exe start command plan.

        Fails closed:
        - Raises ServiceConfigError if config_path_exists is False.
        - Raises ServiceConfigError if device_credential_exists is False.

        Both preconditions must be satisfied before the service is allowed to
        start.  This enforces the 17.6 contract: device must be enrolled and
        config must exist before collectors can run.
        """
        self.validate_service_config()
        if not config_path_exists:
            raise ServiceConfigError(
                f"Cannot build start plan: config path '{self.config_path}' "
                "is absent or inaccessible. "
                "Service cannot start without a valid configuration file."
            )
        if not device_credential_exists:
            raise ServiceConfigError(
                "Cannot build start plan: no device credential found in protected storage. "
                "The device must complete enrollment before the service can start."
            )
        return ["sc", "start", self.service_name]

    def build_stop_command_plan(self) -> list[str]:
        """Generate a deterministic sc.exe stop command plan."""
        self.validate_service_config()
        return ["sc", "stop", self.service_name]

    def build_uninstall_command_plan(self, *, purge: bool = False) -> list[str]:
        """Generate a deterministic sc.exe delete command plan.

        purge=False (default): de-registers service only.  Data directories and
            credentials in Windows Credential Manager are NOT removed.  This is
            the safe default for standard uninstall.

        purge=True: de-registers service.  Caller must separately remove data
            directories and the Credential Manager entry.  Purge is an explicit,
            operator-initiated action distinct from standard uninstall.
        """
        self.validate_service_config()
        if purge:
            return ["sc", "delete", self.service_name, "--purge-data"]
        return ["sc", "delete", self.service_name]

    def execute_live(self, command_plan: list[str]) -> None:
        """Execute a service command on the local Windows host via SCM.

        Raises UnsupportedPlatformError unconditionally on any non-Windows
        platform.  This is the only method that performs live SCM operations.
        All other methods generate command plans only and are safe to call on
        any platform.
        """
        if sys.platform != "win32":
            raise UnsupportedPlatformError(
                f"Live Windows service operations require Windows. "
                f"Current platform: '{sys.platform}'. "
                "Use build_*_command_plan() for cross-platform command plan generation."
            )
        import subprocess  # noqa: PLC0415 — Windows-only execution path

        subprocess.run(command_plan, check=True)


def _map_start_type(start_type: StartType) -> str:
    return {
        "auto": "auto",
        "delayed-auto": "delayed-auto",
        "demand": "demand",
        "disabled": "disabled",
    }[start_type]


def _assert_no_secret_material(operation: str, args: list[str]) -> None:
    """Raise ServiceConfigError if any secret-like pattern appears in the given args."""
    combined = " ".join(args).lower()
    for pattern in _SECRET_PATTERNS:
        if pattern.lower() in combined:
            raise ServiceConfigError(
                f"Secret-like material detected in '{operation}' command args: '{pattern}'. "
                "Service command arguments must never contain secret or token material."
            )


def validate_production_endpoint(endpoint: str) -> None:
    """Validate that an endpoint is acceptable for production use.

    Raises ServiceConfigError if:
    - The scheme is not https://
    - The host matches a known local/private address (localhost, 127.0.0.1, ::1)
    """
    stripped = endpoint.strip().lower()
    if not stripped.startswith("https://"):
        raise ServiceConfigError(
            f"Production endpoint must use HTTPS. Got: '{endpoint}'"
        )
    for host in _FORBIDDEN_PROD_HOSTS:
        if host in stripped:
            raise ServiceConfigError(
                f"Production endpoint cannot be a local or private address. "
                f"Got: '{endpoint}' (matched forbidden host: '{host}')"
            )


def default_frostgate_service_config(
    *,
    executable_path: str,
    working_directory: str,
    config_path: str,
    log_directory: str,
    data_directory: str,
) -> WindowsServiceConfig:
    """Return a WindowsServiceConfig with canonical FrostGate service defaults.

    All path parameters are required — no silent path defaults.
    service_account is always NT SERVICE\\FrostGateAgent (non-privileged virtual account).
    """
    return WindowsServiceConfig(
        service_name="FrostGateAgent",
        display_name="FrostGate Agent",
        description=(
            "FrostGate endpoint telemetry agent — collects and forwards "
            "device telemetry to the FrostGate control plane"
        ),
        executable_path=executable_path,
        working_directory=working_directory,
        config_path=config_path,
        log_directory=log_directory,
        data_directory=data_directory,
        service_account="NT SERVICE\\FrostGateAgent",
        start_type="auto",
        restart_policy="always",
        stop_timeout_seconds=30,
    )
