"""
agent/app/installer/silent_enrollment.py

Silent enrollment install flow contract for task 18.3.

Provides a typed enrollment parameter model, deterministic MSI silent install
command builders (execution, log-safe, and placeholder variants), and token
safety guards for the FrostGate Agent Windows installer.

Security invariants:
- Raw enrollment/bootstrap token never appears in log-safe command output.
- Raw token is install-time only; exchanged for a device credential and discarded.
- Production endpoint rejects HTTP, localhost, RFC 1918, and link-local addresses.
- ENVIRONMENT rejects dev/local for production install flow.
- Silent install uses /qn — no interactive UI is ever permitted.
- Service start is gated on device credential existence, never on raw token presence.
- ENROLLMENT_TOKEN and BOOTSTRAP_TOKEN are mutually exclusive.
- execute_live_enrollment() is platform-gated: raises EnrollmentToolchainError on
  non-Windows or when msiexec is absent.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from agent.app.installer.msi_contract import (
    MsiContractError,
    validate_environment,
    validate_msi_endpoint,
)

# ---------------------------------------------------------------------------
# MSI property names
# ---------------------------------------------------------------------------

MSI_PROP_TENANT_ID: str = "TENANT_ID"
MSI_PROP_ENDPOINT: str = "FROSTGATE_ENDPOINT"  # Python field: control_plane_url
MSI_PROP_TOKEN: str = "ENROLLMENT_TOKEN"
MSI_PROP_ENVIRONMENT: str = "ENVIRONMENT"
MSI_PROP_INSTALLDIR: str = "INSTALLDIR"
MSI_PROP_LOG_LEVEL: str = "LOG_LEVEL"

# Sentinel used in log-safe and redacted output — never a real token value.
TOKEN_REDACTED: str = "<redacted>"

# Placeholder values for documentation and test command plan display.
PLACEHOLDER_TENANT_ID: str = "example-tenant-id"
PLACEHOLDER_ENDPOINT: str = "https://control-plane.example.com"
PLACEHOLDER_TOKEN: str = "placeholder-bootstrap-token"

# ---------------------------------------------------------------------------
# Service credential gate invariant
# ---------------------------------------------------------------------------

# Service start MUST be gated on device credential (device_key + device_key_id)
# existence, not on raw token presence.  The raw token is exchanged for a
# device credential during enrollment; the credential is persisted to OS-protected
# storage (Windows Credential Manager / DPAPI) and the raw token is discarded.
# WindowsServiceConfig.build_start_command_plan() enforces this via its
# device_credential_exists parameter — see agent/app/service/wrapper.py.
SERVICE_CREDENTIAL_GATE_REQUIRED: bool = True

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class EnrollmentValidationError(ValueError):
    """Raised when silent enrollment parameters fail validation."""


class EnrollmentToolchainError(RuntimeError):
    """Raised when live MSI enrollment cannot run (non-Windows or msiexec absent)."""


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SilentEnrollmentParams:
    """Typed silent enrollment parameters for MSI install-time use.

    All fields are install-time only.  This dataclass is never persisted to
    disk; the raw token flows only through build_msiexec_args() and
    execute_live_enrollment() and is discarded after the enrollment exchange.

    Fields:
      tenant_id          — FrostGate tenant identifier (required, non-empty).
      control_plane_url  — Control-plane HTTPS endpoint. Maps to FROSTGATE_ENDPOINT
                           MSI property.  Must be HTTPS; localhost, RFC 1918, and
                           link-local addresses are forbidden.
      environment        — 'prod' or 'staging'.  'dev' and 'local' are forbidden.
      enrollment_token   — Pre-issued enrollment token (mutually exclusive with
                           bootstrap_token).  Install-time only; never persisted.
      bootstrap_token    — Bootstrap token (mutually exclusive with enrollment_token).
                           Functionally identical; maps to the same ENROLLMENT_TOKEN
                           MSI property.
      install_dir        — Optional custom install directory (INSTALLDIR).
      log_level          — Optional log level override (LOG_LEVEL).
    """

    tenant_id: str
    control_plane_url: str
    environment: str
    enrollment_token: str | None = None
    bootstrap_token: str | None = None
    install_dir: str | None = None
    log_level: str | None = None

    def _active_token(self) -> str | None:
        """Return the first non-empty, non-whitespace string token.

        Consistent with the strip()-based checks in validate(): a token that is
        whitespace-only is treated as absent, so bootstrap_token is used even
        when enrollment_token is set but blank.
        """
        if isinstance(self.enrollment_token, str) and self.enrollment_token.strip():
            return self.enrollment_token
        if isinstance(self.bootstrap_token, str) and self.bootstrap_token.strip():
            return self.bootstrap_token
        return None

    def validate(self) -> None:
        """Validate all enrollment parameters.

        Raises EnrollmentValidationError listing all violations found.
        Delegates endpoint and environment format checks to msi_contract validators.
        """
        errors: list[str] = []

        if not isinstance(self.tenant_id, str) or not self.tenant_id.strip():
            errors.append("'tenant_id' must be a non-empty string")

        try:
            validate_msi_endpoint(self.control_plane_url)
        except MsiContractError as exc:
            errors.append(str(exc))

        try:
            validate_environment(self.environment)
        except MsiContractError as exc:
            errors.append(str(exc))

        has_enrollment = bool(
            isinstance(self.enrollment_token, str) and self.enrollment_token.strip()
        )
        has_bootstrap = bool(
            isinstance(self.bootstrap_token, str) and self.bootstrap_token.strip()
        )

        if has_enrollment and has_bootstrap:
            errors.append(
                "enrollment_token and bootstrap_token are mutually exclusive; "
                "supply exactly one"
            )
        elif not has_enrollment and not has_bootstrap:
            errors.append(
                "exactly one of enrollment_token or bootstrap_token must be supplied"
            )

        if errors:
            raise EnrollmentValidationError("; ".join(errors))

    def build_msiexec_args(
        self,
        artifact_path: str,
        *,
        log_path: str | None = None,
        redact_token: bool = False,
    ) -> list[str]:
        """Build a deterministic msiexec argument list for silent install.

        Args:
            artifact_path: Path to the MSI artifact file.
            log_path:       Optional MSI verbose log path.
                            Defaults to %TEMP%\\FrostGateAgent_install.log.
            redact_token:   If True, replace the token with TOKEN_REDACTED.
                            Always use True for output destined for logs.

        Returns a list[str] for subprocess.run(..., shell=False).

        The raw token appears in the list ONLY when redact_token=False.
        Callers MUST NOT log the result of redact_token=False calls.
        """
        self.validate()

        token_val = TOKEN_REDACTED if redact_token else (self._active_token() or "")
        _log_path = log_path or r"%TEMP%\FrostGateAgent_install.log"

        args: list[str] = [
            "msiexec",
            "/i",
            artifact_path,
            "/qn",
            "/l*v",
            _log_path,
            f"{MSI_PROP_TENANT_ID}={self.tenant_id}",
            f"{MSI_PROP_ENDPOINT}={self.control_plane_url}",
            f"{MSI_PROP_TOKEN}={token_val}",
            f"{MSI_PROP_ENVIRONMENT}={self.environment}",
        ]

        if self.install_dir is not None:
            args.append(f"{MSI_PROP_INSTALLDIR}={self.install_dir}")
        if self.log_level is not None:
            args.append(f"{MSI_PROP_LOG_LEVEL}={self.log_level}")

        return args

    def build_log_safe_args(
        self,
        artifact_path: str,
        *,
        log_path: str | None = None,
    ) -> list[str]:
        """Return a msiexec argument list safe for logging (token redacted).

        Safe to write to structured logs, audit events, or debug output.
        """
        return self.build_msiexec_args(
            artifact_path, log_path=log_path, redact_token=True
        )

    def execute_live_enrollment(self, artifact_path: str) -> None:
        """Execute silent MSI install on the local Windows host.

        Raises EnrollmentToolchainError on non-Windows or when msiexec is absent.

        This is the only method that passes the raw token to a subprocess call.
        The token is supplied as a command argument (not written to disk by this
        module) and is not present in any log output from this method.
        Use build_log_safe_args() to generate log-safe representations.
        """
        if sys.platform != "win32":
            raise EnrollmentToolchainError(
                f"Silent MSI enrollment requires Windows with msiexec. "
                f"Current platform: '{sys.platform}'. "
                "Use build_msiexec_args() for cross-platform command plan generation."
            )
        import shutil

        if not shutil.which("msiexec"):
            raise EnrollmentToolchainError(
                "msiexec not found in PATH. "
                "Windows Installer must be available to run silent enrollment."
            )
        import subprocess

        args = self.build_msiexec_args(artifact_path, redact_token=False)
        subprocess.run(args, check=True, shell=False)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def placeholder_enrollment_params() -> SilentEnrollmentParams:
    """Return SilentEnrollmentParams with non-production placeholder values.

    Suitable for documentation display and test command plan generation.
    Passes validate() — never pass to execute_live_enrollment() in production.
    """
    return SilentEnrollmentParams(
        tenant_id=PLACEHOLDER_TENANT_ID,
        control_plane_url=PLACEHOLDER_ENDPOINT,
        environment="prod",
        bootstrap_token=PLACEHOLDER_TOKEN,
    )
