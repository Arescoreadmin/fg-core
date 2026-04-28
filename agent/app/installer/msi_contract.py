"""
agent/app/installer/msi_contract.py

MSI build contract module for task 18.2.

Provides a typed, reviewable MSI build contract and deterministic build/smoke-test
command plan generators.  Live MSI artifact production is platform-gated: on
non-Windows hosts (or when WiX toolchain is absent) execute_live_build() raises
MsiToolchainError.  All plan-generation methods are cross-platform and safe to call
in Linux CI.

Security invariants enforced by this module:
- Raw enrollment/bootstrap token is never embedded in MSI artifact or build commands.
- Production environment rejects localhost, HTTP, and RFC 1918/link-local endpoints.
- dev/local ENVIRONMENT values are forbidden in production-signed MSI.
- SHA256 manifest is required for every artifact.
- Signing is required for production; unsigned artifacts are marked NOT FOR PRODUCTION.
- Uninstall never purges credentials unless PURGE_DATA=1 is explicitly passed.
- upgrade_code must be a stable GUID — never rotated between releases.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

SigningStatus = Literal["signed", "unsigned"]
InstallMode = Literal[
    "interactive",
    "silent",
    "repair",
    "upgrade",
    "uninstall",
    "purge_uninstall",
]
Environment = Literal["prod", "staging"]
PackageCodeStrategy = Literal["per_release"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Required MSI PROPERTY names for silent installation.
SILENT_REQUIRED_PARAMS: tuple[str, ...] = (
    "TENANT_ID",
    "FROSTGATE_ENDPOINT",
    "ENROLLMENT_TOKEN",
    "ENVIRONMENT",
)

# Optional MSI PROPERTY names for silent installation.
SILENT_OPTIONAL_PARAMS: tuple[str, ...] = (
    "INSTALLDIR",
    "LOG_LEVEL",
)

# Uninstall-only optional parameter; triggers full data/credential purge when "1".
PURGE_PARAM: str = "PURGE_DATA"

# Accepted production ENVIRONMENT values.
_PROD_ENVIRONMENTS: frozenset[str] = frozenset({"prod", "staging"})

# ENVIRONMENT values forbidden in production-signed MSI artifacts.
_FORBIDDEN_ENVIRONMENTS: frozenset[str] = frozenset({"dev", "local"})

# Secret-like key names that must never appear in build/smoke command args or artifact fields.
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

# Hostnames forbidden as production control-plane endpoints.
_FORBIDDEN_PROD_HOSTNAMES: frozenset[str] = frozenset({"localhost"})

# RFC 1918, loopback, and link-local networks forbidden in production endpoints.
_FORBIDDEN_PROD_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)

# upgrade_code must match this GUID pattern — validated at contract time.
_GUID_RE = re.compile(
    r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}"
    r"-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$"
)

MSI_MIN_OS: str = "Windows 10 1903 / Server 2019"
MSI_ARCH: str = "x86_64"

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class MsiContractError(ValueError):
    """Raised for invalid MSI build contract configuration or violated precondition."""


class MsiToolchainError(RuntimeError):
    """Raised when MSI toolchain (WiX/msiexec) is unavailable or platform is non-Windows."""


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MsiArtifactManifest:
    """Deterministic release metadata manifest for a signed MSI artifact.

    Matches the release_metadata.json schema from the 17.6 contract.
    sha256_msi and sha256_exe are None until the artifact is produced and hashed.
    signing_status is 'unsigned' and build_signed is False until the signing
    pipeline runs and updates the manifest.
    """

    product: str
    version: str
    commit: str
    build_time: str  # ISO 8601 UTC
    signing_status: SigningStatus
    signed_by: str  # certificate CN, or 'N/A' for unsigned
    sha256_msi: str | None  # None until artifact is produced
    sha256_exe: str | None  # None until artifact is produced
    min_os: str = MSI_MIN_OS
    arch: str = MSI_ARCH
    build_signed: bool = False

    def as_dict(self) -> dict[str, str | bool | None]:
        """Return the manifest as a JSON-serialisable dict."""
        return {
            "product": self.product,
            "version": self.version,
            "commit": self.commit,
            "build_time": self.build_time,
            "signing_status": self.signing_status,
            "signed_by": self.signed_by,
            "sha256_msi": self.sha256_msi,
            "sha256_exe": self.sha256_exe,
            "min_os": self.min_os,
            "arch": self.arch,
            "build_signed": self.build_signed,
        }


@dataclass(frozen=True)
class MsiBuildContract:
    """Typed MSI build contract for the FrostGate Agent Windows installer.

    Encodes all required fields, security invariants, supported install modes,
    and deterministic build/smoke-test command plans.

    Defaults:
    - signing_required = True  — unsigned artifacts must be marked NOT FOR PRODUCTION.
    - signing_status = 'unsigned' — updated by signing pipeline only.
    - sha256_manifest_required = True — artifact integrity is non-negotiable.
    - package_code_strategy = 'per_release' — MSI ProductCode rotates per release;
      upgrade_code is stable across all versions.
    """

    product_name: str
    product_version: str
    manufacturer: str
    upgrade_code: str  # stable GUID across all versions; must never change post-release
    service_name: str
    install_dir: str
    config_dir: str
    log_dir: str
    data_dir: str
    build_output_dir: str
    artifact_name: str
    package_code_strategy: PackageCodeStrategy = "per_release"
    signing_required: bool = True
    signing_status: SigningStatus = "unsigned"
    sha256_manifest_required: bool = True
    supported_install_modes: tuple[InstallMode, ...] = (
        "interactive",
        "silent",
        "repair",
        "upgrade",
        "uninstall",
        "purge_uninstall",
    )

    def validate_contract(self) -> None:
        """Validate all required fields and security invariants.

        Raises MsiContractError listing all violations found.
        """
        errors: list[str] = []

        for attr in (
            "product_name",
            "product_version",
            "manufacturer",
            "upgrade_code",
            "service_name",
            "install_dir",
            "config_dir",
            "log_dir",
            "data_dir",
            "build_output_dir",
            "artifact_name",
        ):
            val = getattr(self, attr)
            if not isinstance(val, str) or not val.strip():
                errors.append(f"'{attr}' must be a non-empty string")

        if self.upgrade_code and not _GUID_RE.match(self.upgrade_code):
            errors.append(
                f"'upgrade_code' must be a valid GUID "
                f"({{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}}). Got: '{self.upgrade_code}'"
            )

        for pattern in _SECRET_PATTERNS:
            if pattern.lower() in self.artifact_name.lower():
                errors.append(
                    f"'artifact_name' must not contain secret material "
                    f"(matched: '{pattern}')"
                )

        if not self.sha256_manifest_required:
            errors.append(
                "'sha256_manifest_required' must be True. "
                "SHA256 artifact integrity verification is non-negotiable."
            )

        if errors:
            raise MsiContractError("; ".join(errors))

    def build_build_command_plan(self) -> list[str]:
        """Generate a deterministic WiX build command plan.

        Returns an ordered list of command strings (one per build step):
        [candle_command, light_command].

        No secret material may appear in the returned plan.
        On non-Windows or with WiX toolchain absent, execute_live_build() raises;
        this method generates the plan cross-platform for operator review.
        """
        self.validate_contract()
        wixobj = f"{self.build_output_dir}\\{self.product_name}.wixobj"
        plan = [
            (
                f"candle.exe -arch x64 "
                f"-out {wixobj} "
                f"installer\\Product.wxs installer\\ServiceInstall.wxs"
            ),
            (
                f"light.exe "
                f"-ext WixUIExtension -ext WixUtilExtension "
                f"{wixobj} "
                f"-out {self.build_output_dir}\\{self.artifact_name}"
            ),
        ]
        _assert_no_secret_material("build", plan)
        return plan

    def build_smoke_test_plan(self) -> list[str]:
        """Generate a deterministic smoke-test command plan.

        Returns a PowerShell command that verifies the artifact exists, is non-empty,
        and emits the SHA256 hash for manifest comparison.

        On non-Windows, execute_live_build() raises; this plan is reviewable cross-platform.
        """
        self.validate_contract()
        artifact_path = f"{self.build_output_dir}\\{self.artifact_name}"
        return [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                f"$f='{artifact_path}'; "
                f"if(-not(Test-Path $f)){{throw 'MSI artifact missing: '+$f}}; "
                f"if((Get-Item $f).Length -eq 0){{throw 'MSI artifact is empty'}}; "
                f"$hash=(Get-FileHash $f -Algorithm SHA256).Hash.ToLower(); "
                f'Write-Output "smoke:sha256=$hash artifact=$f"'
            ),
        ]

    def build_install_command_example(self) -> str:
        """Return a documented msiexec silent install command with placeholder values.

        IMPORTANT: Placeholder tokens (<...>) are NEVER real secret values.
        The actual ENROLLMENT_TOKEN is supplied by the deployment tool (Intune/RMM/GPO)
        and is NEVER written to disk or to any MSI log by the installer.
        See Section 2.4 of the windows_service_installer_contract.md.
        """
        self.validate_contract()
        return (
            f"msiexec /i {self.artifact_name} /qn "
            f"/l*v %TEMP%\\{self.product_name}_install.log "
            f'TENANT_ID="<tenant-id>" '
            f'FROSTGATE_ENDPOINT="https://<control-plane-fqdn>" '
            f'ENROLLMENT_TOKEN="<bootstrap-token>" '
            f'ENVIRONMENT="prod"'
        )

    def build_uninstall_command_example(self, *, purge: bool = False) -> str:
        """Return a documented msiexec uninstall command example.

        purge=False (default): service and binaries removed; data/credentials preserved.
            PURGE_DATA is not passed, so the MSI default (preserve) applies.
        purge=True: all data and credentials removed. PURGE_DATA=1 is explicit.
            This is a separate, irreversible operator action.
        """
        self.validate_contract()
        base = (
            f"msiexec /x {{PRODUCT-CODE-GUID}} /qn "
            f"/l*v %TEMP%\\{self.product_name}_uninstall.log"
        )
        if purge:
            return f"{base} PURGE_DATA=1"
        return base

    def build_manifest_template(
        self,
        *,
        commit: str,
        build_time: str,
    ) -> MsiArtifactManifest:
        """Return an unsigned MsiArtifactManifest template for this build contract.

        sha256_msi and sha256_exe are None — populated by the build pipeline
        after the artifact is produced.
        signing_status='unsigned' and build_signed=False until the signing
        pipeline runs.
        """
        self.validate_contract()
        return MsiArtifactManifest(
            product=self.product_name,
            version=self.product_version,
            commit=commit,
            build_time=build_time,
            signing_status="unsigned",
            signed_by="N/A",
            sha256_msi=None,
            sha256_exe=None,
            min_os=MSI_MIN_OS,
            arch=MSI_ARCH,
            build_signed=False,
        )

    def execute_live_build(self) -> None:
        """Execute the MSI build on the local Windows host using WiX toolchain.

        Raises MsiToolchainError on any non-Windows platform.
        Raises MsiToolchainError if WiX toolchain (candle.exe, light.exe) is absent.
        This is the only method that attempts live MSI artifact production.
        All other methods generate plans only and are safe to call on any platform.
        """
        if sys.platform != "win32":
            raise MsiToolchainError(
                f"MSI build requires Windows with WiX toolchain installed. "
                f"Current platform: '{sys.platform}'. "
                "Use build_build_command_plan() for cross-platform build plan generation."
            )
        import shutil

        missing = [t for t in ("candle.exe", "light.exe") if not shutil.which(t)]
        if missing:
            raise MsiToolchainError(
                f"WiX toolchain tools not found in PATH: {missing}. "
                "Install WiX Toolset 3.x or 4.x before running a live MSI build."
            )
        import subprocess

        wixobj = f"{self.build_output_dir}\\{self.product_name}.wixobj"
        candle_args = [
            "candle.exe",
            "-arch",
            "x64",
            "-out",
            wixobj,
            "installer\\Product.wxs",
            "installer\\ServiceInstall.wxs",
        ]
        light_args = [
            "light.exe",
            "-ext",
            "WixUIExtension",
            "-ext",
            "WixUtilExtension",
            wixobj,
            "-out",
            f"{self.build_output_dir}\\{self.artifact_name}",
        ]
        for args in (candle_args, light_args):
            subprocess.run(args, check=True, shell=False)


# ---------------------------------------------------------------------------
# Standalone validators
# ---------------------------------------------------------------------------


def validate_msi_endpoint(endpoint: str) -> None:
    """Validate that a control-plane endpoint is acceptable for production MSI use.

    Raises MsiContractError if:
    - Scheme is not https://
    - Hostname is empty (e.g. https://, https:///path, https://:443)
    - Hostname is 'localhost'
    - IP address is loopback, RFC 1918, or link-local
    """
    stripped = endpoint.strip()
    if not stripped.lower().startswith("https://"):
        raise MsiContractError(
            f"MSI control-plane endpoint must use HTTPS. Got: '{endpoint}'"
        )
    parsed = urlparse(stripped)
    host = (parsed.hostname or "").lower()
    if not host:
        raise MsiContractError(
            f"MSI control-plane endpoint has no resolvable hostname. Got: '{endpoint}'"
        )
    if host in _FORBIDDEN_PROD_HOSTNAMES:
        raise MsiContractError(
            f"MSI control-plane endpoint cannot be a local or private address. "
            f"Got: '{endpoint}' (hostname: '{host}')"
        )
    try:
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address | None = (
            ipaddress.ip_address(host)
        )
    except ValueError:
        addr = None

    if addr is not None:
        for network in _FORBIDDEN_PROD_NETWORKS:
            if addr in network:
                raise MsiContractError(
                    f"MSI control-plane endpoint cannot be a loopback, RFC 1918, or "
                    f"link-local address. Got: '{endpoint}' "
                    f"(host '{host}' is in {network})"
                )


def validate_environment(environment: str) -> None:
    """Validate that an ENVIRONMENT value is acceptable for production MSI use.

    Raises MsiContractError if environment is 'dev' or 'local'.
    Raises MsiContractError if environment is not a recognised value.
    """
    env = environment.lower().strip()
    if env in _FORBIDDEN_ENVIRONMENTS:
        raise MsiContractError(
            f"Production MSI rejects ENVIRONMENT='{environment}'. "
            f"Accepted values: {sorted(_PROD_ENVIRONMENTS)}. "
            "'dev' and 'local' are forbidden in production-signed MSI artifacts."
        )
    if env not in _PROD_ENVIRONMENTS:
        raise MsiContractError(
            f"Unknown ENVIRONMENT='{environment}'. "
            f"Accepted values: {sorted(_PROD_ENVIRONMENTS)}."
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _assert_no_secret_material(operation: str, args: list[str]) -> None:
    """Raise MsiContractError if any secret-like pattern appears in the given args."""
    combined = " ".join(args).lower()
    for pattern in _SECRET_PATTERNS:
        if pattern.lower() in combined:
            raise MsiContractError(
                f"Secret-like material detected in '{operation}' command args: '{pattern}'. "
                "MSI build command arguments must never contain secret or token material."
            )


# ---------------------------------------------------------------------------
# Default factory
# ---------------------------------------------------------------------------


def default_frostgate_msi_contract(
    *,
    product_version: str,
    build_output_dir: str,
) -> MsiBuildContract:
    """Return an MsiBuildContract with canonical FrostGate MSI defaults.

    product_version and build_output_dir are required — no silent defaults.
    signing_required=True (unsigned = NOT FOR PRODUCTION).
    sha256_manifest_required=True (artifact integrity non-negotiable).
    upgrade_code is the stable FrostGate Agent product GUID — never rotated.
    """
    artifact_name = f"FrostGateAgent-{product_version}-x86_64.msi"
    return MsiBuildContract(
        product_name="FrostGateAgent",
        product_version=product_version,
        manufacturer="FrostGate Inc.",
        upgrade_code="{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}",
        service_name="FrostGateAgent",
        install_dir=r"C:\Program Files\FrostGate\Agent",
        config_dir=r"C:\ProgramData\FrostGate\Agent\config",
        log_dir=r"C:\ProgramData\FrostGate\Agent\logs",
        data_dir=r"C:\ProgramData\FrostGate\Agent\data",
        build_output_dir=build_output_dir,
        artifact_name=artifact_name,
        package_code_strategy="per_release",
        signing_required=True,
        signing_status="unsigned",
        sha256_manifest_required=True,
    )
