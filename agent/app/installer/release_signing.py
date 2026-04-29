"""
agent/app/installer/release_signing.py

Release artifact signing pipeline contract for task 18.6.

Provides typed models and deterministic plan builders for code signing,
SHA256 hash verification, and release manifest production.  All plan
generation is cross-platform and safe to call in Linux CI.

Live signing execution (execute_live_signing()) is platform-gated: raises
SigningToolchainError on non-Windows or when signtool.exe is absent.

Security invariants:
- Signing secrets (PFX passwords, private keys) MUST NEVER appear in plans,
  manifests, logs, or command args.  Certificate thumbprint references use
  environment variable names only (e.g. '$env:FG_SIGNING_THUMBPRINT').
- Unsigned production artifacts are explicitly rejected by validate_release_ready().
- Missing SHA256 manifest blocks production release.
- Manifests MUST NOT contain enrollment tokens, bootstrap tokens, tenant
  credentials, or any secret-looking values.
- Production-ready status is False unless all required artifacts are signed
  and all SHA256 hashes are present and verified.
- No fake signed artifact status is returned when live signing is unavailable.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from typing import Literal

# ---------------------------------------------------------------------------
# Types / literals
# ---------------------------------------------------------------------------

ArtifactType = Literal["msi", "exe", "manifest", "sha256_manifest"]
ArtifactSigningStatus = Literal["signed", "unsigned"]
ReleaseSigningStatus = Literal["signed", "unsigned", "partial"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default Authenticode timestamp authority URL.
_DEFAULT_TIMESTAMP_URL: str = "http://timestamp.digicert.com"

# Secret-like patterns that must never appear in manifest field values or
# signing command args.  Checked by _assert_no_secret_material().
_SECRET_FIELD_PATTERNS: tuple[str, ...] = (
    "pfx_password",
    "private_key",
    "signing_key",
    "BEGIN PRIVATE KEY",
    "BEGIN CERTIFICATE",
    "-----",
    "enrollment_token",
    "bootstrap_token",
    "api_key",
    "bearer",
    "hmac_secret",
)

# Endpoint patterns forbidden in production release metadata.
_FORBIDDEN_PROD_ENDPOINTS: tuple[str, ...] = (
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "example.com",
    "dev.",
    ".local",
)

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SigningToolchainError(RuntimeError):
    """Raised when live signing is attempted without the required toolchain.

    Conditions: non-Windows platform, signtool.exe absent from PATH,
    or certificate thumbprint environment variable is unset.
    """


class UnsignedProductionArtifactError(ValueError):
    """Raised when a production release contains one or more unsigned artifacts.

    Hard-stop sentinel: any code path that would deploy an unsigned artifact
    to a production endpoint must raise this instead of proceeding.
    """


class ReleaseManifestError(ValueError):
    """Raised when release manifest validation fails."""


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReleaseArtifact:
    """Typed model for a single releasable artifact.

    sha256 and size_bytes are None until the artifact is produced and hashed.
    signing_status is 'unsigned' until the signing pipeline updates the model.
    """

    name: str  # filename only, e.g. "FrostGateAgent-1.2.3.msi"
    path: str  # absolute or build-relative path
    artifact_type: ArtifactType
    signing_status: ArtifactSigningStatus = "unsigned"
    sha256: str | None = None  # lowercase hex SHA256 digest
    size_bytes: int | None = None  # None until artifact is produced


@dataclass(frozen=True)
class SigningPlan:
    """Deterministic signing command plan for a single artifact.

    sign_args is a list[str] suitable for subprocess.run(shell=False).
    No signing secrets (PFX passwords, private keys) appear in any field.
    cert_thumbprint_ref is a shell reference (e.g. '$env:FG_SIGNING_THUMBPRINT')
    — the actual thumbprint is injected at signing time from the environment.

    verify_args is the signtool verify command to confirm the signed artifact.
    """

    artifact_path: str
    artifact_type: ArtifactType
    sign_args: list[str]  # signtool sign ... (no secret values)
    verify_args: list[str]  # signtool verify ...
    timestamp_url: str
    cert_thumbprint_ref: str  # env var reference only — never the actual cert value
    is_production: bool


@dataclass(frozen=True)
class ReleaseManifest:
    """Deterministic, auditable release manifest.

    production_ready is True only when all required artifacts are signed,
    all SHA256 hashes are present, and sha256_manifest_path is set.

    MUST NOT contain: signing secrets, private keys, enrollment/bootstrap tokens,
    tenant-specific credentials, or runtime identity material.
    """

    product: str
    version: str
    commit: str  # full git SHA
    build_time: str  # ISO 8601 UTC
    architecture: str
    target_os: str
    build_environment: str
    signing_status: ReleaseSigningStatus
    production_ready: bool
    sha256_manifest_path: str | None
    artifacts: list[ReleaseArtifact]

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable dict with deterministic field ordering."""
        return {
            "product": self.product,
            "version": self.version,
            "commit": self.commit,
            "build_time": self.build_time,
            "architecture": self.architecture,
            "target_os": self.target_os,
            "build_environment": self.build_environment,
            "signing_status": self.signing_status,
            "production_ready": self.production_ready,
            "sha256_manifest_path": self.sha256_manifest_path,
            "artifacts": [
                {
                    "name": a.name,
                    "path": a.path,
                    "artifact_type": a.artifact_type,
                    "signing_status": a.signing_status,
                    "sha256": a.sha256,
                    "size_bytes": a.size_bytes,
                }
                for a in self.artifacts
            ],
        }

    def as_json(self) -> str:
        """Return deterministic JSON representation (sorted keys, 2-space indent)."""
        return json.dumps(self.as_dict(), sort_keys=True, indent=2)


@dataclass(frozen=True)
class HashVerificationResult:
    """Result of verifying a single artifact's SHA256 hash.

    matches: True if computed hash equals expected hash.
    error: 'file_not_found' | 'hash_missing' | None
    """

    artifact_name: str
    expected_sha256: str | None
    computed_sha256: str | None
    matches: bool
    error: str | None


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------


def _assert_no_secret_material(context: str, values: list[str]) -> None:
    """Raise SigningToolchainError if any secret-like pattern appears in values."""
    combined = " ".join(values).lower()
    for pattern in _SECRET_FIELD_PATTERNS:
        if pattern.lower() in combined:
            raise ReleaseManifestError(
                f"Secret-like material detected in '{context}': pattern '{pattern}'. "
                "Signing plans and manifests must never contain keys, passwords, or tokens."
            )


def _assert_no_forbidden_endpoint(context: str, value: str) -> None:
    """Raise ReleaseManifestError if value contains a forbidden production endpoint pattern."""
    lower = value.lower()
    for pattern in _FORBIDDEN_PROD_ENDPOINTS:
        if pattern in lower:
            raise ReleaseManifestError(
                f"Forbidden endpoint pattern '{pattern}' found in '{context}'. "
                "Production release metadata must not reference localhost, dev, or example endpoints."
            )


# ---------------------------------------------------------------------------
# Signing plan builder
# ---------------------------------------------------------------------------


def build_signing_plan(
    *,
    artifact_path: str,
    artifact_type: ArtifactType,
    cert_thumbprint_ref: str,
    timestamp_url: str = _DEFAULT_TIMESTAMP_URL,
    is_production: bool = True,
) -> SigningPlan:
    """Build a deterministic signtool.exe signing command plan.

    Generates the sign and verify argument lists for Authenticode signing.
    All plan-generation is cross-platform.  No live signing occurs here.

    cert_thumbprint_ref must be an environment variable reference such as
    '$env:FG_SIGNING_THUMBPRINT' — never the raw thumbprint value from a
    PFX or certificate store.  The actual value is resolved at signing time.

    Args:
        artifact_path:       Absolute path to the artifact to sign.
        artifact_type:       Type of artifact ('msi', 'exe', etc.).
        cert_thumbprint_ref: Shell env var reference for the cert thumbprint.
        timestamp_url:       RFC 3161 timestamp authority URL.
        is_production:       True if this plan is for a production release.

    Raises:
        ReleaseManifestError: if secret material is detected in any arg.
        ReleaseManifestError: if any parameter is empty.
    """
    for name, val in (
        ("artifact_path", artifact_path),
        ("artifact_type", artifact_type),
        ("cert_thumbprint_ref", cert_thumbprint_ref),
        ("timestamp_url", timestamp_url),
    ):
        if not isinstance(val, str) or not val.strip():
            raise ReleaseManifestError(f"'{name}' must be a non-empty string")

    sign_args: list[str] = [
        "signtool.exe",
        "sign",
        "/fd",
        "sha256",
        "/sha1",
        cert_thumbprint_ref,
        "/tr",
        timestamp_url,
        "/td",
        "sha256",
        "/v",
        artifact_path,
    ]
    verify_args: list[str] = [
        "signtool.exe",
        "verify",
        "/pa",
        "/v",
        artifact_path,
    ]

    _assert_no_secret_material("sign_args", sign_args)
    _assert_no_secret_material("verify_args", verify_args)

    return SigningPlan(
        artifact_path=artifact_path,
        artifact_type=artifact_type,
        sign_args=sign_args,
        verify_args=verify_args,
        timestamp_url=timestamp_url,
        cert_thumbprint_ref=cert_thumbprint_ref,
        is_production=is_production,
    )


def execute_live_signing(plan: SigningPlan) -> None:
    """Execute the signing plan on the local Windows host.

    Raises SigningToolchainError unconditionally on non-Windows.
    Raises SigningToolchainError if signtool.exe is not in PATH.

    This is the only method that performs live signing.  All other functions
    generate plans only and are safe to call on any platform.
    """
    if sys.platform != "win32":
        raise SigningToolchainError(
            f"Live artifact signing requires Windows with signtool.exe. "
            f"Current platform: '{sys.platform}'. "
            "Use build_signing_plan() for cross-platform plan generation. "
            "Unsigned artifacts MUST NOT be deployed to production."
        )
    import os
    import re
    import shutil

    if not shutil.which("signtool.exe") and not shutil.which("signtool"):
        raise SigningToolchainError(
            "signtool.exe not found in PATH. "
            "Install Windows SDK or ensure signtool.exe is on PATH. "
            "Unsigned artifacts MUST NOT be deployed to production."
        )

    # Resolve $env:VAR_NAME reference to the actual thumbprint value.
    # subprocess.run(shell=False) does not expand shell environment references,
    # so we must resolve the value explicitly before building the arg list.
    ref = plan.cert_thumbprint_ref
    env_match = re.match(r"^\$env:(\w+)$", ref, re.IGNORECASE)
    if env_match:
        var_name = env_match.group(1)
        thumbprint = os.environ.get(var_name)
        if not thumbprint or not thumbprint.strip():
            raise SigningToolchainError(
                f"Certificate thumbprint environment variable '{var_name}' is not set or empty. "
                "Set the variable to the certificate SHA1 thumbprint before signing. "
                "Unsigned artifacts MUST NOT be deployed to production."
            )
        resolved_args = [thumbprint if arg == ref else arg for arg in plan.sign_args]
    else:
        resolved_args = list(plan.sign_args)

    import subprocess

    subprocess.run(resolved_args, check=True, shell=False)


# ---------------------------------------------------------------------------
# Release manifest builder
# ---------------------------------------------------------------------------


def build_release_manifest(
    *,
    product: str,
    version: str,
    commit: str,
    build_time: str,
    build_environment: str,
    artifacts: list[ReleaseArtifact],
    sha256_manifest_path: str | None = None,
    architecture: str = "x64",
    target_os: str = "Windows 10 (1607) / Server 2016+",
) -> ReleaseManifest:
    """Build a deterministic release manifest.

    Computes production_ready and signing_status from the provided artifacts.
    production_ready is True only when:
    - all artifacts with artifact_type in ('msi', 'exe') are signed
    - all artifacts have a non-None sha256
    - sha256_manifest_path is not None

    Args:
        product:              Product name (e.g. "FrostGate Agent").
        version:              Release version (e.g. "1.2.3").
        commit:               Full git SHA of the release commit.
        build_time:           ISO 8601 UTC build timestamp.
        build_environment:    Build environment identifier (e.g. "github-actions").
        artifacts:            List of ReleaseArtifact objects.
        sha256_manifest_path: Path to the SHA256 hash manifest file.
        architecture:         Target architecture (default: 'x64').
        target_os:            Minimum target OS (default: 'Windows 10 ...').

    Raises:
        ReleaseManifestError: if required parameters are empty or secret material detected.
    """
    for name, val in (
        ("product", product),
        ("version", version),
        ("commit", commit),
        ("build_time", build_time),
        ("build_environment", build_environment),
    ):
        if not isinstance(val, str) or not val.strip():
            raise ReleaseManifestError(f"'{name}' must be a non-empty string")

    _assert_no_secret_material(
        "manifest metadata", [product, version, commit, build_environment]
    )

    required_types: frozenset[ArtifactType] = frozenset({"msi", "exe"})
    all_signed = all(
        a.signing_status == "signed"
        for a in artifacts
        if a.artifact_type in required_types
    )
    all_hashed = all(
        a.sha256 is not None for a in artifacts if a.artifact_type in required_types
    )
    required_artifacts_exist = any(a.artifact_type in required_types for a in artifacts)

    production_ready: bool = (
        all_signed
        and all_hashed
        and bool(sha256_manifest_path and sha256_manifest_path.strip())
        and required_artifacts_exist
    )

    signed_count = sum(
        1
        for a in artifacts
        if a.artifact_type in required_types and a.signing_status == "signed"
    )
    required_count = sum(1 for a in artifacts if a.artifact_type in required_types)

    if required_count == 0:
        signing_status: ReleaseSigningStatus = "unsigned"
    elif signed_count == required_count:
        signing_status = "signed"
    elif signed_count == 0:
        signing_status = "unsigned"
    else:
        signing_status = "partial"

    return ReleaseManifest(
        product=product,
        version=version,
        commit=commit,
        build_time=build_time,
        architecture=architecture,
        target_os=target_os,
        build_environment=build_environment,
        signing_status=signing_status,
        production_ready=production_ready,
        sha256_manifest_path=sha256_manifest_path,
        artifacts=list(artifacts),
    )


# ---------------------------------------------------------------------------
# Manifest validator
# ---------------------------------------------------------------------------


def validate_release_ready(
    manifest: ReleaseManifest,
    *,
    require_production: bool = True,
) -> None:
    """Validate all conditions for a production release.

    Raises:
        UnsignedProductionArtifactError: if require_production and any required
            artifact (msi, exe) is unsigned.
        ReleaseManifestError: for any other invariant violation (missing hash,
            missing sha256_manifest_path, empty version, secret material,
            forbidden endpoint values).

    This function is idempotent and does not modify the manifest.
    """
    errors: list[str] = []

    if not manifest.version.strip():
        errors.append("version must be non-empty")
    if not manifest.commit.strip():
        errors.append("commit must be non-empty")
    if not manifest.product.strip():
        errors.append("product must be non-empty")

    if not manifest.sha256_manifest_path or not manifest.sha256_manifest_path.strip():
        errors.append(
            "sha256_manifest_path is required — missing SHA256 manifest blocks release"
        )

    required_types: frozenset[ArtifactType] = frozenset({"msi", "exe"})
    for artifact in manifest.artifacts:
        if artifact.artifact_type not in required_types:
            continue
        if artifact.sha256 is None:
            errors.append(f"artifact '{artifact.name}' is missing SHA256 hash")
        elif not artifact.sha256.strip():
            errors.append(f"artifact '{artifact.name}' has empty SHA256 hash")

    _all_fields = [
        manifest.product,
        manifest.version,
        manifest.commit,
        manifest.build_environment,
        manifest.build_time,
    ]
    try:
        _assert_no_secret_material("manifest validation", _all_fields)
    except ReleaseManifestError as exc:
        errors.append(str(exc))

    for field_name, field_value in (
        ("build_environment", manifest.build_environment),
        ("product", manifest.product),
    ):
        try:
            _assert_no_forbidden_endpoint(field_name, field_value)
        except ReleaseManifestError as exc:
            errors.append(str(exc))

    if errors:
        raise ReleaseManifestError(
            f"Release manifest validation failed: {'; '.join(errors)}"
        )

    if require_production:
        unsigned = [
            a.name
            for a in manifest.artifacts
            if a.artifact_type in required_types and a.signing_status == "unsigned"
        ]
        if unsigned:
            raise UnsignedProductionArtifactError(
                f"Production release requires all artifacts to be signed. "
                f"Unsigned artifacts: {unsigned}. "
                "Sign with build_signing_plan() + execute_live_signing() on Windows. "
                "Unsigned artifacts MUST NOT be deployed to production endpoints."
            )


# ---------------------------------------------------------------------------
# Hash verification
# ---------------------------------------------------------------------------


def verify_artifact_hashes(
    artifacts: list[ReleaseArtifact],
) -> list[HashVerificationResult]:
    """Verify SHA256 hashes of artifacts against their expected values.

    Reads each artifact from its path and computes the SHA256 digest.
    Returns a structured result for each artifact.

    Results:
        - matches=True if computed hash equals expected hash (case-insensitive).
        - error='file_not_found' if the artifact path does not exist.
        - error='hash_missing' if the artifact has no expected sha256.
        - matches=False if hashes differ.

    Safe to call on any platform.  Does not require signing toolchain.
    """
    results: list[HashVerificationResult] = []

    for artifact in artifacts:
        if artifact.sha256 is None:
            results.append(
                HashVerificationResult(
                    artifact_name=artifact.name,
                    expected_sha256=None,
                    computed_sha256=None,
                    matches=False,
                    error="hash_missing",
                )
            )
            continue

        try:
            computed = _sha256_file(artifact.path)
        except FileNotFoundError:
            results.append(
                HashVerificationResult(
                    artifact_name=artifact.name,
                    expected_sha256=artifact.sha256,
                    computed_sha256=None,
                    matches=False,
                    error="file_not_found",
                )
            )
            continue

        matches = computed.lower() == artifact.sha256.lower()
        results.append(
            HashVerificationResult(
                artifact_name=artifact.name,
                expected_sha256=artifact.sha256,
                computed_sha256=computed,
                matches=matches,
                error=None,
            )
        )

    return results


def _sha256_file(path: str) -> str:
    """Compute SHA256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
