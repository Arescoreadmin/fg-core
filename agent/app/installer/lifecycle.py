"""
agent/app/installer/lifecycle.py

Upgrade and uninstall hardening boundary for task 18.5.

Defines typed plan models and builders for upgrade, normal uninstall, and
purge uninstall operations.  All plan generation is cross-platform and safe
to call in Linux CI.  No live MSI/SCM execution is performed here.

Security invariants:
- Upgrade NEVER deletes OS-protected device credentials.
- Upgrade NEVER purges collected state or data directories.
- Upgrade NEVER re-enrolls silently.
- Upgrade NEVER embeds enrollment/bootstrap token material.
- Normal uninstall NEVER purges credentials or collected state.
- Purge uninstall deletes credentials through CredentialStore.delete() only.
- No filesystem path guessing is used for credential deletion.
- Credential deletion failures are surfaced — access-denied and API failures
  are NOT swallowed; only true not-found cases are treated as already removed.
- No broad except/pass on credential cleanup.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from agent.app.credentials.local_store import (
    CredentialNotFoundError,
    CredentialStorageError,
    CredentialStore,
)

# ---------------------------------------------------------------------------
# Types / literals
# ---------------------------------------------------------------------------

CredentialCleanupStatus = Literal["removed", "preserved", "not_found", "failed"]

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class LifecycleError(ValueError):
    """Raised for invalid lifecycle plan parameters or violated preconditions."""


class CredentialCleanupError(RuntimeError):
    """Raised when credential deletion fails for a non-not-found reason.

    Surfaces access-denied, API failures, and other Win32 errors so callers
    cannot silently treat a failed deletion as success.
    """


# ---------------------------------------------------------------------------
# Upgrade plan
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UpgradePlan:
    """Deterministic upgrade plan produced by build_upgrade_plan().

    An upgrade plan describes the MSI upgrade action only.  It explicitly
    documents what is preserved so callers can verify the invariants.

    Invariants (enforced by build_upgrade_plan() and validate_upgrade_plan()):
    - credential_action is always 'preserve' — credentials are NEVER deleted.
    - data_action is always 'preserve' — collected state is NEVER purged.
    - no_reenroll is always True — no silent re-enrollment.
    - token_material_present is always False — no raw token in plan.
    - msiexec_args contains no secret-like token patterns.
    """

    # What the upgrade does to device credentials.
    credential_action: Literal["preserve"]
    # What the upgrade does to collected data / state directories.
    data_action: Literal["preserve"]
    # True if enrollment is NOT triggered by this upgrade.
    no_reenroll: bool
    # True if any token material appears in msiexec_args — must always be False.
    token_material_present: bool
    # Artifact path for msiexec /i.
    artifact_path: str
    # New version string being installed.
    new_version: str
    # Stable upgrade GUID (product-specific, never rotated).
    upgrade_code: str
    # Deterministic msiexec argument list for the upgrade operation.
    msiexec_args: list[str]


@dataclass(frozen=True)
class UninstallPlan:
    """Deterministic normal uninstall plan produced by build_uninstall_plan().

    Normal uninstall de-registers the service and removes installed binaries.
    It explicitly PRESERVES credentials and collected state.

    Invariants:
    - credential_action is 'preserve' — OS-protected credential is NOT deleted.
    - data_action is 'preserve' — collected state is NOT purged.
    - stops_service_first is True — service must be stopped before removal.
    - purge is False — this plan is not a purge.
    """

    credential_action: Literal["preserve"]
    data_action: Literal["preserve"]
    stops_service_first: bool
    purge: Literal[False]
    service_name: str
    artifact_path: str
    # Ordered steps for operator review.
    steps: list[str]


@dataclass(frozen=True)
class PurgePlan:
    """Deterministic purge uninstall plan produced by build_purge_uninstall_plan().

    Purge uninstall is an explicit, destructive operation.  It stops the service,
    de-registers it, removes binaries, deletes the OS-protected device credential
    through CredentialStore.delete(), and removes collected data directories.

    Credential deletion uses the 18.4 CredentialStore API exclusively.
    No filesystem path guessing is used.

    Invariants:
    - purge is True — this is always a purge.
    - credential_action is 'delete_via_store' — deletion goes through the API.
    - data_action is 'delete' — data directories are explicitly removed.
    - stops_service_first is True — service must be stopped before removal.
    """

    purge: Literal[True]
    credential_action: Literal["delete_via_store"]
    data_action: Literal["delete"]
    stops_service_first: bool
    service_name: str
    artifact_path: str
    tenant_id: str
    device_id: str
    data_directory: str
    log_directory: str
    # Ordered steps for operator review.
    steps: list[str]


# ---------------------------------------------------------------------------
# Credential cleanup result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CredentialCleanupResult:
    """Structured result of a credential deletion attempt during purge.

    status values:
    - 'removed'   — credential was found and successfully deleted.
    - 'not_found' — credential did not exist (already removed); treated as success.
    - 'preserved' — deletion was skipped (purge=False or explicit preserve).
    - 'failed'    — deletion was attempted but failed (access-denied, API error).
                    Callers MUST NOT treat 'failed' as success.

    detail provides a human-readable explanation (no secret material).
    """

    status: CredentialCleanupStatus
    detail: str


# ---------------------------------------------------------------------------
# Secret-pattern guard
# ---------------------------------------------------------------------------

_TOKEN_PATTERNS: tuple[str, ...] = (
    "ENROLLMENT_TOKEN",
    "BOOTSTRAP_TOKEN",
    "enrollment_token",
    "bootstrap_token",
    "api_key",
    "bearer",
    "hmac_secret",
    "signing_secret",
)


def _assert_no_token_material(context: str, args: list[str]) -> None:
    """Raise LifecycleError if any token-like pattern appears in args."""
    combined = " ".join(args).lower()
    for pattern in _TOKEN_PATTERNS:
        if pattern.lower() in combined:
            raise LifecycleError(
                f"Token material detected in '{context}' plan args: '{pattern}'. "
                "Upgrade/uninstall plans must never contain raw token or secret material."
            )


# ---------------------------------------------------------------------------
# Upgrade plan builder
# ---------------------------------------------------------------------------

# MSI property name used by the installer for upgrade mode.
_MSI_PROP_UPGRADE_CODE: str = "UPGRADECODE"


def build_upgrade_plan(
    *,
    artifact_path: str,
    new_version: str,
    upgrade_code: str,
    tenant_id: str,
    device_id: str,
) -> UpgradePlan:
    """Build a deterministic upgrade plan that preserves enrollment and collected state.

    The plan passes msiexec /i in upgrade mode.  It does NOT include any
    enrollment/bootstrap token, does NOT delete credentials, does NOT purge
    data, and does NOT trigger re-enrollment.

    Args:
        artifact_path: Absolute path to the new MSI artifact.
        new_version:   Human-readable version string (e.g. "1.2.3").
        upgrade_code:  Stable product upgrade GUID — must not be empty.
        tenant_id:     Tenant identifier (for plan documentation only; never in args).
        device_id:     Device identifier (for plan documentation only; never in args).

    Raises:
        LifecycleError: if any parameter is empty or if token material is detected.
    """
    for name, val in (
        ("artifact_path", artifact_path),
        ("new_version", new_version),
        ("upgrade_code", upgrade_code),
        ("tenant_id", tenant_id),
        ("device_id", device_id),
    ):
        if not isinstance(val, str) or not val.strip():
            raise LifecycleError(f"'{name}' must be a non-empty string")

    msiexec_args: list[str] = [
        "msiexec",
        "/i",
        artifact_path,
        "/qn",
        "/l*v",
        r"%TEMP%\FrostGateAgent_upgrade.log",
    ]
    _assert_no_token_material("upgrade", msiexec_args)

    return UpgradePlan(
        credential_action="preserve",
        data_action="preserve",
        no_reenroll=True,
        token_material_present=False,
        artifact_path=artifact_path,
        new_version=new_version,
        upgrade_code=upgrade_code,
        msiexec_args=msiexec_args,
    )


def validate_upgrade_plan(plan: UpgradePlan) -> None:
    """Validate all invariants on an UpgradePlan.

    Raises LifecycleError if any invariant is violated.
    Safe to call repeatedly — does not modify the plan.
    """
    errors: list[str] = []

    if plan.credential_action != "preserve":
        errors.append(
            f"upgrade credential_action must be 'preserve', got '{plan.credential_action}'"
        )
    if plan.data_action != "preserve":
        errors.append(
            f"upgrade data_action must be 'preserve', got '{plan.data_action}'"
        )
    if not plan.no_reenroll:
        errors.append(
            "upgrade no_reenroll must be True — silent re-enrollment is forbidden"
        )
    if plan.token_material_present:
        errors.append(
            "upgrade token_material_present must be False — no raw token in plan"
        )
    if not plan.artifact_path.strip():
        errors.append("upgrade artifact_path must be non-empty")
    if not plan.new_version.strip():
        errors.append("upgrade new_version must be non-empty")
    if not plan.upgrade_code.strip():
        errors.append("upgrade upgrade_code must be non-empty")

    _assert_no_token_material("upgrade validation", plan.msiexec_args)

    if errors:
        raise LifecycleError(f"UpgradePlan validation failed: {'; '.join(errors)}")


# ---------------------------------------------------------------------------
# Normal uninstall plan builder
# ---------------------------------------------------------------------------


def build_uninstall_plan(
    *,
    service_name: str,
    artifact_path: str,
) -> UninstallPlan:
    """Build a deterministic normal uninstall plan.

    Normal uninstall stops the service, de-registers it, and removes installed
    binaries.  It explicitly PRESERVES OS-protected device credentials and
    collected data directories.  No credential deletion is performed.

    Args:
        service_name:  Windows service name (e.g. "FrostGateAgent").
        artifact_path: Path to the MSI artifact for msiexec /x.

    Raises:
        LifecycleError: if any parameter is empty.
    """
    for name, val in (
        ("service_name", service_name),
        ("artifact_path", artifact_path),
    ):
        if not isinstance(val, str) or not val.strip():
            raise LifecycleError(f"'{name}' must be a non-empty string")

    steps: list[str] = [
        f"sc stop {service_name}",
        f"msiexec /x {artifact_path} /qn /l*v %TEMP%\\FrostGateAgent_uninstall.log",
        "# Device credential preserved in Windows Credential Manager",
        "# Collected data preserved in data_directory",
    ]

    return UninstallPlan(
        credential_action="preserve",
        data_action="preserve",
        stops_service_first=True,
        purge=False,
        service_name=service_name,
        artifact_path=artifact_path,
        steps=steps,
    )


def validate_uninstall_plan(plan: UninstallPlan) -> None:
    """Validate all invariants on an UninstallPlan.

    Raises LifecycleError if any invariant is violated.
    """
    errors: list[str] = []

    if plan.credential_action != "preserve":
        errors.append(
            f"normal uninstall credential_action must be 'preserve', "
            f"got '{plan.credential_action}'"
        )
    if plan.data_action != "preserve":
        errors.append(
            f"normal uninstall data_action must be 'preserve', got '{plan.data_action}'"
        )
    if not plan.stops_service_first:
        errors.append("normal uninstall stops_service_first must be True")
    if plan.purge is not False:
        errors.append("normal uninstall purge must be False")
    if not plan.service_name.strip():
        errors.append("normal uninstall service_name must be non-empty")
    if not plan.artifact_path.strip():
        errors.append("normal uninstall artifact_path must be non-empty")
    if not plan.steps:
        errors.append("normal uninstall steps must be non-empty")

    if errors:
        raise LifecycleError(f"UninstallPlan validation failed: {'; '.join(errors)}")


# ---------------------------------------------------------------------------
# Purge uninstall plan builder
# ---------------------------------------------------------------------------


def build_purge_uninstall_plan(
    *,
    service_name: str,
    artifact_path: str,
    tenant_id: str,
    device_id: str,
    data_directory: str,
    log_directory: str,
) -> PurgePlan:
    """Build a deterministic purge uninstall plan.

    Purge uninstall is an explicit, destructive operation that:
    1. Stops the service.
    2. De-registers the service via msiexec /x.
    3. Deletes the OS-protected device credential via CredentialStore.delete().
    4. Removes collected data and log directories.

    Credential deletion MUST go through CredentialStore.delete() — no filesystem
    path guessing for credential cleanup.

    Args:
        service_name:   Windows service name.
        artifact_path:  MSI artifact path for msiexec /x.
        tenant_id:      Tenant ID for credential lookup.
        device_id:      Device ID for credential lookup.
        data_directory: Path to collected data directory.
        log_directory:  Path to log directory.

    Raises:
        LifecycleError: if any parameter is empty.
    """
    for name, val in (
        ("service_name", service_name),
        ("artifact_path", artifact_path),
        ("tenant_id", tenant_id),
        ("device_id", device_id),
        ("data_directory", data_directory),
        ("log_directory", log_directory),
    ):
        if not isinstance(val, str) or not val.strip():
            raise LifecycleError(f"'{name}' must be a non-empty string")

    steps: list[str] = [
        f"sc stop {service_name}",
        f"msiexec /x {artifact_path} /qn /l*v %TEMP%\\FrostGateAgent_purge.log",
        f"[credential-store] delete tenant={tenant_id!r} device={device_id!r}",
        f"[filesystem] remove {data_directory}",
        f"[filesystem] remove {log_directory}",
    ]

    return PurgePlan(
        purge=True,
        credential_action="delete_via_store",
        data_action="delete",
        stops_service_first=True,
        service_name=service_name,
        artifact_path=artifact_path,
        tenant_id=tenant_id,
        device_id=device_id,
        data_directory=data_directory,
        log_directory=log_directory,
        steps=steps,
    )


# ---------------------------------------------------------------------------
# Credential cleanup executor
# ---------------------------------------------------------------------------


def execute_credential_cleanup(
    store: CredentialStore,
    *,
    tenant_id: str,
    device_id: str,
    purge: bool,
) -> CredentialCleanupResult:
    """Execute credential deletion through the CredentialStore API.

    Args:
        store:     OS-protected credential store (from 18.4).
        tenant_id: Tenant identifier.
        device_id: Device identifier.
        purge:     If False, credential is preserved and status is 'preserved'.
                   If True, deletion is attempted via store.delete().

    Returns:
        CredentialCleanupResult with status in ('removed', 'not_found', 'preserved', 'failed').

    Raises:
        CredentialCleanupError: if store.delete() raises any error other than
            CredentialNotFoundError.  Access-denied and API failures are surfaced —
            callers MUST NOT treat 'failed' as success.

    Note:
        This function does NOT use filesystem paths for credential cleanup.
        It does NOT guess credential storage locations.
        It does NOT swallow access-denied or API failures.
    """
    if not purge:
        return CredentialCleanupResult(
            status="preserved",
            detail=(
                f"Credential for tenant={tenant_id!r} device={device_id!r} "
                "preserved (purge=False)"
            ),
        )

    # Check presence first so conforming idempotent stores (which do not raise
    # CredentialNotFoundError on delete) produce accurate audit status.
    if not store.exists(tenant_id, device_id):
        return CredentialCleanupResult(
            status="not_found",
            detail=(
                f"Credential for tenant={tenant_id!r} device={device_id!r} "
                "was not present in store (already removed)"
            ),
        )

    try:
        store.delete(tenant_id, device_id)
        return CredentialCleanupResult(
            status="removed",
            detail=(
                f"Credential for tenant={tenant_id!r} device={device_id!r} "
                "deleted from OS-protected store"
            ),
        )
    except CredentialNotFoundError:
        # Rare race: credential disappeared between exists() and delete().
        return CredentialCleanupResult(
            status="not_found",
            detail=(
                f"Credential for tenant={tenant_id!r} device={device_id!r} "
                "was not present in store (already removed)"
            ),
        )
    except CredentialStorageError as exc:
        raise CredentialCleanupError(
            f"Failed to delete credential for tenant={tenant_id!r} "
            f"device={device_id!r}: {exc}"
        ) from exc
