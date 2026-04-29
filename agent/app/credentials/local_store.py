"""
agent/app/credentials/local_store.py

Local credential storage boundary for task 18.4.

Defines the typed credential storage interface, the production Windows Credential
Manager backend (DPAPI-backed), and an explicit platform-failure path for
non-Windows production deployments.

Security invariants:
- Device credentials are NEVER stored in plaintext files.
- Device credentials are NEVER stored in environment variables.
- Device credentials are NEVER stored in agent.toml or any config file.
- Production Linux/macOS raises UnsupportedCredentialStoreError — no silent fallback.
- TestOnlyInMemoryCredentialStore is NEVER returned by get_credential_store()
  in mode='production'.
- DeviceCredential repr/str/redacted() never expose the device_key value.
- enrollment/bootstrap tokens are never accepted by this module (only device credentials).
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

# Sentinel used in redacted output and repr/str — never a real credential value.
DEVICE_KEY_REDACTED: str = "<redacted>"

# Windows Credential Manager target name prefix.
_CRED_TARGET_PREFIX: str = "FrostGate/agent"
_CRED_TYPE_GENERIC: int = 1  # CRED_TYPE_GENERIC
_WINERR_NOT_FOUND: int = 1168  # ERROR_NOT_FOUND — credential target does not exist

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CredentialStorageError(RuntimeError):
    """Base error for credential store operations."""


class CredentialNotFoundError(CredentialStorageError):
    """Raised when the requested credential does not exist in the store."""


class UnsupportedCredentialStoreError(CredentialStorageError):
    """Raised when no OS-protected credential store is available on this platform."""


class PlaintextCredentialStorageRejected(ValueError):
    """Raised if an attempt is made to store a credential via a plaintext path.

    This is a hard-stop sentinel — any code path that would write credentials
    to a file, environment variable, or config must raise this instead.
    """


# ---------------------------------------------------------------------------
# Credential model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, repr=False)
class DeviceCredential:
    """Device credential issued by the enrollment exchange.

    device_key is the protected HMAC secret used for control-plane authentication.
    It MUST only flow through OS-protected storage and MUST NEVER appear in:
    - plaintext files
    - environment variables
    - config files (agent.toml or equivalent)
    - log output
    - repr() or str() output

    Use redacted() to produce a log-safe dict for audit events.
    """

    tenant_id: str
    device_id: str
    device_key: str  # protected secret — NEVER log, NEVER persist plaintext
    device_key_id: str  # public prefix used as API key identifier
    issued_at: str  # ISO 8601 UTC timestamp

    def __repr__(self) -> str:
        return (
            f"DeviceCredential("
            f"tenant_id={self.tenant_id!r}, "
            f"device_id={self.device_id!r}, "
            f"device_key={DEVICE_KEY_REDACTED}, "
            f"device_key_id={self.device_key_id!r}, "
            f"issued_at={self.issued_at!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def redacted(self) -> dict[str, str]:
        """Return a log-safe dict with device_key replaced by DEVICE_KEY_REDACTED.

        Safe to pass to structured logging or audit events.
        Never pass the unredacted credential to any logging call.
        """
        return {
            "tenant_id": self.tenant_id,
            "device_id": self.device_id,
            "device_key": DEVICE_KEY_REDACTED,
            "device_key_id": self.device_key_id,
            "issued_at": self.issued_at,
        }

    def validate(self) -> None:
        """Validate all credential fields are non-empty strings.

        Raises CredentialStorageError listing all violations found.
        Called by store() before writing to any backend.
        """
        errors: list[str] = []
        for field_name in (
            "tenant_id",
            "device_id",
            "device_key",
            "device_key_id",
            "issued_at",
        ):
            val = getattr(self, field_name)
            if not isinstance(val, str) or not val.strip():
                errors.append(f"'{field_name}' must be a non-empty string")
        if errors:
            raise CredentialStorageError(
                f"Invalid DeviceCredential: {'; '.join(errors)}"
            )


# ---------------------------------------------------------------------------
# Protocol (storage interface)
# ---------------------------------------------------------------------------


@runtime_checkable
class CredentialStore(Protocol):
    """OS-protected credential storage interface.

    All implementations must be backed by OS-protected storage (Windows Credential
    Manager, macOS Keychain, or equivalent).  Plaintext file and environment
    variable backends are forbidden by this contract.
    """

    def store(self, credential: DeviceCredential) -> None:
        """Persist credential to OS-protected storage.

        Raises CredentialStorageError if the credential is invalid.
        Raises UnsupportedCredentialStoreError if the backend is unavailable.
        """
        ...

    def load(self, tenant_id: str, device_id: str) -> DeviceCredential:
        """Load credential from OS-protected storage.

        Raises CredentialNotFoundError if no credential exists for this tenant/device.
        Raises UnsupportedCredentialStoreError if the backend is unavailable.
        """
        ...

    def delete(self, tenant_id: str, device_id: str) -> None:
        """Remove credential from OS-protected storage.

        Idempotent: does not raise if the credential does not exist.
        Raises UnsupportedCredentialStoreError if the backend is unavailable.
        """
        ...

    def exists(self, tenant_id: str, device_id: str) -> bool:
        """Return True if a credential exists for this tenant/device pair.

        Raises UnsupportedCredentialStoreError if the backend is unavailable.
        """
        ...


# ---------------------------------------------------------------------------
# Windows Credential Manager backend (production — Windows only)
# ---------------------------------------------------------------------------


def _cred_target(tenant_id: str, device_id: str) -> str:
    return f"{_CRED_TARGET_PREFIX}/{tenant_id}/{device_id}"


class WindowsCredentialManagerStore:
    """Production credential store backed by Windows Credential Manager (DPAPI).

    Credentials are stored as CRED_TYPE_GENERIC entries under the target:
      FrostGate/agent/{tenant_id}/{device_id}

    The credential blob is a JSON document containing all DeviceCredential fields.
    Windows Credential Manager encrypts the blob on disk using DPAPI, keyed to
    the local machine account.

    All methods raise UnsupportedCredentialStoreError on non-Windows platforms
    or when pywin32 is not installed.  This is fail-closed behavior — there is
    no plaintext fallback.
    """

    def _require_platform(self) -> None:
        if sys.platform != "win32":
            raise UnsupportedCredentialStoreError(
                f"WindowsCredentialManagerStore requires Windows with pywin32 installed. "
                f"Current platform: '{sys.platform}'. "
                "Plaintext credential storage is forbidden. "
                "Use get_credential_store(mode='test') for unit tests."
            )
        try:
            import win32cred  # noqa: F401
        except ImportError as exc:
            raise UnsupportedCredentialStoreError(
                "pywin32 is not installed — Windows Credential Manager unavailable. "
                "Install pywin32: pip install pywin32"
            ) from exc

    def store(self, credential: DeviceCredential) -> None:
        self._require_platform()
        credential.validate()
        import win32cred

        blob = json.dumps(
            {
                "tenant_id": credential.tenant_id,
                "device_id": credential.device_id,
                "device_key": credential.device_key,
                "device_key_id": credential.device_key_id,
                "issued_at": credential.issued_at,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        win32cred.CredWrite(
            {
                "Type": _CRED_TYPE_GENERIC,
                "TargetName": _cred_target(credential.tenant_id, credential.device_id),
                "CredentialBlob": blob,
                "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
                "Comment": (
                    f"FrostGate Agent device credential — "
                    f"tenant={credential.tenant_id} device={credential.device_id}"
                ),
            },
            0,
        )

    def load(self, tenant_id: str, device_id: str) -> DeviceCredential:
        self._require_platform()
        import win32cred

        target = _cred_target(tenant_id, device_id)
        try:
            result = win32cred.CredRead(target, _CRED_TYPE_GENERIC)
        except Exception as exc:
            if getattr(exc, "winerror", None) == _WINERR_NOT_FOUND:
                raise CredentialNotFoundError(
                    f"No credential found for tenant={tenant_id!r} device={device_id!r}"
                ) from exc
            raise CredentialStorageError(
                f"Failed to read credential for tenant={tenant_id!r} device={device_id!r}: {exc}"
            ) from exc
        blob = json.loads(result["CredentialBlob"])
        return DeviceCredential(
            tenant_id=blob["tenant_id"],
            device_id=blob["device_id"],
            device_key=blob["device_key"],
            device_key_id=blob["device_key_id"],
            issued_at=blob["issued_at"],
        )

    def delete(self, tenant_id: str, device_id: str) -> None:
        self._require_platform()
        import win32cred

        target = _cred_target(tenant_id, device_id)
        try:
            win32cred.CredDelete(target, _CRED_TYPE_GENERIC)
        except Exception as exc:
            if getattr(exc, "winerror", None) == _WINERR_NOT_FOUND:
                return  # idempotent — credential was already absent
            raise CredentialStorageError(
                f"Failed to delete credential for tenant={tenant_id!r} device={device_id!r}: {exc}"
            ) from exc

    def exists(self, tenant_id: str, device_id: str) -> bool:
        self._require_platform()
        import win32cred

        target = _cred_target(tenant_id, device_id)
        try:
            win32cred.CredRead(target, _CRED_TYPE_GENERIC)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Test-only in-memory store
# ---------------------------------------------------------------------------


class TestOnlyInMemoryCredentialStore:
    """In-memory credential store for unit tests ONLY.

    MUST NOT be used in production code.
    - Provides no persistence (credentials are lost when the process exits).
    - Provides no OS-level protection or encryption.
    - Is NEVER returned by get_credential_store(mode='production').

    Instantiate directly in test code only:
        store = TestOnlyInMemoryCredentialStore()
    """

    __test__ = False  # prevent pytest from collecting this class as a test suite

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], DeviceCredential] = {}

    def store(self, credential: DeviceCredential) -> None:
        credential.validate()
        self._store[(credential.tenant_id, credential.device_id)] = credential

    def load(self, tenant_id: str, device_id: str) -> DeviceCredential:
        key = (tenant_id, device_id)
        if key not in self._store:
            raise CredentialNotFoundError(
                f"No credential found for tenant={tenant_id!r} device={device_id!r}"
            )
        return self._store[key]

    def delete(self, tenant_id: str, device_id: str) -> None:
        self._store.pop((tenant_id, device_id), None)

    def exists(self, tenant_id: str, device_id: str) -> bool:
        return (tenant_id, device_id) in self._store


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def get_credential_store(
    *,
    platform: str | None = None,
    mode: str = "production",
) -> CredentialStore:
    """Return the appropriate credential store for the current platform and mode.

    Args:
        platform: Override sys.platform for testing only. In all production
                  call sites, omit this argument entirely.
        mode:     'production' (default) — requires OS-protected storage.
                  'test' — returns TestOnlyInMemoryCredentialStore.
                  Any other value raises ValueError.

    Production behavior (mode='production'):
        Windows  → WindowsCredentialManagerStore (DPAPI-backed).
        Linux    → raises UnsupportedCredentialStoreError (no fallback).
        macOS    → raises UnsupportedCredentialStoreError (no fallback).
        Other    → raises UnsupportedCredentialStoreError (no fallback).

    Test behavior (mode='test'):
        Any platform → TestOnlyInMemoryCredentialStore.
        MUST NOT be called in production code paths.

    Raises:
        UnsupportedCredentialStoreError: production mode, unsupported platform.
        ValueError: unknown mode value.
    """
    if mode == "test":
        return TestOnlyInMemoryCredentialStore()
    if mode != "production":
        raise ValueError(
            f"Unknown credential store mode '{mode}'. "
            "Valid values: 'production', 'test'."
        )

    _platform = platform or sys.platform

    if _platform == "win32":
        return WindowsCredentialManagerStore()

    raise UnsupportedCredentialStoreError(
        f"No OS-protected credential store is available on platform '{_platform}'. "
        "Plaintext credential storage is unconditionally forbidden. "
        "On Windows, credentials are stored in Windows Credential Manager (DPAPI-backed). "
        "On Linux/macOS, use an OS-protected mechanism such as HashiCorp Vault, "
        "a hardware security module, or a deployment-injected secret. "
        "For unit tests, use get_credential_store(mode='test')."
    )
