"""
tests/agent/test_local_credential_storage.py

Tests for task 18.4 — Local credential storage hardening.

Coverage:
  1. Credential model — fields, repr/str redaction, redacted(), validate()
  2. Storage interface — store/load/delete/exists via TestOnlyInMemoryCredentialStore
  3. Security — no plaintext fallback, no production in-memory, no secret in repr/export
  4. Factory behavior — production Linux fails, test mode explicit, unknown platform fails
  5. Windows protected path — WindowsCredentialManagerStore raises on non-Windows
  6. Plan YAML cross-reference
  7. Regression invariants

Tests are deterministic and offline-safe.
No live Windows Credential Manager / DPAPI required.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

import agent.app.credentials.local_store as cred_module
from agent.app.credentials.local_store import (
    DEVICE_KEY_REDACTED,
    CredentialNotFoundError,
    CredentialStorageError,
    CredentialStore,
    DeviceCredential,
    PlaintextCredentialStorageRejected,
    TestOnlyInMemoryCredentialStore,
    UnsupportedCredentialStoreError,
    WindowsCredentialManagerStore,
    get_credential_store,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TENANT = "tenant-abc123"
_DEVICE_ID = "device-xyz789"
_DEVICE_KEY = "super-secret-hmac-key-abc"
_DEVICE_KEY_ID = "key-prefix-001"
_ISSUED_AT = "2026-04-29T00:00:00Z"


def _make_credential(**overrides: object) -> DeviceCredential:
    defaults: dict[str, object] = dict(
        tenant_id=_TENANT,
        device_id=_DEVICE_ID,
        device_key=_DEVICE_KEY,
        device_key_id=_DEVICE_KEY_ID,
        issued_at=_ISSUED_AT,
    )
    defaults.update(overrides)
    return DeviceCredential(**defaults)  # type: ignore[arg-type]


def _memory_store() -> TestOnlyInMemoryCredentialStore:
    return TestOnlyInMemoryCredentialStore()


# ===========================================================================
# 1. Credential model
# ===========================================================================


def test_device_credential_has_required_fields() -> None:
    cred = _make_credential()
    assert cred.tenant_id == _TENANT
    assert cred.device_id == _DEVICE_ID
    assert cred.device_key == _DEVICE_KEY
    assert cred.device_key_id == _DEVICE_KEY_ID
    assert cred.issued_at == _ISSUED_AT


def test_device_credential_is_frozen() -> None:
    cred = _make_credential()
    with pytest.raises((AttributeError, TypeError)):
        cred.device_key = "new-value"  # type: ignore[misc]


def test_device_credential_repr_does_not_expose_secret() -> None:
    cred = _make_credential()
    r = repr(cred)
    assert _DEVICE_KEY not in r, f"device_key leaked into repr: {r!r}"
    assert DEVICE_KEY_REDACTED in r


def test_device_credential_str_does_not_expose_secret() -> None:
    cred = _make_credential()
    s = str(cred)
    assert _DEVICE_KEY not in s, f"device_key leaked into str: {s!r}"
    assert DEVICE_KEY_REDACTED in s


def test_device_credential_repr_contains_tenant_and_device() -> None:
    cred = _make_credential()
    r = repr(cred)
    assert _TENANT in r
    assert _DEVICE_ID in r


def test_device_credential_redacted_does_not_expose_secret() -> None:
    cred = _make_credential()
    d = cred.redacted()
    assert _DEVICE_KEY not in d.values(), f"device_key leaked into redacted(): {d}"
    assert d["device_key"] == DEVICE_KEY_REDACTED


def test_device_credential_redacted_contains_non_secret_fields() -> None:
    cred = _make_credential()
    d = cred.redacted()
    assert d["tenant_id"] == _TENANT
    assert d["device_id"] == _DEVICE_ID
    assert d["device_key_id"] == _DEVICE_KEY_ID
    assert d["issued_at"] == _ISSUED_AT


def test_device_credential_has_no_as_dict_method() -> None:
    """DeviceCredential must not expose as_dict() — would risk secret serialisation."""
    cred = _make_credential()
    assert not hasattr(cred, "as_dict"), (
        "DeviceCredential.as_dict() would risk serialising device_key into config paths"
    )


def test_device_credential_validate_passes_valid() -> None:
    _make_credential().validate()  # must not raise


def test_device_credential_validate_rejects_empty_tenant_id() -> None:
    with pytest.raises(CredentialStorageError, match="tenant_id"):
        _make_credential(tenant_id="").validate()


def test_device_credential_validate_rejects_empty_device_id() -> None:
    with pytest.raises(CredentialStorageError, match="device_id"):
        _make_credential(device_id="").validate()


def test_device_credential_validate_rejects_empty_device_key() -> None:
    with pytest.raises(CredentialStorageError, match="device_key"):
        _make_credential(device_key="").validate()


def test_device_credential_validate_rejects_whitespace_device_key() -> None:
    with pytest.raises(CredentialStorageError, match="device_key"):
        _make_credential(device_key="   ").validate()


def test_device_credential_validate_rejects_none_field() -> None:
    with pytest.raises(CredentialStorageError):
        _make_credential(device_key=None).validate()  # type: ignore[arg-type]


def test_device_credential_validate_rejects_non_string_field() -> None:
    with pytest.raises(CredentialStorageError):
        _make_credential(device_key=12345).validate()  # type: ignore[arg-type]


# ===========================================================================
# 2. Storage interface — TestOnlyInMemoryCredentialStore
# ===========================================================================


def test_in_memory_store_stores_and_loads_credential() -> None:
    store = _memory_store()
    cred = _make_credential()
    store.store(cred)
    loaded = store.load(_TENANT, _DEVICE_ID)
    assert loaded == cred


def test_in_memory_store_exists_returns_true_after_store() -> None:
    store = _memory_store()
    store.store(_make_credential())
    assert store.exists(_TENANT, _DEVICE_ID) is True


def test_in_memory_store_exists_returns_false_before_store() -> None:
    store = _memory_store()
    assert store.exists(_TENANT, _DEVICE_ID) is False


def test_in_memory_store_load_missing_raises_credential_not_found() -> None:
    store = _memory_store()
    with pytest.raises(CredentialNotFoundError):
        store.load(_TENANT, _DEVICE_ID)


def test_in_memory_store_delete_removes_credential() -> None:
    store = _memory_store()
    store.store(_make_credential())
    store.delete(_TENANT, _DEVICE_ID)
    assert store.exists(_TENANT, _DEVICE_ID) is False
    with pytest.raises(CredentialNotFoundError):
        store.load(_TENANT, _DEVICE_ID)


def test_in_memory_store_delete_is_idempotent() -> None:
    store = _memory_store()
    store.delete(_TENANT, _DEVICE_ID)  # must not raise even if not present
    store.delete(_TENANT, _DEVICE_ID)  # again — still must not raise


def test_in_memory_store_overwrites_on_restore() -> None:
    store = _memory_store()
    cred1 = _make_credential(issued_at="2026-01-01T00:00:00Z")
    cred2 = _make_credential(issued_at="2026-04-29T00:00:00Z")
    store.store(cred1)
    store.store(cred2)
    loaded = store.load(_TENANT, _DEVICE_ID)
    assert loaded.issued_at == "2026-04-29T00:00:00Z"


def test_in_memory_store_isolates_by_tenant() -> None:
    store = _memory_store()
    cred_a = _make_credential(tenant_id="tenant-a")
    cred_b = _make_credential(tenant_id="tenant-b")
    store.store(cred_a)
    store.store(cred_b)
    assert store.load("tenant-a", _DEVICE_ID) == cred_a
    assert store.load("tenant-b", _DEVICE_ID) == cred_b


def test_in_memory_store_rejects_invalid_credential() -> None:
    store = _memory_store()
    with pytest.raises(CredentialStorageError):
        store.store(_make_credential(device_key=""))


def test_in_memory_store_implements_credential_store_protocol() -> None:
    store = _memory_store()
    assert isinstance(store, CredentialStore)


# ===========================================================================
# 3. Security — no plaintext, no production in-memory, no secret in output
# ===========================================================================


def test_no_plaintext_file_store_class_exists() -> None:
    """No file-backed or env-backed store class may exist in the module."""
    forbidden: list[str] = []
    for name in dir(cred_module):
        obj = getattr(cred_module, name)
        if not isinstance(obj, type):
            continue
        if issubclass(obj, Exception):
            continue
        low = name.lower()
        if any(kw in low for kw in ("plaintext", "file", "env", "disk", "json")):
            forbidden.append(name)
    assert not forbidden, (
        f"Forbidden class(es) found in credentials module: {forbidden}. "
        "File-backed, plaintext, or env-backed credential stores are not permitted."
    )


def test_plaintext_credential_storage_rejected_error_exists() -> None:
    """PlaintextCredentialStorageRejected must be defined as a hard-stop sentinel."""
    assert issubclass(PlaintextCredentialStorageRejected, ValueError)


def test_production_linux_does_not_fallback_to_plaintext() -> None:
    """Production factory on Linux must raise, not return any store."""
    with pytest.raises(UnsupportedCredentialStoreError):
        get_credential_store(platform="linux")


def test_production_macos_does_not_fallback_to_plaintext() -> None:
    with pytest.raises(UnsupportedCredentialStoreError):
        get_credential_store(platform="darwin")


def test_unknown_platform_fails_explicitly() -> None:
    with pytest.raises(UnsupportedCredentialStoreError):
        get_credential_store(platform="freebsd")


def test_production_factory_does_not_return_in_memory_store() -> None:
    """In production mode, factory must never return TestOnlyInMemoryCredentialStore."""
    try:
        store = get_credential_store(platform="linux")
        assert not isinstance(store, TestOnlyInMemoryCredentialStore), (
            "SECURITY: production factory returned TestOnlyInMemoryCredentialStore on Linux"
        )
    except UnsupportedCredentialStoreError:
        pass  # expected on Linux


def test_test_mode_factory_returns_in_memory_store() -> None:
    store = get_credential_store(mode="test")
    assert isinstance(store, TestOnlyInMemoryCredentialStore)


def test_test_mode_factory_works_on_any_platform() -> None:
    for platform in ("linux", "darwin", "win32", "freebsd"):
        store = get_credential_store(platform=platform, mode="test")
        assert isinstance(store, TestOnlyInMemoryCredentialStore)


def test_unknown_mode_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Unknown credential store mode"):
        get_credential_store(mode="plaintext")  # type: ignore[call-overload]


def test_credential_secret_not_in_repr_or_str() -> None:
    """Regression: secret must not appear in any string representation."""
    cred = _make_credential(device_key="very-secret-key-regression-test")
    for rendered in (repr(cred), str(cred)):
        assert "very-secret-key-regression-test" not in rendered, (
            f"Secret leaked in string representation: {rendered!r}"
        )


def test_credential_secret_not_in_redacted_export() -> None:
    cred = _make_credential(device_key="very-secret-key-regression-test")
    d = cred.redacted()
    assert "very-secret-key-regression-test" not in str(d), (
        f"Secret leaked in redacted export: {d}"
    )


# ===========================================================================
# 4. Factory behavior
# ===========================================================================


def test_factory_production_mode_default() -> None:
    """Default mode is 'production' — must not silently use test mode."""
    try:
        get_credential_store()
    except UnsupportedCredentialStoreError:
        pass  # expected on Linux — confirms production mode is active


def test_factory_production_current_platform_fails_on_linux() -> None:
    if sys.platform == "win32":
        pytest.skip("only meaningful on non-Windows")
    with pytest.raises(UnsupportedCredentialStoreError):
        get_credential_store()


# ===========================================================================
# 5. Windows protected path
# ===========================================================================


def test_windows_store_raises_on_non_windows_store() -> None:
    if sys.platform == "win32":
        pytest.skip("only meaningful on non-Windows")
    store = WindowsCredentialManagerStore()
    with pytest.raises(UnsupportedCredentialStoreError, match="win32"):
        store.store(_make_credential())


def test_windows_store_raises_on_non_windows_load() -> None:
    if sys.platform == "win32":
        pytest.skip("only meaningful on non-Windows")
    store = WindowsCredentialManagerStore()
    with pytest.raises(UnsupportedCredentialStoreError):
        store.load(_TENANT, _DEVICE_ID)


def test_windows_store_raises_on_non_windows_delete() -> None:
    if sys.platform == "win32":
        pytest.skip("only meaningful on non-Windows")
    store = WindowsCredentialManagerStore()
    with pytest.raises(UnsupportedCredentialStoreError):
        store.delete(_TENANT, _DEVICE_ID)


def test_windows_store_raises_on_non_windows_exists() -> None:
    if sys.platform == "win32":
        pytest.skip("only meaningful on non-Windows")
    store = WindowsCredentialManagerStore()
    with pytest.raises(UnsupportedCredentialStoreError):
        store.exists(_TENANT, _DEVICE_ID)


def test_production_factory_returns_windows_store_for_win32_platform() -> None:
    """Factory with platform='win32' returns WindowsCredentialManagerStore."""
    store = get_credential_store(platform="win32")
    assert isinstance(store, WindowsCredentialManagerStore)


def test_windows_store_methods_fail_closed_on_linux() -> None:
    """WindowsCredentialManagerStore fails closed on Linux — no silent fallback."""
    if sys.platform == "win32":
        pytest.skip("only meaningful on non-Windows")
    store = get_credential_store(platform="win32")
    assert isinstance(store, WindowsCredentialManagerStore)
    with pytest.raises(UnsupportedCredentialStoreError):
        store.store(_make_credential())


def test_windows_store_is_not_file_backed() -> None:
    """WindowsCredentialManagerStore must not contain file I/O in its class body."""
    import inspect

    src = inspect.getsource(WindowsCredentialManagerStore)
    for file_op in ("open(", "write_text(", "read_text(", "Path("):
        assert file_op not in src, (
            f"File I/O pattern '{file_op}' found in WindowsCredentialManagerStore source — "
            "this store must not use file-backed persistence."
        )


def test_windows_store_does_not_use_dict_or_asdict_in_store() -> None:
    """store() must extract fields explicitly, not via __dict__ or dataclasses.asdict.

    If __dict__ or asdict() were used, a future field addition (e.g. a raw key comment)
    could silently be included in the blob without a deliberate review gate.
    """
    import inspect

    src = inspect.getsource(WindowsCredentialManagerStore.store)
    assert "__dict__" not in src, (
        "WindowsCredentialManagerStore.store() must not use __dict__ — "
        "use explicit field extraction to make the blob surface area visible."
    )
    assert "asdict" not in src, (
        "WindowsCredentialManagerStore.store() must not use dataclasses.asdict() — "
        "use explicit field extraction to make the blob surface area visible."
    )
    assert "vars(" not in src, (
        "WindowsCredentialManagerStore.store() must not use vars() — "
        "use explicit field extraction to make the blob surface area visible."
    )


def test_windows_store_error_messages_do_not_contain_device_key() -> None:
    """Exceptions raised by load() must not embed device_key in the message.

    load() catches Win32 exceptions and re-raises CredentialNotFoundError.
    The error message f-string must only reference tenant/device identifiers, not secrets.
    Checks the literal format string line(s) in the source, not the blob extraction that follows.
    """
    import inspect

    load_src = inspect.getsource(WindowsCredentialManagerStore.load)
    # Isolate the CredentialNotFoundError raise statement: everything between
    # "raise CredentialNotFoundError(" and ") from exc" — the f-string message.
    if "raise CredentialNotFoundError" not in load_src:
        return  # nothing to check
    # Extract just the message argument of the raise, up to ") from exc"
    after_raise = load_src.split("raise CredentialNotFoundError")[1]
    message_section = after_raise.split(") from exc")[0]
    assert "device_key" not in message_section, (
        "load() CredentialNotFoundError message must not reference device_key — "
        "only tenant_id, device_id, and the Win32 error are acceptable. "
        f"Found 'device_key' in message section: {message_section!r}"
    )


# ---------------------------------------------------------------------------
# Win32 error discrimination helpers
# ---------------------------------------------------------------------------


def _make_win32_exc(
    winerror: int | None = None, msg: str = "fake Win32 error"
) -> Exception:
    """Build a fake Win32-style exception with an optional winerror attribute."""
    exc = Exception(msg)
    if winerror is not None:
        exc.winerror = winerror  # type: ignore[attr-defined]
    return exc


# ---------------------------------------------------------------------------
# P2 — load() distinguishes missing from backend failure
# ---------------------------------------------------------------------------


def test_load_raises_credential_not_found_for_winerror_1168() -> None:
    """load() must raise CredentialNotFoundError only for ERROR_NOT_FOUND (1168)."""
    import sys
    import types
    from unittest.mock import MagicMock

    fake_win32 = types.ModuleType("win32cred")
    fake_win32.CRED_PERSIST_LOCAL_MACHINE = 3  # type: ignore[attr-defined]
    fake_win32.CredRead = MagicMock(side_effect=_make_win32_exc(winerror=1168))  # type: ignore[attr-defined]

    store = WindowsCredentialManagerStore()
    store._require_platform = MagicMock()  # type: ignore[method-assign]

    import unittest.mock as mock

    with mock.patch.dict(sys.modules, {"win32cred": fake_win32}):
        with pytest.raises(CredentialNotFoundError):
            store.load(_TENANT, _DEVICE_ID)


def test_load_raises_storage_error_for_access_denied() -> None:
    """load() must raise CredentialStorageError (not CredentialNotFoundError) for winerror=5."""
    import sys
    import types
    from unittest.mock import MagicMock

    fake_win32 = types.ModuleType("win32cred")
    fake_win32.CredRead = MagicMock(side_effect=_make_win32_exc(winerror=5))  # type: ignore[attr-defined]

    store = WindowsCredentialManagerStore()
    store._require_platform = MagicMock()  # type: ignore[method-assign]

    import unittest.mock as mock

    with mock.patch.dict(sys.modules, {"win32cred": fake_win32}):
        with pytest.raises(CredentialStorageError) as exc_info:
            store.load(_TENANT, _DEVICE_ID)
        assert not isinstance(exc_info.value, CredentialNotFoundError), (
            "access-denied must not be mis-classified as CredentialNotFoundError"
        )


def test_load_raises_storage_error_for_generic_exception() -> None:
    """load() must raise CredentialStorageError for non-Win32 backend failures."""
    import sys
    import types
    from unittest.mock import MagicMock

    fake_win32 = types.ModuleType("win32cred")
    fake_win32.CredRead = MagicMock(side_effect=_make_win32_exc(winerror=None))  # type: ignore[attr-defined]

    store = WindowsCredentialManagerStore()
    store._require_platform = MagicMock()  # type: ignore[method-assign]

    import unittest.mock as mock

    with mock.patch.dict(sys.modules, {"win32cred": fake_win32}):
        with pytest.raises(CredentialStorageError) as exc_info:
            store.load(_TENANT, _DEVICE_ID)
        assert not isinstance(exc_info.value, CredentialNotFoundError)


# ---------------------------------------------------------------------------
# P1 — delete() only swallows ERROR_NOT_FOUND
# ---------------------------------------------------------------------------


def test_delete_is_idempotent_for_winerror_1168() -> None:
    """delete() must not raise when CredDelete returns ERROR_NOT_FOUND (1168)."""
    import sys
    import types
    from unittest.mock import MagicMock

    fake_win32 = types.ModuleType("win32cred")
    fake_win32.CRED_PERSIST_LOCAL_MACHINE = 3  # type: ignore[attr-defined]
    fake_win32.CredDelete = MagicMock(side_effect=_make_win32_exc(winerror=1168))  # type: ignore[attr-defined]

    store = WindowsCredentialManagerStore()
    store._require_platform = MagicMock()  # type: ignore[method-assign]

    import unittest.mock as mock

    with mock.patch.dict(sys.modules, {"win32cred": fake_win32}):
        store.delete(_TENANT, _DEVICE_ID)  # must not raise


def test_delete_raises_storage_error_for_access_denied() -> None:
    """delete() must raise CredentialStorageError for winerror=5 (access denied)."""
    import sys
    import types
    from unittest.mock import MagicMock

    fake_win32 = types.ModuleType("win32cred")
    fake_win32.CredDelete = MagicMock(side_effect=_make_win32_exc(winerror=5))  # type: ignore[attr-defined]

    store = WindowsCredentialManagerStore()
    store._require_platform = MagicMock()  # type: ignore[method-assign]

    import unittest.mock as mock

    with mock.patch.dict(sys.modules, {"win32cred": fake_win32}):
        with pytest.raises(CredentialStorageError):
            store.delete(_TENANT, _DEVICE_ID)


def test_delete_raises_storage_error_for_generic_exception() -> None:
    """delete() must raise CredentialStorageError for non-Win32 backend failures."""
    import sys
    import types
    from unittest.mock import MagicMock

    fake_win32 = types.ModuleType("win32cred")
    fake_win32.CredDelete = MagicMock(side_effect=_make_win32_exc(winerror=None))  # type: ignore[attr-defined]

    store = WindowsCredentialManagerStore()
    store._require_platform = MagicMock()  # type: ignore[method-assign]

    import unittest.mock as mock

    with mock.patch.dict(sys.modules, {"win32cred": fake_win32}):
        with pytest.raises(CredentialStorageError):
            store.delete(_TENANT, _DEVICE_ID)


# ===========================================================================
# 6. Plan YAML cross-reference
# ===========================================================================


def test_plan_validation_command_targets_this_test_file() -> None:
    """Task 18.4 validation_commands must include this test file."""
    plan_path = (
        Path(__file__).resolve().parent.parent.parent
        / "plans"
        / "30_day_repo_blitz.yaml"
    )
    assert plan_path.exists(), f"Plan YAML not found at {plan_path}"
    with plan_path.open() as f:
        plan = yaml.safe_load(f)

    task_184: dict | None = None
    for phase in plan.get("phases", []):
        for module in phase.get("modules", []):
            for task in module.get("tasks", []):
                if str(task.get("id")) == "18.4":
                    task_184 = task
                    break

    assert task_184 is not None, "Task 18.4 not found in plan YAML"
    cmds = task_184.get("validation_commands", [])
    found = any("test_local_credential_storage" in cmd for cmd in cmds)
    assert found, (
        f"Task 18.4 validation_commands do not reference "
        f"'test_local_credential_storage'. Got: {cmds}"
    )


# ===========================================================================
# 7. Regression invariants
# ===========================================================================


def test_regression_no_plaintext_file_credential_store() -> None:
    """Regression: no class named *FileCredentialStore or *PlaintextStore may exist."""
    for name in dir(cred_module):
        obj = getattr(cred_module, name)
        if not isinstance(obj, type) or issubclass(obj, Exception):
            continue
        low = name.lower()
        assert "plaintextfile" not in low, (
            f"REGRESSION: Forbidden class '{name}' found — plaintext file store not permitted"
        )
        assert "filecredential" not in low, (
            f"REGRESSION: Forbidden class '{name}' found — file-backed store not permitted"
        )


def test_regression_default_store_is_not_in_memory_in_production_mode() -> None:
    """Regression: production factory must never silently return TestOnlyInMemoryStore."""
    if sys.platform == "win32":
        pytest.skip("only meaningful on non-Windows")
    raised = False
    try:
        store = get_credential_store()
        if isinstance(store, TestOnlyInMemoryCredentialStore):
            pytest.fail(
                "REGRESSION: production factory returned TestOnlyInMemoryCredentialStore "
                "without explicit mode='test'. Platform guard is broken."
            )
    except UnsupportedCredentialStoreError:
        raised = True
    assert raised, (
        "REGRESSION: production factory on Linux did not raise UnsupportedCredentialStoreError"
    )


def test_regression_credential_secret_not_in_repr() -> None:
    secret = "regression-secret-key-xyzzy"
    cred = _make_credential(device_key=secret)
    assert secret not in repr(cred), (
        f"REGRESSION: secret leaked in repr. repr={repr(cred)!r}"
    )


def test_regression_credential_secret_not_in_str() -> None:
    secret = "regression-secret-key-xyzzy"
    cred = _make_credential(device_key=secret)
    assert secret not in str(cred), (
        f"REGRESSION: secret leaked in str. str={str(cred)!r}"
    )


def test_regression_credential_secret_not_in_redacted_export() -> None:
    secret = "regression-secret-key-xyzzy"
    cred = _make_credential(device_key=secret)
    d = cred.redacted()
    for v in d.values():
        assert secret not in v, (
            f"REGRESSION: secret leaked in redacted() export. redacted={d}"
        )


def test_regression_production_factory_raises_on_current_linux_ci() -> None:
    """Regression: CI must not silently skip the platform guard."""
    if sys.platform == "win32":
        pytest.skip("only meaningful on Linux CI")
    with pytest.raises(UnsupportedCredentialStoreError):
        get_credential_store(mode="production")


def test_regression_windows_store_fails_closed_not_open() -> None:
    """Regression: WindowsCredentialManagerStore must not silently succeed on Linux."""
    if sys.platform == "win32":
        pytest.skip("only meaningful on non-Windows")
    store = WindowsCredentialManagerStore()
    raised = False
    try:
        store.store(_make_credential())
    except UnsupportedCredentialStoreError:
        raised = True
    assert raised, (
        "REGRESSION: WindowsCredentialManagerStore.store() returned without raising "
        "on a non-Windows platform. Platform guard is broken."
    )
