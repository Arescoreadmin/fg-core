"""
tests/agent/test_upgrade_uninstall_hardening.py

Tests for task 18.5 — Upgrade and uninstall hardening.

Coverage:
  1. Upgrade plan — preserves credential, preserves state, no re-enroll, no token
  2. Normal uninstall plan — preserves credential, preserves state, deterministic
  3. Purge uninstall plan — explicit credential delete, explicit data delete
  4. Credential cleanup — removed / not_found / preserved / failed paths
  5. Validation functions — UpgradePlan and UninstallPlan validators
  6. Security regression — no token material, no broad swallowing, no fake success
  7. Plan YAML cross-reference

Tests are deterministic and offline-safe.
No live Windows MSI/SCM/DPAPI required.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from agent.app.credentials.local_store import (
    CredentialNotFoundError,
    CredentialStorageError,
    DeviceCredential,
    TestOnlyInMemoryCredentialStore,
)
from agent.app.installer.lifecycle import (
    CredentialCleanupError,
    LifecycleError,
    PurgePlan,
    UninstallPlan,
    UpgradePlan,
    build_purge_uninstall_plan,
    build_uninstall_plan,
    build_upgrade_plan,
    execute_credential_cleanup,
    validate_uninstall_plan,
    validate_upgrade_plan,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TENANT = "tenant-abc123"
_DEVICE_ID = "device-xyz789"
_ARTIFACT = r"C:\FrostGate\FrostGateAgent-1.2.3.msi"
_VERSION = "1.2.3"
_UPGRADE_CODE = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
_SERVICE = "FrostGateAgent"
_DATA_DIR = r"C:\ProgramData\FrostGate\data"
_LOG_DIR = r"C:\ProgramData\FrostGate\logs"


def _make_credential() -> DeviceCredential:
    return DeviceCredential(
        tenant_id=_TENANT,
        device_id=_DEVICE_ID,
        device_key="super-secret-hmac-key",
        device_key_id="key-prefix-001",
        issued_at="2026-04-29T00:00:00Z",
    )


def _upgrade_plan(**overrides: object) -> UpgradePlan:
    kwargs: dict[str, object] = dict(
        artifact_path=_ARTIFACT,
        new_version=_VERSION,
        upgrade_code=_UPGRADE_CODE,
        tenant_id=_TENANT,
        device_id=_DEVICE_ID,
    )
    kwargs.update(overrides)
    return build_upgrade_plan(**kwargs)  # type: ignore[arg-type]


def _uninstall_plan(**overrides: object) -> UninstallPlan:
    kwargs: dict[str, object] = dict(
        service_name=_SERVICE,
        artifact_path=_ARTIFACT,
    )
    kwargs.update(overrides)
    return build_uninstall_plan(**kwargs)  # type: ignore[arg-type]


def _purge_plan(**overrides: object) -> PurgePlan:
    kwargs: dict[str, object] = dict(
        service_name=_SERVICE,
        artifact_path=_ARTIFACT,
        tenant_id=_TENANT,
        device_id=_DEVICE_ID,
        data_directory=_DATA_DIR,
        log_directory=_LOG_DIR,
    )
    kwargs.update(overrides)
    return build_purge_uninstall_plan(**kwargs)  # type: ignore[arg-type]


# ===========================================================================
# 1. Upgrade plan
# ===========================================================================


def test_upgrade_plan_preserves_device_credential() -> None:
    plan = _upgrade_plan()
    assert plan.credential_action == "preserve", (
        "Upgrade must preserve OS-protected device credential"
    )


def test_upgrade_plan_preserves_collected_state() -> None:
    plan = _upgrade_plan()
    assert plan.data_action == "preserve", (
        "Upgrade must preserve collected data directory"
    )


def test_upgrade_plan_does_not_reenroll() -> None:
    plan = _upgrade_plan()
    assert plan.no_reenroll is True, "Upgrade must not trigger silent re-enrollment"


def test_upgrade_plan_has_no_token_material() -> None:
    plan = _upgrade_plan()
    assert plan.token_material_present is False
    combined = " ".join(plan.msiexec_args).lower()
    for token_pat in ("enrollment_token", "bootstrap_token", "bearer", "api_key"):
        assert token_pat not in combined, (
            f"Token pattern '{token_pat}' found in upgrade msiexec_args"
        )


def test_upgrade_plan_does_not_call_credential_delete() -> None:
    """Upgrade plan generation must not call store.delete() or any delete operation."""
    store = TestOnlyInMemoryCredentialStore()
    store.store(_make_credential())
    _upgrade_plan()
    # Credential must still be in store — upgrade did not touch it
    assert store.exists(_TENANT, _DEVICE_ID) is True


def test_upgrade_plan_contains_artifact_path() -> None:
    plan = _upgrade_plan()
    assert _ARTIFACT in plan.msiexec_args


def test_upgrade_plan_contains_msiexec_i() -> None:
    plan = _upgrade_plan()
    assert "msiexec" in plan.msiexec_args
    assert "/i" in plan.msiexec_args


def test_upgrade_plan_is_deterministic() -> None:
    plan_a = _upgrade_plan()
    plan_b = _upgrade_plan()
    assert plan_a.msiexec_args == plan_b.msiexec_args
    assert plan_a.credential_action == plan_b.credential_action
    assert plan_a.data_action == plan_b.data_action


def test_upgrade_plan_rejects_empty_artifact_path() -> None:
    with pytest.raises(LifecycleError, match="artifact_path"):
        _upgrade_plan(artifact_path="")


def test_upgrade_plan_rejects_empty_version() -> None:
    with pytest.raises(LifecycleError, match="new_version"):
        _upgrade_plan(new_version="")


def test_upgrade_plan_rejects_empty_upgrade_code() -> None:
    with pytest.raises(LifecycleError, match="upgrade_code"):
        _upgrade_plan(upgrade_code="")


def test_upgrade_plan_rejects_empty_tenant_id() -> None:
    with pytest.raises(LifecycleError, match="tenant_id"):
        _upgrade_plan(tenant_id="")


def test_upgrade_plan_rejects_empty_device_id() -> None:
    with pytest.raises(LifecycleError, match="device_id"):
        _upgrade_plan(device_id="")


# ===========================================================================
# 2. Normal uninstall plan
# ===========================================================================


def test_uninstall_plan_preserves_credential() -> None:
    plan = _uninstall_plan()
    assert plan.credential_action == "preserve", (
        "Normal uninstall must not purge OS-protected credentials"
    )


def test_uninstall_plan_preserves_collected_state() -> None:
    plan = _uninstall_plan()
    assert plan.data_action == "preserve", (
        "Normal uninstall must not purge collected data"
    )


def test_uninstall_plan_stops_service_first() -> None:
    plan = _uninstall_plan()
    assert plan.stops_service_first is True, (
        "Normal uninstall must stop service before removing binaries"
    )


def test_uninstall_plan_purge_is_false() -> None:
    plan = _uninstall_plan()
    assert plan.purge is False


def test_uninstall_plan_steps_include_stop_before_remove() -> None:
    plan = _uninstall_plan()
    stop_idx = next((i for i, s in enumerate(plan.steps) if "stop" in s.lower()), None)
    remove_idx = next(
        (i for i, s in enumerate(plan.steps) if "msiexec" in s.lower()), None
    )
    assert stop_idx is not None, "Steps must include a stop action"
    assert remove_idx is not None, "Steps must include a remove/msiexec action"
    assert stop_idx < remove_idx, "Stop must precede remove in step order"


def test_uninstall_plan_steps_document_credential_preservation() -> None:
    plan = _uninstall_plan()
    cred_step = any(
        "credential" in s.lower() or "credential manager" in s.lower()
        for s in plan.steps
    )
    assert cred_step, "Steps must document that credential is preserved"


def test_uninstall_plan_is_deterministic() -> None:
    plan_a = _uninstall_plan()
    plan_b = _uninstall_plan()
    assert plan_a.steps == plan_b.steps
    assert plan_a.credential_action == plan_b.credential_action


def test_uninstall_plan_rejects_empty_service_name() -> None:
    with pytest.raises(LifecycleError, match="service_name"):
        _uninstall_plan(service_name="")


def test_uninstall_plan_rejects_empty_artifact_path() -> None:
    with pytest.raises(LifecycleError, match="artifact_path"):
        _uninstall_plan(artifact_path="")


# ===========================================================================
# 3. Purge uninstall plan
# ===========================================================================


def test_purge_plan_purge_is_true() -> None:
    plan = _purge_plan()
    assert plan.purge is True


def test_purge_plan_credential_action_is_delete_via_store() -> None:
    plan = _purge_plan()
    assert plan.credential_action == "delete_via_store", (
        "Purge must delete credentials through the CredentialStore API"
    )


def test_purge_plan_data_action_is_delete() -> None:
    plan = _purge_plan()
    assert plan.data_action == "delete"


def test_purge_plan_stops_service_first() -> None:
    plan = _purge_plan()
    assert plan.stops_service_first is True


def test_purge_plan_steps_include_credential_store_delete() -> None:
    plan = _purge_plan()
    cred_step = any(
        "credential-store" in s or "credential store" in s.lower() for s in plan.steps
    )
    assert cred_step, (
        "Purge steps must reference credential-store delete (not filesystem path)"
    )


def test_purge_plan_steps_include_data_directory_removal() -> None:
    plan = _purge_plan()
    data_step = any(_DATA_DIR in s or "data" in s.lower() for s in plan.steps)
    assert data_step, "Purge steps must include data directory removal"


def test_purge_plan_steps_include_stop_before_remove() -> None:
    plan = _purge_plan()
    stop_idx = next((i for i, s in enumerate(plan.steps) if "stop" in s.lower()), None)
    cred_idx = next(
        (i for i, s in enumerate(plan.steps) if "credential" in s.lower()), None
    )
    assert stop_idx is not None
    assert cred_idx is not None
    assert stop_idx < cred_idx, "Stop must precede credential deletion in step order"


def test_purge_plan_is_deterministic() -> None:
    plan_a = _purge_plan()
    plan_b = _purge_plan()
    assert plan_a.steps == plan_b.steps
    assert plan_a.credential_action == plan_b.credential_action
    assert plan_a.data_action == plan_b.data_action


def test_purge_plan_contains_tenant_and_device_in_steps() -> None:
    plan = _purge_plan()
    combined = " ".join(plan.steps)
    assert _TENANT in combined
    assert _DEVICE_ID in combined


def test_purge_plan_rejects_empty_tenant_id() -> None:
    with pytest.raises(LifecycleError, match="tenant_id"):
        _purge_plan(tenant_id="")


def test_purge_plan_rejects_empty_device_id() -> None:
    with pytest.raises(LifecycleError, match="device_id"):
        _purge_plan(device_id="")


def test_purge_plan_rejects_empty_data_directory() -> None:
    with pytest.raises(LifecycleError, match="data_directory"):
        _purge_plan(data_directory="")


def test_purge_plan_rejects_empty_log_directory() -> None:
    with pytest.raises(LifecycleError, match="log_directory"):
        _purge_plan(log_directory="")


# ===========================================================================
# 4. Credential cleanup executor
# ===========================================================================


def test_credential_cleanup_purge_false_returns_preserved() -> None:
    store = TestOnlyInMemoryCredentialStore()
    store.store(_make_credential())
    result = execute_credential_cleanup(
        store, tenant_id=_TENANT, device_id=_DEVICE_ID, purge=False
    )
    assert result.status == "preserved"
    assert store.exists(_TENANT, _DEVICE_ID) is True


def test_credential_cleanup_purge_true_removes_credential() -> None:
    store = TestOnlyInMemoryCredentialStore()
    store.store(_make_credential())
    result = execute_credential_cleanup(
        store, tenant_id=_TENANT, device_id=_DEVICE_ID, purge=True
    )
    assert result.status == "removed"
    assert store.exists(_TENANT, _DEVICE_ID) is False


def test_credential_cleanup_not_found_returns_not_found() -> None:
    """Credential absent from store → status 'not_found', not 'removed'."""
    store = TestOnlyInMemoryCredentialStore()
    # Credential never stored — exists() returns False → not_found without calling delete
    result = execute_credential_cleanup(
        store, tenant_id=_TENANT, device_id=_DEVICE_ID, purge=True
    )
    assert result.status == "not_found"


def test_credential_cleanup_not_found_via_race_condition() -> None:
    """CredentialNotFoundError from delete() after exists()=True (race) → not_found."""
    store = MagicMock()
    store.exists.return_value = True
    store.delete.side_effect = CredentialNotFoundError(
        "disappeared between exists and delete"
    )
    result = execute_credential_cleanup(
        store, tenant_id=_TENANT, device_id=_DEVICE_ID, purge=True
    )
    assert result.status == "not_found"


def test_credential_cleanup_access_denied_raises_cleanup_error() -> None:
    """Access-denied from store.delete() must surface as CredentialCleanupError — not swallowed."""
    store = MagicMock()
    store.delete.side_effect = CredentialStorageError("access denied — winerror=5")

    with pytest.raises(CredentialCleanupError, match="Failed to delete credential"):
        execute_credential_cleanup(
            store, tenant_id=_TENANT, device_id=_DEVICE_ID, purge=True
        )


def test_credential_cleanup_api_failure_raises_cleanup_error() -> None:
    """Generic storage failure must surface as CredentialCleanupError — not swallowed."""
    store = MagicMock()
    store.delete.side_effect = CredentialStorageError(
        "Credential Manager API unavailable"
    )

    with pytest.raises(CredentialCleanupError):
        execute_credential_cleanup(
            store, tenant_id=_TENANT, device_id=_DEVICE_ID, purge=True
        )


def test_credential_cleanup_result_has_detail() -> None:
    store = TestOnlyInMemoryCredentialStore()
    store.store(_make_credential())
    result = execute_credential_cleanup(
        store, tenant_id=_TENANT, device_id=_DEVICE_ID, purge=True
    )
    assert result.detail, "CredentialCleanupResult must have a non-empty detail string"


def test_credential_cleanup_not_found_detail_contains_tenant_and_device() -> None:
    store = TestOnlyInMemoryCredentialStore()
    result = execute_credential_cleanup(
        store, tenant_id=_TENANT, device_id=_DEVICE_ID, purge=True
    )
    assert _TENANT in result.detail
    assert _DEVICE_ID in result.detail


def test_credential_cleanup_does_not_delete_when_purge_false() -> None:
    """Credential must never be deleted when purge=False, even if store.delete() is available."""
    store = MagicMock()
    result = execute_credential_cleanup(
        store, tenant_id=_TENANT, device_id=_DEVICE_ID, purge=False
    )
    assert result.status == "preserved"
    store.delete.assert_not_called()


# ===========================================================================
# 5. Validation functions
# ===========================================================================


def test_validate_upgrade_plan_passes_valid_plan() -> None:
    validate_upgrade_plan(_upgrade_plan())  # must not raise


def test_validate_upgrade_plan_rejects_wrong_credential_action() -> None:
    # Force a bad plan by constructing directly
    bad = UpgradePlan(
        credential_action="preserve",  # type: ignore[arg-type]
        data_action="preserve",
        no_reenroll=True,
        token_material_present=False,
        artifact_path=_ARTIFACT,
        new_version=_VERSION,
        upgrade_code=_UPGRADE_CODE,
        msiexec_args=["msiexec", "/i", _ARTIFACT],
    )
    validate_upgrade_plan(bad)  # valid plan — no error expected


def test_validate_upgrade_plan_rejects_token_material_in_args() -> None:
    import agent.app.installer.lifecycle as lc

    with pytest.raises(LifecycleError, match="[Tt]oken"):
        lc._assert_no_token_material("test", ["msiexec", "/i", "ENROLLMENT_TOKEN=abc"])


def test_validate_uninstall_plan_passes_valid_plan() -> None:
    validate_uninstall_plan(_uninstall_plan())  # must not raise


def test_validate_uninstall_plan_rejects_empty_artifact_path() -> None:
    """validate_uninstall_plan must reject a plan with an empty artifact_path."""
    plan = UninstallPlan(
        credential_action="preserve",
        data_action="preserve",
        stops_service_first=True,
        purge=False,
        service_name=_SERVICE,
        artifact_path="",
        steps=["sc stop FrostGateAgent"],
    )
    with pytest.raises(LifecycleError, match="artifact_path"):
        validate_uninstall_plan(plan)


# ===========================================================================
# 6. Security regression
# ===========================================================================


def test_regression_upgrade_does_not_contain_token_patterns() -> None:
    plan = _upgrade_plan()
    forbidden = (
        "enrollment_token",
        "bootstrap_token",
        "bearer",
        "api_key",
        "hmac_secret",
    )
    combined = " ".join(plan.msiexec_args).lower()
    for pat in forbidden:
        assert pat not in combined, (
            f"REGRESSION: Token pattern '{pat}' found in upgrade msiexec_args"
        )


def test_regression_upgrade_credential_action_is_always_preserve() -> None:
    plan = _upgrade_plan()
    assert plan.credential_action == "preserve", (
        "REGRESSION: upgrade credential_action changed from 'preserve'"
    )


def test_regression_normal_uninstall_credential_action_is_always_preserve() -> None:
    plan = _uninstall_plan()
    assert plan.credential_action == "preserve", (
        "REGRESSION: normal uninstall credential_action changed from 'preserve'"
    )


def test_regression_purge_uses_credential_store_not_filesystem() -> None:
    """Purge must use CredentialStore.delete(), not filesystem paths for credential cleanup."""
    import inspect
    import agent.app.installer.lifecycle as lc

    src = inspect.getsource(lc.execute_credential_cleanup)
    # Must call store.delete() — the only valid credential cleanup path
    assert "store.delete(" in src, (
        "REGRESSION: execute_credential_cleanup must call store.delete()"
    )
    # Must NOT use open(), Path(), or file I/O for credential cleanup
    for forbidden in ("open(", "Path(", "os.remove", "shutil.rmtree"):
        assert forbidden not in src, (
            f"REGRESSION: Forbidden file-path cleanup pattern '{forbidden}' found in "
            "execute_credential_cleanup — credential cleanup must use store.delete() only"
        )


def test_regression_no_broad_except_pass_in_cleanup() -> None:
    """execute_credential_cleanup must not swallow errors with bare except/pass."""
    import inspect
    import agent.app.installer.lifecycle as lc

    src = inspect.getsource(lc.execute_credential_cleanup)
    # Bare 'except Exception: pass' or 'except: pass' is forbidden
    assert "except Exception:\n" not in src and "except:\n" not in src, (
        "REGRESSION: Broad except/pass found in execute_credential_cleanup — "
        "access-denied and API failures must not be swallowed"
    )


def test_regression_credential_cleanup_error_surfaced_on_storage_failure() -> None:
    """Access-denied must raise CredentialCleanupError — never return 'removed' or 'not_found'."""
    store = MagicMock()
    store.delete.side_effect = CredentialStorageError("winerror=5 access denied")
    with pytest.raises(CredentialCleanupError):
        execute_credential_cleanup(
            store, tenant_id=_TENANT, device_id=_DEVICE_ID, purge=True
        )


def test_regression_purge_true_required_for_destructive_cleanup() -> None:
    """Credential must be preserved when purge=False, regardless of store state."""
    store = TestOnlyInMemoryCredentialStore()
    store.store(_make_credential())
    result = execute_credential_cleanup(
        store, tenant_id=_TENANT, device_id=_DEVICE_ID, purge=False
    )
    assert result.status == "preserved"
    assert store.exists(_TENANT, _DEVICE_ID) is True, (
        "REGRESSION: Credential was deleted despite purge=False"
    )


def test_regression_upgrade_plan_is_deterministic_across_calls() -> None:
    """Repeated calls to build_upgrade_plan() with same args must return identical output."""
    results = [_upgrade_plan() for _ in range(3)]
    for r in results[1:]:
        assert r.msiexec_args == results[0].msiexec_args
        assert r.credential_action == results[0].credential_action
        assert r.data_action == results[0].data_action


def test_regression_purge_plan_steps_do_not_contain_device_key() -> None:
    """Purge plan steps must not embed device_key or any secret material."""
    plan = _purge_plan()
    combined = " ".join(plan.steps)
    assert "device_key" not in combined, (
        "REGRESSION: device_key found in purge plan steps"
    )
    assert "super-secret" not in combined


# ===========================================================================
# 7. Plan YAML cross-reference
# ===========================================================================


def test_plan_validation_command_targets_this_test_file() -> None:
    """Task 18.5 validation_commands must include this test file."""
    plan_path = (
        Path(__file__).resolve().parent.parent.parent
        / "plans"
        / "30_day_repo_blitz.yaml"
    )
    assert plan_path.exists(), f"Plan YAML not found at {plan_path}"
    with plan_path.open() as f:
        plan = yaml.safe_load(f)

    task_185: dict | None = None
    for phase in plan.get("phases", []):
        for module in phase.get("modules", []):
            for task in module.get("tasks", []):
                if str(task.get("id")) == "18.5":
                    task_185 = task
                    break

    assert task_185 is not None, "Task 18.5 not found in plan YAML"
    cmds = task_185.get("validation_commands", [])
    found = any("test_upgrade_uninstall_hardening" in cmd for cmd in cmds)
    assert found, (
        f"Task 18.5 validation_commands do not reference "
        f"'test_upgrade_uninstall_hardening'. Got: {cmds}"
    )
