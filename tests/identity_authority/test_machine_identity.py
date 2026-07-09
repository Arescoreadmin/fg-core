"""tests/identity_authority/test_machine_identity.py — Machine identity tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from api.identity_authority.machine_identity import MachineIdentityAuthority, MachineIdentityRecord


@pytest.fixture
def machine_auth():
    return MachineIdentityAuthority()


def _make_record(**kwargs) -> MachineIdentityRecord:
    defaults = dict(
        key_id="key-id-001",
        key_prefix="fg_live_001",
        tenant_id="tenant-123",
        roles=frozenset(["assessor"]),
        scopes=frozenset(["assessment:write"]),
        is_active=True,
    )
    defaults.update(kwargs)
    return MachineIdentityRecord(**defaults)


def test_authenticate_api_key_success(machine_auth):
    record = _make_record(key_hash="$argon2id$v=19$...", hash_alg="argon2id")
    with patch.object(machine_auth, "_load_key_record", return_value=record):
        with patch.object(machine_auth, "_verify_secret", return_value=True):
            with patch.object(machine_auth, "_touch_last_used"):
                identity = machine_auth.authenticate_api_key(
                    "fg_live_001", "secret", db=MagicMock()
                )

    assert identity.subject == "fg_live_001"
    assert identity.identity_type == "machine"
    assert identity.tenant_binding is not None
    assert identity.tenant_binding.tenant_id == "tenant-123"
    assert "assessor" in identity.tenant_binding.roles


def test_authenticate_api_key_not_found_raises(machine_auth):
    with patch.object(machine_auth, "_load_key_record", return_value=None):
        with pytest.raises(ValueError, match="not found"):
            machine_auth.authenticate_api_key("fg_live_missing", "secret", db=MagicMock())


def test_authenticate_api_key_inactive_raises(machine_auth):
    record = _make_record(is_active=False)
    with patch.object(machine_auth, "_load_key_record", return_value=record):
        with pytest.raises(ValueError, match="inactive"):
            machine_auth.authenticate_api_key("fg_live_001", "secret", db=MagicMock())


def test_authenticate_api_key_bad_secret_raises(machine_auth):
    record = _make_record(key_hash="$argon2id$v=19$...", hash_alg="argon2id")
    with patch.object(machine_auth, "_load_key_record", return_value=record):
        with patch.object(machine_auth, "_verify_secret", return_value=False):
            with pytest.raises(ValueError, match="invalid"):
                machine_auth.authenticate_api_key("fg_live_001", "wrong", db=MagicMock())


def test_verify_secret_no_hash_raises(machine_auth):
    record = _make_record(key_hash=None, hash_alg=None)
    with pytest.raises(ValueError, match="no stored hash"):
        machine_auth._verify_secret("fg_live_001", "secret", record)


def test_authenticate_api_key_no_db_raises(machine_auth):
    with pytest.raises(ValueError, match="database session"):
        machine_auth.authenticate_api_key("key-id-001", "secret", db=None)


def test_authenticate_api_key_from_state_no_auth(machine_auth):
    state = MagicMock()
    state.auth = None
    result = machine_auth.authenticate_api_key_from_state(state)
    assert result is None


def test_authenticate_api_key_from_state_with_key(machine_auth):
    auth_state = MagicMock()
    auth_state.key_id = "key-id-001"
    auth_state.key_prefix = "fg_live_001"
    auth_state.tenant_id = "tenant-123"
    auth_state.roles = ["viewer"]
    auth_state.scopes = ["assessment:read"]

    state = MagicMock()
    state.auth = auth_state

    identity = machine_auth.authenticate_api_key_from_state(state)
    assert identity is not None
    assert identity.subject == "fg_live_001"
    assert identity.identity_type == "machine"
    assert identity.tenant_binding.tenant_id == "tenant-123"


def test_authenticate_api_key_from_state_no_key_id(machine_auth):
    auth_state = MagicMock()
    auth_state.key_id = None

    state = MagicMock()
    state.auth = auth_state

    result = machine_auth.authenticate_api_key_from_state(state)
    assert result is None


def test_build_identity_has_correct_permissions(machine_auth):
    record = _make_record(roles=frozenset(["tenant_admin"]))
    identity = machine_auth._build_identity(record)

    assert "key.manage" in identity.tenant_binding.permissions
    assert "user.invite" in identity.tenant_binding.permissions


def test_get_machine_authority_singleton(monkeypatch):
    from api.identity_authority.machine_identity import get_machine_authority

    a1 = get_machine_authority()
    a2 = get_machine_authority()
    assert a1 is a2
