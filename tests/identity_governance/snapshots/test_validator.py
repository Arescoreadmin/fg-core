"""tests/identity_governance/snapshots/test_validator.py — SecretValidator tests."""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from api.identity_governance.models import IdentityLifecycleState
from api.identity_governance.snapshots.meta import SnapshotMeta
from api.identity_governance.snapshots.types import IdentitySnapshot, PolicySnapshot
from api.identity_governance.snapshots.validator import (
    SecretValidator,
    SnapshotValidationError,
)
from api.identity_governance.models import PolicyDecision


_TS = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
_FP = "a" * 64


def _meta() -> SnapshotMeta:
    return SnapshotMeta(
        tenant_id="tenant-a",
        generated_at=_TS,
        fingerprint=_FP,
        schema_version="identity/1.0",
        replay_version="deadbeef12345678",
        source_version="identity/1.0.0",
    )


def _clean_snap(
    identity_id: str = "user-1",
    roles: tuple[str, ...] = ("admin",),
) -> IdentitySnapshot:
    return IdentitySnapshot(
        meta=_meta(),
        identity_id=identity_id,
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        roles=roles,
        permissions=("read:all",),
        capabilities=(),
    )


@pytest.fixture
def validator() -> SecretValidator:
    return SecretValidator()


class TestCleanSnapshots:
    def test_clean_snapshot_passes(self, validator: SecretValidator) -> None:
        snap = _clean_snap()
        validator.validate(snap)  # should not raise

    def test_is_safe_true_for_clean(self, validator: SecretValidator) -> None:
        snap = _clean_snap()
        assert validator.is_safe(snap) is True

    def test_policy_snapshot_passes(self, validator: SecretValidator) -> None:
        snap = PolicySnapshot(
            meta=_meta(),
            subject="user-1",
            policies_evaluated=3,
            decision=PolicyDecision.ALLOW,
            matched_policy_id="p-1",
            conditions_checked=("mfa", "lifecycle"),
        )
        validator.validate(snap)


class TestSecretKeyDetection:
    def _make_snap_with_summary(self, key: str, value: str) -> IdentitySnapshot:
        """Use identity_summary to inject a custom key/value pair."""
        # We test validator directly via a custom dataclass
        # because existing snapshot types don't have arbitrary fields.
        # We'll call _to_serializable manually and test _walk.
        raise NotImplementedError("Use direct dict test below")

    def test_password_key_in_dict_raises(self, validator: SecretValidator) -> None:
        # Test the validator's internal walk via a plain dict representation
        with pytest.raises(SnapshotValidationError):
            validator._walk({"password": "secret123"}, "root")

    def test_token_key_in_dict_raises(self, validator: SecretValidator) -> None:
        with pytest.raises(SnapshotValidationError):
            validator._walk({"token": "my-token"}, "root")

    def test_secret_key_in_dict_raises(self, validator: SecretValidator) -> None:
        with pytest.raises(SnapshotValidationError):
            validator._walk({"secret": "shhhh"}, "root")

    def test_api_key_in_dict_raises(self, validator: SecretValidator) -> None:
        with pytest.raises(SnapshotValidationError):
            validator._walk({"api_key": "sk-abc123"}, "root")

    def test_private_key_in_dict_raises(self, validator: SecretValidator) -> None:
        with pytest.raises(SnapshotValidationError):
            validator._walk({"private_key": "rsa-key-data"}, "root")

    def test_refresh_token_key_in_dict_raises(self, validator: SecretValidator) -> None:
        with pytest.raises(SnapshotValidationError):
            validator._walk({"refresh_token": "rt-value"}, "root")

    def test_is_safe_false_for_secret_key(self, validator: SecretValidator) -> None:
        # Create a custom dataclass with a secret field to test is_safe end-to-end
        @dataclasses.dataclass(frozen=True)
        class BadSnap:
            meta: SnapshotMeta
            token: str  # type: ignore[misc]

        bad = BadSnap(meta=_meta(), token="some-token-value")
        assert validator.is_safe(bad) is False


class TestSecretValueDetection:
    def test_jwt_looking_value_raises(self, validator: SecretValidator) -> None:
        # A realistic JWT-looking string (3 base64 segments, length > 50)
        fake_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        with pytest.raises(SnapshotValidationError):
            validator._walk({"some_field": fake_jwt}, "root")

    def test_bearer_token_value_raises(self, validator: SecretValidator) -> None:
        with pytest.raises(SnapshotValidationError):
            validator._walk({"header": "bearer abc123token"}, "root")

    def test_basic_auth_value_raises(self, validator: SecretValidator) -> None:
        with pytest.raises(SnapshotValidationError):
            validator._walk({"header": "basic dXNlcjpwYXNz"}, "root")

    def test_sk_prefix_raises(self, validator: SecretValidator) -> None:
        with pytest.raises(SnapshotValidationError):
            validator._walk({"api_value": "sk-proj-abc123"}, "root")


class TestSafeKeyExceptions:
    def test_fingerprint_key_safe(self, validator: SecretValidator) -> None:
        # "fingerprint" key with a SHA-256 hex value should NOT trigger
        sha256_hex = "a" * 64
        validator._walk({"fingerprint": sha256_hex}, "root")  # should not raise

    def test_event_hash_key_safe(self, validator: SecretValidator) -> None:
        sha256_hex = "b" * 64
        validator._walk({"event_hash": sha256_hex}, "root")  # should not raise

    def test_previous_hash_key_safe(self, validator: SecretValidator) -> None:
        sha256_hex = "c" * 64
        validator._walk({"previous_hash": sha256_hex}, "root")  # should not raise

    def test_tenant_id_in_meta_is_safe(self, validator: SecretValidator) -> None:
        snap = _clean_snap()
        # tenant_id is not a secret key
        validator.validate(snap)


class TestIsSafe:
    def test_returns_true_for_clean(self, validator: SecretValidator) -> None:
        snap = _clean_snap()
        assert validator.is_safe(snap) is True

    def test_returns_false_without_raising(self, validator: SecretValidator) -> None:
        @dataclasses.dataclass(frozen=True)
        class BadSnap:
            meta: SnapshotMeta
            password: str  # type: ignore[misc]

        bad = BadSnap(meta=_meta(), password="secret")
        # is_safe must not raise — just return False
        result = validator.is_safe(bad)
        assert result is False


class TestCrossTenantValidation:
    def test_tenant_id_in_meta_not_flagged(self, validator: SecretValidator) -> None:
        """tenant_id is a known governance field, not a secret key."""
        snap = _clean_snap()
        # Should pass — tenant_id is not in _SECRET_KEY_PATTERNS
        validator.validate(snap)

    def test_different_tenants_each_validated_independently(
        self, validator: SecretValidator
    ) -> None:
        snap_a = IdentitySnapshot(
            meta=SnapshotMeta(
                tenant_id="tenant-a",
                generated_at=_TS,
                fingerprint=_FP,
                schema_version="identity/1.0",
                replay_version="abc",
                source_version="identity/1.0.0",
            ),
            identity_id="user-1",
            lifecycle_state=IdentityLifecycleState.ACTIVE,
            roles=(),
            permissions=(),
            capabilities=(),
        )
        snap_b = IdentitySnapshot(
            meta=SnapshotMeta(
                tenant_id="tenant-b",
                generated_at=_TS,
                fingerprint=_FP,
                schema_version="identity/1.0",
                replay_version="def",
                source_version="identity/1.0.0",
            ),
            identity_id="user-2",
            lifecycle_state=IdentityLifecycleState.ACTIVE,
            roles=(),
            permissions=(),
            capabilities=(),
        )
        # Both should pass
        validator.validate(snap_a)
        validator.validate(snap_b)
