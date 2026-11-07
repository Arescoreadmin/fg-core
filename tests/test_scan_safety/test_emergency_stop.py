"""L14-SCAN-SAFETY-001 — emergency stop adversarial tests."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)

from services.field_assessment.scan_authorization import (
    ScanAuthorizationError,
    _PLATFORM_STOP_PERMISSION,
    _TENANT_STOP_PERMISSION,
    clear_emergency_stop,
    request_emergency_stop,
)

_TENANT_A = "tenant-estop-a"
_TENANT_B = "tenant-estop-b"
_ACTOR = "operator-estop"
_STOP_ID = "00000000-0000-0000-0000-000000000001"


def _make_insert_db(stop_row=None) -> MagicMock:
    db = MagicMock()
    result = MagicMock()
    result.fetchone.return_value = stop_row
    db.execute.return_value = result
    return db


def _make_clear_db(*, select_row=None) -> MagicMock:
    """DB for clear_emergency_stop: first execute SELECT, second execute UPDATE."""
    db = MagicMock()
    select_result = MagicMock()
    select_result.fetchone.return_value = select_row

    update_result = MagicMock()

    db.execute.side_effect = [select_result, update_result]
    return db


class TestRequestEmergencyStop:
    def test_operator_with_permission_activates_tenant_stop(self):
        now = datetime.now(timezone.utc)
        stop_row = (_STOP_ID, f"tenant:{_TENANT_A}", True, now)
        db = _make_insert_db(stop_row=stop_row)

        result = request_emergency_stop(
            db,
            scope=f"tenant:{_TENANT_A}",
            reason="suspected unauthorized activity",
            actor=_ACTOR,
            actor_tenant_id=_TENANT_A,
            permissions=[_TENANT_STOP_PERMISSION],
        )
        assert result["is_active"] is True
        assert result["scope"] == f"tenant:{_TENANT_A}"
        db.commit.assert_called_once()

    def test_activation_without_permission_denied(self):
        db = _make_insert_db()
        with pytest.raises(ScanAuthorizationError) as exc_info:
            request_emergency_stop(
                db,
                scope=f"tenant:{_TENANT_A}",
                reason="test",
                actor=_ACTOR,
                actor_tenant_id=_TENANT_A,
                permissions=[],  # no permissions
            )
        assert exc_info.value.audit_code == "EMERGENCY_STOP_PERMISSION_DENIED"
        db.execute.assert_not_called()

    def test_platform_stop_requires_platform_permission(self):
        db = _make_insert_db()
        with pytest.raises(ScanAuthorizationError) as exc_info:
            request_emergency_stop(
                db,
                scope="platform",
                reason="test",
                actor=_ACTOR,
                actor_tenant_id=_TENANT_A,
                permissions=[_TENANT_STOP_PERMISSION],  # tenant only, not platform
            )
        assert exc_info.value.audit_code == "EMERGENCY_STOP_PERMISSION_DENIED"

    def test_platform_stop_with_platform_permission_succeeds(self):
        now = datetime.now(timezone.utc)
        db = _make_insert_db(stop_row=(_STOP_ID, "platform", True, now))
        result = request_emergency_stop(
            db,
            scope="platform",
            reason="critical incident",
            actor=_ACTOR,
            actor_tenant_id=_TENANT_A,
            permissions=[_PLATFORM_STOP_PERMISSION],
        )
        assert result["is_active"] is True
        assert result["scope"] == "platform"

    def test_cross_tenant_stop_denied(self):
        """Operator from tenant A cannot activate stop scoped to tenant B."""
        db = _make_insert_db()
        with pytest.raises(ScanAuthorizationError) as exc_info:
            request_emergency_stop(
                db,
                scope=f"tenant:{_TENANT_B}",  # targeting tenant B
                reason="test",
                actor=_ACTOR,
                actor_tenant_id=_TENANT_A,  # actor is from tenant A
                permissions=[_TENANT_STOP_PERMISSION],
            )
        assert exc_info.value.audit_code == "EMERGENCY_STOP_CROSS_TENANT_DENIED"

    def test_invalid_scope_raises(self):
        db = _make_insert_db()
        with pytest.raises(ScanAuthorizationError) as exc_info:
            request_emergency_stop(
                db,
                scope="invalid_scope",
                reason="test",
                actor=_ACTOR,
                actor_tenant_id=_TENANT_A,
                permissions=[_TENANT_STOP_PERMISSION, _PLATFORM_STOP_PERMISSION],
            )
        assert exc_info.value.audit_code == "EMERGENCY_STOP_INVALID_SCOPE"

    def test_engagement_stop_with_permission_succeeds(self):
        now = datetime.now(timezone.utc)
        eng_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        db = _make_insert_db(stop_row=(_STOP_ID, f"engagement:{eng_id}", True, now))
        result = request_emergency_stop(
            db,
            scope=f"engagement:{eng_id}",
            reason="single engagement stop",
            actor=_ACTOR,
            actor_tenant_id=_TENANT_A,
            permissions=[_TENANT_STOP_PERMISSION],
        )
        assert result["is_active"] is True


class TestClearEmergencyStop:
    def test_clear_with_permission_deactivates_stop(self):
        select_row = (_STOP_ID, f"tenant:{_TENANT_A}", True)
        db = _make_clear_db(select_row=select_row)

        result = clear_emergency_stop(
            db,
            stop_id=_STOP_ID,
            actor=_ACTOR,
            actor_tenant_id=_TENANT_A,
            permissions=[_TENANT_STOP_PERMISSION],
        )
        assert result["is_active"] is False
        db.commit.assert_called_once()

    def test_clear_without_permission_denied(self):
        select_row = (_STOP_ID, f"tenant:{_TENANT_A}", True)
        db = _make_clear_db(select_row=select_row)

        with pytest.raises(ScanAuthorizationError) as exc_info:
            clear_emergency_stop(
                db,
                stop_id=_STOP_ID,
                actor=_ACTOR,
                actor_tenant_id=_TENANT_A,
                permissions=[],
            )
        assert exc_info.value.audit_code == "EMERGENCY_STOP_CLEAR_PERMISSION_DENIED"

    def test_clear_already_cleared_is_idempotent(self):
        select_row = (_STOP_ID, f"tenant:{_TENANT_A}", False)  # is_active=False
        db = _make_clear_db(select_row=select_row)

        result = clear_emergency_stop(
            db,
            stop_id=_STOP_ID,
            actor=_ACTOR,
            actor_tenant_id=_TENANT_A,
            permissions=[_TENANT_STOP_PERMISSION],
        )
        assert result["idempotent"] is True
        assert result["is_active"] is False

    def test_clear_nonexistent_stop_raises(self):
        db = _make_clear_db(select_row=None)

        with pytest.raises(ScanAuthorizationError) as exc_info:
            clear_emergency_stop(
                db,
                stop_id="nonexistent-id",
                actor=_ACTOR,
                actor_tenant_id=_TENANT_A,
                permissions=[_TENANT_STOP_PERMISSION],
            )
        assert exc_info.value.audit_code == "EMERGENCY_STOP_NOT_FOUND"

    def test_clear_cross_tenant_denied(self):
        """Operator from tenant A cannot clear stop scoped to tenant B."""
        select_row = (_STOP_ID, f"tenant:{_TENANT_B}", True)
        db = _make_clear_db(select_row=select_row)

        with pytest.raises(ScanAuthorizationError) as exc_info:
            clear_emergency_stop(
                db,
                stop_id=_STOP_ID,
                actor=_ACTOR,
                actor_tenant_id=_TENANT_A,
                permissions=[_TENANT_STOP_PERMISSION],
            )
        assert exc_info.value.audit_code == "EMERGENCY_STOP_CLEAR_CROSS_TENANT_DENIED"
