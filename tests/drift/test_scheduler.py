"""Tests for connector run scheduling registry."""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
import api.db_models_drift  # noqa: F401

from services.connectors.drift.scheduler import (
    InvalidCronExpression,
    deactivate_schedule,
    list_schedules,
    upsert_schedule,
    validate_cron_expression,
)

_TENANT = "tenant-sched-test"
_ENGAGEMENT = "eng-sched-001"
_ACTOR = "ops@example.com"


@pytest.fixture()
def engine():
    import api.signed_artifacts  # noqa: F401
    os.environ.setdefault("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    os.environ.setdefault(
        "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    with Session(engine) as session:
        yield session


class TestValidateCronExpression:
    def test_valid_5_field_expression(self) -> None:
        validate_cron_expression("0 6 * * 1")  # no exception

    def test_valid_step_expression(self) -> None:
        validate_cron_expression("0 */6 * * *")  # every 6h

    def test_too_few_fields_raises(self) -> None:
        with pytest.raises(InvalidCronExpression, match="5 fields"):
            validate_cron_expression("0 6 * *")

    def test_too_many_fields_raises(self) -> None:
        with pytest.raises(InvalidCronExpression, match="5 fields"):
            validate_cron_expression("0 6 * * * 2026")

    def test_invalid_characters_raises(self) -> None:
        with pytest.raises(InvalidCronExpression, match="invalid characters"):
            validate_cron_expression("0 6 * * MON")

    def test_empty_string_raises(self) -> None:
        with pytest.raises(InvalidCronExpression):
            validate_cron_expression("")


class TestUpsertSchedule:
    def test_creates_new_schedule(self, db: Session) -> None:
        sched, is_new = upsert_schedule(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            source_type="microsoft_graph",
            cron_expression="0 6 * * 1",
            created_by=_ACTOR,
        )
        assert is_new is True
        assert sched.cron_expression == "0 6 * * 1"
        assert sched.is_active is True

    def test_updates_existing_schedule(self, db: Session) -> None:
        upsert_schedule(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            source_type="microsoft_graph",
            cron_expression="0 6 * * 1",
            created_by=_ACTOR,
        )
        sched, is_new = upsert_schedule(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            source_type="microsoft_graph",
            cron_expression="0 */12 * * *",
            created_by=_ACTOR,
        )
        assert is_new is False
        assert sched.cron_expression == "0 */12 * * *"

    def test_invalid_cron_raises(self, db: Session) -> None:
        with pytest.raises(InvalidCronExpression):
            upsert_schedule(
                db,
                tenant_id=_TENANT,
                engagement_id=_ENGAGEMENT,
                source_type="microsoft_graph",
                cron_expression="bad cron",
                created_by=_ACTOR,
            )

    def test_different_source_types_independent(self, db: Session) -> None:
        s1, _ = upsert_schedule(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            source_type="microsoft_graph",
            cron_expression="0 6 * * 1",
            created_by=_ACTOR,
        )
        s2, _ = upsert_schedule(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            source_type="okta",
            cron_expression="0 8 * * 1",
            created_by=_ACTOR,
        )
        assert s1.id != s2.id


class TestListSchedules:
    def test_returns_all_schedules_for_engagement(self, db: Session) -> None:
        upsert_schedule(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            source_type="microsoft_graph",
            cron_expression="0 6 * * 1",
            created_by=_ACTOR,
        )
        upsert_schedule(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            source_type="okta",
            cron_expression="0 8 * * *",
            created_by=_ACTOR,
        )
        rows = list_schedules(db, tenant_id=_TENANT, engagement_id=_ENGAGEMENT)
        assert len(rows) == 2

    def test_empty_when_no_schedules(self, db: Session) -> None:
        rows = list_schedules(db, tenant_id=_TENANT, engagement_id="nonexistent")
        assert rows == []


class TestDeactivateSchedule:
    def test_deactivates_active_schedule(self, db: Session) -> None:
        upsert_schedule(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            source_type="microsoft_graph",
            cron_expression="0 6 * * 1",
            created_by=_ACTOR,
        )
        result = deactivate_schedule(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            source_type="microsoft_graph",
        )
        assert result is True
        rows = list_schedules(db, tenant_id=_TENANT, engagement_id=_ENGAGEMENT)
        assert all(not r.is_active for r in rows if r.source_type == "microsoft_graph")

    def test_deactivate_nonexistent_returns_false(self, db: Session) -> None:
        result = deactivate_schedule(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            source_type="nonexistent",
        )
        assert result is False
