"""Tests for drift alert fingerprinting, deduplication, and family grouping."""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
import api.db_models_drift  # noqa: F401

from services.connectors.drift.alerts import (
    create_or_refresh_alert,
    emit_drift_alerts,
    list_active_alerts,
    resolve_alert,
)

_TENANT = "tenant-alerts-test"
_ENGAGEMENT = "eng-alerts-001"


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


class TestCreateOrRefreshAlert:
    def test_creates_new_alert(self, db: Session) -> None:
        alert = create_or_refresh_alert(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            pattern="drift.regressed",
            finding_id="f-001",
            severity="critical",
            title="Finding regressed",
            description="Test",
        )
        assert alert.is_active is True
        assert alert.finding_id == "f-001"

    def test_deduplicates_same_fingerprint(self, db: Session) -> None:
        a1 = create_or_refresh_alert(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            pattern="drift.regressed",
            finding_id="f-dedup",
            severity="high",
            title="A",
            description="B",
        )
        a2 = create_or_refresh_alert(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            pattern="drift.regressed",
            finding_id="f-dedup",
            severity="high",
            title="A",
            description="B",
        )
        assert a1.id == a2.id

    def test_different_severity_different_fingerprint(self, db: Session) -> None:
        a1 = create_or_refresh_alert(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            pattern="drift.regressed",
            finding_id="f-sev",
            severity="high",
            title="A",
            description="B",
        )
        a2 = create_or_refresh_alert(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            pattern="drift.regressed",
            finding_id="f-sev",
            severity="critical",
            title="A",
            description="B",
        )
        assert a1.id != a2.id


class TestResolveAlert:
    def test_resolves_active_alert(self, db: Session) -> None:
        create_or_refresh_alert(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            pattern="drift.escalated",
            finding_id="f-res",
            severity="high",
            title="X",
            description="Y",
        )
        resolved = resolve_alert(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            pattern="drift.escalated",
            finding_id="f-res",
            severity="high",
        )
        assert resolved is True

    def test_resolve_nonexistent_returns_false(self, db: Session) -> None:
        result = resolve_alert(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            pattern="drift.regressed",
            finding_id="nonexistent",
            severity="low",
        )
        assert result is False

    def test_resolved_alert_not_in_active_list(self, db: Session) -> None:
        create_or_refresh_alert(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            pattern="drift.new_high_critical",
            finding_id="f-list",
            severity="critical",
            title="Z",
            description="W",
        )
        resolve_alert(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            pattern="drift.new_high_critical",
            finding_id="f-list",
            severity="critical",
        )
        active = list_active_alerts(db, tenant_id=_TENANT, engagement_id=_ENGAGEMENT)
        assert all(a.finding_id != "f-list" for a in active)


class TestEmitDriftAlerts:
    def test_regressed_finding_emits_alert(self, db: Session) -> None:
        findings = [
            {
                "finding_id": "f-r1",
                "severity": "critical",
                "title": "Critical regressed",
                "delta_class": "regressed",
                "nist_ai_rmf_mappings": [],
                "baseline_severity": None,
            }
        ]
        alerts = emit_drift_alerts(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            drift_findings=findings,
        )
        assert len(alerts) == 1
        assert alerts[0].pattern == "drift.regressed"

    def test_new_low_finding_no_alert(self, db: Session) -> None:
        findings = [
            {
                "finding_id": "f-low",
                "severity": "low",
                "title": "Low new",
                "delta_class": "new",
                "nist_ai_rmf_mappings": [],
                "baseline_severity": None,
            }
        ]
        alerts = emit_drift_alerts(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            drift_findings=findings,
        )
        assert len(alerts) == 0

    def test_family_alert_created_at_threshold(self, db: Session) -> None:
        findings = [
            {
                "finding_id": f"f-fam-{i}",
                "severity": "high",
                "title": f"Finding {i}",
                "delta_class": "regressed",
                "nist_ai_rmf_mappings": [{"function": "GOVERN"}],
                "baseline_severity": None,
            }
            for i in range(3)
        ]
        alerts = emit_drift_alerts(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            drift_findings=findings,
        )
        family_alerts = [a for a in alerts if a.pattern == "drift.domain_cluster"]
        assert len(family_alerts) == 1
        assert family_alerts[0].alert_family == "GOVERN"

    def test_persisted_finding_no_alert(self, db: Session) -> None:
        findings = [
            {
                "finding_id": "f-per",
                "severity": "critical",
                "title": "Persisted",
                "delta_class": "persisted",
                "nist_ai_rmf_mappings": [],
                "baseline_severity": "critical",
            }
        ]
        alerts = emit_drift_alerts(
            db,
            tenant_id=_TENANT,
            engagement_id=_ENGAGEMENT,
            drift_findings=findings,
        )
        assert len(alerts) == 0
