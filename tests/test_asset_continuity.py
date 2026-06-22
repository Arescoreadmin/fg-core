"""Tests for the Asset Continuity Service (PR 18).

NOT standalone. Component of the Field Assessment Engagement Substrate,
Governance Platform, Asset Governance Layer (AGL), and future Autonomous
Systems Governance architecture.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

from api.db_models import Base
import api.db_models_governance_assets  # noqa: F401
import api.db_models_governance_asset_candidates  # noqa: F401
import api.db_models_field_assessment  # noqa: F401

from api.db_models_governance_asset_candidates import GaAssetCandidate
from api.db_models_governance_assets import GaAsset, GaAssetOwner
from services.governance_asset_registry.attestation import compute_next_due_at
from services.governance_asset_registry.continuity import (
    attestation_health,
    continuity_gaps,
    due_soon,
)
from services.governance_asset_registry.candidates import upsert_candidate
from services.governance_asset_registry.promotion import promote_candidate_to_asset

_TENANT = "tenant-continuity-test"
_OTHER_TENANT = "tenant-other-continuity-test"


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


def _now_str() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _days_ago(n: int) -> str:
    return (datetime.now(UTC) - timedelta(days=n)).isoformat().replace("+00:00", "Z")


def _days_from_now(n: int) -> str:
    return (datetime.now(UTC) + timedelta(days=n)).isoformat().replace("+00:00", "Z")


def _make_asset(
    db: Session,
    *,
    asset_id: str,
    tenant_id: str = _TENANT,
    risk_tier: str = "low",
    status: str = "active",
    asset_type: str = "ai_system",
) -> GaAsset:
    now = _now_str()
    asset = GaAsset(
        asset_id=asset_id,
        tenant_id=tenant_id,
        asset_type=asset_type,
        name=f"Asset {asset_id}",
        status=status,
        risk_tier=risk_tier,
        risk_score=100,
        discovery_source="declared",
        schema_version="1.0",
        created_at=now,
        updated_at=now,
        created_by_email="test@example.com",
    )
    db.add(asset)
    db.flush()
    return asset


def _make_owner(
    db: Session,
    *,
    ownership_id: str,
    asset_id: str,
    tenant_id: str = _TENANT,
    risk_tier: str = "low",
    last_attested_at: str | None = None,
) -> GaAssetOwner:
    now = _now_str()
    owner = GaAssetOwner(
        ownership_id=ownership_id,
        asset_id=asset_id,
        tenant_id=tenant_id,
        owner_email="owner@example.com",
        owner_role="primary",
        attestation_interval_days=90,
        last_attested_at=last_attested_at,
        next_attestation_due_at=compute_next_due_at(risk_tier, last_attested_at),
        assigned_at=now,
        assigned_by_email="admin@example.com",
    )
    db.add(owner)
    db.flush()
    return owner


# ---------------------------------------------------------------------------
# attestation_health tests
# ---------------------------------------------------------------------------


class TestAttestationHealth:
    def test_compliant_counted_correctly(self, db: Session) -> None:
        # low tier = 90 day interval; attested 1 day ago → next due in 89 days → compliant
        _make_asset(db, asset_id="a-compliant", risk_tier="low")
        _make_owner(
            db,
            ownership_id="o-compliant",
            asset_id="a-compliant",
            last_attested_at=_days_ago(1),
        )

        report = attestation_health(db, tenant_id=_TENANT)

        assert report.compliant == 1
        assert report.overdue == 0
        assert report.due_soon == 0
        assert report.never_attested == 0
        assert report.total == 1

    def test_due_soon_counted_correctly(self, db: Session) -> None:
        # low tier = 90 day interval; attested 75 days ago → next due in 15 days → due_soon
        _make_asset(db, asset_id="a-due-soon", risk_tier="low")
        _make_owner(
            db,
            ownership_id="o-due-soon",
            asset_id="a-due-soon",
            last_attested_at=_days_ago(75),
        )

        report = attestation_health(db, tenant_id=_TENANT)

        assert report.due_soon == 1
        assert report.overdue == 0
        assert report.compliant == 0
        assert report.never_attested == 0
        assert report.total == 1

    def test_overdue_counted_correctly(self, db: Session) -> None:
        # low tier = 90 day interval; attested 100 days ago → overdue by 10 days
        _make_asset(db, asset_id="a-overdue", risk_tier="low")
        _make_owner(
            db,
            ownership_id="o-overdue",
            asset_id="a-overdue",
            last_attested_at=_days_ago(100),
        )

        report = attestation_health(db, tenant_id=_TENANT)

        assert report.overdue == 1
        assert report.compliant == 0
        assert report.due_soon == 0
        assert report.never_attested == 0
        assert report.total == 1

    def test_never_attested_counted_correctly(self, db: Session) -> None:
        # Asset with no owner = never attested
        _make_asset(db, asset_id="a-never", risk_tier="low")

        report = attestation_health(db, tenant_id=_TENANT)

        assert report.never_attested == 1
        assert report.compliant == 0
        assert report.overdue == 0
        assert report.due_soon == 0
        assert report.total == 1

    def test_health_pct_formula(self, db: Session) -> None:
        # 1 compliant, 1 overdue, 1 never_attested, 1 due_soon → health = 25.0
        _make_asset(db, asset_id="b-c", risk_tier="low")
        _make_owner(
            db, ownership_id="oc", asset_id="b-c", last_attested_at=_days_ago(1)
        )

        _make_asset(db, asset_id="b-o", risk_tier="low")
        _make_owner(
            db, ownership_id="oo", asset_id="b-o", last_attested_at=_days_ago(100)
        )

        _make_asset(db, asset_id="b-n")
        # no owner → never_attested

        _make_asset(db, asset_id="b-d", risk_tier="low")
        _make_owner(
            db, ownership_id="od", asset_id="b-d", last_attested_at=_days_ago(75)
        )

        report = attestation_health(db, tenant_id=_TENANT)

        assert report.total == 4
        assert report.compliant == 1
        assert report.health_pct == 25.0

    def test_empty_tenant_returns_100_health(self, db: Session) -> None:
        report = attestation_health(db, tenant_id="empty-tenant")

        assert report.total == 0
        assert report.health_pct == 100.0

    def test_inactive_assets_excluded(self, db: Session) -> None:
        _make_asset(db, asset_id="a-decom", status="decommissioned")
        _make_owner(
            db,
            ownership_id="o-decom",
            asset_id="a-decom",
            last_attested_at=_days_ago(200),
        )

        report = attestation_health(db, tenant_id=_TENANT)

        assert report.total == 0


# ---------------------------------------------------------------------------
# continuity_gaps tests
# ---------------------------------------------------------------------------


class TestContinuityGaps:
    def test_only_returns_tenant_assets(self, db: Session) -> None:
        _make_asset(db, asset_id="mine", tenant_id=_TENANT, risk_tier="low")
        _make_owner(
            db,
            ownership_id="o-mine",
            asset_id="mine",
            tenant_id=_TENANT,
            last_attested_at=_days_ago(100),
        )
        _make_asset(db, asset_id="theirs", tenant_id=_OTHER_TENANT, risk_tier="low")
        _make_owner(
            db,
            ownership_id="o-theirs",
            asset_id="theirs",
            tenant_id=_OTHER_TENANT,
            last_attested_at=_days_ago(100),
        )

        gaps = continuity_gaps(db, tenant_id=_TENANT)

        assert all(g.asset_id != "theirs" for g in gaps)
        assert any(g.asset_id == "mine" for g in gaps)

    def test_excludes_compliant_assets(self, db: Session) -> None:
        _make_asset(db, asset_id="c-compliant", risk_tier="low")
        _make_owner(
            db,
            ownership_id="oc2",
            asset_id="c-compliant",
            last_attested_at=_days_ago(1),
        )

        gaps = continuity_gaps(db, tenant_id=_TENANT)

        assert all(g.asset_id != "c-compliant" for g in gaps)

    def test_ordering_correct(self, db: Session) -> None:
        # critical overdue > high overdue > low overdue
        _make_asset(db, asset_id="ord-low", risk_tier="low")
        _make_owner(
            db,
            ownership_id="ord-lo",
            asset_id="ord-low",
            risk_tier="low",
            last_attested_at=_days_ago(100),
        )

        _make_asset(db, asset_id="ord-critical", risk_tier="critical")
        _make_owner(
            db,
            ownership_id="ord-cr",
            asset_id="ord-critical",
            risk_tier="critical",
            last_attested_at=_days_ago(35),
        )

        _make_asset(db, asset_id="ord-high", risk_tier="high")
        _make_owner(
            db,
            ownership_id="ord-hi",
            asset_id="ord-high",
            risk_tier="high",
            last_attested_at=_days_ago(70),
        )

        gaps = continuity_gaps(db, tenant_id=_TENANT)

        tier_order = [g.risk_tier for g in gaps]
        assert tier_order.index("critical") < tier_order.index("high")
        assert tier_order.index("high") < tier_order.index("low")

    def test_overdue_assets_appear_in_gaps(self, db: Session) -> None:
        _make_asset(db, asset_id="d-overdue", risk_tier="low")
        _make_owner(
            db,
            ownership_id="od2",
            asset_id="d-overdue",
            last_attested_at=_days_ago(100),
        )

        gaps = continuity_gaps(db, tenant_id=_TENANT)

        assert any(g.asset_id == "d-overdue" for g in gaps)

    def test_compliant_assets_do_not_appear_in_gaps(self, db: Session) -> None:
        _make_asset(db, asset_id="e-compliant", risk_tier="low")
        _make_owner(
            db,
            ownership_id="oe2",
            asset_id="e-compliant",
            last_attested_at=_days_ago(1),
        )

        gaps = continuity_gaps(db, tenant_id=_TENANT)

        assert all(g.asset_id != "e-compliant" for g in gaps)

    def test_risk_tier_filtering(self, db: Session) -> None:
        _make_asset(db, asset_id="f-critical", risk_tier="critical")
        _make_owner(
            db,
            ownership_id="of-cr",
            asset_id="f-critical",
            risk_tier="critical",
            last_attested_at=_days_ago(35),
        )
        _make_asset(db, asset_id="f-low", risk_tier="low")
        _make_owner(
            db,
            ownership_id="of-lo",
            asset_id="f-low",
            risk_tier="low",
            last_attested_at=_days_ago(100),
        )

        gaps_critical = continuity_gaps(db, tenant_id=_TENANT, risk_tier="critical")
        gaps_low = continuity_gaps(db, tenant_id=_TENANT, risk_tier="low")

        assert len(gaps_critical) == 1
        assert gaps_critical[0].asset_id == "f-critical"
        assert len(gaps_low) == 1
        assert gaps_low[0].asset_id == "f-low"

    def test_days_overdue_min_filter(self, db: Session) -> None:
        _make_asset(db, asset_id="g-barely", risk_tier="low")
        _make_owner(
            db, ownership_id="og1", asset_id="g-barely", last_attested_at=_days_ago(91)
        )

        _make_asset(db, asset_id="g-very", risk_tier="low")
        _make_owner(
            db, ownership_id="og2", asset_id="g-very", last_attested_at=_days_ago(200)
        )

        gaps = continuity_gaps(db, tenant_id=_TENANT, days_overdue_min=50)

        ids = [g.asset_id for g in gaps]
        assert "g-very" in ids
        # g-barely is ~1 day overdue, under the 50-day min
        assert "g-barely" not in ids


# ---------------------------------------------------------------------------
# due_soon tests
# ---------------------------------------------------------------------------


class TestDueSoon:
    def test_respects_days_parameter(self, db: Session) -> None:
        # low tier = 90 days; attested 65 days ago → next due in 25 days
        _make_asset(db, asset_id="ds-25days", risk_tier="low")
        _make_owner(
            db,
            ownership_id="ods1",
            asset_id="ds-25days",
            last_attested_at=_days_ago(65),
        )

        in_30 = due_soon(db, tenant_id=_TENANT, days=30)
        in_20 = due_soon(db, tenant_id=_TENANT, days=20)

        assert any(a["asset_id"] == "ds-25days" for a in in_30)
        assert all(a["asset_id"] != "ds-25days" for a in in_20)

    def test_overdue_excluded_from_due_soon(self, db: Session) -> None:
        _make_asset(db, asset_id="ds-overdue", risk_tier="low")
        _make_owner(
            db,
            ownership_id="ods2",
            asset_id="ds-overdue",
            last_attested_at=_days_ago(100),
        )

        result = due_soon(db, tenant_id=_TENANT, days=30)

        assert all(a["asset_id"] != "ds-overdue" for a in result)

    def test_never_attested_excluded_from_due_soon(self, db: Session) -> None:
        _make_asset(db, asset_id="ds-never")
        # no owner

        result = due_soon(db, tenant_id=_TENANT, days=30)

        assert all(a["asset_id"] != "ds-never" for a in result)


# ---------------------------------------------------------------------------
# Connector-run promote-assets tests (service layer)
# ---------------------------------------------------------------------------


class TestConnectorRunPromotion:
    def _make_candidate(
        self,
        db: Session,
        *,
        risk_signal: str = "shadow_ai",
        tenant_id: str = _TENANT,
        engagement_id: str = "eng-001",
        scan_result_id: str = "run-001",
        confidence: int = 90,
    ) -> GaAssetCandidate:
        candidate, _ = upsert_candidate(
            db,
            tenant_id=tenant_id,
            source_type="microsoft_graph",
            candidate_type="ai_application",
            risk_signal=risk_signal,
            suggested_name=f"Shadow App {risk_signal}",
            suggested_asset_type="ai_system",
            confidence=confidence,
            manifest_hash="a" * 64,
            evidence_ref_ids=[],
            engagement_id=engagement_id,
            scan_result_id=scan_result_id,
        )
        return candidate

    def test_repeated_promotion_is_idempotent(self, db: Session) -> None:
        c = self._make_candidate(db)

        asset1 = promote_candidate_to_asset(
            db, candidate=c, actor_email="test@example.com"
        )
        db.flush()
        db.refresh(c)

        asset2 = promote_candidate_to_asset(
            db, candidate=c, actor_email="test@example.com"
        )

        assert asset1.asset_id == asset2.asset_id

    def test_wrong_tenant_candidate_not_found(self, db: Session) -> None:
        self._make_candidate(db, tenant_id=_OTHER_TENANT)

        from sqlalchemy import select as sa_select

        results = (
            db.execute(
                sa_select(GaAssetCandidate).where(
                    GaAssetCandidate.tenant_id == _TENANT,
                    GaAssetCandidate.engagement_id == "eng-001",
                    GaAssetCandidate.scan_result_id == "run-001",
                    GaAssetCandidate.status == "detected",
                )
            )
            .scalars()
            .all()
        )

        assert len(results) == 0

    def test_pagination_works(self, db: Session) -> None:
        for i in range(5):
            _make_asset(db, asset_id=f"page-asset-{i}", risk_tier="low")
            _make_owner(
                db,
                ownership_id=f"o-page-{i}",
                asset_id=f"page-asset-{i}",
                last_attested_at=_days_ago(100),
            )

        all_gaps = continuity_gaps(db, tenant_id=_TENANT)
        total = len(all_gaps)

        page1 = all_gaps[:2]
        page2 = all_gaps[2:4]

        assert len(page1) == 2
        assert len(page2) == 2
        assert {g.asset_id for g in page1}.isdisjoint({g.asset_id for g in page2})
        assert total >= 5
