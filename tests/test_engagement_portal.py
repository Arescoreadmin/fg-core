"""Tests for PR 18.2 — Engagement Portal Authority (core).

Coverage:
  EP-1   to EP-30:   models.py — enums, constants, exception hierarchy
  EP-31  to EP-80:   schemas.py — extra=forbid validation, required field enforcement
  EP-81  to EP-130:  repository.py — CRUD, append-only guards, tenant isolation
  EP-131 to EP-180:  engine.py — health/dashboard/workspaces/preferences/activity
  EP-181 to EP-200:  validators.py — input validation
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from api.db import get_engine
from api.db_models_engagement_portal import (
    PortalEngagementActivity,
)
from services.engagement_portal.engine import EngagementPortalEngine
from services.engagement_portal.health import get_health_response
from services.engagement_portal.models import (
    ACTIVITY_LOG_RETENTION_DAYS,
    PORTAL_SCHEMA_VERSION,
    PortalAccessDenied as PortalAccessDeniedModel,
    PortalActivityEventType,
    PortalEntityNotFound as PortalEntityNotFoundModel,
    PortalError,
    PortalNotificationStatus,
    PortalNotificationType,
    PortalSearchError as PortalSearchErrorModel,
    PortalWorkspaceType,
)
from services.engagement_portal.repository import (
    count_activities,
    count_notifications,
    fetch_preferences,
    insert_activity,
    insert_notification,
    list_activities,
    list_notifications,
    mark_notification_delivered,
    upsert_preferences,
)
from services.engagement_portal.schemas import (
    AcknowledgeNotificationRequest,
    ActivityFeedResponse,
    DashboardResponse,
    EngagementPortalError,
    EvidenceWorkspaceResponse,
    HealthResponse,
    NotificationListResponse,
    PortalAccessDenied,
    PortalActivityError,
    PortalConfigError,
    PortalEntityNotFound,
    PortalNotificationError,
    PortalSearchError,
    PortalStatisticsError,
    PortalStatisticsResponse,
    PortalTimelineError,
    PortalWorkspaceError,
    PreferencesResponse,
    RecordActivityRequest,
    RemediationWorkspaceResponse,
    ReportWorkspaceResponse,
    SearchRequest,
    SearchResponse,
    TimelineResponse,
    TransparencyWorkspaceResponse,
    TrustWorkspaceResponse,
    UpdatePreferencesRequest,
)
from services.engagement_portal.statistics import compute_portal_statistics
from services.engagement_portal.validators import (
    validate_limit_offset,
    validate_search_query,
    validate_tenant_id,
)

_TENANT = "tenant-ep-001"
_TENANT_B = "tenant-ep-002"


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def svc(db):
    return EngagementPortalEngine(db, tenant_id=_TENANT)


@pytest.fixture()
def svc_b(db):
    return EngagementPortalEngine(db, tenant_id=_TENANT_B)


# ===========================================================================
# EP-1 to EP-30: models.py — enums, constants, exception hierarchy
# ===========================================================================


@pytest.mark.parametrize(
    "value",
    [
        "evidence",
        "verification",
        "reports",
        "remediation",
        "trust",
        "transparency",
        "timeline",
        "search",
    ],
)
def test_EP_1_workspace_type_values(value):
    assert any(member.value == value for member in PortalWorkspaceType)


def test_EP_2_workspace_type_count():
    assert len(PortalWorkspaceType) == 8


@pytest.mark.parametrize(
    "value",
    [
        "dashboard_viewed",
        "evidence_viewed",
        "report_viewed",
        "report_downloaded",
        "remediation_viewed",
        "trust_viewed",
        "transparency_viewed",
        "verification_viewed",
        "search_performed",
        "notification_sent",
        "preference_updated",
        "timeline_viewed",
    ],
)
def test_EP_3_activity_event_type_values(value):
    assert any(member.value == value for member in PortalActivityEventType)


def test_EP_4_activity_event_count():
    assert len(PortalActivityEventType) == 12


@pytest.mark.parametrize("value", ["PENDING", "DELIVERED", "FAILED", "ARCHIVED"])
def test_EP_5_notification_status_values(value):
    assert any(m.value == value for m in PortalNotificationStatus)


@pytest.mark.parametrize(
    "value",
    [
        "report_ready",
        "evidence_requested",
        "evidence_approved",
        "evidence_rejected",
        "verification_requested",
        "remediation_overdue",
        "assessment_completed",
        "reminder",
    ],
)
def test_EP_6_notification_type_values(value):
    assert any(m.value == value for m in PortalNotificationType)


def test_EP_7_schema_version_constant():
    assert PORTAL_SCHEMA_VERSION == "1.0"


def test_EP_8_retention_constant_positive():
    assert ACTIVITY_LOG_RETENTION_DAYS == 365
    assert ACTIVITY_LOG_RETENTION_DAYS > 0


def test_EP_9_error_base_class():
    assert issubclass(PortalError, Exception)


def test_EP_10_entity_not_found_subclass():
    assert issubclass(PortalEntityNotFoundModel, PortalError)


def test_EP_11_access_denied_subclass():
    assert issubclass(PortalAccessDeniedModel, PortalError)


def test_EP_12_search_error_subclass():
    assert issubclass(PortalSearchErrorModel, PortalError)


@pytest.mark.parametrize("member", list(PortalWorkspaceType))
def test_EP_13_workspace_type_is_str(member):
    assert isinstance(member.value, str)


@pytest.mark.parametrize("member", list(PortalActivityEventType))
def test_EP_14_activity_event_is_str(member):
    assert isinstance(member.value, str)


@pytest.mark.parametrize("member", list(PortalNotificationStatus))
def test_EP_15_notification_status_is_str(member):
    assert isinstance(member.value, str)


@pytest.mark.parametrize("member", list(PortalNotificationType))
def test_EP_16_notification_type_is_str(member):
    assert isinstance(member.value, str)


def test_EP_17_engagement_portal_error_base():
    assert issubclass(EngagementPortalError, Exception)


@pytest.mark.parametrize(
    "exc_cls",
    [
        PortalEntityNotFound,
        PortalAccessDenied,
        PortalSearchError,
        PortalNotificationError,
        PortalConfigError,
        PortalTimelineError,
        PortalActivityError,
        PortalStatisticsError,
        PortalWorkspaceError,
    ],
)
def test_EP_18_exception_subclasses(exc_cls):
    assert issubclass(exc_cls, EngagementPortalError)


def test_EP_19_enum_iteration_is_deterministic():
    values_1 = [m.value for m in PortalWorkspaceType]
    values_2 = [m.value for m in PortalWorkspaceType]
    assert values_1 == values_2


def test_EP_20_enum_lookup_by_value():
    assert PortalWorkspaceType("evidence") is PortalWorkspaceType.EVIDENCE


# ===========================================================================
# EP-31 to EP-80: schemas.py — extra=forbid + required fields
# ===========================================================================


def test_EP_31_update_preferences_default():
    req = UpdatePreferencesRequest()
    assert req.notification_email is True


def test_EP_32_update_preferences_with_fields():
    req = UpdatePreferencesRequest(
        theme="dark", notification_email=False, timezone="UTC", language="en"
    )
    assert req.theme == "dark"
    assert req.notification_email is False


def test_EP_33_update_preferences_extra_forbid():
    with pytest.raises(ValidationError):
        UpdatePreferencesRequest(theme="dark", unknown_field="x")  # type: ignore[call-arg]


@pytest.mark.parametrize("query", ["x", "search", "hello world", "a" * 100])
def test_EP_34_search_request_valid(query):
    req = SearchRequest(query=query)
    assert req.query == query


def test_EP_35_search_request_empty_query_rejected():
    with pytest.raises(ValidationError):
        SearchRequest(query="")


def test_EP_36_search_request_long_query_rejected():
    with pytest.raises(ValidationError):
        SearchRequest(query="x" * 513)


def test_EP_37_search_request_default_limits():
    req = SearchRequest(query="q")
    assert req.limit == 50
    assert req.offset == 0


def test_EP_38_search_request_limit_upper_bound():
    with pytest.raises(ValidationError):
        SearchRequest(query="q", limit=501)


def test_EP_39_search_request_offset_negative():
    with pytest.raises(ValidationError):
        SearchRequest(query="q", offset=-1)


def test_EP_40_acknowledge_notification_request_valid():
    req = AcknowledgeNotificationRequest(notification_id="abc-123")
    assert req.notification_id == "abc-123"


def test_EP_41_acknowledge_notification_extra_forbid():
    with pytest.raises(ValidationError):
        AcknowledgeNotificationRequest(notification_id="x", extra="y")  # type: ignore[call-arg]


def test_EP_42_record_activity_request_valid():
    req = RecordActivityRequest(event_type="dashboard_viewed")
    assert req.event_type == "dashboard_viewed"


def test_EP_43_record_activity_request_metadata():
    req = RecordActivityRequest(event_type="x", metadata={"a": 1})
    assert req.metadata == {"a": 1}


def test_EP_44_record_activity_request_extra_forbid():
    with pytest.raises(ValidationError):
        RecordActivityRequest(event_type="x", bogus=1)  # type: ignore[call-arg]


def test_EP_45_health_response_fields():
    h = HealthResponse(
        status="ok", schema_version="1.0", timestamp="2025-01-01T00:00:00Z"
    )
    assert h.status == "ok"


def test_EP_46_health_response_extra_forbid():
    with pytest.raises(ValidationError):
        HealthResponse(  # type: ignore[call-arg]
            status="ok", schema_version="1", timestamp="t", extra="x"
        )


def test_EP_47_dashboard_response_minimal():
    d = DashboardResponse(
        tenant_id="t",
        engagement_id=None,
        overall_readiness=None,
        governance_score=None,
        assessment_progress=None,
        evidence_collected=0,
        evidence_verified=0,
        evidence_freshness_pct=None,
        open_findings=0,
        remediation_progress=None,
        pending_approvals=0,
        latest_report_id=None,
        latest_report_state=None,
        verification_status=None,
        trust_status=None,
        transparency_status=None,
        generated_at="2025-01-01T00:00:00Z",
    )
    assert d.tenant_id == "t"


def test_EP_48_dashboard_response_extra_forbid():
    with pytest.raises(ValidationError):
        DashboardResponse(
            tenant_id="t",
            engagement_id=None,
            overall_readiness=None,
            governance_score=None,
            assessment_progress=None,
            evidence_collected=0,
            evidence_verified=0,
            evidence_freshness_pct=None,
            open_findings=0,
            remediation_progress=None,
            pending_approvals=0,
            latest_report_id=None,
            latest_report_state=None,
            verification_status=None,
            trust_status=None,
            transparency_status=None,
            generated_at="t",
            extra="x",  # type: ignore[call-arg]
        )


def test_EP_49_timeline_response_empty():
    r = TimelineResponse(items=[], total=0, offset=0, limit=10)
    assert r.total == 0


def test_EP_50_evidence_workspace_empty():
    r = EvidenceWorkspaceResponse(items=[], total=0, offset=0, limit=10)
    assert r.items == []


def test_EP_51_report_workspace_empty():
    r = ReportWorkspaceResponse(items=[], total=0, offset=0, limit=10)
    assert r.limit == 10


def test_EP_52_remediation_workspace_empty():
    r = RemediationWorkspaceResponse(items=[], total=0, offset=0, limit=10)
    assert r.offset == 0


def test_EP_53_trust_workspace_minimal():
    r = TrustWorkspaceResponse(
        trust_manifest=None,
        signing_algorithm=None,
        key_provider=None,
        provider_version=None,
        trust_digest=None,
        verified=False,
        last_signed_at=None,
        history_count=0,
    )
    assert r.verified is False


def test_EP_54_transparency_workspace_minimal():
    r = TransparencyWorkspaceResponse(
        transparency_root=None,
        merkle_root=None,
        append_only_confirmed=True,
        sequence_count=0,
        last_entry_at=None,
        proof_available=False,
    )
    assert r.append_only_confirmed is True


def test_EP_55_activity_feed_empty():
    r = ActivityFeedResponse(items=[], total=0, offset=0, limit=10)
    assert r.items == []


def test_EP_56_statistics_response():
    r = PortalStatisticsResponse(
        tenant_id="t",
        total_activities=0,
        total_reports_viewed=0,
        total_evidence_viewed=0,
        total_searches=0,
        active_notifications=0,
        preferences_set=False,
        computed_at="2025-01-01T00:00:00Z",
    )
    assert r.preferences_set is False


def test_EP_57_search_response_empty():
    r = SearchResponse(query="q", items=[], total=0, took_ms=1)
    assert r.query == "q"


def test_EP_58_notification_list_empty():
    r = NotificationListResponse(items=[], total=0, offset=0, limit=10)
    assert r.total == 0


def test_EP_59_preferences_response_defaults():
    r = PreferencesResponse(
        tenant_id="t",
        theme=None,
        notification_email=True,
        timezone=None,
        language=None,
        updated_at=None,
    )
    assert r.notification_email is True


@pytest.mark.parametrize("limit", [0, -1, 501])
def test_EP_60_search_request_invalid_limit(limit):
    with pytest.raises(ValidationError):
        SearchRequest(query="q", limit=limit)


@pytest.mark.parametrize("theme", [None, "dark", "light"])
def test_EP_61_update_preferences_theme_variants(theme):
    req = UpdatePreferencesRequest(theme=theme)
    assert req.theme == theme


@pytest.mark.parametrize(
    "event_type",
    [
        "dashboard_viewed",
        "search_performed",
        "preference_updated",
        "report_viewed",
        "evidence_viewed",
    ],
)
def test_EP_62_record_activity_event_variants(event_type):
    req = RecordActivityRequest(event_type=event_type)
    assert req.event_type == event_type


def test_EP_63_search_request_scope_list():
    req = SearchRequest(query="q", scope=["report", "evidence"])
    assert req.scope == ["report", "evidence"]


def test_EP_64_search_request_no_scope():
    req = SearchRequest(query="q")
    assert req.scope is None


@pytest.mark.parametrize("offset", [0, 1, 100, 1000])
def test_EP_65_search_request_offset_variants(offset):
    req = SearchRequest(query="q", offset=offset)
    assert req.offset == offset


@pytest.mark.parametrize("notif_email", [True, False])
def test_EP_66_preferences_notification_flag(notif_email):
    req = UpdatePreferencesRequest(notification_email=notif_email)
    assert req.notification_email is notif_email


def test_EP_67_record_activity_with_workspace():
    req = RecordActivityRequest(event_type="x", workspace="reports")
    assert req.workspace == "reports"


def test_EP_68_record_activity_empty_event_type_rejected():
    with pytest.raises(ValidationError):
        RecordActivityRequest(event_type="")


@pytest.mark.parametrize("query_len", [1, 50, 100, 511, 512])
def test_EP_69_search_request_query_lengths(query_len):
    q = "a" * query_len
    req = SearchRequest(query=q)
    assert len(req.query) == query_len


def test_EP_70_dashboard_response_extras_blocked():
    with pytest.raises(ValidationError):
        DashboardResponse.model_validate(
            {
                "tenant_id": "t",
                "engagement_id": None,
                "overall_readiness": None,
                "governance_score": None,
                "assessment_progress": None,
                "evidence_collected": 0,
                "evidence_verified": 0,
                "evidence_freshness_pct": None,
                "open_findings": 0,
                "remediation_progress": None,
                "pending_approvals": 0,
                "latest_report_id": None,
                "latest_report_state": None,
                "verification_status": None,
                "trust_status": None,
                "transparency_status": None,
                "generated_at": "t",
                "weird": "x",
            }
        )


# ===========================================================================
# EP-81 to EP-130: repository.py — CRUD + tenant isolation
# ===========================================================================


def test_EP_81_upsert_preferences_inserts(db):
    row = upsert_preferences(
        db,
        tenant_id=_TENANT,
        theme="dark",
        notification_email=True,
        timezone="UTC",
        language="en",
    )
    assert row.tenant_id == _TENANT
    assert row.theme == "dark"
    assert row.notification_email == 1


def test_EP_82_upsert_preferences_updates(db):
    upsert_preferences(
        db,
        tenant_id=_TENANT,
        theme="dark",
        notification_email=True,
        timezone=None,
        language=None,
    )
    row = upsert_preferences(
        db,
        tenant_id=_TENANT,
        theme="light",
        notification_email=False,
        timezone="EST",
        language="es",
    )
    assert row.theme == "light"
    assert row.notification_email == 0
    assert row.timezone == "EST"
    assert row.language == "es"


def test_EP_83_fetch_preferences_missing_returns_none(db):
    assert fetch_preferences(db, tenant_id="t-missing") is None


def test_EP_84_fetch_preferences_after_upsert(db):
    upsert_preferences(
        db,
        tenant_id=_TENANT,
        theme="dark",
        notification_email=True,
        timezone=None,
        language=None,
    )
    row = fetch_preferences(db, tenant_id=_TENANT)
    assert row is not None
    assert row.theme == "dark"


def test_EP_85_preferences_tenant_isolation(db):
    upsert_preferences(
        db,
        tenant_id=_TENANT,
        theme="dark",
        notification_email=True,
        timezone=None,
        language=None,
    )
    upsert_preferences(
        db,
        tenant_id=_TENANT_B,
        theme="light",
        notification_email=False,
        timezone=None,
        language=None,
    )
    a = fetch_preferences(db, tenant_id=_TENANT)
    b = fetch_preferences(db, tenant_id=_TENANT_B)
    assert a is not None and b is not None
    assert a.theme == "dark"
    assert b.theme == "light"


def test_EP_86_insert_activity_returns_row(db):
    row = insert_activity(
        db, tenant_id=_TENANT, event_type="dashboard_viewed", workspace="dashboard"
    )
    assert isinstance(row, PortalEngagementActivity)
    assert row.tenant_id == _TENANT
    assert row.event_type == "dashboard_viewed"


def test_EP_87_list_activities_empty(db):
    items, total = list_activities(db, tenant_id="t-empty")
    assert items == []
    assert total == 0


def test_EP_88_list_activities_returns_inserted(db):
    insert_activity(db, tenant_id=_TENANT, event_type="dashboard_viewed")
    items, total = list_activities(db, tenant_id=_TENANT)
    assert total >= 1
    assert any(i.event_type == "dashboard_viewed" for i in items)


def test_EP_89_count_activities_filter_by_event(db):
    insert_activity(db, tenant_id=_TENANT, event_type="report_viewed")
    insert_activity(db, tenant_id=_TENANT, event_type="evidence_viewed")
    n = count_activities(db, tenant_id=_TENANT, event_type="report_viewed")
    assert n >= 1


def test_EP_90_activity_tenant_isolation(db):
    insert_activity(db, tenant_id=_TENANT, event_type="x")
    items, _ = list_activities(db, tenant_id=_TENANT_B)
    assert items == []


def test_EP_91_activity_append_only_update_blocked(db):
    row = insert_activity(db, tenant_id=_TENANT, event_type="x")
    db.commit()
    row.event_type = "modified"
    with pytest.raises(RuntimeError, match="append-only"):
        db.commit()


def test_EP_92_activity_append_only_delete_blocked(db):
    row = insert_activity(db, tenant_id=_TENANT, event_type="x")
    db.commit()
    db.delete(row)
    with pytest.raises(RuntimeError, match="append-only"):
        db.commit()


def test_EP_93_insert_notification_returns_pending(db):
    row = insert_notification(
        db, tenant_id=_TENANT, notification_type="report_ready", subject="s", body="b"
    )
    assert row.status == "PENDING"
    assert row.subject == "s"


def test_EP_94_list_notifications_returns_inserted(db):
    insert_notification(db, tenant_id=_TENANT, notification_type="reminder")
    items, total = list_notifications(db, tenant_id=_TENANT)
    assert total >= 1


def test_EP_95_count_notifications_filter_status(db):
    insert_notification(db, tenant_id=_TENANT, notification_type="x")
    n = count_notifications(db, tenant_id=_TENANT, status="PENDING")
    assert n >= 1


def test_EP_96_notification_tenant_isolation(db):
    insert_notification(db, tenant_id=_TENANT, notification_type="x")
    items, _ = list_notifications(db, tenant_id=_TENANT_B)
    assert items == []


def test_EP_97_mark_notification_delivered(db):
    row = insert_notification(db, tenant_id=_TENANT, notification_type="x")
    db.commit()
    updated = mark_notification_delivered(db, tenant_id=_TENANT, notification_id=row.id)
    assert updated is not None
    assert updated.status == "DELIVERED"
    assert updated.delivered_at is not None


def test_EP_98_mark_notification_delivered_missing(db):
    out = mark_notification_delivered(
        db, tenant_id=_TENANT, notification_id="missing-id"
    )
    assert out is None


def test_EP_99_mark_notification_wrong_tenant_no_op(db):
    row = insert_notification(db, tenant_id=_TENANT, notification_type="x")
    db.commit()
    out = mark_notification_delivered(db, tenant_id=_TENANT_B, notification_id=row.id)
    assert out is None


@pytest.mark.parametrize("n", [1, 3, 5])
def test_EP_100_list_activities_pagination(db, n):
    for _ in range(n):
        insert_activity(db, tenant_id=_TENANT, event_type="x")
    items, total = list_activities(db, tenant_id=_TENANT, limit=2, offset=0)
    assert total >= n
    assert len(items) <= 2


@pytest.mark.parametrize("workspace", ["reports", "evidence", "trust"])
def test_EP_101_list_activities_workspace_filter(db, workspace):
    insert_activity(db, tenant_id=_TENANT, event_type="x", workspace=workspace)
    items, _ = list_activities(db, tenant_id=_TENANT, workspace=workspace)
    assert all(i.workspace == workspace for i in items)


def test_EP_102_preferences_unique_per_tenant(db):
    upsert_preferences(
        db,
        tenant_id=_TENANT,
        theme="dark",
        notification_email=True,
        timezone=None,
        language=None,
    )
    row1 = fetch_preferences(db, tenant_id=_TENANT)
    upsert_preferences(
        db,
        tenant_id=_TENANT,
        theme="light",
        notification_email=False,
        timezone=None,
        language=None,
    )
    row2 = fetch_preferences(db, tenant_id=_TENANT)
    assert row1 is not None and row2 is not None
    assert row1.id == row2.id


@pytest.mark.parametrize("status", ["PENDING", "DELIVERED", "FAILED", "ARCHIVED"])
def test_EP_103_count_notifications_status_filters(db, status):
    n = count_notifications(db, tenant_id="t-empty-status", status=status)
    assert n == 0


@pytest.mark.parametrize("event_type", list("abcde"))
def test_EP_104_insert_activity_event_variants(db, event_type):
    row = insert_activity(db, tenant_id=_TENANT, event_type=event_type)
    assert row.event_type == event_type


def test_EP_105_insert_activity_with_metadata_json(db):
    row = insert_activity(
        db, tenant_id=_TENANT, event_type="x", metadata_json='{"k":"v"}'
    )
    assert row.metadata_json == '{"k":"v"}'


# ===========================================================================
# EP-131 to EP-180: engine.py
# ===========================================================================


def test_EP_131_health_returns_health_response(svc):
    h = svc.health()
    assert isinstance(h, HealthResponse)
    assert h.status == "ok"


def test_EP_132_get_health_response_top_level():
    h = get_health_response()
    assert h.schema_version == "1.0"


def test_EP_133_dashboard_returns_response(svc):
    d = svc.get_dashboard()
    assert isinstance(d, DashboardResponse)
    assert d.tenant_id == _TENANT


def test_EP_134_dashboard_defaults_when_no_reports(svc):
    d = svc.get_dashboard()
    assert d.latest_report_id is None
    assert d.evidence_collected == 0


def test_EP_135_get_timeline_empty(svc):
    r = svc.get_timeline()
    assert isinstance(r, TimelineResponse)
    assert r.items == []


def test_EP_136_get_evidence_workspace_empty(svc):
    r = svc.get_evidence_workspace()
    assert isinstance(r, EvidenceWorkspaceResponse)
    assert r.items == []


def test_EP_137_get_report_workspace_empty(svc):
    r = svc.get_report_workspace()
    assert isinstance(r, ReportWorkspaceResponse)
    assert r.items == []


def test_EP_138_get_remediation_workspace_empty(svc):
    r = svc.get_remediation_workspace()
    assert isinstance(r, RemediationWorkspaceResponse)


def test_EP_139_get_trust_workspace_safe_defaults(svc):
    r = svc.get_trust_workspace()
    assert isinstance(r, TrustWorkspaceResponse)
    assert r.verified is False
    assert r.history_count == 0


def test_EP_140_get_transparency_workspace_safe_defaults(svc):
    r = svc.get_transparency_workspace()
    assert isinstance(r, TransparencyWorkspaceResponse)
    assert r.append_only_confirmed is True
    assert r.sequence_count == 0


def test_EP_141_get_activity_feed_empty(svc):
    r = svc.get_activity_feed()
    assert isinstance(r, ActivityFeedResponse)
    assert r.items == []


def test_EP_142_get_statistics(svc):
    r = svc.get_statistics()
    assert isinstance(r, PortalStatisticsResponse)
    assert r.tenant_id == _TENANT
    assert r.total_activities >= 0


def test_EP_143_search_empty_returns_zero(svc):
    r = svc.search("no-match-zzz-xyz")
    assert isinstance(r, SearchResponse)
    assert r.total == 0
    assert r.items == []


def test_EP_144_get_notifications_empty(svc):
    r = svc.get_notifications()
    assert isinstance(r, NotificationListResponse)
    assert r.items == []


def test_EP_145_get_preferences_defaults_when_missing(svc):
    r = svc.get_preferences()
    assert r.tenant_id == _TENANT
    assert r.notification_email is True
    assert r.theme is None


def test_EP_146_update_preferences(svc):
    out = svc.update_preferences(
        UpdatePreferencesRequest(
            theme="dark", notification_email=False, timezone="UTC", language="en"
        )
    )
    assert out.theme == "dark"
    assert out.notification_email is False


def test_EP_147_record_activity_inserts_row(svc, db):
    svc.record_activity("dashboard_viewed", workspace="dashboard")
    db.commit()
    items, total = list_activities(db, tenant_id=_TENANT)
    assert total >= 1


def test_EP_148_record_activity_empty_event_rejected(svc):
    with pytest.raises(PortalAccessDenied):
        svc.record_activity("")


def test_EP_149_engine_requires_tenant_id():
    with pytest.raises(PortalAccessDenied):
        EngagementPortalEngine(db=None, tenant_id="")  # type: ignore[arg-type]


def test_EP_150_engine_tenant_isolation(svc, svc_b, db):
    svc.record_activity("dashboard_viewed")
    db.commit()
    items_a, _ = list_activities(db, tenant_id=_TENANT)
    items_b, _ = list_activities(db, tenant_id=_TENANT_B)
    assert any(i.event_type == "dashboard_viewed" for i in items_a)
    assert not any(i.event_type == "dashboard_viewed" for i in items_b)


def test_EP_151_dashboard_with_assessment_id(svc):
    d = svc.get_dashboard(assessment_id="assess-001")
    assert d.engagement_id == "assess-001"


@pytest.mark.parametrize("limit,offset", [(10, 0), (50, 0), (100, 10), (1, 5)])
def test_EP_152_paginated_workspaces(svc, limit, offset):
    r = svc.get_report_workspace(limit=limit, offset=offset)
    assert r.limit == limit
    assert r.offset == offset


def test_EP_153_search_with_short_query_via_engine(svc):
    r = svc.search("x")
    assert r.query == "x"


def test_EP_154_search_records_took_ms(svc):
    r = svc.search("hello")
    assert r.took_ms is not None
    assert r.took_ms >= 0


def test_EP_155_statistics_computed_at_set(svc):
    r = svc.get_statistics()
    assert r.computed_at != ""


def test_EP_156_dashboard_generated_at_set(svc):
    d = svc.get_dashboard()
    assert d.generated_at != ""


def test_EP_157_preferences_persisted_after_update(svc):
    svc.update_preferences(
        UpdatePreferencesRequest(
            theme="dark", notification_email=True, timezone=None, language=None
        )
    )
    r = svc.get_preferences()
    assert r.theme == "dark"


def test_EP_158_preferences_double_update(svc):
    svc.update_preferences(
        UpdatePreferencesRequest(
            theme="dark", notification_email=True, timezone=None, language=None
        )
    )
    svc.update_preferences(
        UpdatePreferencesRequest(
            theme="light", notification_email=False, timezone=None, language=None
        )
    )
    r = svc.get_preferences()
    assert r.theme == "light"
    assert r.notification_email is False


def test_EP_159_activity_feed_after_inserts(svc, db):
    svc.record_activity("dashboard_viewed")
    svc.record_activity("report_viewed")
    db.commit()
    r = svc.get_activity_feed()
    assert r.total >= 2


def test_EP_160_activity_feed_workspace_filter(svc, db):
    svc.record_activity("report_viewed", workspace="reports")
    db.commit()
    r = svc.get_activity_feed(workspace="reports")
    assert all(it.workspace == "reports" for it in r.items)


@pytest.mark.parametrize(
    "method_name",
    [
        "get_dashboard",
        "get_timeline",
        "get_evidence_workspace",
        "get_report_workspace",
        "get_remediation_workspace",
        "get_trust_workspace",
        "get_transparency_workspace",
        "get_activity_feed",
        "get_statistics",
        "get_notifications",
        "get_preferences",
    ],
)
def test_EP_161_engine_methods_callable(svc, method_name):
    getattr(svc, method_name)()


def test_EP_162_search_with_match_returns_zero_when_no_reports(svc):
    r = svc.search("anything")
    assert r.total == 0


def test_EP_163_search_response_shape(svc):
    r = svc.search("anything")
    assert hasattr(r, "items")
    assert hasattr(r, "query")
    assert hasattr(r, "total")
    assert hasattr(r, "took_ms")


def test_EP_164_record_activity_with_summary(svc, db):
    svc.record_activity(
        "report_viewed",
        workspace="reports",
        entity_id="r-1",
        actor_id="a-1",
        summary="viewed report",
    )
    db.commit()
    items, _ = list_activities(db, tenant_id=_TENANT)
    assert any(i.summary == "viewed report" for i in items)


# ===========================================================================
# EP-181 to EP-220: validators.py + statistics
# ===========================================================================


@pytest.mark.parametrize("tid", ["", "   ", "\t"])
def test_EP_181_validate_tenant_id_rejects_empty(tid):
    with pytest.raises(PortalAccessDenied):
        validate_tenant_id(tid)


@pytest.mark.parametrize("tid", ["t1", "tenant-x", "abc-123"])
def test_EP_182_validate_tenant_id_accepts_valid(tid):
    validate_tenant_id(tid)  # should not raise


@pytest.mark.parametrize("query", ["", "   "])
def test_EP_183_validate_search_query_rejects_empty(query):
    with pytest.raises(PortalSearchError):
        validate_search_query(query)


def test_EP_184_validate_search_query_too_long():
    with pytest.raises(PortalSearchError):
        validate_search_query("x" * 513)


@pytest.mark.parametrize("limit", [0, -1, 501, 1000])
def test_EP_185_validate_limit_offset_rejects_bad_limit(limit):
    with pytest.raises(PortalSearchError):
        validate_limit_offset(limit, 0)


def test_EP_186_validate_limit_offset_rejects_negative_offset():
    with pytest.raises(PortalSearchError):
        validate_limit_offset(50, -1)


@pytest.mark.parametrize("limit,offset", [(1, 0), (50, 0), (500, 1000)])
def test_EP_187_validate_limit_offset_accepts_valid(limit, offset):
    validate_limit_offset(limit, offset)


def test_EP_188_statistics_zero_initial(db):
    s = compute_portal_statistics(db, tenant_id="t-stats-empty")
    assert s["total_activities"] == 0
    assert s["preferences_set"] is False


def test_EP_189_statistics_after_inserts(db):
    insert_activity(db, tenant_id=_TENANT, event_type="report_viewed")
    insert_activity(db, tenant_id=_TENANT, event_type="evidence_viewed")
    insert_activity(db, tenant_id=_TENANT, event_type="search_performed")
    s = compute_portal_statistics(db, tenant_id=_TENANT)
    assert s["total_activities"] >= 3
    assert s["total_reports_viewed"] >= 1
    assert s["total_evidence_viewed"] >= 1
    assert s["total_searches"] >= 1


def test_EP_190_statistics_preferences_set(db):
    upsert_preferences(
        db,
        tenant_id="t-pref-stats",
        theme="dark",
        notification_email=True,
        timezone=None,
        language=None,
    )
    s = compute_portal_statistics(db, tenant_id="t-pref-stats")
    assert s["preferences_set"] is True


def test_EP_191_statistics_active_notifications_count(db):
    insert_notification(db, tenant_id="t-notif-stats", notification_type="x")
    s = compute_portal_statistics(db, tenant_id="t-notif-stats")
    assert s["active_notifications"] >= 1


@pytest.mark.parametrize("limit", [1, 50, 100, 500])
def test_EP_192_valid_limits(limit):
    validate_limit_offset(limit, 0)


@pytest.mark.parametrize("offset", [0, 1, 100, 1000])
def test_EP_193_valid_offsets(offset):
    validate_limit_offset(50, offset)


def test_EP_194_search_query_strip_check():
    with pytest.raises(PortalSearchError):
        validate_search_query("    ")


def test_EP_195_search_query_normal():
    validate_search_query("a")


def test_EP_196_search_query_max_boundary():
    validate_search_query("x" * 512)


@pytest.mark.parametrize(
    "fn,args",
    [
        (validate_tenant_id, ("",)),
        (validate_search_query, ("",)),
        (validate_limit_offset, (-1, 0)),
        (validate_limit_offset, (50, -5)),
    ],
)
def test_EP_197_validator_failure_modes(fn, args):
    with pytest.raises(Exception):
        fn(*args)


def test_EP_198_dashboard_zero_defaults_when_no_data(svc):
    d = svc.get_dashboard()
    assert d.evidence_collected == 0
    assert d.evidence_verified == 0
    assert d.open_findings == 0
    assert d.pending_approvals == 0


def test_EP_199_engine_record_activity_idempotent(svc, db):
    svc.record_activity("dashboard_viewed")
    svc.record_activity("dashboard_viewed")
    db.commit()
    n = count_activities(db, tenant_id=_TENANT, event_type="dashboard_viewed")
    assert n >= 2


def test_EP_200_engine_search_query_must_be_non_empty(svc):
    with pytest.raises(PortalSearchError):
        svc.search("")
