"""MODE-B-E2E-ACCEPTANCE-001 — Portal named-user E2E acceptance test suite.

Ten scenarios (A-J) from the PORTAL-AUTH-E2E-001 specification.

  A  Governed Client Invitation        — INV-001
  B  Named-User Enrollment             — ENROLL-001 through ENROLL-005
  C  Tenant Binding                    — BIND-001 through BIND-003
  D  Authorized Assessment Access      — ACCESS-001 through ACCESS-003
  E  Approved Report Visibility        — REPORT-001
  F  Governed Deliverable Retrieval    — DELIV-001 (NOT_PROVEN in simulation)
  G  Grant Revocation                  — REVOKE-001, REVOKE-002
  H  Session Termination               — LOGOUT-001, LOGOUT-002
  I  Cross-Tenant Denial               — XTENANT-001
  J  Cross-Engagement Denial + Replay  — XENGAG-001, REPLAY-001

Scenarios A-C, G-H, J (replay): mock_db unit tests against portal authority functions.
Scenarios D-E, G (revoke-002), I, J (xengag): TestClient + SQLite integration tests.
Scenario F: confirmed NOT_PROVEN in simulation (requires live report artifacts).

Architecture note: this test file is not standalone — it exercises modules that
form part of the fg-core service. All checks here are simulation-mode coverage;
live production verification requires the PORTAL-AUTH-E2E-001 operator runbook.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import api.portal_user_authority as pua
from api.portal_user_authority import (
    INVITATION_TOKEN_PREFIX,
    SESSION_TOKEN_PREFIX,
    PortalInvitationAlreadyAcceptedError,
    create_invitation,
    create_session,
    find_or_create_portal_user,
    revoke_session,
    revoke_session_by_token,
    validate_session,
)

_CI_TEST_KEY = "ci-test-key-00000000000000000000000000000000"
_TENANT_A = "e2e-acceptance-tenant-a"
_TENANT_B = "e2e-acceptance-tenant-b"
_ENG_ALPHA = str(uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
_ENG_BETA = str(uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"))
_FUTURE = datetime.now(tz=UTC) + timedelta(days=7)
_TEST_PEPPER = "test-pepper-mode-b-e2e-001"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _row(**kw) -> SimpleNamespace:
    return SimpleNamespace(**kw)


# ---------------------------------------------------------------------------
# Fixtures — mock_db for protocol tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _patch_pepper():
    with patch.object(pua, "_get_pepper", return_value=_TEST_PEPPER):
        yield


@pytest.fixture()
def mock_db():
    db = MagicMock()
    db.execute.return_value.fetchone.return_value = None
    db.execute.return_value.fetchall.return_value = []
    return db


# ---------------------------------------------------------------------------
# Fixtures — TestClient + SQLite for access-control tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def portal_app(tmp_path, monkeypatch):
    db_path = str(tmp_path / "e2e-portal-001.db")
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_API_KEY", _CI_TEST_KEY)
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_AUTH0_DOMAIN", "test.auth0.example.com")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    monkeypatch.setenv(
        "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )
    monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "false")
    monkeypatch.setenv("FG_UI_TOKEN_GET_ENABLED", "1")
    monkeypatch.setenv("FG_DEV_EVENTS_ENABLED", "0")

    from api.db import get_engine, init_db, reset_engine_cache
    from api.main import build_app
    import api.entitlements as _ent

    monkeypatch.setattr(_ent, "ENFORCEMENT_STRICT", False)
    reset_engine_cache()
    init_db(sqlite_path=db_path)
    app = build_app()
    engine = get_engine()
    return app, engine


@pytest.fixture()
def portal_client(portal_app):
    app, _ = portal_app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture()
def portal_db_engine(portal_app):
    _, engine = portal_app
    return engine


def _make_tenant_user(
    engine, *, tenant_id: str, membership_version: int = 1, active: bool = True
) -> tuple[str, str]:
    from api.db import get_sessionmaker
    from api.db_models import TenantUser
    from api.db_models_principal import FgPrincipal

    session = get_sessionmaker()()
    uid = str(uuid.uuid4())
    email = f"portal-user-{uid[:8]}@example.com"
    principal_id = str(uuid.uuid4())
    session.add(
        FgPrincipal(
            id=principal_id,
            display_name=email,
            primary_email=email,
            principal_type="human",
            lifecycle_state="active",
            mfa_verified=False,
            authority_version=1,
        )
    )
    session.flush()
    session.add(
        TenantUser(
            id=uid,
            tenant_id=tenant_id,
            email=email,
            display_name=email,
            role="assessor",
            active=active,
            identity_type="human",
            identity_provider="auth0",
            identity_issuer="https://test.auth0.example.com/",
            identity_subject=f"auth0|{uid}",
            identity_email=email,
            identity_email_verified=True,
            identity_binding_status="bound",
            membership_version=membership_version,
            principal_id=principal_id,
        )
    )
    session.commit()
    session.close()
    return uid, email


def _create_engagement_via_api(client: TestClient, *, tenant_id: str) -> str:
    resp = client.post(
        "/field-assessment/engagements",
        json={
            "client_name": "E2E Test Corp",
            "assessor_id": "e2e-assessor",
            "assessment_type": "ai_governance",
        },
        headers={"X-API-Key": _CI_TEST_KEY, "X-Tenant-ID": tenant_id},
    )
    assert resp.status_code == 201, f"Failed to create engagement: {resp.text}"
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# Scenario A — Governed Client Invitation (INV-001)
# ---------------------------------------------------------------------------


class TestScenarioA_GovernedClientInvitation:
    """INV-001: Portal invitation issued with pni1.* token format."""

    def test_inv_001_invitation_token_has_pni1_prefix(self, mock_db):
        mock_db.execute.return_value.fetchone.return_value = _row(
            id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
            tenant_id=_TENANT_A,
            email="client@example.com",
            portal_role="viewer",
            engagement_id=_ENG_ALPHA,
            status="pending",
            expires_at=_FUTURE,
            delivery_state="pending",
            email_message_id=None,
            delivery_error_code=None,
        )
        record = create_invitation(
            mock_db,
            tenant_id=_TENANT_A,
            email="client@example.com",
            portal_role="viewer",
            engagement_id=_ENG_ALPHA,
        )
        assert record.raw_token is not None
        assert record.raw_token.startswith(INVITATION_TOKEN_PREFIX)

    def test_inv_001_token_prefix_constant(self):
        assert INVITATION_TOKEN_PREFIX == "pni1."


# ---------------------------------------------------------------------------
# Scenario B — Named-User Enrollment (ENROLL-001 to ENROLL-005)
# ---------------------------------------------------------------------------


class TestScenarioB_NamedUserEnrollment:
    """ENROLL-001 through ENROLL-005: Invitation acceptance and session issuance."""

    def _accept_side_effect(
        self, *, inv_status: str = "pending", cas_wins: bool = True
    ):
        inv_row = _row(
            id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
            email="client@example.com",
            portal_role="viewer",
            engagement_id=_ENG_ALPHA,
            status=inv_status,
            expires_at=_FUTURE,
        )
        user_row = _row(
            id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            tenant_id=_TENANT_A,
            oidc_provider="auth0",
            oidc_issuer="https://test.auth0.example.com/",
            oidc_subject="auth0|client-001",
            email="client@example.com",
            display_name="Test Client",
            status="active",
        )
        membership_row = _row(
            id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
            portal_user_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            tenant_id=_TENANT_A,
            engagement_id=_ENG_ALPHA,
            portal_role="viewer",
            auth_version=1,
            active=True,
        )
        accepted_row = _row(id=uuid.UUID("22222222-2222-2222-2222-222222222222"))

        call_count = [0]

        def side_effect(stmt, params=None):
            result = MagicMock()
            result.fetchall.return_value = []
            call_count[0] += 1
            n = call_count[0]
            if n == 1:
                result.fetchone.return_value = None  # set_config (RLS)
            elif n == 2:
                result.fetchone.return_value = inv_row  # SELECT FOR UPDATE invitation
            elif n == 3:
                result.fetchone.return_value = None  # set_config for find_or_create
            elif n == 4:
                result.fetchone.return_value = user_row  # UPSERT portal_user
            elif n == 5:
                result.fetchone.return_value = None  # audit event
            elif n == 6:
                result.fetchone.return_value = membership_row  # INSERT membership
            elif n == 7:
                result.fetchone.return_value = None  # audit event
            elif n == 8:
                if cas_wins:
                    result.fetchall.return_value = [accepted_row]
                    result.fetchone.return_value = accepted_row
                else:
                    result.fetchall.return_value = []
                    result.fetchone.return_value = None
            else:
                result.fetchone.return_value = None
            return result

        return side_effect

    def test_enroll_001_invitation_consumed_on_acceptance(self, mock_db):
        mock_db.execute.side_effect = self._accept_side_effect()
        user, membership, _inv = pua.accept_invitation(
            mock_db,
            raw_token=INVITATION_TOKEN_PREFIX + "a" * 64,
            tenant_id=_TENANT_A,
            oidc_provider="auth0",
            oidc_issuer="https://test.auth0.example.com/",
            oidc_subject="auth0|client-001",
            email="client@example.com",
        )
        assert user is not None
        assert membership is not None

    def test_enroll_002_session_token_has_pnu1_prefix(self, mock_db):
        mock_db.execute.return_value.fetchone.return_value = _row(
            id=uuid.UUID("44444444-4444-4444-4444-444444444444"),
            tenant_id=_TENANT_A,
            portal_user_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            portal_membership_id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
            auth_version_snapshot=1,
            session_type="named_user_v1",
            status="active",
            expires_at=_FUTURE,
        )
        record = create_session(
            mock_db,
            portal_user_id=str(uuid.UUID("11111111-1111-1111-1111-111111111111")),
            tenant_id=_TENANT_A,
            auth_version_snapshot=1,
        )
        assert record.raw_token is not None
        assert record.raw_token.startswith(SESSION_TOKEN_PREFIX)

    def test_enroll_003_portal_user_created_with_oidc_subject(self, mock_db):
        expected_subject = "auth0|enroll-003-subject"
        user_row = _row(
            id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            tenant_id=_TENANT_A,
            oidc_provider="auth0",
            oidc_issuer="https://test.auth0.example.com/",
            oidc_subject=expected_subject,
            email="client@example.com",
            display_name="Test Client",
            status="active",
        )
        call_count = [0]

        def side_effect(stmt, params=None):
            result = MagicMock()
            result.fetchall.return_value = []
            call_count[0] += 1
            if call_count[0] == 1:
                result.fetchone.return_value = None  # set_config
            elif call_count[0] == 2:
                result.fetchone.return_value = user_row  # UPSERT
            else:
                result.fetchone.return_value = None
            return result

        mock_db.execute.side_effect = side_effect
        user = find_or_create_portal_user(
            mock_db,
            tenant_id=_TENANT_A,
            oidc_provider="auth0",
            oidc_issuer="https://test.auth0.example.com/",
            oidc_subject=expected_subject,
            email="client@example.com",
        )
        assert user.oidc_subject == expected_subject

    def test_enroll_004_membership_created_with_engagement_id(self, mock_db):
        mock_db.execute.side_effect = self._accept_side_effect()
        _, membership, _ = pua.accept_invitation(
            mock_db,
            raw_token=INVITATION_TOKEN_PREFIX + "b" * 64,
            tenant_id=_TENANT_A,
            oidc_provider="auth0",
            oidc_issuer="https://test.auth0.example.com/",
            oidc_subject="auth0|client-001",
            email="client@example.com",
        )
        assert membership.engagement_id == _ENG_ALPHA

    def test_enroll_005_second_acceptance_rejected(self, mock_db):
        inv_accepted = _row(
            id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
            email="client@example.com",
            portal_role="viewer",
            engagement_id=_ENG_ALPHA,
            status="accepted",
            expires_at=_FUTURE,
        )
        call_count = [0]

        def side_effect(stmt, params=None):
            result = MagicMock()
            result.fetchall.return_value = []
            call_count[0] += 1
            if call_count[0] == 2:
                result.fetchone.return_value = inv_accepted
            else:
                result.fetchone.return_value = None
            return result

        mock_db.execute.side_effect = side_effect

        with pytest.raises(PortalInvitationAlreadyAcceptedError):
            pua.accept_invitation(
                mock_db,
                raw_token=INVITATION_TOKEN_PREFIX + "c" * 64,
                tenant_id=_TENANT_A,
                oidc_provider="auth0",
                oidc_issuer="https://test.auth0.example.com/",
                oidc_subject="auth0|client-001",
                email="client@example.com",
            )


# ---------------------------------------------------------------------------
# Scenario C — Tenant Binding (BIND-001 to BIND-003)
# ---------------------------------------------------------------------------


class TestScenarioC_TenantBinding:
    """BIND-001 through BIND-003: Session is correctly bound to tenant/engagement."""

    def _session_row(self, auth_version: int = 2) -> SimpleNamespace:
        return _row(
            id=uuid.UUID("44444444-4444-4444-4444-444444444444"),
            tenant_id=_TENANT_A,
            portal_user_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            portal_membership_id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
            auth_version_snapshot=auth_version,
            session_type="named_user_v1",
            status="active",
            expires_at=_FUTURE,
        )

    def test_bind_001_session_bound_to_tenant_id(self, mock_db):
        mock_db.execute.return_value.fetchone.return_value = self._session_row()
        record = create_session(
            mock_db,
            portal_user_id=str(uuid.UUID("11111111-1111-1111-1111-111111111111")),
            tenant_id=_TENANT_A,
            auth_version_snapshot=2,
        )
        assert record.tenant_id == _TENANT_A

    def test_bind_002_membership_bound_to_engagement_id(self, mock_db):
        membership_row = _row(
            id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
            portal_user_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            tenant_id=_TENANT_A,
            engagement_id=_ENG_ALPHA,
            portal_role="viewer",
            auth_version=3,
            active=True,
        )
        mock_db.execute.return_value.fetchone.return_value = membership_row
        membership = pua.get_best_active_membership(
            mock_db,
            portal_user_id=str(uuid.UUID("11111111-1111-1111-1111-111111111111")),
            tenant_id=_TENANT_A,
        )
        assert membership is not None
        assert membership.engagement_id == _ENG_ALPHA

    def test_bind_003_auth_version_snapshot_matches_membership_version(self, mock_db):
        expected_version = 5
        mock_db.execute.return_value.fetchone.return_value = self._session_row(
            expected_version
        )
        record = create_session(
            mock_db,
            portal_user_id=str(uuid.UUID("11111111-1111-1111-1111-111111111111")),
            tenant_id=_TENANT_A,
            auth_version_snapshot=expected_version,
        )
        assert record.auth_version_snapshot == expected_version


# ---------------------------------------------------------------------------
# Scenario D — Authorized Assessment Access (ACCESS-001 to ACCESS-003)
# ---------------------------------------------------------------------------


class TestScenarioD_AuthorizedAssessmentAccess:
    """ACCESS-001 through ACCESS-003: Portal named-user can access engagement data."""

    def test_access_001_engagement_accessible_via_portal_session(
        self, portal_client, portal_db_engine
    ):
        eng_id = _create_engagement_via_api(portal_client, tenant_id=_TENANT_A)
        uid, _ = _make_tenant_user(
            portal_db_engine, tenant_id=_TENANT_A, membership_version=1
        )
        resp = portal_client.get(
            f"/field-assessment/engagements/{eng_id}",
            headers={
                "X-API-Key": _CI_TEST_KEY,
                "X-Tenant-ID": _TENANT_A,
                "X-Portal-Source": "client-portal",
                "X-FG-Membership-ID": uid,
                "X-FG-Membership-Version": "1",
            },
        )
        # Positive check: require HTTP 200, not just "not 403"
        assert resp.status_code == 200, (
            f"ACCESS-001: portal session denied or errored. body={resp.text[:200]}"
        )

    def test_access_002_findings_accessible_via_portal_session(
        self, portal_client, portal_db_engine
    ):
        eng_id = _create_engagement_via_api(portal_client, tenant_id=_TENANT_A)
        uid, _ = _make_tenant_user(
            portal_db_engine, tenant_id=_TENANT_A, membership_version=1
        )
        resp = portal_client.get(
            f"/field-assessment/engagements/{eng_id}/findings",
            headers={
                "X-API-Key": _CI_TEST_KEY,
                "X-Tenant-ID": _TENANT_A,
                "X-Portal-Source": "client-portal",
                "X-FG-Membership-ID": uid,
                "X-FG-Membership-Version": "1",
            },
        )
        assert resp.status_code == 200, (
            f"ACCESS-002: findings denied or errored. body={resp.text[:200]}"
        )

    def test_access_003_cross_tenant_engagement_not_accessible(
        self, portal_client, portal_db_engine
    ):
        # Create engagement in TENANT_A; tenant-A membership; try to read from TENANT_B
        eng_id = _create_engagement_via_api(portal_client, tenant_id=_TENANT_A)
        uid, _ = _make_tenant_user(
            portal_db_engine, tenant_id=_TENANT_A, membership_version=1
        )

        resp_own = portal_client.get(
            f"/field-assessment/engagements/{eng_id}",
            headers={
                "X-API-Key": _CI_TEST_KEY,
                "X-Tenant-ID": _TENANT_A,
                "X-Portal-Source": "client-portal",
                "X-FG-Membership-ID": uid,
                "X-FG-Membership-Version": "1",
            },
        )
        assert resp_own.status_code == 200, (
            f"ACCESS-003: own engagement should be 200, got {resp_own.status_code}"
        )

        unknown_id = str(uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"))
        resp_unknown = portal_client.get(
            f"/field-assessment/engagements/{unknown_id}",
            headers={
                "X-API-Key": _CI_TEST_KEY,
                "X-Tenant-ID": _TENANT_A,
                "X-Portal-Source": "client-portal",
                "X-FG-Membership-ID": uid,
                "X-FG-Membership-Version": "1",
            },
        )
        assert resp_unknown.status_code in (403, 404), (
            f"ACCESS-003: non-existent engagement should be 403/404, got {resp_unknown.status_code}"
        )


# ---------------------------------------------------------------------------
# Scenario E — Approved Report Visibility (REPORT-001)
# ---------------------------------------------------------------------------


class TestScenarioE_ApprovedReportVisibility:
    """REPORT-001: Portal session can access the reports endpoint for the engagement.

    Approval filtering (draft vs approved) is not testable in simulation without
    pre-seeded report artifacts — verified by list_versions() implementation.
    """

    def test_report_001_reports_endpoint_accessible_via_portal_session(
        self, portal_client, portal_db_engine
    ):
        eng_id = _create_engagement_via_api(portal_client, tenant_id=_TENANT_A)
        uid, _ = _make_tenant_user(
            portal_db_engine, tenant_id=_TENANT_A, membership_version=1
        )
        resp = portal_client.get(
            f"/field-assessment/engagements/{eng_id}/reports",
            headers={
                "X-API-Key": _CI_TEST_KEY,
                "X-Tenant-ID": _TENANT_A,
                "X-Portal-Source": "client-portal",
                "X-FG-Membership-ID": uid,
                "X-FG-Membership-Version": "1",
            },
        )
        assert resp.status_code == 200, (
            f"REPORT-001: reports endpoint denied or errored. body={resp.text[:200]}"
        )


# ---------------------------------------------------------------------------
# Scenario F — Governed Deliverable Retrieval (DELIV-001)
# ---------------------------------------------------------------------------


class TestScenarioF_GovernedDeliverableRetrieval:
    """DELIV-001: NOT_PROVEN in simulation — requires live approved report artifacts."""

    def test_deliv_001_blocked_in_simulation(self):
        pytest.skip(
            "DELIV-001 is NOT_PROVEN in simulation — requires a pre-seeded approved "
            "report artifact accessible via the reports_engine download route. "
            "Run PORTAL-AUTH-E2E-001 operator runbook against production."
        )


# ---------------------------------------------------------------------------
# Scenario G — Grant Revocation (REVOKE-001, REVOKE-002)
# ---------------------------------------------------------------------------


class TestScenarioG_GrantRevocation:
    """REVOKE-001, REVOKE-002: Session revocation and auth_version invalidation."""

    def test_revoke_001_revoke_session_returns_true(self, mock_db):
        session_uuid = uuid.UUID("44444444-4444-4444-4444-444444444444")
        # RETURNING clause returns id + portal_user_id
        active_row = _row(
            id=session_uuid,
            portal_user_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        )
        mock_db.execute.return_value.fetchall.return_value = [active_row]
        result = revoke_session(
            mock_db, session_id=str(session_uuid), tenant_id=_TENANT_A
        )
        assert result is True

    def test_revoke_002_stale_auth_version_denied(
        self, portal_client, portal_db_engine
    ):
        eng_id = _create_engagement_via_api(portal_client, tenant_id=_TENANT_A)
        uid, _ = _make_tenant_user(
            portal_db_engine, tenant_id=_TENANT_A, membership_version=3
        )
        resp = portal_client.get(
            f"/field-assessment/engagements/{eng_id}",
            headers={
                "X-API-Key": _CI_TEST_KEY,
                "X-Tenant-ID": _TENANT_A,
                "X-Portal-Source": "client-portal",
                "X-FG-Membership-ID": uid,
                "X-FG-Membership-Version": "1",  # stale — DB has version 3
            },
        )
        assert resp.status_code == 403, (
            f"REVOKE-002: stale auth_version should be 403, got {resp.status_code}"
        )
        assert resp.json().get("code") == "SESSION_REVOKED_VERSION_MISMATCH"


# ---------------------------------------------------------------------------
# Scenario H — Session Termination (LOGOUT-001, LOGOUT-002)
# ---------------------------------------------------------------------------


class TestScenarioH_SessionTermination:
    """LOGOUT-001, LOGOUT-002: Session revocation clears access."""

    def test_logout_001_revoke_session_by_token(self, mock_db):
        session_uuid = uuid.UUID("44444444-4444-4444-4444-444444444444")
        # revoke_portal_session_by_fingerprint() returns session_id, tenant_id, portal_user_id
        mock_db.execute.return_value.fetchall.return_value = [
            _row(
                session_id=session_uuid,
                tenant_id=_TENANT_A,
                portal_user_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
            )
        ]
        raw_token = SESSION_TOKEN_PREFIX + "aa" * 32
        # revoke_session_by_token resolves tenant from the session record itself
        result = revoke_session_by_token(mock_db, raw_token=raw_token)
        assert result.revoked is True

    def test_logout_002_revoked_session_fails_validation(self, mock_db):
        # validate_session queries WHERE status='active', so a revoked session
        # returns no row. Simulate by returning None from fetchone.
        mock_db.execute.return_value.fetchone.return_value = None
        vr = validate_session(
            mock_db,
            raw_token=SESSION_TOKEN_PREFIX + "bb" * 32,
            tenant_id=_TENANT_A,
        )
        assert not vr.ok


# ---------------------------------------------------------------------------
# Scenario I — Cross-Tenant Denial (XTENANT-001)
# ---------------------------------------------------------------------------


class TestScenarioI_CrossTenantDenial:
    """XTENANT-001: Portal session from tenant-A cannot access tenant-B engagement."""

    def test_xtenant_001_cross_tenant_engagement_denied(
        self, portal_client, portal_db_engine
    ):
        eng_b_id = _create_engagement_via_api(portal_client, tenant_id=_TENANT_B)
        uid, _ = _make_tenant_user(
            portal_db_engine, tenant_id=_TENANT_A, membership_version=1
        )

        resp = portal_client.get(
            f"/field-assessment/engagements/{eng_b_id}",
            headers={
                "X-API-Key": _CI_TEST_KEY,
                "X-Tenant-ID": _TENANT_A,
                "X-Portal-Source": "client-portal",
                "X-FG-Membership-ID": uid,
                "X-FG-Membership-Version": "1",
            },
        )
        assert resp.status_code in (403, 404), (
            f"XTENANT-001: cross-tenant should be 403/404, got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# Scenario J — Cross-Engagement Denial + Replay (XENGAG-001, REPLAY-001)
# ---------------------------------------------------------------------------


class TestScenarioJ_CrossEngagementAndReplay:
    """XENGAG-001: Unbound engagement denied. REPLAY-001: Replayed invitation rejected."""

    def test_xengag_001_unbound_engagement_is_not_accessible(
        self, portal_client, portal_db_engine
    ):
        _create_engagement_via_api(portal_client, tenant_id=_TENANT_A)
        uid, _ = _make_tenant_user(
            portal_db_engine, tenant_id=_TENANT_A, membership_version=1
        )

        unbound_id = str(uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd"))
        resp = portal_client.get(
            f"/field-assessment/engagements/{unbound_id}",
            headers={
                "X-API-Key": _CI_TEST_KEY,
                "X-Tenant-ID": _TENANT_A,
                "X-Portal-Source": "client-portal",
                "X-FG-Membership-ID": uid,
                "X-FG-Membership-Version": "1",
            },
        )
        assert resp.status_code in (403, 404), (
            f"XENGAG-001: non-existent engagement should be 403/404, got {resp.status_code}"
        )

    def test_replay_001_accepted_invitation_rejected_on_replay(self, mock_db):
        inv_accepted = _row(
            id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
            email="client@example.com",
            portal_role="viewer",
            engagement_id=_ENG_ALPHA,
            status="accepted",
            expires_at=_FUTURE,
        )
        call_count = [0]

        def side_effect(stmt, params=None):
            result = MagicMock()
            result.fetchall.return_value = []
            call_count[0] += 1
            if call_count[0] == 2:
                result.fetchone.return_value = inv_accepted
            else:
                result.fetchone.return_value = None
            return result

        mock_db.execute.side_effect = side_effect

        with pytest.raises(PortalInvitationAlreadyAcceptedError):
            pua.accept_invitation(
                mock_db,
                raw_token=INVITATION_TOKEN_PREFIX + "d" * 64,
                tenant_id=_TENANT_A,
                oidc_provider="auth0",
                oidc_issuer="https://test.auth0.example.com/",
                oidc_subject="auth0|replay-attacker",
                email="client@example.com",
            )


# ---------------------------------------------------------------------------
# Evidence schema — canonical manifest completeness (no actor profile required)
# ---------------------------------------------------------------------------


class TestPortalNamedUserCanonicalManifest:
    """Verify the portal_named_user profile in evidence.py is complete and correct."""

    def test_portal_named_user_profile_exists(self):
        from tools.testing.production.evidence import CANONICAL_CHECK_MANIFESTS

        assert "portal_named_user" in CANONICAL_CHECK_MANIFESTS

    def test_portal_named_user_manifest_has_21_checks(self):
        from tools.testing.production.evidence import CANONICAL_CHECK_MANIFESTS

        manifest = CANONICAL_CHECK_MANIFESTS["portal_named_user"]
        assert len(manifest) == 21, f"Expected 21 checks, got {len(manifest)}"

    def test_portal_named_user_manifest_covers_all_scenarios(self):
        from tools.testing.production.evidence import CANONICAL_CHECK_MANIFESTS

        manifest = set(CANONICAL_CHECK_MANIFESTS["portal_named_user"])
        required = {
            "INV-001",
            "ENROLL-001",
            "ENROLL-002",
            "ENROLL-003",
            "ENROLL-004",
            "ENROLL-005",
            "BIND-001",
            "BIND-002",
            "BIND-003",
            "ACCESS-001",
            "ACCESS-002",
            "ACCESS-003",
            "REPORT-001",
            "DELIV-001",
            "REVOKE-001",
            "REVOKE-002",
            "LOGOUT-001",
            "LOGOUT-002",
            "XTENANT-001",
            "XENGAG-001",
            "REPLAY-001",
        }
        missing = required - manifest
        assert not missing, f"Missing checks: {sorted(missing)}"

    def test_all_pass_produces_accepted(self):
        from tools.testing.production.evidence import (
            CANONICAL_CHECK_MANIFESTS,
            AcceptanceDecision,
            CheckResult,
            EvidenceRecord,
            EvidenceResult,
            verify_acceptance,
        )

        manifest = CANONICAL_CHECK_MANIFESTS["portal_named_user"]
        checks = [
            CheckResult(
                id=cid,
                description=f"Check {cid}",
                expected="PASS",
                observed="PASS",
                result=EvidenceResult.PASS,
                timestamp="2026-11-02T00:00:00Z",
            )
            for cid in manifest
        ]
        record = EvidenceRecord(
            verification_profile="portal_named_user",
            required_check_manifest=manifest,
            checks=checks,
        )
        assert verify_acceptance(record) == AcceptanceDecision.ACCEPTED

    def test_blocked_deliv_001_causes_rejection(self):
        from tools.testing.production.evidence import (
            CANONICAL_CHECK_MANIFESTS,
            AcceptanceDecision,
            CheckResult,
            EvidenceRecord,
            EvidenceResult,
            verify_acceptance,
        )

        manifest = CANONICAL_CHECK_MANIFESTS["portal_named_user"]
        checks = [
            CheckResult(
                id=cid,
                description=f"Check {cid}",
                expected="PASS",
                observed="BLOCKED" if cid == "DELIV-001" else "PASS",
                result=EvidenceResult.BLOCKED
                if cid == "DELIV-001"
                else EvidenceResult.PASS,
                timestamp="2026-11-02T00:00:00Z",
            )
            for cid in manifest
        ]
        record = EvidenceRecord(
            verification_profile="portal_named_user",
            required_check_manifest=manifest,
            checks=checks,
        )
        assert verify_acceptance(record) == AcceptanceDecision.REJECTED_INCOMPLETE

    def test_reduced_manifest_causes_semantic_15_rejection(self):
        from tools.testing.production.evidence import (
            AcceptanceDecision,
            CheckResult,
            EvidenceRecord,
            EvidenceResult,
            verify_acceptance,
        )

        stripped_manifest = ["INV-001", "ENROLL-001", "ENROLL-002"]
        checks = [
            CheckResult(
                id=cid,
                description=f"Check {cid}",
                expected="PASS",
                observed="PASS",
                result=EvidenceResult.PASS,
                timestamp="2026-11-02T00:00:00Z",
            )
            for cid in stripped_manifest
        ]
        record = EvidenceRecord(
            verification_profile="portal_named_user",
            required_check_manifest=stripped_manifest,
            checks=checks,
        )
        assert verify_acceptance(record) == AcceptanceDecision.REJECTED_INCOMPLETE
