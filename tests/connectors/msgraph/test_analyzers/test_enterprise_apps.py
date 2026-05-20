"""Tests for Enterprise App / Service Principal Analyzer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .conftest import TENANT_ID, make_client
from services.connectors.msgraph.analyzers import enterprise_apps


def _app(aid: str, *, days_old: int = 10) -> dict:
    created = (datetime.now(timezone.utc) - timedelta(days=days_old)).isoformat()
    return {
        "id": aid,
        "displayName": f"App {aid}",
        "createdDateTime": created,
        "requiredResourceAccess": [],
    }


def _sp(
    sid: str,
    *,
    enabled: bool = True,
    verified: bool = True,
    days_inactive: int | None = None,
) -> dict:
    vp = {"verifiedPublisherId": "pub123"} if verified else {}
    last_signin = None
    if days_inactive is not None:
        last_signin = (
            datetime.now(timezone.utc) - timedelta(days=days_inactive)
        ).isoformat()
    return {
        "id": sid,
        "appId": f"app-{sid}",
        "accountEnabled": enabled,
        "verifiedPublisher": vp,
        "signInActivity": {"lastSignInDateTime": last_signin} if last_signin else None,
    }


def test_new_app_30d_counted():
    apps = [_app("a1", days_old=10)]
    client = make_client(
        {
            "/applications": apps,
            "/servicePrincipals": [],
            "/oauth2PermissionGrants": [],
        }
    )
    result, findings, _ = enterprise_apps.run(client, TENANT_ID)
    assert result.new_apps_30d == 1
    assert any("30" in f.evidence_summary for f in findings)


def test_stale_sp_90d_counted():
    sps = [_sp("sp1", days_inactive=100)]
    client = make_client(
        {
            "/applications": [],
            "/servicePrincipals": sps,
            "/oauth2PermissionGrants": [],
        }
    )
    result, findings, _ = enterprise_apps.run(client, TENANT_ID)
    assert result.stale_apps_90d == 1


def test_user_consented_grant_counted():
    grants = [{"consentType": "Principal", "clientId": "c1", "scope": "Mail.Read"}]
    client = make_client(
        {
            "/applications": [],
            "/servicePrincipals": [],
            "/oauth2PermissionGrants": grants,
        }
    )
    result, _, _ = enterprise_apps.run(client, TENANT_ID)
    assert result.user_consented_sensitive == 1


def test_inventory_finding_always_present():
    client = make_client(
        {
            "/applications": [],
            "/servicePrincipals": [],
            "/oauth2PermissionGrants": [],
        }
    )
    _, findings, _ = enterprise_apps.run(client, TENANT_ID)
    assert any(
        "inventory" in f.finding_id
        or "service principals" in f.evidence_summary.lower()
        for f in findings
    )
