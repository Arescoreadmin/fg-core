"""Tests for OAuth Consent Analyzer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from .conftest import TENANT_ID
from services.connectors.msgraph.analyzers import oauth_consent


def _grant(
    *,
    consent: str = "Principal",
    scope: str = "Mail.Read offline_access",
    days_old: int = 10,
    client_id: str = "c1",
) -> dict:
    start = (datetime.now(timezone.utc) - timedelta(days=days_old)).isoformat()
    return {
        "clientId": client_id,
        "consentType": consent,
        "scope": scope,
        "startTime": start,
    }


def _sp(verified: bool = True) -> dict:
    vp = {"verifiedPublisherId": "pub1"} if verified else {}
    return {"id": "c1", "appId": "app1", "verifiedPublisher": vp}


def test_score_3_grant_triggers_critical():
    # score 3: unverified + offline_access + data scope
    grants = [_grant(scope="Mail.Read offline_access")]
    client = MagicMock()
    client.get_all.return_value = grants
    client.get_one.return_value = _sp(verified=False)

    result, findings, _ = oauth_consent.run(client, TENANT_ID)
    assert result.score_3_critical == 1
    assert any(f.severity == "critical" for f in findings)


def test_score_2_grant_triggers_high():
    # score 2: unverified + offline_access, no data scope
    grants = [_grant(scope="offline_access openid")]
    client = MagicMock()
    client.get_all.return_value = grants
    client.get_one.return_value = _sp(verified=False)

    result, findings, _ = oauth_consent.run(client, TENANT_ID)
    assert result.score_2_high == 1
    assert any(f.severity == "high" for f in findings)


def test_stale_grant_180d_triggers_finding():
    grants = [_grant(days_old=200)]
    client = MagicMock()
    client.get_all.return_value = grants
    client.get_one.return_value = _sp(verified=True)

    result, findings, _ = oauth_consent.run(client, TENANT_ID)
    assert result.stale_grants_180d == 1
    assert any("180" in f.evidence_summary for f in findings)


def test_admin_unverified_data_triggers_oauth_003():
    grants = [_grant(consent="AllPrincipals", scope="Mail.Read offline_access")]
    client = MagicMock()
    client.get_all.return_value = grants
    client.get_one.return_value = _sp(verified=False)

    _, findings, _ = oauth_consent.run(client, TENANT_ID)
    # OAUTH_003 is admin-consented unverified with data scope
    titles = [f.title for f in findings]
    assert any("admin" in t.lower() or "Admin" in t for t in titles)


def test_inventory_finding_always_present():
    client = MagicMock()
    client.get_all.return_value = []
    _, findings, _ = oauth_consent.run(client, TENANT_ID)
    assert len(findings) >= 1  # OAUTH_005 inventory always appended
