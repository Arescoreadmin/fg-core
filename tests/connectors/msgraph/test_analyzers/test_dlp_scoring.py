"""Tests for DLP Exposure Composite Scorer."""

from __future__ import annotations

from services.connectors.msgraph.analyzers.dlp_scoring import score_grants


def _grant(client_id: str, scope: str, consent: str = "Principal") -> dict:
    return {"clientId": client_id, "consentType": consent, "scope": scope}


def _sp(verified: bool = True, app_id: str = "app1") -> dict:
    vp = {"verifiedPublisherId": "p1"} if verified else {}
    return {"id": "c1", "appId": app_id, "verifiedPublisher": vp}


def test_max_score_user_consented_unverified_with_data_scope():
    grants = [_grant("c1", "Mail.ReadWrite offline_access", "Principal")]
    sp_map = {"c1": _sp(verified=False, app_id="app1")}
    result = score_grants(grants, sp_map, approved_app_ids=set())
    assert len(result.profiles) == 1
    p = result.profiles[0]
    assert p.composite_score >= 7
    assert p.recommended_action == "block"
    assert result.critical_count == 1


def test_approved_app_gets_zero_publisher_trust_score():
    grants = [_grant("c1", "Mail.Read", "AllPrincipals")]
    sp_map = {"c1": _sp(verified=False, app_id="approved_app")}
    result = score_grants(grants, sp_map, approved_app_ids={"approved_app"})
    p = result.profiles[0]
    assert p.publisher_trust_score == 0


def test_worst_case_grant_wins_per_client():
    # Two grants for same client — higher score should win
    grants = [
        _grant("c1", "openid", "AllPrincipals"),  # low score
        _grant("c1", "Mail.ReadWrite offline_access", "Principal"),  # high score
    ]
    sp_map = {"c1": _sp(verified=False)}
    result = score_grants(grants, sp_map, approved_app_ids=set())
    assert len(result.profiles) == 1  # deduplicated
    assert result.profiles[0].composite_score >= 7


def test_empty_grants_produces_empty_result():
    result = score_grants([], {}, approved_app_ids=set())
    assert result.profiles == []
    assert result.critical_count == 0
