"""DLP Exposure Composite Scorer — Step 16.

Cross-analyzer post-processing that combines EnterpriseApp, OAuthConsent,
and AISignal outputs to produce per-app DLPExposureProfile scores (0-9).
"""

from __future__ import annotations

from typing import Any

from services.connectors.msgraph.schema.analyzer_outputs import (
    DLPExposureProfile,
    DLPExposureResult,
)

# Data access tier scoring (0-3)
_DATA_SCOPES_HIGH = frozenset(
    {
        "Mail.ReadWrite",
        "Files.ReadWrite",
        "User.ReadWrite.All",
        "Directory.ReadWrite.All",
    }
)
_DATA_SCOPES_MED = frozenset(
    {"Mail.Read", "Files.Read", "Calendars.Read", "Contacts.Read", "User.Read.All"}
)
_DATA_SCOPES_LOW = frozenset({"openid", "profile", "email", "offline_access"})

# Score thresholds
_CRITICAL_THRESHOLD = 7
_HIGH_THRESHOLD = 5
_MEDIUM_THRESHOLD = 3


def _data_access_score(scopes: set[str]) -> int:
    if scopes & _DATA_SCOPES_HIGH:
        return 3
    if scopes & _DATA_SCOPES_MED:
        return 2
    if scopes & _DATA_SCOPES_LOW:
        return 1
    return 0


def _consent_score(consent_type: str) -> int:
    # User-consented = higher risk (3), admin-consented with review = medium (1)
    if consent_type == "Principal":
        return 3
    if consent_type == "AllPrincipals":
        return 1
    return 2  # unknown


def _publisher_trust_score(is_unverified: bool, is_approved: bool) -> int:
    if is_approved:
        return 0
    if is_unverified:
        return 3
    return 1


def _recommended_action(composite: int) -> str:
    if composite >= _CRITICAL_THRESHOLD:
        return "block"
    if composite >= _HIGH_THRESHOLD:
        return "review"
    if composite >= _MEDIUM_THRESHOLD:
        return "monitor"
    return "accept"


def _highest_severity(composite: int) -> str:
    if composite >= _CRITICAL_THRESHOLD:
        return "critical"
    if composite >= _HIGH_THRESHOLD:
        return "high"
    if composite >= _MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def score_grants(
    grants: list[dict[str, Any]],
    sp_map: dict[str, dict[str, Any]],
    approved_app_ids: set[str],
) -> DLPExposureResult:
    """Produce DLPExposureResult from raw OAuth grants and SP metadata."""
    profiles: list[DLPExposureProfile] = []
    critical_count = 0
    high_count = 0
    medium_count = 0

    # Deduplicate by clientId — worst-case grant wins
    worst_by_client: dict[str, DLPExposureProfile] = {}

    for grant in grants:
        client_id = grant.get("clientId", "")
        sp = sp_map.get(client_id, {})
        app_id = sp.get("appId", client_id)

        scope_str: str = grant.get("scope", "") or ""
        scopes = set(scope_str.split())
        consent_type = grant.get("consentType", "")
        is_unverified = not (sp.get("verifiedPublisher") or {}).get(
            "verifiedPublisherId"
        )
        is_approved = app_id in approved_app_ids

        da_score = _data_access_score(scopes)
        cs_score = _consent_score(consent_type)
        pt_score = _publisher_trust_score(is_unverified, is_approved)
        composite = da_score + cs_score + pt_score

        profile = DLPExposureProfile(
            app_id=app_id,
            app_category="ai"
            if "ai" in (sp.get("displayName") or "").lower()
            else "app",
            composite_score=composite,
            data_access_score=da_score,
            consent_score=cs_score,
            publisher_trust_score=pt_score,
            highest_severity=_highest_severity(composite),
            recommended_action=_recommended_action(composite),
        )

        existing = worst_by_client.get(client_id)
        if existing is None or composite > existing.composite_score:
            worst_by_client[client_id] = profile

    for profile in worst_by_client.values():
        profiles.append(profile)
        if profile.composite_score >= _CRITICAL_THRESHOLD:
            critical_count += 1
        elif profile.composite_score >= _HIGH_THRESHOLD:
            high_count += 1
        elif profile.composite_score >= _MEDIUM_THRESHOLD:
            medium_count += 1

    profiles.sort(key=lambda p: p.composite_score, reverse=True)

    return DLPExposureResult(
        profiles=profiles,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
    )
