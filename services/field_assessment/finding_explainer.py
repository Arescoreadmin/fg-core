"""Plain-language finding explanation service.

NOT STANDALONE — component of the Field Assessment Engagement Substrate.

Produces deterministic, privacy-preserving explanations from structured
analyzer output. No LLM calls. Every explanation is traceable to a
cryptographically-verified scan result via source_scan_ids.

Entity names are never available (raw_payload is metadata-only by design).
Counts and aggregate signals come from normalized_payload["summary"].
Finding definitions (title, recommendation) come from the FindingDef registry.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from services.canonical import utc_iso8601_z_now
from services.field_assessment.store import (
    FindingNotFound,
    get_finding,
    list_evidence_links,
    get_scan_result,
    ScanResultNotFound,
)

try:
    from services.connectors.msgraph.findings.registry import REGISTRY as _MSGRAPH_REGISTRY
except ImportError:
    _MSGRAPH_REGISTRY: dict[str, Any] = {}

_TTL_SECONDS = 300
_CACHE: dict[tuple[str, str], tuple[float, "FindingExplanation"]] = {}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AffectedEntitySummary:
    entity_type: str
    count: int
    label: str


@dataclass(frozen=True)
class FindingExplanation:
    plain_summary: str
    what_it_means: str
    affected_entities: list[AffectedEntitySummary]
    registry_recommendation: str
    evidence_count: int
    source_scan_ids: list[str]
    last_seen: str
    explanation_confidence: float
    generated_at: str
    schema_version: str = "1.0"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def explain_finding(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    finding_id: str,
) -> FindingExplanation:
    """Return a plain-language explanation for a normalized finding.

    Raises FindingNotFound if the finding does not exist for this tenant.
    Uses a 5-minute in-process TTL cache keyed on (engagement_id, finding_id).
    """
    cache_key = (engagement_id, finding_id)
    now_ts = time.monotonic()
    if cache_key in _CACHE:
        expires_at, cached = _CACHE[cache_key]
        if now_ts < expires_at:
            return cached

    finding = get_finding(
        db,
        finding_id=finding_id,
        engagement_id=engagement_id,
        tenant_id=tenant_id,
    )

    # Strip "msgraph." namespace prefix to get the registry code.
    raw_type = finding.finding_type or ""
    if raw_type.startswith("msgraph."):
        code = raw_type[len("msgraph."):]
    else:
        code = raw_type

    finding_def = _MSGRAPH_REGISTRY.get(code)

    # Load linked scan results (evidence_entity_type = "scan_result").
    evidence_links = list_evidence_links(
        db,
        engagement_id=engagement_id,
        tenant_id=tenant_id,
        source_entity_id=finding_id,
        limit=20,
    )
    scan_links = [
        lnk for lnk in evidence_links if lnk.evidence_entity_type == "scan_result"
    ]

    scans: list[Any] = []
    for lnk in scan_links:
        try:
            scan = get_scan_result(
                db,
                scan_result_id=lnk.evidence_entity_id,
                engagement_id=engagement_id,
                tenant_id=tenant_id,
            )
            scans.append(scan)
        except ScanResultNotFound:
            continue

    source_scan_ids = [s.id for s in scans]
    evidence_count = len(scans)

    # Derive last_seen from the most recent scan.
    last_seen = ""
    if scans:
        last_seen = max((s.collected_at or "") for s in scans)

    # Merge normalized_payload summary dicts from all linked scans.
    merged_summary: dict[str, Any] = {}
    for scan in scans:
        payload = scan.normalized_payload or {}
        summary = payload.get("summary", {})
        for section, data in summary.items():
            if isinstance(data, dict):
                merged_summary.setdefault(section, {}).update(data)

    # Dispatch to the appropriate template.
    prefix = code.split("-")[0] if "-" in code else ""
    dispatch: dict[str, Any] = {
        "MFA": _explain_mfa,
        "CA": _explain_ca,
        "APP": _explain_app,
        "OAUTH": _explain_oauth,
        "AI": _explain_ai,
        "GUEST": _explain_guest,
        "PRIV": _explain_priv,
    }
    handler = dispatch.get(prefix, _explain_generic)
    plain_summary, what_it_means, affected_entities = handler(
        finding, finding_def, merged_summary
    )

    registry_recommendation = (
        finding_def.recommendation if finding_def else finding.description or ""
    )

    # Confidence: high if known type + evidence present + scan is fresh.
    if finding_def and evidence_count > 0:
        if last_seen:
            try:
                from datetime import datetime, timezone
                scan_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - scan_dt).days
                confidence = 1.0 if age_days <= 30 else 0.7
            except ValueError:
                confidence = 0.7
        else:
            confidence = 0.7
    elif finding_def:
        confidence = 0.7
    else:
        confidence = 0.4

    result = FindingExplanation(
        plain_summary=plain_summary,
        what_it_means=what_it_means,
        affected_entities=affected_entities,
        registry_recommendation=registry_recommendation,
        evidence_count=evidence_count,
        source_scan_ids=source_scan_ids,
        last_seen=last_seen or utc_iso8601_z_now(),
        explanation_confidence=confidence,
        generated_at=utc_iso8601_z_now(),
    )
    _CACHE[cache_key] = (now_ts + _TTL_SECONDS, result)
    return result


# ---------------------------------------------------------------------------
# Template functions
# ---------------------------------------------------------------------------


def _explain_mfa(
    finding: Any,
    finding_def: Any,
    summary: dict[str, Any],
) -> tuple[str, str, list[AffectedEntitySummary]]:
    mfa = summary.get("mfa", {})
    total = int(mfa.get("total_enabled_users", 0))
    admin_no_mfa = int(mfa.get("admin_no_mfa", 0))
    no_mfa = int(mfa.get("no_mfa", 0))
    weak_only = int(mfa.get("weak_mfa_only", 0))
    coverage_pct = float(mfa.get("coverage_pct", 0.0))

    title = finding_def.title if finding_def else finding.title

    if admin_no_mfa > 0:
        plain_summary = (
            f"{admin_no_mfa} administrator account{'s' if admin_no_mfa != 1 else ''} "
            f"in your organization {'have' if admin_no_mfa != 1 else 'has'} no MFA registered."
        )
    elif no_mfa > 0:
        plain_summary = (
            f"{no_mfa} of {total} user accounts have no multi-factor authentication enabled "
            f"({coverage_pct:.0f}% coverage)."
        )
    else:
        plain_summary = f"MFA finding: {title}."

    what_it_means = (
        f"Multi-factor authentication gaps mean an attacker who obtains a password can "
        f"immediately access your organization's data. "
    )
    if admin_no_mfa > 0:
        what_it_means += (
            f"Administrator accounts without MFA are the primary initial access vector "
            f"in over 90% of identity-based breaches. Remediating {admin_no_mfa} admin "
            f"account{'s' if admin_no_mfa != 1 else ''} should be the first action taken."
        )
    elif weak_only > 0:
        what_it_means += (
            f"{weak_only} account{'s use' if weak_only != 1 else ' uses'} SMS or voice MFA, "
            f"which can be bypassed by SIM-swapping attacks. Upgrading to phishing-resistant "
            f"methods (FIDO2 or Microsoft Authenticator) closes this gap."
        )

    entities: list[AffectedEntitySummary] = []
    if admin_no_mfa > 0:
        entities.append(AffectedEntitySummary("admin_user", admin_no_mfa, "administrator accounts without MFA"))
    if no_mfa > 0:
        entities.append(AffectedEntitySummary("user", no_mfa, "user accounts without MFA"))
    if weak_only > 0:
        entities.append(AffectedEntitySummary("user", weak_only, "accounts using SMS/voice MFA only"))
    return plain_summary, what_it_means, entities


def _explain_ca(
    finding: Any,
    finding_def: Any,
    summary: dict[str, Any],
) -> tuple[str, str, list[AffectedEntitySummary]]:
    ca = summary.get("conditional_access", {})
    total = int(ca.get("total_policies", 0))
    enabled = int(ca.get("enabled_policies", 0))
    has_legacy_block = bool(ca.get("has_legacy_auth_block", False))
    has_admin_mfa = bool(ca.get("has_admin_mfa_requirement", False))
    broad_exclusions = int(ca.get("broad_exclusion_count", 0))

    title = finding_def.title if finding_def else finding.title

    if total == 0:
        plain_summary = "Your organization has no Conditional Access policies enabled."
    elif not has_legacy_block:
        plain_summary = (
            "No Conditional Access policy is blocking legacy authentication protocols "
            "(IMAP, POP3, SMTP AUTH), which bypass MFA."
        )
    elif not has_admin_mfa:
        plain_summary = (
            "No Conditional Access policy requires MFA for administrator accounts."
        )
    elif broad_exclusions > 0:
        plain_summary = (
            f"{broad_exclusions} Conditional Access {'policies have' if broad_exclusions != 1 else 'policy has'} "
            f"broad user exclusions (more than 10 excluded users)."
        )
    else:
        plain_summary = f"Conditional Access finding: {title}."

    what_it_means = (
        "Conditional Access policies are your primary control for enforcing authentication "
        "requirements across the organization. "
    )
    if not has_legacy_block:
        what_it_means += (
            "Legacy authentication protocols do not support MFA and are exploited in the "
            "majority of password spray attacks against Microsoft 365 tenants. Blocking "
            "them is a zero-downtime, high-impact remediation."
        )
    elif broad_exclusions > 0:
        what_it_means += (
            f"Wide exclusion lists create unmonitored bypass paths. Each excluded user "
            f"represents a potential policy gap that attackers can target."
        )

    entities: list[AffectedEntitySummary] = []
    entities.append(AffectedEntitySummary("policy", enabled, f"enabled policies of {total} total"))
    if broad_exclusions > 0:
        entities.append(AffectedEntitySummary("policy", broad_exclusions, "policies with broad exclusions"))
    return plain_summary, what_it_means, entities


def _explain_app(
    finding: Any,
    finding_def: Any,
    summary: dict[str, Any],
) -> tuple[str, str, list[AffectedEntitySummary]]:
    apps = summary.get("enterprise_apps", {})
    unverified_high = int(apps.get("unverified_publisher_high_priv", 0))
    stale = int(apps.get("stale_apps_90d", 0))
    new_apps = int(apps.get("new_apps_30d", 0))
    user_consented = int(apps.get("user_consented_sensitive", 0))
    total = int(apps.get("total_apps", 0))

    title = finding_def.title if finding_def else finding.title

    if unverified_high > 0:
        plain_summary = (
            f"{unverified_high} enterprise application{'s' if unverified_high != 1 else ''} "
            f"with unverified publishers hold high-privilege directory permissions."
        )
    elif stale > 0:
        plain_summary = (
            f"{stale} application{'s have' if stale != 1 else ' has'} had no sign-in activity "
            f"in 90+ days but still hold active permissions."
        )
    elif new_apps > 0:
        plain_summary = (
            f"{new_apps} new application{'s were' if new_apps != 1 else ' was'} registered "
            f"in your tenant in the last 30 days — authorization should be verified."
        )
    else:
        plain_summary = f"Enterprise application finding: {title}."

    what_it_means = (
        f"Your tenant has {total} registered enterprise applications. "
    )
    if unverified_high > 0:
        what_it_means += (
            "Applications from unverified publishers with Directory.ReadWrite or Mail.ReadWrite "
            "permissions can read or modify any user's data. These represent a direct data "
            "exfiltration risk and should be reviewed or removed immediately."
        )
    elif stale > 0:
        what_it_means += (
            "Stale applications accumulate permissions over time and are rarely monitored. "
            "Removing them reduces your attack surface without impacting active workloads."
        )

    entities: list[AffectedEntitySummary] = []
    if unverified_high > 0:
        entities.append(AffectedEntitySummary("app", unverified_high, "unverified apps with high-privilege permissions"))
    if stale > 0:
        entities.append(AffectedEntitySummary("app", stale, "stale apps (90+ days inactive)"))
    if new_apps > 0:
        entities.append(AffectedEntitySummary("app", new_apps, "new apps in last 30 days"))
    if user_consented > 0:
        entities.append(AffectedEntitySummary("app", user_consented, "user-consented apps accessing sensitive resources"))
    return plain_summary, what_it_means, entities


def _explain_oauth(
    finding: Any,
    finding_def: Any,
    summary: dict[str, Any],
) -> tuple[str, str, list[AffectedEntitySummary]]:
    oauth = summary.get("oauth_consent", {})
    score_3 = int(oauth.get("score_3_critical", 0))
    score_2 = int(oauth.get("score_2_high", 0))
    user_consented = int(oauth.get("user_consented", 0))
    stale = int(oauth.get("stale_grants_180d", 0))
    total = int(oauth.get("total_grants", 0))
    unverified = int(oauth.get("unverified_publisher_grants", 0))

    title = finding_def.title if finding_def else finding.title

    if score_3 > 0:
        plain_summary = (
            f"{score_3} OAuth {'grant meets' if score_3 == 1 else 'grants meet'} all three "
            f"high-risk criteria: unverified publisher, offline access, and data-access scopes."
        )
    elif score_2 > 0:
        plain_summary = (
            f"{score_2} OAuth {'grant has' if score_2 == 1 else 'grants have'} elevated risk — "
            f"two or more risk factors including unverified publisher or offline_access scope."
        )
    elif stale > 0:
        plain_summary = (
            f"{stale} OAuth {'grant has' if stale == 1 else 'grants have'} had no activity "
            f"in 180+ days but retain active access permissions."
        )
    else:
        plain_summary = f"OAuth consent finding: {title}."

    what_it_means = (
        f"Your organization has {total} OAuth grants covering {user_consented} user-consented "
        f"connections to third-party applications. "
    )
    if score_3 > 0:
        what_it_means += (
            "Grants with all three risk factors can silently read email, files, and calendar "
            "data with no user interaction required. These should be revoked immediately and "
            "admin consent workflow enabled to prevent recurrence."
        )
    elif unverified > 0:
        what_it_means += (
            f"{unverified} grants are to unverified publishers — these apps have not been "
            "vetted by Microsoft and may not comply with data handling requirements."
        )

    entities: list[AffectedEntitySummary] = []
    if score_3 > 0:
        entities.append(AffectedEntitySummary("app", score_3, "OAuth grants with critical risk score (3/3)"))
    if score_2 > 0:
        entities.append(AffectedEntitySummary("app", score_2, "OAuth grants with elevated risk score (2/3)"))
    if stale > 0:
        entities.append(AffectedEntitySummary("app", stale, "stale OAuth grants (180+ days inactive)"))
    return plain_summary, what_it_means, entities


def _explain_ai(
    finding: Any,
    finding_def: Any,
    summary: dict[str, Any],
) -> tuple[str, str, list[AffectedEntitySummary]]:
    ai = summary.get("ai_signals", {})
    shadow = int(ai.get("shadow_ai_apps", 0))
    dlp_critical = int(ai.get("dlp_score_3_critical", 0))
    dlp_high = int(ai.get("dlp_score_2_high", 0))
    unapproved = int(ai.get("unapproved_ai_apps", 0))
    copilot_active = int(ai.get("copilot_active_users", 0))
    user_consented_ai = int(ai.get("user_consented_ai", 0))

    title = finding_def.title if finding_def else finding.title

    if dlp_critical > 0:
        plain_summary = (
            f"{dlp_critical} AI application{'s have' if dlp_critical != 1 else ' has'} "
            f"maximum data-loss exposure — uncontrolled access to sensitive organizational data."
        )
    elif unapproved > 0:
        plain_summary = (
            f"{unapproved} AI application{'s were' if unapproved != 1 else ' was'} detected "
            f"with no corresponding admin approval record."
        )
    elif shadow > 0:
        plain_summary = (
            f"{shadow} shadow AI application{'s are' if shadow != 1 else ' is'} in use across "
            f"your organization without IT governance."
        )
    elif copilot_active > 0 and title:
        plain_summary = (
            f"Microsoft Copilot is active for {copilot_active} users but an AI acceptable "
            f"use policy has not been detected."
        )
    else:
        plain_summary = f"AI governance finding: {title}."

    what_it_means = "AI applications present unique data governance risks because they "
    if dlp_critical > 0:
        what_it_means += (
            "can process and transmit sensitive business data to external AI models. "
            f"The {dlp_critical} application{'s' if dlp_critical != 1 else ''} flagged at "
            "maximum DLP exposure have full access to email, files, or directory data — "
            "these should be blocked immediately pending a formal risk review."
        )
    elif unapproved > 0:
        what_it_means += (
            "require specific data processing agreements. Unapproved AI tools may send "
            "internal data to AI models operated by vendors who have not signed your "
            "organization's data processing agreements or BAA."
        )
    else:
        what_it_means += (
            "can store and learn from organizational data. Without governance controls "
            "employees may inadvertently share confidential information with AI services "
            "that do not have appropriate data handling agreements."
        )

    entities: list[AffectedEntitySummary] = []
    if dlp_critical > 0:
        entities.append(AffectedEntitySummary("app", dlp_critical, "AI apps with maximum DLP exposure"))
    if dlp_high > 0:
        entities.append(AffectedEntitySummary("app", dlp_high, "AI apps with elevated DLP exposure"))
    if shadow > 0:
        entities.append(AffectedEntitySummary("app", shadow, "shadow AI apps (no IT governance)"))
    if unapproved > 0:
        entities.append(AffectedEntitySummary("app", unapproved, "unapproved AI apps"))
    if user_consented_ai > 0:
        entities.append(AffectedEntitySummary("user", user_consented_ai, "users with self-consented AI app access"))
    return plain_summary, what_it_means, entities


def _explain_guest(
    finding: Any,
    finding_def: Any,
    summary: dict[str, Any],
) -> tuple[str, str, list[AffectedEntitySummary]]:
    guest = summary.get("guest_exposure", {})
    total = int(guest.get("total_guests", 0))
    priv_role = int(guest.get("privileged_role_guests", 0))
    stale = int(guest.get("stale_guests_90d", 0))
    never_activated = int(guest.get("never_activated", 0))
    sensitive_groups = int(guest.get("sensitive_group_guests", 0))

    title = finding_def.title if finding_def else finding.title

    if priv_role > 0:
        plain_summary = (
            f"{priv_role} guest account{'s hold' if priv_role != 1 else ' holds'} "
            f"privileged directory role assignments."
        )
    elif stale > 0:
        plain_summary = (
            f"{stale} guest account{'s have' if stale != 1 else ' has'} had no sign-in "
            f"activity in 90+ days but remain active in your directory."
        )
    elif never_activated > 0:
        plain_summary = (
            f"{never_activated} guest {'invitations were' if never_activated != 1 else 'invitation was'} "
            f"sent but never accepted — these accounts have never been used."
        )
    else:
        plain_summary = f"Guest account finding: {title}."

    what_it_means = (
        f"Your tenant has {total} guest accounts from external organizations. "
    )
    if priv_role > 0:
        what_it_means += (
            "Guest accounts should never hold privileged roles. An external user with "
            "an administrator role can access and modify your entire directory. "
            "These assignments should be removed immediately."
        )
    elif stale > 0:
        what_it_means += (
            "Stale guest accounts represent dormant attack vectors — if the guest's home "
            "organization is compromised, attackers can use those credentials to access "
            "your organization's data. Removing inactive guests reduces this risk."
        )

    entities: list[AffectedEntitySummary] = []
    if priv_role > 0:
        entities.append(AffectedEntitySummary("guest_user", priv_role, "guests with privileged role assignments"))
    if sensitive_groups > 0:
        entities.append(AffectedEntitySummary("guest_user", sensitive_groups, "guests in sensitive security groups"))
    if stale > 0:
        entities.append(AffectedEntitySummary("guest_user", stale, "stale guests (90+ days no sign-in)"))
    if never_activated > 0:
        entities.append(AffectedEntitySummary("guest_user", never_activated, "never-activated guest invitations"))
    return plain_summary, what_it_means, entities


def _explain_priv(
    finding: Any,
    finding_def: Any,
    summary: dict[str, Any],
) -> tuple[str, str, list[AffectedEntitySummary]]:
    priv = summary.get("privileged_roles", {})
    global_admin_count = int(priv.get("global_admin_count", 0))
    permanent = int(priv.get("permanent_assignments", 0))
    synced = int(priv.get("synced_account_admins", 0))
    pim_enrolled = int(priv.get("pim_enrolled_admins", 0))
    time_bound = int(priv.get("time_bound_assignments", 0))

    title = finding_def.title if finding_def else finding.title

    if global_admin_count > 5:
        plain_summary = (
            f"{global_admin_count} Global Administrator accounts exist in your tenant. "
            f"Microsoft recommends no more than 4."
        )
    elif permanent > 0 and time_bound == 0:
        plain_summary = (
            f"{permanent} privileged role assignment{'s are' if permanent != 1 else ' is'} "
            f"permanently active — no time-bounding through Privileged Identity Management."
        )
    elif synced > 0:
        plain_summary = (
            f"{synced} administrator account{'s use' if synced != 1 else ' uses'} "
            f"on-premises synchronized identities, exposing the cloud tenant to on-prem compromise."
        )
    elif global_admin_count > 0:
        plain_summary = (
            f"{global_admin_count} Global Administrator account{'s are' if global_admin_count != 1 else ' is'} "
            f"configured. The recommended maximum is 2–4 dedicated break-glass accounts."
        )
    else:
        plain_summary = f"Privileged identity finding: {title}."

    what_it_means = "Privileged role management is critical because Global Administrators "
    if global_admin_count > 5:
        what_it_means += (
            "have unrestricted access to your entire Microsoft 365 environment. "
            f"Reducing from {global_admin_count} to 2–4 dedicated accounts minimizes "
            "the blast radius of an account compromise and reduces standing access."
        )
    elif permanent > 0:
        what_it_means += (
            "with permanent assignments can act at any time without justification or approval. "
            "PIM time-bound assignments require re-authentication and a business justification "
            "each time elevated access is used, creating an audit trail and reducing risk."
        )
    elif synced > 0:
        what_it_means += (
            "accounts synchronized from on-premises Active Directory mean a compromise of "
            "your on-prem environment can cascade into the cloud tenant. Cloud-only admin "
            "accounts are isolated from on-prem attacks."
        )
    else:
        what_it_means += (
            "can read, modify, or delete all data in your organization. "
            "Minimizing the number of permanently assigned privileged accounts is a "
            "fundamental zero-trust principle."
        )

    entities: list[AffectedEntitySummary] = []
    if global_admin_count > 0:
        entities.append(AffectedEntitySummary("admin_user", global_admin_count, "Global Administrator accounts"))
    if permanent > 0:
        entities.append(AffectedEntitySummary("admin_user", permanent, "permanent privileged role assignments (no PIM)"))
    if synced > 0:
        entities.append(AffectedEntitySummary("admin_user", synced, "admin accounts synced from on-premises AD"))
    if pim_enrolled > 0:
        entities.append(AffectedEntitySummary("admin_user", pim_enrolled, "PIM-enrolled admin accounts (positive signal)"))
    return plain_summary, what_it_means, entities


def _explain_generic(
    finding: Any,
    finding_def: Any,
    summary: dict[str, Any],  # noqa: ARG001
) -> tuple[str, str, list[AffectedEntitySummary]]:
    title = finding_def.title if finding_def else finding.title
    description = (
        finding_def.recommendation if finding_def else finding.description or ""
    )
    plain_summary = title or "Security finding identified."
    what_it_means = description or (
        "This finding indicates a potential risk in your organization's security posture. "
        "Review the technical details and follow the recommended remediation steps."
    )
    return plain_summary, what_it_means, []
