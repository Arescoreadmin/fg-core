"""Finding definitions — control mappings, severity, remediation metadata.

All finding codes, titles, framework mappings, and remediation guidance
are defined here.  Analyzers reference these definitions by code; they
never construct Finding objects with inline strings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class FindingDef:
    code: str
    control_id: str
    framework_refs: tuple[str, ...]
    severity: Literal["critical", "high", "medium", "low", "informational"]
    title: str
    recommendation: str
    remediation_effort: Literal["low", "medium", "high"]
    remediation_owner: Literal["IT", "Legal", "HR", "Exec", "Vendor"]
    affected_entities: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# MFA Coverage
# ---------------------------------------------------------------------------

MFA_001 = FindingDef(
    code="MFA-001",
    control_id="NIST-AI-RMF-GOVERN-1.2",
    framework_refs=(
        "NIST-AI-RMF",
        "FFIEC-CAT-Baseline",
        "HIPAA-164.312(d)",
        "CMMC-IA.L2-3.5.3",
    ),
    severity="critical",
    title="Admin account(s) with no MFA registered",
    recommendation="Immediately enforce MFA on all administrator accounts via Conditional Access policy requiring phishing-resistant MFA (FIDO2 or Microsoft Authenticator).",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("admin_user",),
)

MFA_002 = FindingDef(
    code="MFA-002",
    control_id="NIST-AI-RMF-GOVERN-1.4",
    framework_refs=(
        "NIST-AI-RMF",
        "FFIEC-CAT-Baseline",
        "HIPAA-164.312(d)",
        "CMMC-IA.L2-3.5.3",
    ),
    severity="high",
    title="MFA coverage below 80%",
    recommendation="Enable Security Defaults or deploy Conditional Access to require MFA for all users. Target 95%+ coverage within 30 days.",
    remediation_effort="medium",
    remediation_owner="IT",
    affected_entities=("user",),
)

MFA_003 = FindingDef(
    code="MFA-003",
    control_id="NIST-AI-RMF-GOVERN-1.4",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Baseline", "HIPAA-164.312(d)"),
    severity="medium",
    title="MFA coverage between 80–95%",
    recommendation="Close remaining MFA gaps. Focus on accounts accessing sensitive resources and admin-adjacent roles.",
    remediation_effort="medium",
    remediation_owner="IT",
    affected_entities=("user",),
)

MFA_004 = FindingDef(
    code="MFA-004",
    control_id="NIST-AI-RMF-GOVERN-1.4",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Evolved", "HIPAA-164.312(d)"),
    severity="medium",
    title="Users relying solely on SMS or voice call MFA (phishable)",
    recommendation="Migrate affected users from SMS/voice MFA to phishing-resistant methods (FIDO2, Microsoft Authenticator with number matching).",
    remediation_effort="medium",
    remediation_owner="IT",
    affected_entities=("user",),
)

MFA_005 = FindingDef(
    code="MFA-005",
    control_id="NIST-AI-RMF-GOVERN-1.4",
    framework_refs=("NIST-AI-RMF",),
    severity="informational",
    title="MFA coverage above 95% — positive signal",
    recommendation="Maintain coverage and monitor for new account provisioning without MFA enrollment.",
    remediation_effort="low",
    remediation_owner="IT",
)

# ---------------------------------------------------------------------------
# Conditional Access
# ---------------------------------------------------------------------------

CA_001 = FindingDef(
    code="CA-001",
    control_id="NIST-AI-RMF-GOVERN-1.4",
    framework_refs=(
        "NIST-AI-RMF",
        "FFIEC-CAT-Baseline",
        "HIPAA-164.312(a)(1)",
        "CMMC-AC.L2-3.1.3",
    ),
    severity="critical",
    title="No policy blocking legacy authentication protocols",
    recommendation="Create a Conditional Access policy blocking all legacy auth (Exchange ActiveSync, IMAP, POP3, SMTP AUTH). Legacy auth bypasses MFA — this is a critical gap exploited in over 90% of password spray attacks.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("policy",),
)

CA_002 = FindingDef(
    code="CA-002",
    control_id="NIST-AI-RMF-GOVERN-1.2",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Baseline", "HIPAA-164.312(a)(1)"),
    severity="critical",
    title="No MFA requirement for privileged roles in Conditional Access",
    recommendation="Create a Conditional Access policy requiring phishing-resistant MFA for all privileged role holders (Global Admin, Security Admin, Privileged Role Admin).",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("policy", "admin_user"),
)

CA_003 = FindingDef(
    code="CA-003",
    control_id="NIST-AI-RMF-GOVERN-1.4",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Baseline", "HIPAA-164.312(a)(1)"),
    severity="high",
    title="No Conditional Access policies enabled",
    recommendation="Enable Microsoft Security Defaults as an immediate baseline or deploy a Conditional Access policy requiring MFA for all users.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("policy",),
)

CA_004 = FindingDef(
    code="CA-004",
    control_id="NIST-AI-RMF-MANAGE-2.2",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Evolved", "HIPAA-164.312(a)(1)"),
    severity="high",
    title="Broad user exclusions in MFA policies (>10 excluded users)",
    recommendation="Audit and reduce exclusion lists. Create named exception groups with time-limited membership and quarterly review cadence.",
    remediation_effort="medium",
    remediation_owner="IT",
    affected_entities=("user", "policy"),
)

CA_005 = FindingDef(
    code="CA-005",
    control_id="NIST-AI-RMF-MANAGE-2.2",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Evolved", "HIPAA-164.312(a)(1)"),
    severity="medium",
    title="No compliant device requirement for corporate data access",
    recommendation="Require device compliance (Intune enrollment + compliance policy) for access to corporate resources via Conditional Access.",
    remediation_effort="high",
    remediation_owner="IT",
    affected_entities=("device", "policy"),
)

CA_006 = FindingDef(
    code="CA-006",
    control_id="NIST-AI-RMF-MANAGE-2.2",
    framework_refs=("NIST-AI-RMF",),
    severity="medium",
    title="No sign-in risk policy (P2 feature)",
    recommendation="If AAD P2 is licensed, deploy a sign-in risk policy requiring MFA or blocking at medium+ risk. Note: requires Azure AD Premium P2.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("policy",),
)

CA_007 = FindingDef(
    code="CA-007",
    control_id="NIST-AI-RMF-GOVERN-1.4",
    framework_refs=("NIST-AI-RMF",),
    severity="informational",
    title="Conditional Access policy coverage summary",
    recommendation="Review policy coverage regularly. Ensure all new user populations are included in CA policy scope.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("policy",),
)

# ---------------------------------------------------------------------------
# Enterprise Apps
# ---------------------------------------------------------------------------

APP_001 = FindingDef(
    code="APP-001",
    control_id="NIST-AI-RMF-MAP-4.2",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Innovative", "HIPAA-164.314(a)"),
    severity="high",
    title="Application(s) with unverified publisher holding high-privilege permissions",
    recommendation="Review each unverified app. Remove or re-consent under admin oversight. Require publisher verification for apps with Directory.ReadWrite, Mail.ReadWrite, or Files.ReadWrite permissions.",
    remediation_effort="medium",
    remediation_owner="IT",
    affected_entities=("app",),
)

APP_002 = FindingDef(
    code="APP-002",
    control_id="NIST-AI-RMF-MAP-4.2",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Baseline", "HIPAA-164.308(a)(5)"),
    severity="high",
    title="Stale applications (90+ days no activity) with active permissions",
    recommendation="Disable or remove applications with no sign-in activity in 90+ days. Retain only apps with documented business justification.",
    remediation_effort="medium",
    remediation_owner="IT",
    affected_entities=("app",),
)

APP_003 = FindingDef(
    code="APP-003",
    control_id="NIST-AI-RMF-GOVERN-1.7",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Innovative"),
    severity="medium",
    title="New applications created in last 30 days — verify authorization",
    recommendation="Confirm each new application was authorized through the change management process. Unknown apps should be reviewed and removed if not authorized.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("app",),
)

APP_004 = FindingDef(
    code="APP-004",
    control_id="NIST-AI-RMF-GOVERN-1.7",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Innovative", "HIPAA-164.314(a)"),
    severity="medium",
    title="User-consented apps with access to sensitive resources (no admin review)",
    recommendation="Enable admin consent workflow to require approval before users can grant app permissions. Review and revoke existing user-consented grants to sensitive resources.",
    remediation_effort="medium",
    remediation_owner="IT",
    affected_entities=("app", "user"),
)

APP_005 = FindingDef(
    code="APP-005",
    control_id="NIST-AI-RMF-MAP-4.2",
    framework_refs=("NIST-AI-RMF",),
    severity="informational",
    title="Enterprise application and service principal inventory summary",
    recommendation="Maintain an app inventory with owner, business justification, and last-reviewed date. Review quarterly.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("app",),
)

# ---------------------------------------------------------------------------
# OAuth Consent
# ---------------------------------------------------------------------------

OAUTH_001 = FindingDef(
    code="OAUTH-001",
    control_id="NIST-AI-RMF-MAP-4.2",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Innovative", "HIPAA-164.314(a)"),
    severity="critical",
    title="User-consented OAuth grant with full risk profile (score 3)",
    recommendation="Immediately revoke grants meeting all three risk criteria: unverified publisher + offline_access + data-access scope. Enable admin consent workflow to prevent recurrence.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("app", "user"),
)

OAUTH_002 = FindingDef(
    code="OAUTH-002",
    control_id="NIST-AI-RMF-MEASURE-2.10",
    framework_refs=("NIST-AI-RMF", "HIPAA-164.314(a)"),
    severity="high",
    title="User-consented OAuth grant with elevated risk (score 2)",
    recommendation="Review grants meeting two risk criteria. Prioritize revocation of grants with offline_access to unverified publishers.",
    remediation_effort="medium",
    remediation_owner="IT",
    affected_entities=("app", "user"),
)

OAUTH_003 = FindingDef(
    code="OAUTH-003",
    control_id="NIST-AI-RMF-MAP-4.2",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Baseline", "HIPAA-164.314(a)"),
    severity="high",
    title="Admin-consented OAuth grant to unverified publisher with data-access scopes",
    recommendation="Review admin-consented grants to unverified publishers. Request publisher verification or migrate to verified alternatives.",
    remediation_effort="medium",
    remediation_owner="IT",
    affected_entities=("app",),
)

OAUTH_004 = FindingDef(
    code="OAUTH-004",
    control_id="NIST-AI-RMF-MAP-4.2",
    framework_refs=("NIST-AI-RMF",),
    severity="medium",
    title="Stale OAuth grants (180+ days, no recent activity)",
    recommendation="Revoke OAuth grants with no activity in 180+ days. Implement automated grant expiry policy.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("app",),
)

OAUTH_005 = FindingDef(
    code="OAUTH-005",
    control_id="NIST-AI-RMF-MEASURE-2.10",
    framework_refs=("NIST-AI-RMF",),
    severity="informational",
    title="OAuth grant inventory and consent type breakdown",
    recommendation="Review OAuth grant inventory quarterly. Enable admin consent workflow for ongoing governance.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("app",),
)

# ---------------------------------------------------------------------------
# AI Signals
# ---------------------------------------------------------------------------

AI_001 = FindingDef(
    code="AI-001",
    control_id="NIST-AI-RMF-GOVERN-1.7",
    framework_refs=(
        "NIST-AI-RMF",
        "FFIEC-CAT-Innovative",
        "HIPAA-164.308(a)(1)",
        "CMMC-AC.L2-3.1.3",
    ),
    severity="critical",
    title="AI application with maximum DLP exposure score (score 3) — uncontrolled data access",
    recommendation="Block the application immediately via Conditional Access app restriction. Document a risk acceptance or remediation plan before re-enabling. Notify legal and compliance.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("app",),
)

AI_002 = FindingDef(
    code="AI-002",
    control_id="NIST-AI-RMF-MAP-4.2",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Innovative", "HIPAA-164.308(a)(1)"),
    severity="high",
    title="AI application with elevated DLP exposure score (score 2)",
    recommendation="Review with IT and Legal. Determine if a BAA or DPA is in place. Restrict to approved users pending review.",
    remediation_effort="medium",
    remediation_owner="Legal",
    affected_entities=("app",),
)

AI_003 = FindingDef(
    code="AI-003",
    control_id="NIST-AI-RMF-MAP-3.1",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Innovative", "HIPAA-164.308(a)(1)"),
    severity="high",
    title="AI applications detected with no corresponding admin approval record",
    recommendation="Establish an AI vendor approval process. Block unapproved AI apps via Conditional Access. Require security review and DPA before approving any AI tool.",
    remediation_effort="high",
    remediation_owner="IT",
    affected_entities=("app",),
)

AI_004 = FindingDef(
    code="AI-004",
    control_id="NIST-AI-RMF-GOVERN-1.7",
    framework_refs=("NIST-AI-RMF",),
    severity="medium",
    title="Copilot active but no AI acceptable use policy detected",
    recommendation="Publish and communicate an AI Acceptable Use Policy covering Copilot. Include data handling, prohibited inputs, and escalation procedures.",
    remediation_effort="medium",
    remediation_owner="Legal",
    affected_entities=("policy",),
)

AI_005 = FindingDef(
    code="AI-005",
    control_id="NIST-AI-RMF-MAP-4.2",
    framework_refs=("NIST-AI-RMF",),
    severity="medium",
    title="AI application permissions granted by users, not governed by admin",
    recommendation="Enable admin consent workflow. Revoke user-consented AI app grants. Re-consent under admin oversight with documented approval.",
    remediation_effort="medium",
    remediation_owner="IT",
    affected_entities=("app", "user"),
)

AI_006 = FindingDef(
    code="AI-006",
    control_id="NIST-AI-RMF-MEASURE-2.10",
    framework_refs=("NIST-AI-RMF",),
    severity="informational",
    title="AI application inventory — licensed vs shadow vs unknown",
    recommendation="Maintain a living AI vendor inventory updated quarterly. Include contract status, BAA/DPA status, and approved use cases.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("app",),
)

# ---------------------------------------------------------------------------
# Guest Exposure
# ---------------------------------------------------------------------------

GUEST_001 = FindingDef(
    code="GUEST-001",
    control_id="NIST-AI-RMF-GOVERN-1.4",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Baseline", "HIPAA-164.312(a)(1)"),
    severity="high",
    title="Guest account(s) with privileged role assignment",
    recommendation="Remove privileged role assignments from all guest accounts immediately. Guest accounts should never hold directory roles.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("guest_user", "role"),
)

GUEST_002 = FindingDef(
    code="GUEST-002",
    control_id="NIST-AI-RMF-MAP-2.2",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Baseline", "HIPAA-164.312(a)(1)"),
    severity="high",
    title="Guest account(s) in sensitive security groups",
    recommendation="Review guest membership in sensitive groups. Remove guests from groups with privileged access to data or systems.",
    remediation_effort="medium",
    remediation_owner="IT",
    affected_entities=("guest_user", "group"),
)

GUEST_003 = FindingDef(
    code="GUEST-003",
    control_id="NIST-AI-RMF-MAP-2.2",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Baseline"),
    severity="medium",
    title="Stale guest accounts (90+ days no sign-in)",
    recommendation="Remove or disable guest accounts with no sign-in in 90+ days unless documented business justification exists. Implement automated stale guest review.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("guest_user",),
)

GUEST_004 = FindingDef(
    code="GUEST-004",
    control_id="NIST-AI-RMF-MAP-2.2",
    framework_refs=("NIST-AI-RMF",),
    severity="medium",
    title="Never-activated guest accounts (invited, never signed in)",
    recommendation="Remove guest invitations that were never accepted after 30 days. Re-invite only if access is still needed.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("guest_user",),
)

GUEST_005 = FindingDef(
    code="GUEST-005",
    control_id="NIST-AI-RMF-GOVERN-1.4",
    framework_refs=("NIST-AI-RMF",),
    severity="informational",
    title="Guest account inventory and activity summary",
    recommendation="Review guest accounts quarterly. Implement an expiry policy (90 days unless renewed) via Azure AD access reviews.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("guest_user",),
)

# ---------------------------------------------------------------------------
# Privileged Roles
# ---------------------------------------------------------------------------

PRIV_001 = FindingDef(
    code="PRIV-001",
    control_id="NIST-AI-RMF-GOVERN-1.2",
    framework_refs=(
        "NIST-AI-RMF",
        "FFIEC-CAT-Baseline",
        "HIPAA-164.312(a)(2)(i)",
        "CMMC-IA.L2-3.5.3",
    ),
    severity="critical",
    title="Global Administrator account with no MFA",
    recommendation="Enforce MFA immediately on all Global Administrator accounts. This is the highest-priority finding in any tenant assessment.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("admin_user",),
)

PRIV_002 = FindingDef(
    code="PRIV-002",
    control_id="NIST-AI-RMF-GOVERN-1.2",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Evolved", "HIPAA-164.312(a)(2)(i)"),
    severity="high",
    title="More than 5 Global Administrator accounts",
    recommendation="Reduce Global Admin count to 2–4. Assign dedicated privileged admin accounts separate from daily-use accounts. Use PIM for just-in-time elevation.",
    remediation_effort="medium",
    remediation_owner="IT",
    affected_entities=("admin_user",),
)

PRIV_003 = FindingDef(
    code="PRIV-003",
    control_id="NIST-AI-RMF-GOVERN-1.2",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Baseline"),
    severity="high",
    title="Administrator accounts using synchronized (on-premises) identities",
    recommendation="Migrate admin accounts to cloud-only identities. On-prem synced admin accounts expose the cloud tenant to on-prem compromise pathways.",
    remediation_effort="high",
    remediation_owner="IT",
    affected_entities=("admin_user",),
)

PRIV_004 = FindingDef(
    code="PRIV-004",
    control_id="NIST-AI-RMF-GOVERN-1.4",
    framework_refs=("NIST-AI-RMF", "FFIEC-CAT-Evolved", "HIPAA-164.312(a)(2)(i)"),
    severity="high",
    title="Permanent privileged role assignments (no PIM time-bounding)",
    recommendation="Migrate permanent role assignments to PIM time-bound eligible assignments. Require justification and approval for role activation.",
    remediation_effort="medium",
    remediation_owner="IT",
    affected_entities=("admin_user", "role"),
)

PRIV_005 = FindingDef(
    code="PRIV-005",
    control_id="NIST-AI-RMF-GOVERN-1.2",
    framework_refs=("NIST-AI-RMF",),
    severity="medium",
    title="3–5 Global Administrator accounts (above recommended minimum)",
    recommendation="Review necessity of each Global Admin account. Reduce to 2 dedicated break-glass accounts plus emergency access. Document each account's purpose.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("admin_user",),
)

PRIV_006 = FindingDef(
    code="PRIV-006",
    control_id="NIST-AI-RMF-GOVERN-1.2",
    framework_refs=("NIST-AI-RMF",),
    severity="informational",
    title="Privileged role inventory by role type",
    recommendation="Maintain a privileged role inventory. Review quarterly and remove stale assignments.",
    remediation_effort="low",
    remediation_owner="IT",
    affected_entities=("admin_user", "role"),
)


# ---------------------------------------------------------------------------
# Registry — lookup by code
# ---------------------------------------------------------------------------

REGISTRY: dict[str, FindingDef] = {
    d.code: d
    for d in [
        MFA_001,
        MFA_002,
        MFA_003,
        MFA_004,
        MFA_005,
        CA_001,
        CA_002,
        CA_003,
        CA_004,
        CA_005,
        CA_006,
        CA_007,
        APP_001,
        APP_002,
        APP_003,
        APP_004,
        APP_005,
        OAUTH_001,
        OAUTH_002,
        OAUTH_003,
        OAUTH_004,
        OAUTH_005,
        AI_001,
        AI_002,
        AI_003,
        AI_004,
        AI_005,
        AI_006,
        GUEST_001,
        GUEST_002,
        GUEST_003,
        GUEST_004,
        GUEST_005,
        PRIV_001,
        PRIV_002,
        PRIV_003,
        PRIV_004,
        PRIV_005,
        PRIV_006,
    ]
}


def get_finding_def(code: str) -> FindingDef:
    try:
        return REGISTRY[code]
    except KeyError as exc:
        raise KeyError(f"unknown finding code: {code}") from exc
