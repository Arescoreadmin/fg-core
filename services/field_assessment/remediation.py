"""Remediation prioritization, effort estimation, and step generation.

NOT STANDALONE — component of the Field Assessment Engagement Substrate.

Priority score formula (range 0–65):
  score = severity_base
        + exploitability_bonus
        + confidence_factor
        + source_bonus

  severity_base:        critical=40, high=30, medium=20, low=10, info=0
  exploitability_bonus: based on finding family (network=15, identity=12,
                        cloud-data=10, sharing=8, passive-recon=5)
  confidence_factor:    effective confidence >= 80 → +5
                        60–79 → 0
                        < 60  → -5  (stale or low-confidence evidence)
  source_bonus:         scan-confirmed (evidence_ref_ids present) → +5

Phase thresholds:
  score >= 50 → immediate  (0–30 days)
  score >= 35 → short_term (31–60 days)
  else        → planned    (61–90 days)

Effort level — two-tier lookup:
  1. finding_type override table (specific per finding_type string)
  2. family-level default (first segment of finding_type, lower-cased)
"""

from __future__ import annotations

from typing import Any

# MS Graph registry — optional import; fall back to empty dict if connector not installed.
try:
    from services.connectors.msgraph.findings.registry import (
        REGISTRY as _IMPORTED_MSGRAPH_REGISTRY,
    )
except ImportError:
    _IMPORTED_MSGRAPH_REGISTRY = {}

_MSGRAPH_REGISTRY_BY_TITLE: dict[str, Any] = {
    d.title: d for d in _IMPORTED_MSGRAPH_REGISTRY.values()
}

# Known MS Graph family codes — used by _type_prefix for step dispatch.
_KNOWN_FAMILIES = frozenset({"MFA", "CA", "APP", "OAUTH", "AI", "GUEST", "PRIV"})

# ---------------------------------------------------------------------------
# Scoring tables
# ---------------------------------------------------------------------------

_SEVERITY_BASE: dict[str, int] = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
    "info": 0,
}

# Exploitability bonus by finding family (lower-cased first segment of finding_type).
# Reflects the directness of the attack path — externally reachable and
# credential-based findings score highest.
_EXPLOITABILITY_BY_FAMILY: dict[str, int] = {
    # Externally reachable attack surface
    "network": 15,
    # Identity / authentication — direct account compromise
    "mfa": 12,
    "priv": 12,
    "entra": 10,
    "ca": 10,
    # Cloud credential / data access
    "oauth": 10,
    "endpoint": 10,
    # Data exfiltration surface
    "sharepoint": 8,
    "sharepoint_onedrive": 8,
    "guest": 8,
    "ai": 8,
    # Application surface
    "app": 7,
    # Passive recon — aids enumeration but not directly exploitable
    "dns_email": 5,
    "web_headers": 5,
}
_EXPLOITABILITY_DEFAULT = 5

# Effort level by finding family.
_EFFORT_BY_FAMILY: dict[str, str] = {
    # Low — config toggle, DNS change, or automated cert renewal
    "mfa": "low",
    "guest": "low",
    "dns_email": "low",
    "web_headers": "low",
    # Medium — policy configuration or phased rollout
    "ca": "medium",
    "priv": "medium",
    "network": "medium",
    "endpoint": "medium",
    "entra": "medium",
    "sharepoint": "medium",
    "sharepoint_onedrive": "medium",
    # High — app governance, process-heavy, or user-facing changes
    "app": "high",
    "oauth": "high",
    "ai": "high",
}

# Per-finding-type effort overrides (checked before family lookup).
_EFFORT_BY_FINDING_TYPE: dict[str, str] = {
    "endpoint.stale_devices": "low",  # bulk cleanup script
    "endpoint.unmanaged_devices": "high",  # MDM enrollment campaign
    "network.invalid_tls_certificates": "low",  # cert renewal, often automated
    "oauth.unverified_publishers": "medium",  # app review process, not full removal
}

PHASE_IMMEDIATE = "immediate"
PHASE_SHORT_TERM = "short_term"
PHASE_PLANNED = "planned"
PHASE_ORDER = [PHASE_IMMEDIATE, PHASE_SHORT_TERM, PHASE_PLANNED]

PHASE_META: dict[str, dict[str, str]] = {
    PHASE_IMMEDIATE: {"label": "Immediate", "window": "0–30 days"},
    PHASE_SHORT_TERM: {"label": "Short-term", "window": "31–60 days"},
    PHASE_PLANNED: {"label": "Planned", "window": "61–90 days"},
}

PHASE_IMMEDIATE_THRESHOLD = 50
PHASE_SHORT_TERM_THRESHOLD = 35

NIST_TOTAL_CONTROLS = 69


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _normalize_family(finding: Any) -> str:
    """Return lower-cased finding family for lookup in family dicts.

    Strips the 'msgraph.' prefix and returns the first dot- or dash-delimited
    segment, lower-cased.  Examples:
      'network.unsafe_services_exposed' → 'network'
      'msgraph.MFA-001'                → 'mfa'
      'endpoint.non_compliant_devices' → 'endpoint'
    """
    raw = (getattr(finding, "finding_type", "") or "").lower()
    if raw.startswith("msgraph."):
        raw = raw[len("msgraph.") :]
    return raw.split(".")[0].split("-")[0]


def _get_exploitability_bonus(finding: Any) -> int:
    return _EXPLOITABILITY_BY_FAMILY.get(
        _normalize_family(finding), _EXPLOITABILITY_DEFAULT
    )


def _get_confidence_factor(finding: Any) -> int:
    from services.field_assessment.confidence import degrade_confidence

    base = int(getattr(finding, "confidence_score", 70) or 70)
    updated_at = str(getattr(finding, "updated_at", "") or "")
    effective = degrade_confidence(base, updated_at) if updated_at else base
    if effective >= 80:
        return 5
    if effective >= 60:
        return 0
    return -5


def _get_source_bonus(finding: Any) -> int:
    refs = getattr(finding, "evidence_ref_ids", None) or []
    return 5 if refs else 0


def _type_prefix(finding: Any) -> str:
    """Extract the MS Graph family code for step template dispatch.

    Resolution order:
    1. Strip 'msgraph.' prefix; if the resulting first segment is a known family
       code (MFA/CA/APP/OAUTH/AI/GUEST/PRIV), return it directly.
    2. Look up finding.title in the MS Graph registry by title to recover the
       real finding code (e.g. 'MFA-001'), then extract the prefix from that.
    3. Fall back to '' (routes to generic template).
    """
    raw = getattr(finding, "finding_type", "") or ""
    code = raw[len("msgraph.") :] if raw.startswith("msgraph.") else raw

    first = code.split("-")[0] if "-" in code else code
    if first in _KNOWN_FAMILIES:
        return first

    title = getattr(finding, "title", "") or ""
    if title and _MSGRAPH_REGISTRY_BY_TITLE:
        defn = _MSGRAPH_REGISTRY_BY_TITLE.get(title)
        if defn is not None:
            real_code = getattr(defn, "code", "") or ""
            real_prefix = real_code.split("-")[0] if "-" in real_code else ""
            if real_prefix in _KNOWN_FAMILIES:
                return real_prefix

    return ""


# ---------------------------------------------------------------------------
# Public scoring API
# ---------------------------------------------------------------------------


def compute_priority_score(finding: Any) -> int:
    """Return a priority score in the range 0–65.

    Higher score = should be remediated sooner.  Use assign_phase() to map
    the score to an execution phase.
    """
    base = _SEVERITY_BASE.get(getattr(finding, "severity", "") or "", 0)
    score = (
        base
        + _get_exploitability_bonus(finding)
        + _get_confidence_factor(finding)
        + _get_source_bonus(finding)
    )
    return max(0, score)


def compute_effort_level(finding: Any) -> str:
    """Return 'low', 'medium', or 'high' effort estimate.

    Checks finding-type-level overrides first, then family-level defaults.
    """
    finding_type = (getattr(finding, "finding_type", "") or "").lower()
    if finding_type in _EFFORT_BY_FINDING_TYPE:
        return _EFFORT_BY_FINDING_TYPE[finding_type]
    return _EFFORT_BY_FAMILY.get(_normalize_family(finding), "medium")


def assign_phase(priority_score: int) -> str:
    if priority_score >= PHASE_IMMEDIATE_THRESHOLD:
        return PHASE_IMMEDIATE
    if priority_score >= PHASE_SHORT_TERM_THRESHOLD:
        return PHASE_SHORT_TERM
    return PHASE_PLANNED


# ---------------------------------------------------------------------------
# Remediation steps — template-based, deterministic, no LLM
# ---------------------------------------------------------------------------


def generate_remediation_steps(finding: Any) -> list[str]:
    """Return ordered, actionable remediation steps for a finding.

    Dispatch order: MS Graph family prefix → connector family → generic.
    """
    # MS Graph step dispatch
    ms_dispatch: dict[str, Any] = {
        "MFA": _steps_mfa,
        "CA": _steps_ca,
        "APP": _steps_app,
        "OAUTH": _steps_oauth,
        "AI": _steps_ai,
        "GUEST": _steps_guest,
        "PRIV": _steps_priv,
    }
    ms_prefix = _type_prefix(finding)
    if ms_prefix in ms_dispatch:
        return ms_dispatch[ms_prefix](finding)

    # Connector family dispatch
    connector_dispatch: dict[str, Any] = {
        "network": _steps_network,
        "endpoint": _steps_endpoint,
        "dns_email": _steps_dns_email,
        "web_headers": _steps_web_headers,
        "sharepoint": _steps_sharepoint,
        "sharepoint_onedrive": _steps_sharepoint,
        "entra": _steps_entra,
        "oauth": _steps_oauth,
    }
    family = _normalize_family(finding)
    handler = connector_dispatch.get(family, _steps_generic)
    return handler(finding)


def _steps_mfa(finding: Any) -> list[str]:  # noqa: ARG001
    return [
        "Open Azure Active Directory → Users → Per-user MFA.",
        "Filter to accounts with MFA status 'Disabled' — prioritize administrator accounts first.",
        "Select affected accounts and enable MFA enforcement.",
        "Notify affected users — they will be prompted to register an authenticator app on next sign-in.",
        "In Conditional Access, create a policy requiring MFA for all users on all cloud apps as a permanent enforcement layer.",
        "After 48 hours, re-run the MS Graph scan to confirm MFA coverage has improved.",
    ]


def _steps_ca(finding: Any) -> list[str]:  # noqa: ARG001
    return [
        "Open Azure Active Directory → Security → Conditional Access → Policies.",
        "Select 'New policy' and name it 'Block Legacy Authentication'.",
        "Under Assignments → Users, set to 'All users'.",
        "Under Conditions → Client apps, enable 'Exchange ActiveSync clients' and 'Other clients'.",
        "Under Access controls → Grant, select 'Block access'.",
        "Enable the policy in 'Report-only' mode for 24 hours to check for sign-in impact.",
        "Switch to 'On' once confirmed no legitimate traffic uses legacy protocols.",
        "Re-run the MS Graph scan to verify the finding is resolved.",
    ]


def _steps_app(finding: Any) -> list[str]:  # noqa: ARG001
    return [
        "Open Azure Active Directory → Enterprise applications.",
        "Filter to applications flagged as high-risk (unverified publisher + high-privilege permissions).",
        "For each flagged app: review the business owner, confirm it is still required, and document the decision.",
        "Revoke permissions or disable apps no longer needed: select the app → Properties → 'Enabled for users to sign in' → No.",
        "For stale apps (90+ days no sign-in): export the list, confirm with the app owner, then delete if unused.",
        "Enable admin consent workflow: Azure AD → Enterprise applications → Consent and permissions → Enable admin consent requests.",
        "Re-run the MS Graph scan after changes are applied.",
    ]


def _steps_oauth(finding: Any) -> list[str]:  # noqa: ARG001
    return [
        "Open Azure Active Directory → Enterprise applications → review OAuth grants.",
        "Focus on grants with offline_access + mail/file read-write scopes from unverified publishers.",
        "For critical-risk grants (score 3/3): revoke immediately via 'Revoke admin consent'.",
        "Enable admin consent workflow to prevent users from self-consenting future grants.",
        "Review user-consented grants: Azure AD → Enterprise applications → User consent → review and revoke as needed.",
        "Set tenant-wide consent policy: Azure AD → Enterprise applications → Consent and permissions → 'Do not allow user consent'.",
        "Re-run the MS Graph scan to confirm high-risk grants have been removed.",
    ]


def _steps_ai(finding: Any) -> list[str]:  # noqa: ARG001
    return [
        "Compile a list of AI applications in use from the MS Graph scan results (shadow AI and unapproved apps).",
        "For each app: verify whether a data processing agreement (DPA) or BAA is in place with the vendor.",
        "Block unapproved AI apps without a DPA: Azure AD → Enterprise applications → disable the app.",
        "Draft an AI acceptable use policy (AUP) defining approved AI tools and data classification limits.",
        "Enable Microsoft Purview DLP policies to flag or block sensitive data being sent to unapproved AI endpoints.",
        "Create an AI application approval workflow: users request access, security reviews the DPA, admin grants consent.",
        "Re-run the MS Graph scan after 30 days to verify shadow AI app count has decreased.",
    ]


def _steps_guest(finding: Any) -> list[str]:  # noqa: ARG001
    return [
        "Open Azure Active Directory → Users → filter by 'User type = Guest'.",
        "Identify guests with privileged roles: Azure AD → Roles and administrators → search each role for guest members → remove immediately.",
        "Export the full guest list and run an access review: Azure AD → Identity Governance → Access reviews → New review.",
        "For guests with no sign-in in 90+ days: contact the internal sponsor and remove if access is no longer needed.",
        "Delete pending never-activated invitation records.",
        "Set a recurring access review (quarterly) for all external guests via Identity Governance.",
        "Re-run the MS Graph scan to confirm privileged guest accounts have been removed.",
    ]


def _steps_priv(finding: Any) -> list[str]:  # noqa: ARG001
    return [
        "Open Azure Active Directory → Roles and administrators → Global Administrator.",
        "Review the list — target 2–4 dedicated break-glass accounts only. Remove all other permanent Global Admin assignments.",
        "Migrate remaining admins to Privileged Identity Management (PIM) for just-in-time access.",
        "Azure AD → Privileged Identity Management → Azure AD roles → Assignments → Add eligible assignment for each admin.",
        "Set activation duration to 8 hours max, with justification and MFA required on activation.",
        "For on-prem synced admin accounts: create cloud-only admin accounts and remove synced accounts from all privileged roles.",
        "Re-run the MS Graph scan to verify Global Admin count and permanent assignments have decreased.",
    ]


def _steps_network(finding: Any) -> list[str]:
    hint = getattr(finding, "remediation_hint", "") or ""
    finding_type = (getattr(finding, "finding_type", "") or "").lower()
    if "unsafe_services" in finding_type:
        return [
            "Identify the firewall rules or security groups exposing RDP (3389), VNC (5900), Telnet (23), and FTP (21).",
            "Remove or restrict public access rules. Allow only from known management IP ranges or through a VPN.",
            "Replace Telnet with SSH (port 22) and FTP with SFTP or FTPS where the service is still required.",
            "For RDP and VNC, deploy a VPN gateway or zero-trust network access (ZTNA) proxy in front of the service.",
            "Re-run the Network Scan after changes to confirm the ports are no longer reachable.",
        ]
    if "plain_http" in finding_type:
        return [
            "Obtain a TLS certificate for the affected hosts from a trusted CA (e.g. Let's Encrypt / ACME).",
            "Configure the web server to listen on port 443 with TLS.",
            "Add an HTTP→HTTPS redirect on port 80 (301 permanent redirect).",
            "Enable HSTS with a minimum max-age of 6 months once TLS is confirmed stable.",
            "Re-run the Network Scan and Web Security Headers scan to confirm the finding is resolved.",
        ]
    if "tls" in finding_type or "certificate" in finding_type:
        return [
            "Identify the affected host's certificate renewal process and current CA.",
            "Renew or replace the certificate with one from a trusted public CA.",
            "Automate renewal using ACME / Let's Encrypt or your CA's ACME endpoint.",
            "Verify the certificate chain is complete (no missing intermediate certs).",
            "Re-run the Network Scan to confirm the certificate is valid and not expired.",
        ]
    if "ai_port" in finding_type:
        return [
            "Identify which AI model server (Ollama, Gradio, Jupyter, etc.) is exposed on the open port.",
            "Restrict the port to localhost or an internal network interface — do not bind to 0.0.0.0.",
            "Add authentication to the model server API if it must be remotely accessible.",
            "Place a reverse proxy with auth (e.g. nginx + OAuth2 proxy) in front of the endpoint.",
            "Re-run the Network Scan to confirm the port is no longer publicly accessible.",
        ]
    return _steps_generic_with_hint(hint)


def _steps_endpoint(finding: Any) -> list[str]:
    finding_type = (getattr(finding, "finding_type", "") or "").lower()
    hint = getattr(finding, "remediation_hint", "") or ""
    if "non_compliant" in finding_type:
        return [
            "Open Microsoft Intune admin center → Devices → Compliance policies.",
            "Review which compliance policy conditions the flagged devices are failing.",
            "For each non-compliant device: check if the issue is OS version, encryption, or lock screen.",
            "Enforce remediation via Conditional Access: block non-compliant devices from accessing corporate resources.",
            "Notify device owners with a clear deadline. Use Intune's 'Send message' to device feature.",
            "Re-run the Endpoint Inventory scan after 7 days to confirm compliance state has improved.",
        ]
    if "unmanaged" in finding_type:
        return [
            "Export the list of unmanaged devices from the Endpoint Inventory scan.",
            "Contact device owners and confirm whether each device is used for corporate work.",
            "Enroll corporate devices in Microsoft Intune: Settings → Accounts → Access work or school → Enroll.",
            "For BYOD: deploy Intune MAM (Mobile Application Management) without full device enrollment.",
            "Create a Conditional Access policy requiring compliant or managed devices for corporate app access.",
            "Re-run the Endpoint Inventory scan to confirm managed device count has increased.",
        ]
    if "stale" in finding_type:
        return [
            "Export the list of stale devices (90+ days no sign-in) from the scan results.",
            "Contact device owners to confirm whether each device is still in use.",
            "Disable stale device objects in Azure AD: Azure AD → Devices → select device → Disable.",
            "After 30 days of no activity post-disable, delete the device object.",
            "Establish a quarterly device lifecycle cleanup process using this scan as the data source.",
        ]
    if "unencrypted" in finding_type:
        return [
            "Open Intune admin center → Devices → Configuration profiles → Create profile.",
            "Create a Windows configuration profile → Endpoint protection → Windows Encryption → BitLocker.",
            "Set 'BitLocker base settings → Encrypt devices' to 'Require'.",
            "Assign the profile to the affected device group.",
            "For macOS: create a configuration profile → FileVault → enable FileVault.",
            "Re-run the Endpoint Inventory scan to confirm encryption is now enabled on all devices.",
        ]
    return _steps_generic_with_hint(hint)


def _steps_dns_email(finding: Any) -> list[str]:
    finding_type = (getattr(finding, "finding_type", "") or "").lower()
    hint = getattr(finding, "remediation_hint", "") or ""
    if "dmarc" in finding_type:
        return [
            "Log in to your DNS provider and navigate to the DNS records for your domain.",
            "Add or update the DMARC TXT record: _dmarc.yourdomain.com → 'v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com'.",
            "Start with p=none (monitoring only), then escalate to p=quarantine after reviewing RUA reports for 2–4 weeks.",
            "Set up a DMARC report inbox or use a DMARC reporting service (e.g. dmarcian, Valimail) to review aggregate reports.",
            "Once no legitimate mail is failing DMARC, escalate to p=reject for maximum enforcement.",
            "Re-run the DNS & Email scan to confirm the DMARC record is present and policy is enforced.",
        ]
    if "spf" in finding_type:
        return [
            "Identify all mail-sending services for your domain (Google Workspace, Microsoft 365, Mailchimp, etc.).",
            "Log in to your DNS provider and add a TXT record: yourdomain.com → 'v=spf1 include:_spf.google.com ~all'.",
            "Replace the include: values with the correct SPF includes for your actual mail senders.",
            "Do NOT use +all — use ~all (softfail) initially, then -all (hardfail) once you have confirmed all senders.",
            "Re-run the DNS & Email scan to confirm SPF is present and does not use +all.",
        ]
    if "dkim" in finding_type:
        return [
            "Log in to your email provider (Google Workspace, Microsoft 365, etc.) and navigate to DKIM settings.",
            "Generate a DKIM key pair and note the selector name (e.g. 'google', 'selector1').",
            "Add the DKIM TXT record provided by your email provider to your DNS: selector._domainkey.yourdomain.com.",
            "Enable DKIM signing in your email provider's admin console.",
            "Wait 24–48 hours for DNS propagation, then re-run the DNS & Email scan with the correct selector.",
        ]
    if "dnssec" in finding_type:
        return [
            "Contact your domain registrar to enable DNSSEC for your domain.",
            "Most registrars have a one-click DNSSEC enable in the domain management portal.",
            "Once enabled, confirm DS records have propagated: use a DNSSEC checker (e.g. dnssec-analyzer.verisignlabs.com).",
            "Re-run the DNS & Email scan to confirm DNSSEC is enabled.",
        ]
    return _steps_generic_with_hint(hint)


def _steps_web_headers(finding: Any) -> list[str]:
    finding_type = (getattr(finding, "finding_type", "") or "").lower()
    hint = getattr(finding, "remediation_hint", "") or ""
    if "hsts" in finding_type:
        return [
            "Ensure your server is running HTTPS with a valid certificate before enabling HSTS.",
            "Add the Strict-Transport-Security header to your web server config:",
            "  nginx: add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload';",
            "  Apache: Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains'",
            "Start with max-age=86400 (1 day) and increase to 31536000 (1 year) once confirmed stable.",
            "Re-run the Web Security Headers scan to confirm HSTS is present with correct max-age.",
        ]
    if "csp" in finding_type or "content_security" in finding_type:
        return [
            "Audit your page's inline scripts and styles — CSP will block unsafe-inline if not addressed.",
            "Add a Content-Security-Policy header. Start with report-only mode:",
            "  Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; report-uri /csp-report",
            "Review CSP violation reports for 1–2 weeks to identify all required sources.",
            "Transition to enforced mode once the policy is stable, removing 'unsafe-inline' and wildcard sources.",
            "Re-run the Web Security Headers scan to confirm CSP is present without unsafe directives.",
        ]
    if "x_frame" in finding_type or "frame" in finding_type:
        return [
            "Add the X-Frame-Options header to prevent clickjacking:",
            "  nginx: add_header X-Frame-Options SAMEORIGIN;",
            "  Apache: Header always set X-Frame-Options SAMEORIGIN",
            "Alternatively, use CSP frame-ancestors directive: Content-Security-Policy: frame-ancestors 'self'",
            "Re-run the Web Security Headers scan to confirm X-Frame-Options is present.",
        ]
    return _steps_generic_with_hint(hint)


def _steps_sharepoint(finding: Any) -> list[str]:
    finding_type = (getattr(finding, "finding_type", "") or "").lower()
    hint = getattr(finding, "remediation_hint", "") or ""
    if "anonymous" in finding_type:
        return [
            "Open SharePoint admin center → Policies → Sharing.",
            "Set 'External sharing' to 'New and existing guests' or 'Only people in your organization' — remove 'Anyone'.",
            "For existing anonymous links: run PowerShell to enumerate and revoke:",
            "  Get-SPOSite | Get-SPOSiteGroup | where { $_.Users -match 'Everyone' }",
            "Audit the files identified as anonymously shared and revoke 'Anyone with the link' permissions.",
            "Enable expiry on sharing links: SharePoint admin center → Sharing → set maximum link expiry to 30 days.",
            "Re-run the SharePoint scan to confirm anonymous sharing has been reduced.",
        ]
    if "external" in finding_type:
        return [
            "Open SharePoint admin center → Policies → Sharing.",
            "Restrict external sharing to 'New and existing guests' (requires sign-in) rather than 'Anyone'.",
            "Review current external shares: SharePoint admin center → Reports → Sharing report.",
            "Contact file owners for each external share — confirm the share is still needed.",
            "Remove external access from files and folders that no longer require it.",
            "Set an expiry policy on all external sharing links.",
            "Re-run the SharePoint scan to confirm external share count has decreased.",
        ]
    return _steps_generic_with_hint(hint)


def _steps_entra(finding: Any) -> list[str]:
    finding_type = (getattr(finding, "finding_type", "") or "").lower()
    hint = getattr(finding, "remediation_hint", "") or ""
    if "pim" in finding_type or "permanent" in finding_type:
        return [
            "Open Azure AD → Privileged Identity Management → Azure AD roles → Assignments.",
            "For each permanent privileged role assignment, click 'Remove permanent' and create an eligible assignment.",
            "Set activation duration to 8 hours, require justification and MFA on activation.",
            "Configure approval workflow for Global Administrator activations.",
            "Re-run the Entra Governance scan to confirm PIM eligible assignments are in place.",
        ]
    if "access_review" in finding_type:
        return [
            "Open Azure AD → Identity Governance → Access reviews → New access review.",
            "Create a recurring quarterly review covering Global Administrator and other privileged roles.",
            "Assign reviewers (manager or security team) and set a 2-week review window.",
            "Enable 'Auto-apply results' to automatically remove access for users not reviewed.",
            "Re-run the Entra Governance scan after the next review cycle to confirm findings are resolved.",
        ]
    if "risky_user" in finding_type or "risk" in finding_type:
        return [
            "Open Azure AD → Security → Identity Protection → Risky users.",
            "For HIGH risk users: require immediate password reset and MFA re-registration.",
            "Dismiss false positives only after confirming the sign-in was legitimate.",
            "Create a User Risk Policy in Conditional Access: risk level High → require password change.",
            "Re-run the Entra Governance scan to confirm risky users have been remediated.",
        ]
    return _steps_generic_with_hint(hint)


def _steps_generic_with_hint(hint: str) -> list[str]:
    if hint:
        return [
            hint,
            "Document the remediation action taken and retain evidence for your assessment record.",
            "Re-run the relevant scan after remediation to confirm the finding is resolved.",
        ]
    return [
        "Review the finding details and consult your security team on the appropriate remediation approach.",
        "Document the remediation action taken and retain evidence for your assessment record.",
        "Re-run the relevant scan after remediation to confirm the finding is resolved.",
    ]


def _steps_generic(finding: Any) -> list[str]:
    hint = getattr(finding, "remediation_hint", "") or ""
    return _steps_generic_with_hint(hint)
