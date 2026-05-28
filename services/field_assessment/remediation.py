"""Remediation prioritization, effort estimation, and step generation.

NOT STANDALONE — component of the Field Assessment Engagement Substrate.

Priority score formula:
  score = (severity_weight * 8) + scan_evidence_bonus + nist_coverage_bonus

  severity_weight:     critical=4, high=3, medium=2, low=1, info=0
  scan_evidence_bonus: min(len(evidence_ref_ids), 5)
  nist_coverage_bonus: min(len(nist_ai_rmf_mappings), 10)

  Score range: 0–55. Higher = higher priority.

Phase thresholds:
  score >= 28 → immediate  (0–30 days)  — critical/high, scan-confirmed
  score >= 16 → short_term (31–60 days) — high/medium, well-evidenced
  else        → planned    (61–90 days) — medium/low or sparse evidence

Effort heuristic by finding_type prefix:
  MFA, GUEST → low    (identity changes, operator-level)
  CA, PRIV   → medium (policy configuration)
  APP, OAUTH, AI → high (app governance, process-heavy)
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

# Known family prefixes for connector-imported finding types.
_KNOWN_FAMILIES = frozenset({"MFA", "CA", "APP", "OAUTH", "AI", "GUEST", "PRIV"})

_SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

_EFFORT_BY_PREFIX: dict[str, str] = {
    "MFA": "low",
    "GUEST": "low",
    "CA": "medium",
    "PRIV": "medium",
    "APP": "high",
    "OAUTH": "high",
    "AI": "high",
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

NIST_TOTAL_CONTROLS = 69


def _type_prefix(finding: Any) -> str:
    """Extract the family prefix from a finding_type string.

    Resolution order:
    1. Strip "msgraph." prefix; if the resulting first segment is a known family
       code (MFA/CA/APP/OAUTH/AI/GUEST/PRIV), return it directly.
    2. Look up finding.title in the MS Graph registry by title to recover the
       real finding code (e.g. "MFA-001"), then extract the prefix from that.
    3. Fall back to "" (routes to generic template).
    """
    raw = finding.finding_type or ""
    code = raw[len("msgraph.") :] if raw.startswith("msgraph.") else raw

    # Step 1 — fast path: first segment is already a known family code.
    first = code.split("-")[0] if "-" in code else code
    if first in _KNOWN_FAMILIES:
        return first

    # Step 2 — title-index lookup in MS Graph registry.
    title = getattr(finding, "title", "") or ""
    if title and _MSGRAPH_REGISTRY_BY_TITLE:
        defn = _MSGRAPH_REGISTRY_BY_TITLE.get(title)
        if defn is not None:
            real_code = getattr(defn, "code", "") or ""
            real_prefix = real_code.split("-")[0] if "-" in real_code else ""
            if real_prefix in _KNOWN_FAMILIES:
                return real_prefix

    # Step 3 — generic fallback.
    return ""


def compute_priority_score(finding: Any) -> int:
    weight = _SEVERITY_WEIGHT.get(finding.severity or "", 0)
    scan_bonus = min(len(finding.evidence_ref_ids or []), 5)
    nist_bonus = min(len(finding.nist_ai_rmf_mappings or []), 10)
    return weight * 8 + scan_bonus + nist_bonus


def compute_effort_level(finding: Any) -> str:
    return _EFFORT_BY_PREFIX.get(_type_prefix(finding), "medium")


def assign_phase(priority_score: int) -> str:
    if priority_score >= 28:
        return PHASE_IMMEDIATE
    if priority_score >= 16:
        return PHASE_SHORT_TERM
    return PHASE_PLANNED


# ---------------------------------------------------------------------------
# Remediation steps — template-based, deterministic, no LLM
# ---------------------------------------------------------------------------


def generate_remediation_steps(finding: Any) -> list[str]:
    """Return ordered, actionable remediation steps for a finding.

    Steps are template-driven from finding_type prefix. Deterministic and
    safe to cache alongside the explanation manifest.
    """
    dispatch: dict[str, Any] = {
        "MFA": _steps_mfa,
        "CA": _steps_ca,
        "APP": _steps_app,
        "OAUTH": _steps_oauth,
        "AI": _steps_ai,
        "GUEST": _steps_guest,
        "PRIV": _steps_priv,
    }
    handler = dispatch.get(_type_prefix(finding), _steps_generic)
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


def _steps_generic(finding: Any) -> list[str]:
    hint = finding.remediation_hint or ""
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
