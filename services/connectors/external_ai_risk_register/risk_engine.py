"""Deterministic External AI Risk Register engine (PR 3 + Addendum).

Not standalone. Extends PR 1 (AI Tool Discovery) and PR 2 (AI Data Access Mapping).
This module is not standalone. It requires the fg-core API, auth layer, and Postgres substrate.

Generates ExternalAiRiskRecord entries from:
  - PR 1 AI Tool Discovery scan results (tool identity, permissions, publisher)
  - PR 2 AI Data Access Mapping scan results (sensitivity, exposure scope, owner)

All fields are deterministic — no LLM scoring, no speculative values.
Every risk traces back to evidence collected by PR 1 and PR 2.

Risk categories (extensible, no free-form values):
  overprivileged_oauth      — broad *.All or write-all scopes relative to tool purpose
  unverified_publisher      — verified_publisher is False
  tenant_wide_permissions   — admin_consent + tenant-wide exposure scope
  sensitive_data_access     — data sensitivity is high or critical
  unknown_owner             — data_owner/owner_type is Unknown
  no_approval_record        — no governance decision linked to this tool
  no_dpa_baa_vendor_review  — no vendor review governance decision
  shadow_ai                 — tool confidence is suspected or unknown

Risk score bands (numeric → label):
  0–24   → low
  25–49  → moderate
  50–74  → high
  75+    → critical

Scoring factors (additive, evidence-backed):
  unverified publisher                    +25
  admin_consent (tenant-wide scope)       +30
  admin_consent (non-tenant scope)        +15
  sensitivity = critical                  +30
  sensitivity = high                      +20
  sensitivity = moderate                  +10
  multiple sensitive data categories >2   +10
  unknown owner                           +15
  shadow AI (suspected/unknown)           +10
  over-privileged OAuth scopes            +10

Governance state (deterministic from categories):
  ungoverned          — unverified publisher or shadow AI
  partially_governed  — governance/ownership gaps present
  governed            — no governance gaps, publisher verified
  exception_granted   — operator-granted; set via PATCH (cannot be set at generation)
  unknown             — reserved default

Regulatory flags (deterministic from categories + sensitive_data_exposure):
  NIST_AI_RMF     — always
  EU_AI_ACT       — unverified_publisher / tenant_wide_permissions / shadow_ai
  GDPR            — sensitive_data_access
  State_Privacy_Law — sensitive_data_access
  ISO_42001       — no_approval_record / unknown_owner / no_dpa_baa_vendor_review
  HIPAA           — health/medical/PHI exposure signal in sensitive_data_exposure
  PCI_DSS         — payment/card/PCI signal
  SOX             — financial_reporting/accounting signal
  GLBA            — banking/GLBA signal
  FFIEC           — ffiec/federal_financial signal

Graph-ready identifiers (no traversal — identifiers only):
  risk_node_id       "risk:{tenant_id}:{risk_record_id}"
  owner_node_id      "owner:{tenant_id}:{risk_record_id}"
  vendor_node_id     "vendor:{tenant_id}:{vendor_slug}"
  decision_node_id   "decision:{tenant_id}:{risk_record_id}"
  governance_node_id "governance:{tenant_id}:{risk_record_id}"
  graph_node_id      "external_risk:{tenant_id}:{risk_record_id}" (backwards compat)
"""

from __future__ import annotations

import uuid
from typing import Any

RISK_ENGINE_VERSION = "external-ai-risk-engine-v1"
SCHEMA_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Risk categories — ordered by severity for primary category selection
# ---------------------------------------------------------------------------

RISK_CATEGORIES = (
    "tenant_wide_permissions",
    "sensitive_data_access",
    "unverified_publisher",
    "overprivileged_oauth",
    "shadow_ai",
    "unknown_owner",
    "no_dpa_baa_vendor_review",
    "no_approval_record",
)

# ---------------------------------------------------------------------------
# Over-privileged OAuth scope patterns
# ---------------------------------------------------------------------------

_OVERPRIVILEGED_SCOPES: frozenset[str] = frozenset(
    {
        "Files.Read.All",
        "Files.ReadWrite.All",
        "Mail.Read.All",
        "Mail.ReadWrite.All",
        "Mail.Send.All",
        "Sites.Read.All",
        "Sites.ReadWrite.All",
        "Sites.FullControl.All",
        "Drive.Read.All",
        "Drive.ReadWrite.All",
        "Directory.Read.All",
        "Directory.ReadWrite.All",
        "User.Read.All",
        "User.ReadWrite.All",
        "Group.Read.All",
        "Group.ReadWrite.All",
        "AuditLog.Read.All",
        "Chat.Read.All",
        "Chat.ReadWrite.All",
        "ChannelMessage.Read.All",
        "TeamSettings.ReadWrite.All",
        "Calendars.Read.Shared",
        "Contacts.Read.Shared",
    }
)

# ---------------------------------------------------------------------------
# Recommended actions — deterministic from primary category
# ---------------------------------------------------------------------------

_RECOMMENDED_ACTIONS: dict[str, str] = {
    "tenant_wide_permissions": (
        "Review the tenant-wide admin consent grant. Restrict to user-delegated "
        "permissions where possible. Document business justification for tenant-wide access."
    ),
    "sensitive_data_access": (
        "Document data access justification. Obtain a Data Processing Agreement (DPA) "
        "or BAA from the vendor if applicable. Assign a data owner."
    ),
    "unverified_publisher": (
        "Conduct a vendor security review. Verify publisher identity via Microsoft's "
        "publisher verification program. Obtain DPA/BAA if applicable."
    ),
    "overprivileged_oauth": (
        "Review and reduce OAuth permission scopes to the minimum required. "
        "Remove delegated or application permissions that are not used by the tool."
    ),
    "shadow_ai": (
        "Verify AI tool usage with the requester. Obtain formal governance approval "
        "or revoke access from the tenant."
    ),
    "unknown_owner": (
        "Assign a named business owner and technical owner to this AI tool. "
        "Document the owner in the AI tool registry."
    ),
    "no_dpa_baa_vendor_review": (
        "Conduct a vendor review. Obtain a Data Processing Agreement (DPA) or BAA "
        "from the vendor before continued use of this AI tool."
    ),
    "no_approval_record": (
        "Document a formal governance decision approving this AI tool's use. "
        "Include the approver, date, scope, and review schedule."
    ),
}

# ---------------------------------------------------------------------------
# Governance state constants
# ---------------------------------------------------------------------------

GOVERNANCE_STATES = (
    "ungoverned",
    "partially_governed",
    "governed",
    "exception_granted",
    "unknown",
)

OWNER_TYPES = (
    "IT",
    "Security",
    "Compliance",
    "Legal",
    "HR",
    "Finance",
    "Operations",
    "Product",
    "Unknown",
)

VENDOR_REVIEW_STATUSES = (
    "not_reviewed",
    "under_review",
    "approved",
    "restricted",
    "prohibited",
)

REMEDIATION_STATUSES = (
    "not_started",
    "planned",
    "in_progress",
    "completed",
    "risk_accepted",
)

# Ordered for deterministic output
_REGULATORY_FLAG_ORDER: tuple[str, ...] = (
    "EU_AI_ACT",
    "NIST_AI_RMF",
    "ISO_42001",
    "HIPAA",
    "PCI_DSS",
    "SOX",
    "GLBA",
    "FFIEC",
    "GDPR",
    "State_Privacy_Law",
)

# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------


def _score_permissions(permissions: list[str]) -> int:
    """Add points for over-privileged OAuth scopes."""
    for perm in permissions:
        if perm in _OVERPRIVILEGED_SCOPES:
            return 10
    return 0


def _score_sensitivity(sensitivity: str) -> int:
    return {
        "critical": 30,
        "high": 20,
        "moderate": 10,
        "low": 0,
        "unknown": 0,
    }.get(sensitivity, 0)


def _compute_risk_score(
    *,
    verified_publisher: bool,
    admin_consent: bool,
    exposure_scope: str,
    sensitivity: str,
    data_categories: list[str],
    data_owner: str,
    confidence: str,
    permissions: list[str],
) -> int:
    score = 0
    if not verified_publisher:
        score += 25
    if admin_consent:
        if exposure_scope == "tenant":
            score += 30
        else:
            score += 15
    score += _score_sensitivity(sensitivity)
    if len([c for c in data_categories if c not in ("", "unknown")]) > 2:
        score += 10
    if data_owner.lower() in ("unknown", ""):
        score += 15
    if confidence in ("suspected", "unknown"):
        score += 10
    score += _score_permissions(permissions)
    return score


def _score_to_label(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "moderate"
    return "low"


# ---------------------------------------------------------------------------
# Risk category detection
# ---------------------------------------------------------------------------


def _detect_categories(
    *,
    verified_publisher: bool,
    admin_consent: bool,
    exposure_scope: str,
    sensitivity: str,
    data_owner: str,
    confidence: str,
    permissions: list[str],
    has_approval_record: bool,
    has_vendor_review: bool,
) -> list[str]:
    cats: list[str] = []
    if admin_consent and exposure_scope == "tenant":
        cats.append("tenant_wide_permissions")
    if sensitivity in ("high", "critical"):
        cats.append("sensitive_data_access")
    if not verified_publisher:
        cats.append("unverified_publisher")
    if any(p in _OVERPRIVILEGED_SCOPES for p in permissions):
        cats.append("overprivileged_oauth")
    if confidence in ("suspected", "unknown"):
        cats.append("shadow_ai")
    if data_owner.lower() in ("unknown", ""):
        cats.append("unknown_owner")
    if not has_vendor_review:
        cats.append("no_dpa_baa_vendor_review")
    if not has_approval_record:
        cats.append("no_approval_record")
    # Preserve deterministic order
    return [c for c in RISK_CATEGORIES if c in cats]


def _primary_category(categories: list[str]) -> str:
    if not categories:
        return "no_approval_record"
    return categories[0]


# ---------------------------------------------------------------------------
# Risk reason builder
# ---------------------------------------------------------------------------


def _build_risk_reason(
    *,
    tool_name: str,
    vendor: str,
    verified_publisher: bool,
    admin_consent: bool,
    exposure_scope: str,
    sensitivity: str,
    data_categories: list[str],
    data_owner: str,
    confidence: str,
    permissions: list[str],
    categories: list[str],
) -> str:
    parts: list[str] = []

    if not verified_publisher:
        parts.append("publisher is not Microsoft-verified")
    if admin_consent and exposure_scope == "tenant":
        parts.append("tenant-wide admin consent granted")
    elif admin_consent:
        parts.append("admin consent granted")
    if sensitivity in ("high", "critical"):
        cat_str = (
            ", ".join(data_categories[:3]) if data_categories else "sensitive data"
        )
        parts.append(f"{sensitivity} sensitivity data access ({cat_str})")
    if any(p in _OVERPRIVILEGED_SCOPES for p in permissions):
        broad = [p for p in permissions if p in _OVERPRIVILEGED_SCOPES]
        parts.append(f"over-privileged scopes ({', '.join(broad[:3])})")
    if confidence in ("suspected", "unknown"):
        parts.append(f"tool confidence is {confidence} (shadow AI pattern)")
    if data_owner.lower() in ("unknown", ""):
        parts.append("no data owner assigned")
    if "no_approval_record" in categories:
        parts.append("no governance approval record")

    if not parts:
        return f"{tool_name} by {vendor} has no critical risk indicators at this time."

    reason = f"{tool_name} by {vendor}: " + "; ".join(parts) + "."
    return reason[0].upper() + reason[1:]


# ---------------------------------------------------------------------------
# Governance state (deterministic)
# ---------------------------------------------------------------------------


def _determine_governance_state(categories: list[str]) -> str:
    """Return governance_state from risk categories.

    Precedence (most severe first):
      ungoverned          — unverified publisher or shadow AI present
      partially_governed  — ownership/approval/vendor-review gaps
      governed            — no governance gaps detected
    exception_granted is reserved for operator-set values (not generated here).
    """
    cat_set = set(categories)
    if "unverified_publisher" in cat_set or "shadow_ai" in cat_set:
        return "ungoverned"
    if cat_set & {"unknown_owner", "no_approval_record", "no_dpa_baa_vendor_review"}:
        return "partially_governed"
    if cat_set:
        return "partially_governed"
    return "governed"


# ---------------------------------------------------------------------------
# Regulatory flags (deterministic)
# ---------------------------------------------------------------------------


def _determine_regulatory_flags(
    categories: list[str],
    sensitive_data_exposure: list[str],
) -> list[str]:
    """Return ordered list of applicable regulatory frameworks.

    Assignments are deterministic — based solely on categories and
    sensitive_data_exposure content. No AI inference.
    """
    flags: set[str] = {"NIST_AI_RMF"}
    cat_set = set(categories)

    if cat_set & {"unverified_publisher", "tenant_wide_permissions", "shadow_ai"}:
        flags.add("EU_AI_ACT")
    if "sensitive_data_access" in cat_set:
        flags.add("GDPR")
        flags.add("State_Privacy_Law")
    if cat_set & {"no_approval_record", "unknown_owner", "no_dpa_baa_vendor_review"}:
        flags.add("ISO_42001")

    # Industry-specific: keyword signals in sensitive_data_exposure labels
    exposure_lower = {s.lower() for s in sensitive_data_exposure}

    def _has(*keywords: str) -> bool:
        return any(kw in label for label in exposure_lower for kw in keywords)

    if _has("health", "medical", "phi", "hipaa"):
        flags.add("HIPAA")
    if _has("payment", "card", "pci"):
        flags.add("PCI_DSS")
    if _has("sox", "financial_reporting", "accounting"):
        flags.add("SOX")
    if _has("banking", "glba"):
        flags.add("GLBA")
    if _has("ffiec", "federal_financial"):
        flags.add("FFIEC")

    return [f for f in _REGULATORY_FLAG_ORDER if f in flags]


# ---------------------------------------------------------------------------
# Data access summary builder
# ---------------------------------------------------------------------------


def _build_data_access_summary(
    *,
    data_categories: list[str],
    sensitivity: str,
    exposure_scope: str,
    permissions: list[str],
) -> str:
    if not data_categories and not permissions:
        return "No data access mapping available."
    cats = ", ".join(data_categories[:5]) if data_categories else "unknown"
    perm_count = len(permissions)
    return (
        f"Accesses {cats} data ({sensitivity} sensitivity) "
        f"via {perm_count} permission(s); scope: {exposure_scope}."
    )


# ---------------------------------------------------------------------------
# Main engine entry point
# ---------------------------------------------------------------------------


def generate_risk_records(
    *,
    tools: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
    pr1_scan_result_id: str,
    pr2_scan_result_id: str | None,
    tenant_id: str,
    engagement_id: str,
    existing_risk_ids: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Generate deterministic risk records from PR 1 tools and PR 2 mappings.

    Args:
        tools: list of tool dicts from PR 1 normalized_payload["tools"]
        mappings: list of mapping dicts from PR 2 normalized_payload["mappings"]
        pr1_scan_result_id: FK to the PR 1 FaScanResult
        pr2_scan_result_id: FK to the PR 2 FaScanResult (None if PR 2 not yet run)
        tenant_id: tenant partition key
        engagement_id: engagement partition key
        existing_risk_ids: {tool_name: existing_record_id} for idempotent regeneration

    Returns:
        (risk_records, findings) — both are plain dicts ready for bridge import
    """
    if existing_risk_ids is None:
        existing_risk_ids = {}

    # Index mappings by tool_name for O(1) lookup
    mapping_by_tool: dict[str, dict[str, Any]] = {}
    for m in mappings:
        name = str(m.get("tool_name") or "")
        if name:
            mapping_by_tool[name] = m

    risk_records: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for tool in tools:
        tool_name = str(tool.get("tool_name") or "unknown")
        vendor = str(tool.get("vendor") or "unknown")
        tool_id = tool.get("app_id") or tool.get("service_principal_id") or tool_name

        # PR 2 data (may be absent if PR 2 hasn't run)
        m = mapping_by_tool.get(tool_name, {})
        sensitivity = str(m.get("sensitivity") or "unknown")
        data_categories = list(m.get("data_categories") or [])
        data_owner = str(m.get("data_owner") or "Unknown")
        exposure_scope = str(m.get("exposure_scope") or "unknown")

        # PR 1 data
        verified_publisher = bool(tool.get("verified_publisher"))
        admin_consent = bool(tool.get("admin_consent"))
        confidence = str(tool.get("confidence") or "unknown")
        permissions = list(tool.get("permissions") or tool.get("all_permissions") or [])
        if not permissions:
            perm_summary = str(tool.get("permissions_summary") or "")
            if perm_summary and perm_summary != "unknown":
                permissions = [
                    p.strip()
                    for p in perm_summary.replace(",", " ").split()
                    if p.strip()
                ]

        evidence_refs: list[str] = list(tool.get("evidence_refs") or [])
        if pr1_scan_result_id:
            evidence_refs.append(f"ai_tool_discovery:{pr1_scan_result_id}")
        if pr2_scan_result_id and tool_name in mapping_by_tool:
            evidence_refs.append(f"ai_data_access_mapping:{pr2_scan_result_id}")

        categories = _detect_categories(
            verified_publisher=verified_publisher,
            admin_consent=admin_consent,
            exposure_scope=exposure_scope,
            sensitivity=sensitivity,
            data_owner=data_owner,
            confidence=confidence,
            permissions=permissions,
            has_approval_record=False,
            has_vendor_review=False,
        )

        score = _compute_risk_score(
            verified_publisher=verified_publisher,
            admin_consent=admin_consent,
            exposure_scope=exposure_scope,
            sensitivity=sensitivity,
            data_categories=data_categories,
            data_owner=data_owner,
            confidence=confidence,
            permissions=permissions,
        )
        risk_score = _score_to_label(score)
        primary_category = _primary_category(categories)

        risk_reason = _build_risk_reason(
            tool_name=tool_name,
            vendor=vendor,
            verified_publisher=verified_publisher,
            admin_consent=admin_consent,
            exposure_scope=exposure_scope,
            sensitivity=sensitivity,
            data_categories=data_categories,
            data_owner=data_owner,
            confidence=confidence,
            permissions=permissions,
            categories=categories,
        )
        recommended_action = _RECOMMENDED_ACTIONS.get(
            primary_category, _RECOMMENDED_ACTIONS["no_approval_record"]
        )
        data_access_summary = _build_data_access_summary(
            data_categories=data_categories,
            sensitivity=sensitivity,
            exposure_scope=exposure_scope,
            permissions=permissions,
        )
        publisher_trust = "verified" if verified_publisher else "unverified"
        sensitive_exposure = [c for c in data_categories if c not in ("", "unknown")]

        # Use existing ID for idempotent regeneration
        record_id = existing_risk_ids.get(tool_name) or str(uuid.uuid4())
        graph_node_id = f"external_risk:{tenant_id}:{record_id}"

        # Addition 2 — governance state (deterministic)
        governance_state = _determine_governance_state(categories)

        # Addition 5 — regulatory flags (deterministic)
        regulatory_flags = _determine_regulatory_flags(categories, sensitive_exposure)

        # Addition 10 — graph-ready node identifiers
        vendor_slug = vendor.lower().replace(" ", "_").replace("-", "_")[:64]
        risk_node_id = f"risk:{tenant_id}:{record_id}"
        owner_node_id = f"owner:{tenant_id}:{record_id}"
        vendor_node_id = f"vendor:{tenant_id}:{vendor_slug}"
        decision_node_id = f"decision:{tenant_id}:{record_id}"
        governance_node_id = f"governance:{tenant_id}:{record_id}"

        risk_records.append(
            {
                "id": record_id,
                "tenant_id": tenant_id,
                "engagement_id": engagement_id,
                "tool_id": str(tool_id),
                "tool_name": tool_name,
                "vendor": vendor,
                "business_owner": "Unknown",
                "technical_owner": "Unknown",
                # Addition 1 — ownership model
                "risk_owner": None,
                "owner_type": "Unknown",
                "permissions": permissions,
                "data_access_summary": data_access_summary,
                "sensitive_data_exposure": sensitive_exposure,
                "publisher_trust": publisher_trust,
                "user_count": tool.get("user_count"),
                "admin_consent": admin_consent,
                "risk_score": risk_score,
                "risk_reason": risk_reason,
                "risk_category": primary_category,
                "risk_categories": categories,
                "recommended_action": recommended_action,
                # Addition 7 — remediation tracking
                "remediation_status": "not_started",
                "remediation_target_date": None,
                "remediation_completed_at": None,
                "review_status": "unreviewed",
                # Addition 2 — governance state
                "governance_state": governance_state,
                # Addition 3 — decision linkage (populated by future governance workflows)
                "decision_refs": [],
                "risk_acceptance_refs": [],
                "exception_refs": [],
                "approval_refs": [],
                # Addition 4 — vendor governance status (defaults; future PR 3.5)
                "vendor_review_status": "not_reviewed",
                "vendor_dpa_status": "unknown",
                "vendor_baa_status": "unknown",
                "vendor_security_review_status": "unknown",
                "vendor_last_reviewed_at": None,
                # Addition 5 — regulatory flags
                "regulatory_flags": regulatory_flags,
                # Addition 6 — risk aging (first_detected_at/last_observed_at set by bridge)
                "risk_age_days": None,
                "first_detected_at": None,
                "last_observed_at": None,
                "last_reviewed_at": None,
                "evidence_refs": list(dict.fromkeys(evidence_refs)),
                "finding_refs": [],
                "graph_node_id": graph_node_id,
                # Addition 10 — graph-ready node identifiers
                "risk_node_id": risk_node_id,
                "owner_node_id": owner_node_id,
                "vendor_node_id": vendor_node_id,
                "decision_node_id": decision_node_id,
                "governance_node_id": governance_node_id,
                "source_scan_result_id": pr2_scan_result_id,
                "pr1_scan_result_id": pr1_scan_result_id,
            }
        )

        # Generate findings for high/critical risks
        if risk_score in ("critical", "high"):
            findings.append(
                {
                    "type": f"external_ai_risk.{risk_score}",
                    "severity": risk_score,
                    "title": f"AI Risk: {tool_name} — {primary_category.replace('_', ' ').title()}",
                    "description": risk_reason,
                    "recommendation": recommended_action,
                    "tool_name": tool_name,
                    "vendor": vendor,
                    "risk_categories": categories,
                    "evidence_refs": evidence_refs,
                    "risk_record_id": record_id,
                }
            )

    # Sort: critical first, then alphabetical within each band
    _order = {"critical": 0, "high": 1, "moderate": 2, "low": 3}
    risk_records.sort(
        key=lambda r: (
            _order.get(r["risk_score"], 4),
            r["tool_name"],
        )
    )

    return risk_records, findings


def build_summary(risk_records: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregate summary metrics over the generated risk records.

    Addition 8: extended with governance_distribution, vendor_distribution,
    remediation_distribution, regulatory_distribution, and autonomous-governance
    counters (risks_without_review, risks_without_vendor_approval, stale_risks).
    """
    score_dist: dict[str, int] = {"critical": 0, "high": 0, "moderate": 0, "low": 0}
    category_dist: dict[str, int] = {c: 0 for c in RISK_CATEGORIES}
    governance_dist: dict[str, int] = {s: 0 for s in GOVERNANCE_STATES}
    vendor_dist: dict[str, int] = {s: 0 for s in VENDOR_REVIEW_STATUSES}
    remediation_dist: dict[str, int] = {s: 0 for s in REMEDIATION_STATUSES}
    regulatory_dist: dict[str, int] = {}
    ownership_gaps = 0
    governance_gaps = 0
    risks_without_review = 0
    risks_without_vendor_approval = 0
    stale_risks = 0

    for r in risk_records:
        score = r["risk_score"]
        if score in score_dist:
            score_dist[score] += 1
        for cat in r.get("risk_categories") or []:
            if cat in category_dist:
                category_dist[cat] += 1
        if r["business_owner"] in ("Unknown", "") and not r.get("risk_owner"):
            ownership_gaps += 1
        if "no_approval_record" in (r.get("risk_categories") or []):
            governance_gaps += 1

        gov_state = r.get("governance_state") or "unknown"
        governance_dist[gov_state] = governance_dist.get(gov_state, 0) + 1

        vendor_status = r.get("vendor_review_status") or "not_reviewed"
        if vendor_status in vendor_dist:
            vendor_dist[vendor_status] += 1

        rem_status = r.get("remediation_status") or "not_started"
        if rem_status in remediation_dist:
            remediation_dist[rem_status] += 1

        for flag in r.get("regulatory_flags") or []:
            regulatory_dist[flag] = regulatory_dist.get(flag, 0) + 1

        if r.get("review_status") == "unreviewed":
            risks_without_review += 1
        if vendor_status in ("not_reviewed", "unknown"):
            risks_without_vendor_approval += 1
        age = r.get("risk_age_days")
        if isinstance(age, int) and age > 90:
            stale_risks += 1

    return {
        "total_risks": len(risk_records),
        "score_distribution": score_dist,
        "category_distribution": category_dist,
        "ownership_gaps": ownership_gaps,
        "governance_gaps": governance_gaps,
        "shadow_ai_count": category_dist.get("shadow_ai", 0),
        "unverified_publisher_count": category_dist.get("unverified_publisher", 0),
        "tenant_wide_count": category_dist.get("tenant_wide_permissions", 0),
        # Addition 8 — executive dashboard distributions
        "governance_distribution": governance_dist,
        "vendor_distribution": vendor_dist,
        "remediation_distribution": remediation_dist,
        "regulatory_distribution": regulatory_dist,
        # Addition 11 — autonomous governance metadata
        "risks_without_review": risks_without_review,
        "risks_without_vendor_approval": risks_without_vendor_approval,
        "stale_risks": stale_risks,
    }
