"""api/actor_context.py — Provider-agnostic identity contract for FrostGate (H14).

ActorContext is the universal identity representation that flows through the
FrostGate authorization layer. It is populated by an IdentityProvider (Auth0,
Entra, Okta, or API key) and consumed by require_permission().

Routes depend on ActorContext. Routes never import Auth0-specific types.

Permission model:
  - ALL_PERMISSIONS: explicit enumeration of every permission in the system
  - ROLE_PERMISSIONS: role → frozenset[permission] mapping
  - SoD invariants enforced by omission (roles do not inherit across authority boundaries)

SoD design decisions (deliberate, do not remove without compliance review):
  - tenant_admin does NOT inherit compliance_reviewer permissions
    → bank admins cannot approve their own risk acceptances
  - compliance_reviewer does NOT inherit qa_reviewer
    → compliance officers cannot close findings before QA review
  - assessor does NOT have finding.approve
    → assessors cannot self-approve findings they created
  - bundle.generate (assessor) is split from bundle.approve (qa_reviewer)
    → mechanical bundle creation is separate from governance sign-off
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional, TypedDict

# ---------------------------------------------------------------------------
# Permission registry — explicit enumeration, no wildcards
# ---------------------------------------------------------------------------

ALL_PERMISSIONS: frozenset[str] = frozenset(
    {
        # Assessment lifecycle
        "assessment.create",
        "assessment.read",
        # Findings
        "finding.create",
        "finding.read",
        "finding.approve",
        "finding.close",
        # Evidence
        "evidence.upload",
        "evidence.read",
        "evidence.review",
        # Scans
        "scan.trigger",
        "scan.read",
        # Reports
        "report.generate",
        "report.read",
        "report.qa_approve",
        # Verification bundles — generate (assessor) is split from approve (governance)
        "bundle.generate",
        "bundle.approve",
        "bundle.read",
        # Governance decisions
        "risk.accept",
        "exception.grant",
        "governance.decision",
        "governance.read",
        # Cross-boundary promotion
        "governance.promote",
        # Administration — deliberately separate from compliance authority (SoD)
        "key.manage",
        "user.invite",
        "connector.manage",
        "tenant.configure",
        # Platform
        "platform.admin",
        # Actor attribution — read and write non-repudiation records (SoD: separate from governance)
        "actor.read",
        "actor.write",
        # Identity assurance — read and write assurance level / trust score records
        "assurance.read",
        "assurance.write",
    }
)

# ---------------------------------------------------------------------------
# Capability registry — metadata for every permission.
# ALL_PERMISSIONS and CAPABILITY_REGISTRY must stay in sync; a unit test
# enforces this so CI fails before any undocumented capability can ship.
# ---------------------------------------------------------------------------


class _CapabilityMeta(TypedDict):
    display_name: str
    description: str
    risk_level: Literal["low", "medium", "high", "critical"]


CAPABILITY_REGISTRY: dict[str, _CapabilityMeta] = {
    # Assessment lifecycle
    "assessment.create": {
        "display_name": "Create Assessment",
        "description": "Start a new assessment engagement",
        "risk_level": "medium",
    },
    "assessment.read": {
        "display_name": "View Assessment",
        "description": "Read assessment data and status",
        "risk_level": "low",
    },
    # Findings
    "finding.create": {
        "display_name": "Create Finding",
        "description": "Record a new finding against a control or evidence item",
        "risk_level": "medium",
    },
    "finding.read": {
        "display_name": "View Findings",
        "description": "Read findings and their remediation status",
        "risk_level": "low",
    },
    "finding.approve": {
        "display_name": "Approve Finding",
        "description": "Approve or reject a finding — QA sign-off only (SoD: not assessor)",
        "risk_level": "high",
    },
    "finding.close": {
        "display_name": "Close Finding",
        "description": "Mark a finding as resolved or closed",
        "risk_level": "high",
    },
    # Evidence
    "evidence.upload": {
        "display_name": "Upload Evidence",
        "description": "Submit evidence artifacts to an engagement",
        "risk_level": "medium",
    },
    "evidence.read": {
        "display_name": "View Evidence",
        "description": "Read evidence documents and metadata",
        "risk_level": "low",
    },
    "evidence.review": {
        "display_name": "Review Evidence",
        "description": "Validate and annotate uploaded evidence",
        "risk_level": "medium",
    },
    # Scans
    "scan.trigger": {
        "display_name": "Trigger Scan",
        "description": "Initiate a connector scan against a target system",
        "risk_level": "medium",
    },
    "scan.read": {
        "display_name": "View Scan Results",
        "description": "Read scan results and job status",
        "risk_level": "low",
    },
    # Reports
    "report.generate": {
        "display_name": "Generate Report",
        "description": "Compile a draft assessment report",
        "risk_level": "medium",
    },
    "report.read": {
        "display_name": "View Report",
        "description": "Read assessment reports and their sections",
        "risk_level": "low",
    },
    "report.qa_approve": {
        "display_name": "QA Approve Report",
        "description": "Apply final QA sign-off to a report (non-repudiation anchor)",
        "risk_level": "high",
    },
    # Verification bundles
    "bundle.generate": {
        "display_name": "Generate Bundle",
        "description": "Assemble a verification bundle from evidence (mechanical step)",
        "risk_level": "medium",
    },
    "bundle.approve": {
        "display_name": "Approve Bundle",
        "description": "Governance sign-off on a verification bundle (SoD: not assessor)",
        "risk_level": "high",
    },
    "bundle.read": {
        "display_name": "View Bundle",
        "description": "Read verification bundles and their contents",
        "risk_level": "low",
    },
    # Governance decisions — critical; SoD: not tenant_admin, not assessor
    "risk.accept": {
        "display_name": "Accept Risk",
        "description": "Record a formal risk acceptance decision",
        "risk_level": "critical",
    },
    "exception.grant": {
        "display_name": "Grant Exception",
        "description": "Issue a compliance exception for a control",
        "risk_level": "critical",
    },
    "governance.decision": {
        "display_name": "Record Governance Decision",
        "description": "Emit a governance event against an engagement",
        "risk_level": "critical",
    },
    "governance.read": {
        "display_name": "View Governance Intelligence",
        "description": "Read governance intelligence, orchestration, and analytics data",
        "risk_level": "low",
    },
    # Cross-boundary promotion
    "governance.promote": {
        "display_name": "Promote to Governance",
        "description": "Promote an assessment deliverable to autonomous governance",
        "risk_level": "high",
    },
    # Administration — SoD: separate from compliance and QA authority
    "key.manage": {
        "display_name": "Manage API Keys",
        "description": "Mint, rotate, and revoke tenant API keys",
        "risk_level": "high",
    },
    "user.invite": {
        "display_name": "Invite User",
        "description": "Send tenant membership invitations",
        "risk_level": "medium",
    },
    "connector.manage": {
        "display_name": "Manage Connectors",
        "description": "Configure and authorize connector integrations",
        "risk_level": "high",
    },
    "tenant.configure": {
        "display_name": "Configure Tenant",
        "description": "Modify tenant-level settings and identity configuration",
        "risk_level": "high",
    },
    # Platform
    "platform.admin": {
        "display_name": "Platform Administration",
        "description": "Full platform access including cross-tenant operations",
        "risk_level": "critical",
    },
    # Actor attribution
    "actor.read": {
        "display_name": "View Actor Attribution",
        "description": "Read actor identity records and attribution chains (non-repudiation audit)",
        "risk_level": "low",
    },
    "actor.write": {
        "display_name": "Write Actor Attribution",
        "description": "Create and update actor attribution records (service/automation use)",
        "risk_level": "medium",
    },
    # Identity assurance
    "assurance.read": {
        "display_name": "View Identity Assurance",
        "description": "Read actor assurance levels, trust scores, and assurance history",
        "risk_level": "low",
    },
    "assurance.write": {
        "display_name": "Recalculate Identity Assurance",
        "description": "Trigger recomputation of actor assurance level and trust score",
        "risk_level": "medium",
    },
}

# Role → permission mapping.
# Roles are assigned in Auth0 (or via tenant_rbac.py for API keys).
# Every route checks a permission, not a role name.
# Adding a new role: add an entry here; no route changes required.
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset(
        {
            "assessment.read",
            "finding.read",
            "evidence.read",
            "scan.read",
            "report.read",
            "bundle.read",
            "governance.read",
        }
    ),
    "assessor": frozenset(
        {
            # inherits viewer
            "assessment.read",
            "finding.read",
            "evidence.read",
            "scan.read",
            "report.read",
            "bundle.read",
            "governance.read",
            # assessor-only
            "assessment.create",
            "finding.create",
            "evidence.upload",
            "scan.trigger",
            "report.generate",
            "bundle.generate",  # mechanical; approve requires qa_reviewer
        }
    ),
    "qa_reviewer": frozenset(
        {
            # inherits viewer
            "assessment.read",
            "finding.read",
            "evidence.read",
            "scan.read",
            "report.read",
            "bundle.read",
            "governance.read",
            # qa_reviewer-only
            "finding.approve",
            "finding.close",
            "evidence.review",
            "report.qa_approve",
            "bundle.approve",
        }
    ),
    "compliance_reviewer": frozenset(
        {
            # inherits viewer
            "assessment.read",
            "finding.read",
            "evidence.read",
            "scan.read",
            "report.read",
            "bundle.read",
            "governance.read",
            # compliance-only — separate from qa_reviewer (SoD: cannot close findings)
            "risk.accept",
            "exception.grant",
            "governance.decision",
        }
    ),
    "tenant_admin": frozenset(
        {
            # inherits viewer
            "assessment.read",
            "finding.read",
            "evidence.read",
            "scan.read",
            "report.read",
            "bundle.read",
            "governance.read",
            # admin-only — does NOT inherit compliance_reviewer or qa_reviewer (SoD)
            "key.manage",
            "user.invite",
            "connector.manage",
            "tenant.configure",
            "governance.promote",
            # actor attribution — admins can read the attribution audit trail
            "actor.read",
            # identity assurance — admins can read assurance levels/trust scores
            "assurance.read",
        }
    ),
    # platform_admin gets every permission — expanded explicitly, not via wildcard
    "platform_admin": ALL_PERMISSIONS,
    # Future roles — add entries here without touching any route files
    # "auditor": frozenset({...}),
    # "executive_reviewer": frozenset({...}),
    # "external_assessor": frozenset({...}),
    # "autonomous_governance_operator": frozenset({...}),
}

# Role hierarchy for attribution display (most → least privileged)
_ROLE_DISPLAY_HIERARCHY: tuple[str, ...] = (
    "platform_admin",
    "tenant_admin",
    "compliance_reviewer",
    "qa_reviewer",
    "assessor",
    "viewer",
)


def roles_to_permissions(roles: list[str]) -> frozenset[str]:
    """Expand a list of role names to the union of their permissions."""
    result: set[str] = set()
    for role in roles:
        result |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(result)


# ---------------------------------------------------------------------------
# ActorContext
# ---------------------------------------------------------------------------


@dataclass
class ActorContext:
    """Provider-agnostic identity representation.

    Populated by an IdentityProvider (Auth0, Entra, Okta, or API key).
    Consumed by require_permission().

    The subject field is the non-repudiation anchor:
      - Auth0:      "auth0|<id>"
      - Entra:       Azure OID
      - API key:    key prefix
    It is recorded in every governance event and cannot be spoofed after JWT
    validation.
    """

    subject: str  # globally unique identity anchor
    email: str  # empty string if unavailable
    name: str  # display name; empty string if unavailable
    permissions: frozenset  # resolved from roles at auth time
    roles: list[str]  # raw role names — stored in governance events
    auth_source: (
        str  # "oidc_auth0" | "oidc_entra" | "api_key" | "system" | "dev_bypass"
    )
    tenant_id: Optional[str]  # from JWT claim or API key binding
    membership_id: Optional[str] = (
        None  # tenant_users.id — populated after resolver lookup
    )

    def has_permission(self, perm: str) -> bool:
        return perm in self.permissions

    def primary_role(self) -> Optional[str]:
        """Return the most privileged role for attribution recording."""
        for r in _ROLE_DISPLAY_HIERARCHY:
            if r in self.roles:
                return r
        return self.roles[0] if self.roles else None

    def is_dev_bypass(self) -> bool:
        return self.auth_source == "dev_bypass"
