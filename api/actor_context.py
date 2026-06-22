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
from typing import Optional

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
        # Cross-boundary promotion
        "governance.promote",
        # Administration — deliberately separate from compliance authority (SoD)
        "key.manage",
        "user.invite",
        "connector.manage",
        "tenant.configure",
        # Platform
        "platform.admin",
    }
)

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
            # admin-only — does NOT inherit compliance_reviewer or qa_reviewer (SoD)
            "key.manage",
            "user.invite",
            "connector.manage",
            "tenant.configure",
            "governance.promote",
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
