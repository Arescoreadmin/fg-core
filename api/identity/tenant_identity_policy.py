"""Pure provider-neutral tenant identity onboarding decisions.

This module never calls an identity provider, issues sessions, consumes invite
Tokens, or mutates membership state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_identity import (
    TenantIdentityConfig,
    TenantIdentityDomain,
    TenantIdentityProvider,
)

IDENTITY_MODES = frozenset({"managed", "sso", "hybrid"})
IDENTITY_TYPES = frozenset({"human", "service", "agent", "system"})


class IdentityPolicyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class IdentityProviderPolicy:
    id: str | None
    provider: str
    oidc_issuer: str | None
    connection_id: str | None
    organization_id: str | None = None
    status: str = "configured"
    is_primary: bool = False


@dataclass(frozen=True)
class IdentityDomainPolicy:
    domain: str
    domain_type: str = "trusted"
    verification_status: str = "unverified"
    provider_record_id: str | None = None


@dataclass(frozen=True)
class TenantIdentityPolicy:
    tenant_id: str
    identity_mode: str
    provider: str
    provisioning_status: str
    allowed_email_domains: tuple[str, ...] = ()
    required_connection_id: str | None = None
    oidc_issuer: str | None = None
    sso_enforced: bool = False
    maturity_level: str = "level_0"
    capability_flags: tuple[str, ...] = ()
    providers: tuple[IdentityProviderPolicy, ...] = ()
    domains: tuple[IdentityDomainPolicy, ...] = ()


@dataclass(frozen=True)
class IdentityPolicyDecision:
    allowed: bool
    code: str
    reason: str


def normalized_domains(raw: Any) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)):
        raise IdentityPolicyError(
            "IDENTITY_DOMAINS_INVALID", "allowed_email_domains must be a list"
        )
    domains: list[str] = []
    for value in raw:
        if not isinstance(value, str):
            raise IdentityPolicyError(
                "IDENTITY_DOMAINS_INVALID", "email domains must be strings"
            )
        domain = value.strip().lower().rstrip(".")
        if not domain or "@" in domain or domain.startswith(".") or ".." in domain:
            raise IdentityPolicyError(
                "IDENTITY_DOMAINS_INVALID", f"invalid email domain: {value!r}"
            )
        domains.append(domain)
    return tuple(sorted(set(domains)))


def normalize_invite_email(email: str) -> str:
    normalized = email.strip().casefold()
    local, separator, domain = normalized.rpartition("@")
    if (
        separator != "@"
        or not local
        or not domain
        or domain.startswith(".")
        or domain.endswith(".")
        or ".." in domain
    ):
        raise IdentityPolicyError("INVITE_EMAIL_INVALID", "email is not valid")
    return f"{local}@{domain}"


def get_tenant_identity_policy(
    db: Session, tenant_id: str
) -> TenantIdentityPolicy | None:
    row = (
        db.query(TenantIdentityConfig)
        .filter(TenantIdentityConfig.tenant_id == tenant_id)
        .one_or_none()
    )
    if row is None:
        return None
    provider_rows = (
        db.query(TenantIdentityProvider)
        .filter(TenantIdentityProvider.tenant_id == tenant_id)
        .order_by(TenantIdentityProvider.is_primary.desc(), TenantIdentityProvider.id)
        .all()
    )
    domain_rows = (
        db.query(TenantIdentityDomain)
        .filter(TenantIdentityDomain.tenant_id == tenant_id)
        .order_by(TenantIdentityDomain.domain, TenantIdentityDomain.domain_type)
        .all()
    )
    capabilities = (
        row.capability_flags if isinstance(row.capability_flags, dict) else {}
    )
    return TenantIdentityPolicy(
        row.tenant_id,
        row.identity_mode,
        row.provider,
        row.provisioning_status,
        normalized_domains(row.allowed_email_domains),
        row.auth0_connection_id,
        row.oidc_issuer,
        bool(row.sso_enforced),
        row.maturity_level,
        tuple(sorted(str(k) for k, enabled in capabilities.items() if enabled is True)),
        tuple(
            IdentityProviderPolicy(
                p.id,
                p.provider,
                p.oidc_issuer,
                p.connection_id,
                p.organization_id,
                p.status,
                bool(p.is_primary),
            )
            for p in provider_rows
        ),
        tuple(
            IdentityDomainPolicy(
                d.domain, d.domain_type, d.verification_status, d.provider_record_id
            )
            for d in domain_rows
        ),
    )


def require_identity_configured(db: Session, tenant_id: str) -> TenantIdentityPolicy:
    policy = get_tenant_identity_policy(db, tenant_id)
    if policy is None:
        raise IdentityPolicyError(
            "TENANT_IDENTITY_NOT_CONFIGURED",
            "tenant has no explicit identity configuration",
        )
    if policy.provisioning_status != "ready":
        raise IdentityPolicyError(
            "TENANT_IDENTITY_NOT_READY",
            f"tenant identity provisioning status is {policy.provisioning_status!r}",
        )
    return policy


def resolve_required_identity_mode(db: Session, tenant_id: str) -> str:
    return require_identity_configured(db, tenant_id).identity_mode


def validate_invite_email_matches_identity(
    invite_email: str, authenticated_email: str
) -> IdentityPolicyDecision:
    matches = normalize_invite_email(invite_email) == normalize_invite_email(
        authenticated_email
    )
    return IdentityPolicyDecision(
        matches,
        "INVITE_EMAIL_MATCH" if matches else "INVITE_EMAIL_MISMATCH",
        "authenticated email matches invitation"
        if matches
        else "authenticated email does not match invitation",
    )


def is_provider_allowed_for_tenant(
    policy: TenantIdentityPolicy,
    provider: str,
    *,
    issuer: str | None = None,
    connection_id: str | None = None,
) -> bool:
    if policy.providers:
        return any(
            record.status in {"configured", "ready"}
            and record.provider == provider
            and (record.oidc_issuer is None or record.oidc_issuer == issuer)
            and (record.connection_id is None or record.connection_id == connection_id)
            for record in policy.providers
        )
    return (
        provider == policy.provider
        and (policy.oidc_issuer is None or policy.oidc_issuer == issuer)
        and (
            policy.required_connection_id is None
            or policy.required_connection_id == connection_id
        )
    )


def is_connection_allowed_for_tenant(
    policy: TenantIdentityPolicy, connection_id: str | None
) -> bool:
    if policy.providers:
        return any(
            record.status in {"configured", "ready"}
            and (record.connection_id is None or record.connection_id == connection_id)
            for record in policy.providers
        )
    if policy.identity_mode == "managed" and not policy.sso_enforced:
        return policy.required_connection_id in (None, connection_id)
    return bool(
        connection_id
        and policy.required_connection_id
        and connection_id == policy.required_connection_id
    )


def is_email_domain_allowed(policy: TenantIdentityPolicy, email: str) -> bool:
    domain = normalize_invite_email(email).rsplit("@", 1)[1]
    if policy.domains:
        matches = [record for record in policy.domains if record.domain == domain]
        if any(record.domain_type == "blocked" for record in matches):
            return False
        return any(
            record.domain_type in {"trusted", "verified", "federated"}
            for record in matches
        )
    return not policy.allowed_email_domains or domain in policy.allowed_email_domains


def can_membership_be_activated_from_identity(
    *,
    invitation_status: str,
    membership_binding_status: str,
    identity_email_verified: bool,
    invite_email: str,
    authenticated_email: str,
    policy: TenantIdentityPolicy,
    authenticated_provider: str,
    connection_id: str | None,
    authenticated_issuer: str | None = None,
) -> IdentityPolicyDecision:
    checks = [
        (
            invitation_status == "bound",
            "INVITATION_NOT_BOUND",
            "invitation must be bound before membership activation",
        ),
        (
            membership_binding_status == "bound",
            "MEMBERSHIP_IDENTITY_NOT_BOUND",
            "membership identity binding is not complete",
        ),
        (
            identity_email_verified,
            "IDENTITY_EMAIL_UNVERIFIED",
            "identity email is not verified",
        ),
        (
            is_provider_allowed_for_tenant(
                policy,
                authenticated_provider,
                issuer=authenticated_issuer,
                connection_id=connection_id,
            ),
            "IDENTITY_PROVIDER_MISMATCH",
            "identity provider, issuer, or connection is not allowed",
        ),
        (
            is_connection_allowed_for_tenant(policy, connection_id),
            "IDENTITY_CONNECTION_NOT_ALLOWED",
            "connection is not allowed",
        ),
        (
            is_email_domain_allowed(policy, authenticated_email),
            "IDENTITY_EMAIL_DOMAIN_NOT_ALLOWED",
            "email domain is not allowed",
        ),
    ]
    email_decision = validate_invite_email_matches_identity(
        invite_email, authenticated_email
    )
    if not email_decision.allowed:
        return email_decision
    for allowed, code, reason in checks:
        if not allowed:
            return IdentityPolicyDecision(False, code, reason)
    return IdentityPolicyDecision(
        True,
        "MEMBERSHIP_ACTIVATION_ALLOWED",
        "verified identity is bound to the tenant membership",
    )
