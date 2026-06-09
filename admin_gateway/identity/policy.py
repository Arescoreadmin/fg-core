"""Provider-neutral identity policy reads owned by Admin Gateway."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from admin_gateway.identity.models import (
    TenantIdentityConfig,
    TenantIdentityDomain,
    TenantIdentityProvider,
)


class IdentityPolicyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True)
class IdentityProviderPolicy:
    id: str | None
    provider: str
    oidc_issuer: str | None
    connection_id: str | None
    organization_id: str | None
    status: str


@dataclass(frozen=True)
class IdentityDomainPolicy:
    domain: str
    domain_type: str


@dataclass(frozen=True)
class TenantIdentityPolicy:
    tenant_id: str
    identity_mode: str
    provider: str
    provisioning_status: str
    allowed_email_domains: tuple[str, ...]
    required_connection_id: str | None
    oidc_issuer: str | None
    sso_enforced: bool
    providers: tuple[IdentityProviderPolicy, ...]
    domains: tuple[IdentityDomainPolicy, ...]


@dataclass(frozen=True)
class IdentityPolicyDecision:
    allowed: bool


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


def require_identity_configured(db: Session, tenant_id: str) -> TenantIdentityPolicy:
    row = (
        db.query(TenantIdentityConfig)
        .filter(TenantIdentityConfig.tenant_id == tenant_id)
        .one_or_none()
    )
    if row is None:
        raise IdentityPolicyError(
            "TENANT_IDENTITY_NOT_CONFIGURED",
            "tenant has no explicit identity configuration",
        )
    if row.provisioning_status != "ready":
        raise IdentityPolicyError(
            "TENANT_IDENTITY_NOT_READY", "tenant identity policy is not ready"
        )
    providers = (
        db.query(TenantIdentityProvider)
        .filter(TenantIdentityProvider.tenant_id == tenant_id)
        .order_by(TenantIdentityProvider.is_primary.desc(), TenantIdentityProvider.id)
        .all()
    )
    domains = (
        db.query(TenantIdentityDomain)
        .filter(TenantIdentityDomain.tenant_id == tenant_id)
        .order_by(TenantIdentityDomain.domain)
        .all()
    )
    return TenantIdentityPolicy(
        tenant_id=row.tenant_id,
        identity_mode=row.identity_mode,
        provider=row.provider,
        provisioning_status=row.provisioning_status,
        allowed_email_domains=normalized_domains(row.allowed_email_domains),
        required_connection_id=row.auth0_connection_id,
        oidc_issuer=row.oidc_issuer,
        sso_enforced=bool(row.sso_enforced),
        providers=tuple(
            IdentityProviderPolicy(
                id=p.id,
                provider=p.provider,
                oidc_issuer=p.oidc_issuer,
                connection_id=p.connection_id,
                organization_id=p.organization_id,
                status=p.status,
            )
            for p in providers
        ),
        domains=tuple(
            IdentityDomainPolicy(domain=d.domain, domain_type=d.domain_type)
            for d in domains
        ),
    )


def validate_invite_email_matches_identity(
    invite_email: str, authenticated_email: str
) -> IdentityPolicyDecision:
    return IdentityPolicyDecision(
        normalize_invite_email(invite_email)
        == normalize_invite_email(authenticated_email)
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
