"""Auth0 ProviderAdapter implementation.

This module is the only place Auth0-specific logic lives. Routers call
provider-neutral services; services call this adapter through the
ProviderAdapter protocol. This adapter never issues tenant sessions and
never makes direct authorization decisions — it validates identity claims
and returns an AuthenticatedIdentity for Admin Gateway to act on.

Security invariants:
- Auth0 may authenticate. Admin Gateway decides whether a governed session exists.
- Callback state digest is verified before any claim is trusted.
- Organization ID and connection ID are enforced when tenant policy requires them.
- email_verified=True is enforced before any claim is accepted.
- Management tokens, client secrets, and raw tokens are never logged or stored.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional
from urllib.parse import urlencode

import httpx


from admin_gateway.identity.auth0_config import (
    Auth0Config,
    Auth0ConfigError,
    get_auth0_config,
)
from admin_gateway.identity.auth0_management import (
    Auth0ManagementClient,
    Auth0ManagementError,
)
from admin_gateway.identity.auth0_models import (
    Auth0ConnectionResult,
    Auth0IdentityClaims,
    Auth0OrgResult,
    Auth0ProvisioningResult,
)
from admin_gateway.identity.identity_context import AuthenticatedIdentity
from admin_gateway.identity.provider_adapter import (
    AuthInstructions,
    ProviderAdapterError,
)

log = logging.getLogger("admin-gateway.auth0.adapter")

PROVIDER_NAME = "auth0"
REQUIRED_SCOPES = ("openid", "profile", "email")


class Auth0AdapterError(ProviderAdapterError):
    pass


class Auth0Adapter:
    """Auth0 implementation of the ProviderAdapter protocol.

    Accepts an Auth0Config and an optional management client (injectable for
    tests). Falls back to building a live management client from config when
    none is provided.
    """

    def __init__(
        self,
        config: Optional[Auth0Config] = None,
        management_client: Optional[Auth0ManagementClient] = None,
    ) -> None:
        if config is None:
            try:
                config = get_auth0_config()
            except Auth0ConfigError as exc:
                raise Auth0AdapterError(f"AUTH0_CONFIG_MISSING:{exc.code}") from exc
        self._config = config
        self._mgmt: Auth0ManagementClient = (
            management_client
            if management_client is not None
            else Auth0ManagementClient(config)
        )

    # ------------------------------------------------------------------
    # ProviderAdapter protocol — required interface
    # ------------------------------------------------------------------

    def start_invitation_auth(
        self,
        *,
        provider: str,
        state: str,
        connection_id: Optional[str],
        organization_id: Optional[str],
    ) -> AuthInstructions:
        if provider != PROVIDER_NAME:
            raise Auth0AdapterError(f"PROVIDER_NOT_SUPPORTED:{provider}")
        url = self.build_org_aware_login_url(
            state=state,
            connection_id=connection_id,
            organization_id=organization_id,
        )
        return AuthInstructions(
            provider=PROVIDER_NAME,
            connection_id=connection_id,
            organization_id=organization_id,
            auth_start_url=url,
            adapter="auth0",
        )

    def _exchange_code(self, code: str) -> dict[str, Any]:
        """Exchange an authorization code for tokens via POST /oauth/token."""
        payload = {
            "grant_type": "authorization_code",
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
            "code": code,
            "redirect_uri": self._config.callback_url,
        }
        resp = httpx.post(self._config.token_url, json=payload, timeout=10.0)
        if resp.status_code != 200:
            log.warning("auth0.code_exchange_failed status=%d", resp.status_code)
            raise Auth0AdapterError("CODE_EXCHANGE_FAILED")
        return resp.json()

    def validate_callback(
        self, callback_payload: dict[str, Any]
    ) -> AuthenticatedIdentity:
        """Validate an Auth0 callback payload and return a verified identity.

        Accepts either an authorization code (response_type=code flow) or a
        direct id_token (test/internal flows). The caller owns state-digest
        verification. This method validates the ID token signature/claims and
        normalizes them into an AuthenticatedIdentity. It fails closed on any
        claim that does not meet policy.
        """
        id_token = callback_payload.get("id_token")
        code = callback_payload.get("code")

        if not id_token and not code:
            raise Auth0AdapterError("MISSING_ID_TOKEN")

        if not id_token:
            token_response = self._exchange_code(code)  # type: ignore[arg-type]
            id_token = token_response.get("id_token")
            if not id_token:
                raise Auth0AdapterError("MISSING_ID_TOKEN")

        claims = self._verify_id_token(id_token)
        return self._claims_to_authenticated_identity(claims, callback_payload)

    # ------------------------------------------------------------------
    # URL builders
    # ------------------------------------------------------------------

    def build_org_aware_login_url(
        self,
        *,
        state: str,
        connection_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> str:
        """Build an Auth0 /authorize URL with org and connection when required."""
        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": self._config.callback_url,
            "scope": " ".join(REQUIRED_SCOPES),
            "state": state,
        }
        if nonce:
            params["nonce"] = nonce
        if organization_id:
            params["organization"] = organization_id
        if connection_id:
            params["connection"] = connection_id
        return f"{self._config.authorize_url}?{urlencode(params)}"

    def build_managed_signup_or_login_url(
        self,
        *,
        state: str,
        connection_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        nonce: Optional[str] = None,
        screen_hint: str = "signup",
    ) -> str:
        """Build an Auth0 /authorize URL for managed (database) signup/login."""
        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": self._config.callback_url,
            "scope": " ".join(REQUIRED_SCOPES),
            "state": state,
            "screen_hint": screen_hint,
        }
        if nonce:
            params["nonce"] = nonce
        if organization_id:
            params["organization"] = organization_id
        if connection_id:
            params["connection"] = connection_id
        return f"{self._config.authorize_url}?{urlencode(params)}"

    # ------------------------------------------------------------------
    # Provisioning operations (tenant SSO / managed setup)
    # ------------------------------------------------------------------

    def ensure_organization(
        self,
        *,
        tenant_id: str,
        org_name: str,
        display_name: str,
        existing_org_id: Optional[str] = None,
    ) -> Auth0OrgResult:
        """Create or associate an Auth0 Organization for the tenant."""
        try:
            if existing_org_id:
                return self._mgmt.associate_organization(existing_org_id)
            return self._mgmt.create_organization(
                name=org_name,
                display_name=display_name,
                tenant_id=tenant_id,
            )
        except Auth0ManagementError as exc:
            raise Auth0AdapterError(f"ORG_PROVISION_FAILED:{exc.code}") from exc

    def ensure_connection_attached(
        self,
        *,
        org_id: str,
        connection_id: str,
    ) -> Auth0ConnectionResult:
        """Attach the enterprise connection to the org, idempotently."""
        try:
            return self._mgmt.attach_connection_to_org(
                org_id=org_id,
                connection_id=connection_id,
                assign_membership_on_login=False,
            )
        except Auth0ManagementError as exc:
            raise Auth0AdapterError(f"CONNECTION_ATTACH_FAILED:{exc.code}") from exc

    def provision_tenant_identity(
        self,
        *,
        tenant_id: str,
        org_name: str,
        display_name: str,
        connection_id: str,
        existing_org_id: Optional[str] = None,
    ) -> Auth0ProvisioningResult:
        """Full SSO provisioning: create org + attach connection.

        On any failure the caller must NOT activate the tenant identity config
        or any membership. The error_code in the result is safe to store.
        """
        org_result: Optional[Auth0OrgResult] = None
        try:
            org_result = self.ensure_organization(
                tenant_id=tenant_id,
                org_name=org_name,
                display_name=display_name,
                existing_org_id=existing_org_id,
            )
        except Auth0AdapterError as exc:
            return Auth0ProvisioningResult(
                organization_id=None,
                connection_id=None,
                status="failed",
                error_code=exc.code,
            )

        try:
            self.ensure_connection_attached(
                org_id=org_result.organization_id,
                connection_id=connection_id,
            )
        except Auth0AdapterError as exc:
            return Auth0ProvisioningResult(
                organization_id=org_result.organization_id,
                connection_id=None,
                status="partial",
                error_code=exc.code,
            )

        return Auth0ProvisioningResult(
            organization_id=org_result.organization_id,
            connection_id=connection_id,
            status="success",
            error_code=None,
        )

    def provision_invited_user(
        self,
        *,
        tenant_id: str,
        invitation_id: str,
        email: str,
        org_id: Optional[str],
        connection_id: Optional[str],
    ) -> None:
        """No-op at the Auth0 layer: users authenticate via start-auth flow.

        Auth0 does not need to be pre-provisioned per invitation; the org-aware
        login URL handles user routing. This method exists to satisfy the
        interface and provide an extension point for future SCIM push.
        """

    # ------------------------------------------------------------------
    # Invitation policy resolution helpers
    # ------------------------------------------------------------------

    def resolve_invitation_requirements(
        self,
        *,
        identity_mode: str,
        connection_id: Optional[str],
        organization_id: Optional[str],
        allowed_email_domains: tuple[str, ...],
    ) -> dict[str, Any]:
        """Return the Auth0-specific requirements for an invitation start-auth."""
        return {
            "provider": PROVIDER_NAME,
            "identity_mode": identity_mode,
            "connection_id": connection_id,
            "organization_id": organization_id,
            "org_login_required": self._config.org_login_required,
            "allowed_email_domains": list(allowed_email_domains),
        }

    def start_invitation_auth_sso(
        self,
        *,
        state: str,
        connection_id: str,
        organization_id: Optional[str],
        nonce: Optional[str] = None,
    ) -> AuthInstructions:
        """SSO invite start — org + connection required."""
        url = self.build_org_aware_login_url(
            state=state,
            connection_id=connection_id,
            organization_id=organization_id,
            nonce=nonce,
        )
        return AuthInstructions(
            provider=PROVIDER_NAME,
            connection_id=connection_id,
            organization_id=organization_id,
            auth_start_url=url,
            adapter="auth0",
        )

    def start_invitation_auth_managed(
        self,
        *,
        state: str,
        organization_id: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> AuthInstructions:
        """Managed invite start — database connection, no enterprise connection."""
        url = self.build_managed_signup_or_login_url(
            state=state,
            organization_id=organization_id,
            nonce=nonce,
        )
        return AuthInstructions(
            provider=PROVIDER_NAME,
            connection_id=None,
            organization_id=organization_id,
            auth_start_url=url,
            adapter="auth0",
        )

    # ------------------------------------------------------------------
    # Token verification and claim normalization (private)
    # ------------------------------------------------------------------

    def _verify_id_token(self, id_token: str) -> dict[str, Any]:
        """Verify Auth0 ID token using JWKS and return verified claims.

        Enforces: issuer, audience, expiry, signature. Raises Auth0AdapterError
        on any validation failure. Never logs the raw token.
        """
        try:
            import jwt
            from jwt.algorithms import ECAlgorithm, RSAAlgorithm
        except ImportError as exc:
            raise Auth0AdapterError("JWT_LIBRARY_MISSING") from exc

        try:
            header = jwt.get_unverified_header(id_token)
        except Exception as exc:
            raise Auth0AdapterError("TOKEN_HEADER_INVALID") from exc

        kid = header.get("kid")
        try:
            jwks = self._mgmt.get_jwks()
        except Exception as exc:
            raise Auth0AdapterError("JWKS_FETCH_FAILED") from exc

        keys = jwks.get("keys", [])
        key_data = next((k for k in keys if k.get("kid") == kid), None)
        if key_data is None:
            raise Auth0AdapterError("JWKS_KEY_NOT_FOUND")

        alg = header.get("alg", "RS256")
        try:
            public_key: Any
            if alg.startswith(("RS", "PS")):
                public_key = RSAAlgorithm.from_jwk(json.dumps(key_data))
            elif alg.startswith("ES"):
                public_key = ECAlgorithm.from_jwk(json.dumps(key_data))
            else:
                raise Auth0AdapterError("TOKEN_ALG_NOT_SUPPORTED")

            claims = jwt.decode(
                id_token,
                public_key,
                algorithms=[alg],
                audience=self._config.client_id,
                issuer=self._config.issuer,
                options={"require": ["exp", "iss", "sub", "aud"]},
            )
        except Exception as exc:
            log.warning("auth0.token.verification_failed type=%s", type(exc).__name__)
            raise Auth0AdapterError("TOKEN_VERIFICATION_FAILED") from exc

        return claims

    def _claims_to_authenticated_identity(
        self,
        claims: dict[str, Any],
        callback_payload: dict[str, Any],
    ) -> AuthenticatedIdentity:
        """Normalize verified Auth0 claims into AuthenticatedIdentity.

        Enforces:
        - email_verified must be True
        - sub must be present and non-empty
        - email must be present and casefold-normalized
        - issuer must match Auth0 domain
        - org_id if present must come from claims, not raw payload
        """
        subject = claims.get("sub", "").strip()
        if not subject:
            raise Auth0AdapterError("MISSING_SUBJECT")

        email_raw = claims.get("email", "").strip()
        if not email_raw:
            raise Auth0AdapterError("MISSING_EMAIL")

        if not claims.get("email_verified", False):
            raise Auth0AdapterError("EMAIL_NOT_VERIFIED")

        issuer = claims.get("iss", "").rstrip("/") + "/"
        expected = self._config.issuer
        if issuer != expected:
            raise Auth0AdapterError("ISSUER_MISMATCH")

        # org_id comes from the verified token claim, not the raw callback body
        org_id: Optional[str] = claims.get("org_id") or None

        # connection_id is injected server-side by the router from auth_state
        # (key: server_requested_connection_id). Never trust the caller-controlled
        # "connection" field — it is stripped before reaching this method.
        connection_id: Optional[str] = (
            callback_payload.get("server_requested_connection_id") or None
        )

        return AuthenticatedIdentity(
            provider=PROVIDER_NAME,
            issuer=self._config.issuer,
            subject=subject,
            email=email_raw.casefold(),
            email_verified=True,
            connection_id=connection_id,
            organization_id=org_id,
            identity_type="human",
        )

    # ------------------------------------------------------------------
    # Normalize email consistently with PR 1 policy helpers
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_identity_claims(raw_claims: dict[str, Any]) -> Auth0IdentityClaims:
        """Pure claim normalization — no network calls, no secrets required.

        This is used by callers that have already verified the token and just
        need a typed, safe representation of the claims.
        """
        subject = raw_claims.get("sub", "").strip()
        email = raw_claims.get("email", "").strip().casefold()
        email_verified = bool(raw_claims.get("email_verified", False))
        issuer = raw_claims.get("iss", "")
        org_id = raw_claims.get("org_id") or None
        return Auth0IdentityClaims(
            provider=PROVIDER_NAME,
            issuer=issuer,
            subject=subject,
            email=email,
            email_verified=email_verified,
            organization_id=org_id,
            connection_id=None,
            identity_type="human",
        )
