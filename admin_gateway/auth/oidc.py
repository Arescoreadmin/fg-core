"""OIDC authentication client.

Handles OAuth 2.0 / OpenID Connect authentication flow with any compliant provider
(Auth0, Google, Okta, etc.).
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any, Optional, Set
from urllib.parse import urlencode

import httpx

from admin_gateway.auth.config import AuthConfig, get_auth_config
from admin_gateway.auth.session import Session

log = logging.getLogger("admin-gateway.oidc")


@dataclass
class OIDCProvider:
    """OIDC provider configuration from discovery document."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: Optional[str]
    jwks_uri: str
    end_session_endpoint: Optional[str] = None

    @classmethod
    async def discover(cls, issuer: str) -> "OIDCProvider":
        """Discover OIDC provider configuration.

        Args:
            issuer: The OIDC issuer URL

        Returns:
            OIDCProvider with discovered endpoints
        """
        discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"

        # FG-AUD-005: follow_redirects=False prevents redirect-based SSRF.
        async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
            response = await client.get(discovery_url)
            response.raise_for_status()
            config = response.json()

        return cls(
            issuer=config["issuer"],
            authorization_endpoint=config["authorization_endpoint"],
            token_endpoint=config["token_endpoint"],
            userinfo_endpoint=config.get("userinfo_endpoint"),
            jwks_uri=config["jwks_uri"],
            end_session_endpoint=config.get("end_session_endpoint"),
        )


class OIDCClient:
    """OIDC authentication client.

    Handles the OAuth 2.0 authorization code flow with PKCE.
    """

    # State and nonce TTL (10 minutes)
    STATE_TTL = 600

    def __init__(self, config: Optional[AuthConfig] = None):
        """Initialize OIDC client.

        Args:
            config: Auth configuration
        """
        self.config = config or get_auth_config()
        self._provider: Optional[OIDCProvider] = None
        self._provider_cache_time: float = 0
        self._provider_cache_ttl: float = 3600  # 1 hour
        self._pending_states: dict[str, dict] = {}

    async def get_provider(self) -> OIDCProvider:
        """Get OIDC provider configuration (cached).

        Returns:
            OIDCProvider instance
        """
        now = time.time()

        if (
            self._provider
            and (now - self._provider_cache_time) < self._provider_cache_ttl
        ):
            return self._provider

        if not self.config.oidc_issuer:
            raise ValueError("OIDC issuer not configured")

        self._provider = await OIDCProvider.discover(self.config.oidc_issuer)
        self._provider_cache_time = now

        log.info("OIDC provider discovered: %s", self._provider.issuer)
        return self._provider

    def _generate_code_verifier(self) -> str:
        """Generate PKCE code verifier."""
        return secrets.token_urlsafe(64)

    def _generate_code_challenge(self, verifier: str) -> str:
        """Generate PKCE code challenge from verifier."""
        digest = hashlib.sha256(verifier.encode()).digest()
        return secrets.base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    async def get_authorization_url(
        self,
        scopes: Optional[list[str]] = None,
        extra_params: Optional[dict] = None,
    ) -> tuple[str, str, str]:
        """Generate authorization URL for login redirect.

        Args:
            scopes: OAuth scopes to request
            extra_params: Additional parameters to include

        Returns:
            Tuple of (authorization_url, state, code_verifier)
        """
        provider = await self.get_provider()

        # Generate state and PKCE values
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        code_verifier = self._generate_code_verifier()
        code_challenge = self._generate_code_challenge(code_verifier)

        # Store state for validation
        self._pending_states[state] = {
            "nonce": nonce,
            "code_verifier": code_verifier,
            "created_at": time.time(),
        }

        # Clean up old states
        self._cleanup_old_states()

        # Default scopes
        if scopes is None:
            scopes = ["openid", "profile", "email"]

        # Build authorization URL
        params = {
            "response_type": "code",
            "client_id": self.config.oidc_client_id,
            "redirect_uri": self.config.oidc_redirect_url,
            "scope": " ".join(scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        if extra_params:
            params.update(extra_params)

        url = f"{provider.authorization_endpoint}?{urlencode(params)}"
        return url, state, code_verifier

    def _cleanup_old_states(self) -> None:
        """Remove expired pending states."""
        now = time.time()
        expired = [
            state
            for state, data in self._pending_states.items()
            if now - data["created_at"] > self.STATE_TTL
        ]
        for state in expired:
            del self._pending_states[state]

    def validate_state(self, state: str) -> Optional[dict]:
        """Validate and consume a state parameter.

        Args:
            state: The state parameter from callback

        Returns:
            State data if valid, None otherwise
        """
        data = self._pending_states.pop(state, None)
        if not data:
            return None

        # Check TTL
        if time.time() - data["created_at"] > self.STATE_TTL:
            return None

        return data

    async def exchange_code(
        self,
        code: str,
        state: str,
    ) -> dict[str, Any]:
        """Exchange authorization code for tokens.

        Args:
            code: Authorization code from callback
            state: State parameter from callback

        Returns:
            Token response containing access_token, id_token, etc.

        Raises:
            ValueError: If state is invalid
            httpx.HTTPStatusError: If token exchange fails
        """
        state_data = self.validate_state(state)
        if not state_data:
            raise ValueError("Invalid or expired state")

        provider = await self.get_provider()

        # FG-AUD-005: follow_redirects=False on all outbound OIDC calls.
        async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
            response = await client.post(
                provider.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.config.oidc_redirect_url,
                    "client_id": self.config.oidc_client_id,
                    "client_secret": self.config.oidc_client_secret,
                    "code_verifier": state_data["code_verifier"],
                },
            )
            response.raise_for_status()
            return response.json()

    async def get_userinfo(self, access_token: str) -> dict[str, Any]:
        """Fetch user info from OIDC provider.

        Args:
            access_token: OAuth access token

        Returns:
            User info claims
        """
        provider = await self.get_provider()

        if not provider.userinfo_endpoint:
            raise ValueError("Provider does not have userinfo endpoint")

        # FG-AUD-005: follow_redirects=False on all outbound OIDC calls.
        async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
            response = await client.get(
                provider.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            return response.json()

    async def parse_id_token_claims(self, id_token: str) -> dict[str, Any]:
        """Parse and VERIFY claims from ID token using JWKS signature verification.

        FG-AUD-003 patch: previous implementation decoded base64 payload only and
        explicitly stated it was "a simplified implementation for demonstration"
        with no signature verification.  This is not acceptable in production.

        Now:
          1. Fetches JWKS from the OIDC provider (follow_redirects=False enforced).
          2. Selects the JWK matching the JWT 'kid' header.
          3. Cryptographically verifies the signature.
          4. Validates 'exp', 'aud', and 'iss' claims.

        Raises ValueError on any verification failure.  Never returns unverified claims.
        """
        import json

        try:
            import jwt as pyjwt
            from jwt import InvalidTokenError
            from jwt import algorithms as jwt_algorithms
        except ImportError as exc:
            raise RuntimeError(
                "PyJWT[cryptography] is required for ID token verification. "
                "Add 'PyJWT[cryptography]' to requirements.txt."
            ) from exc

        provider = await self.get_provider()

        # FG-AUD-005: follow_redirects=False prevents redirect-based SSRF.
        async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
            resp = await client.get(provider.jwks_uri)
            resp.raise_for_status()
            jwks = resp.json()

        try:
            header = pyjwt.get_unverified_header(id_token)
        except Exception as exc:
            raise ValueError(f"Invalid ID token header: {exc}") from exc

        kid = header.get("kid")
        alg = header.get("alg", "RS256")
        allowed_algs = {
            "RS256", "RS384", "RS512",
            "PS256", "PS384", "PS512",
            "ES256", "ES384", "ES512",
        }
        if alg not in allowed_algs:
            raise ValueError(f"Unsupported token algorithm: {alg!r}")

        keys = jwks.get("keys", [])
        candidate = None
        for k in keys:
            if kid and k.get("kid") == kid:
                candidate = k
                break
        if candidate is None and not kid and keys:
            for k in keys:
                kty = k.get("kty", "")
                if alg.startswith(("RS", "PS")) and kty == "RSA":
                    candidate = k
                    break
                if alg.startswith("ES") and kty == "EC":
                    candidate = k
                    break
        if candidate is None:
            raise ValueError("No matching JWK found for token kid")

        try:
            if alg.startswith(("RS", "PS")):
                public_key = jwt_algorithms.RSAAlgorithm.from_jwk(json.dumps(candidate))
            else:
                public_key = jwt_algorithms.ECAlgorithm.from_jwk(json.dumps(candidate))
        except (ValueError, KeyError) as exc:
            raise ValueError(f"Failed to parse JWK: {exc}") from exc

        try:
            claims = pyjwt.decode(
                id_token,
                public_key,
                algorithms=[alg],
                audience=self.config.oidc_client_id,
                issuer=self.config.oidc_issuer,
                options={
                    "require": ["exp", "iss", "aud"],
                    "verify_exp": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except InvalidTokenError as exc:
            log.warning("ID token signature verification failed: %s", exc)
            raise ValueError(f"Invalid ID token: {exc}") from exc

        return claims

    def extract_scopes_from_claims(self, claims: dict[str, Any]) -> Set[str]:
        """Extract admin scopes from OIDC claims.

        Looks for scopes in:
        1. 'fg_scopes' custom claim (list)
        2. 'roles' claim mapped to scopes
        3. 'groups' claim mapped to scopes

        Args:
            claims: OIDC token claims

        Returns:
            Set of admin scopes
        """
        scopes = set()

        # Direct scopes claim
        fg_scopes = claims.get("fg_scopes", [])
        if isinstance(fg_scopes, list):
            scopes.update(fg_scopes)
        elif isinstance(fg_scopes, str):
            scopes.add(fg_scopes)

        # Map roles to scopes
        roles = claims.get("roles", [])
        if isinstance(roles, list):
            role_mapping = {
                "admin": "console:admin",
                "frostgate-admin": "console:admin",
                "product-manager": "product:write",
                "key-manager": "keys:write",
                "auditor": "audit:read",
            }
            for role in roles:
                if role in role_mapping:
                    scopes.add(role_mapping[role])

        return scopes

    async def create_session_from_tokens(
        self,
        tokens: dict[str, Any],
    ) -> Session:
        """Create a session from OIDC token response.

        Args:
            tokens: Token response from exchange_code

        Returns:
            New Session object
        """
        # Parse and VERIFY ID token claims (FG-AUD-003: now async + signature-verified).
        id_token = tokens.get("id_token", "")
        claims = await self.parse_id_token_claims(id_token) if id_token else {}

        # Try to get additional info from userinfo
        access_token = tokens.get("access_token")
        if access_token:
            try:
                userinfo = await self.get_userinfo(access_token)
                claims.update(userinfo)
            except Exception as e:
                log.warning("Failed to fetch userinfo: %s", e)

        # Extract user info
        user_id = claims.get("sub", "unknown")
        email = claims.get("email")
        name = claims.get("name") or claims.get("preferred_username")

        # Extract scopes
        scopes = self.extract_scopes_from_claims(claims)

        # Extract tenant info
        tenant_id = claims.get("tenant_id")
        allowed_tenants = claims.get("allowed_tenants", [])
        if tenant_id and tenant_id not in allowed_tenants:
            allowed_tenants.append(tenant_id)

        return Session(
            user_id=user_id,
            email=email,
            name=name,
            scopes=scopes,
            claims=claims,
            tenant_id=tenant_id,
        )
