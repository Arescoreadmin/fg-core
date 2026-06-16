from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

import jwt
from jwt.algorithms import RSAAlgorithm

from api.security.outbound_policy import sanitize_url_for_log, validate_target

log = logging.getLogger("frostgate.federation")

FEDERATION_ALLOWED_ALGORITHMS: frozenset[str] = frozenset({"RS256"})
FEDERATION_CLOCK_SKEW_SECONDS: int = int(
    os.getenv("FEDERATION_CLOCK_SKEW_SECONDS", "60")
)


class FederationValidationError(Exception):
    def __init__(self, error_code: str, reason: str) -> None:
        super().__init__(f"{error_code}: {reason}")
        self.error_code = error_code
        self.reason = reason


@dataclass(frozen=True)
class FederationPrincipal:
    subject: str
    issuer: str
    tenant_id: str
    groups: list[str] = field(default_factory=list)
    raw_claims: dict[str, Any] = field(default_factory=dict)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


class JWKSCache:
    def __init__(self) -> None:
        self._doc: dict[str, Any] | None = None
        self._exp = 0.0

    def get(
        self, url: str, ttl_seconds: int = 300, *, force_refresh: bool = False
    ) -> dict[str, Any]:
        now = time.time()
        if self._doc is not None and now < self._exp and not force_refresh:
            return self._doc

        normalized_url, _ = validate_target(url)
        opener = urllib.request.build_opener(_NoRedirect())
        req = urllib.request.Request(
            normalized_url, headers={"Accept": "application/json"}
        )
        try:
            with opener.open(req, timeout=5) as resp:
                status = int(getattr(resp, "status", 200))
                if status != 200:
                    raise ValueError(
                        f"jwks_fetch_failed:{status}:{sanitize_url_for_log(url)}"
                    )
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ValueError(
                f"jwks_fetch_failed:{exc.code}:{sanitize_url_for_log(url)}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ValueError(
                f"jwks_fetch_failed:transport:{sanitize_url_for_log(url)}"
            ) from exc

        self._doc = payload
        self._exp = now + ttl_seconds
        return payload


def _rsa_key_for_kid(jwks: dict[str, Any], kid: str) -> object | None:
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return RSAAlgorithm.from_jwk(json.dumps(key))
    return None


class FederationService:
    def __init__(self) -> None:
        self.cache = JWKSCache()

    def validate_token(self, jwt_token: str) -> FederationPrincipal:
        try:
            return self._do_validate(jwt_token)
        except FederationValidationError as exc:
            log.warning(
                "federation.token_rejected",
                extra={"error_code": exc.error_code, "reason": exc.reason},
            )
            raise

    def _do_validate(self, jwt_token: str) -> FederationPrincipal:
        jwks_url = (os.getenv("FG_FEDERATION_JWKS_URL") or "").strip()
        issuer_cfg = (os.getenv("FG_FEDERATION_ISSUER") or "").strip()
        audience_cfg = (os.getenv("FG_FEDERATION_AUDIENCE") or "").strip()

        if not jwks_url or not issuer_cfg or not audience_cfg:
            raise FederationValidationError(
                "federation_not_configured",
                "FG_FEDERATION_JWKS_URL, FG_FEDERATION_ISSUER, and FG_FEDERATION_AUDIENCE are required",
            )

        # Parse header without verification to extract alg and kid
        try:
            header = jwt.get_unverified_header(jwt_token)
        except Exception as exc:
            raise FederationValidationError(
                "federation_malformed_token", "invalid jwt header"
            ) from exc

        alg = header.get("alg", "")
        if alg not in FEDERATION_ALLOWED_ALGORITHMS:
            raise FederationValidationError(
                "federation_algorithm_rejected",
                f"algorithm {alg!r} is not permitted (allowed: RS256)",
            )

        kid = str(header.get("kid") or "")

        # Resolve signing key from JWKS; retry once on kid miss (handles key rotation)
        try:
            jwks = self.cache.get(jwks_url)
        except ValueError as exc:
            raise FederationValidationError(
                "federation_jwks_unavailable", str(exc)
            ) from exc

        rsa_key = _rsa_key_for_kid(jwks, kid)
        if rsa_key is None:
            log.info("federation.jwks_kid_miss_refreshing", extra={"kid": kid})
            try:
                jwks = self.cache.get(jwks_url, force_refresh=True)
            except ValueError as exc:
                raise FederationValidationError(
                    "federation_jwks_unavailable", str(exc)
                ) from exc
            rsa_key = _rsa_key_for_kid(jwks, kid)

        if rsa_key is None:
            raise FederationValidationError(
                "federation_unknown_kid", f"no JWKS key found for kid={kid!r}"
            )

        # Cryptographic signature + claims verification
        try:
            claims = jwt.decode(
                jwt_token,
                rsa_key,  # type: ignore[arg-type]
                algorithms=["RS256"],
                issuer=issuer_cfg,
                audience=audience_cfg,
                options={"require": ["sub", "exp", "iss", "aud"]},
                leeway=FEDERATION_CLOCK_SKEW_SECONDS,
            )
        except jwt.ExpiredSignatureError as exc:
            raise FederationValidationError(
                "federation_token_expired", "token is expired"
            ) from exc
        except jwt.ImmatureSignatureError as exc:
            raise FederationValidationError(
                "federation_token_not_yet_valid", "token nbf is in the future"
            ) from exc
        except jwt.InvalidIssuerError as exc:
            raise FederationValidationError(
                "federation_invalid_issuer", "issuer mismatch"
            ) from exc
        except jwt.InvalidAudienceError as exc:
            raise FederationValidationError(
                "federation_invalid_audience", "audience mismatch"
            ) from exc
        except jwt.MissingRequiredClaimError as exc:
            raise FederationValidationError(
                "federation_missing_claim", str(exc)
            ) from exc
        except jwt.InvalidTokenError as exc:
            raise FederationValidationError(
                "federation_invalid_token", str(exc)
            ) from exc

        sub = str(claims.get("sub") or "")
        if not sub:
            raise FederationValidationError(
                "federation_missing_sub", "sub claim is required and must be non-empty"
            )

        tenant_id = str(claims.get("tenant_id") or claims.get("tid") or "")
        if not tenant_id:
            raise FederationValidationError(
                "federation_missing_tenant", "tenant_id (or tid) claim is required"
            )

        groups_raw = claims.get("groups")
        groups = [str(g) for g in groups_raw] if isinstance(groups_raw, list) else []

        principal = FederationPrincipal(
            subject=sub,
            issuer=str(claims.get("iss", "")),
            tenant_id=tenant_id,
            groups=groups,
            raw_claims=claims,
        )
        log.info(
            "federation.token_accepted",
            extra={
                "sub_prefix": sub[:16],
                "issuer": issuer_cfg,
                "tenant_id": tenant_id,
                "kid": kid,
            },
        )
        return principal

    def map_roles(self, groups: list[str]) -> list[str]:
        raw = (os.getenv("FG_FEDERATION_GROUP_ROLE_MAP") or "").strip()
        mapping: dict[str, str] = {}
        if raw:
            for item in raw.split(","):
                if ":" in item:
                    g, role = item.split(":", 1)
                    mapping[g.strip()] = role.strip()
        return [mapping[g] for g in groups if g in mapping]
