from __future__ import annotations

import base64
import ipaddress
import json
import os
import socket
import time
import urllib.request
from typing import Any
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# FG-AUD-002 PATCH: SSRF guard for outbound federation/JWKS fetches
# ---------------------------------------------------------------------------

def _is_restricted_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_reserved
    )


def _assert_safe_federation_url(url: str) -> None:
    """Block SSRF before any outbound request to a federation/JWKS endpoint.

    Enforces:
      - scheme must be https (http allowed only via FG_FEDERATION_ALLOW_HTTP=1 for dev)
      - host must not be a private/loopback/link-local/reserved IP
      - all resolved DNS addresses must pass the private-IP check
    Raises ValueError on any violation so callers can surface a clean error.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    allow_http = os.getenv("FG_FEDERATION_ALLOW_HTTP", "0").strip() == "1"

    if scheme not in {"http", "https"}:
        raise ValueError(f"federation_ssrf_blocked: scheme={scheme!r} not allowed")
    if scheme == "http" and not allow_http:
        raise ValueError(
            "federation_ssrf_blocked: http:// not allowed; "
            "set FG_FEDERATION_ALLOW_HTTP=1 only for dev/test overrides"
        )

    host = parsed.hostname
    if not host:
        raise ValueError("federation_ssrf_blocked: missing host")

    # Reject IP literals that are private/loopback.
    try:
        ip_val = ipaddress.ip_address(host)
        if _is_restricted_ip(ip_val):
            raise ValueError(
                f"federation_ssrf_blocked: private/loopback IP literal {ip_val}"
            )
        # IPv6-mapped IPv4 addresses (::ffff:192.168.x.x).
        if isinstance(ip_val, ipaddress.IPv6Address) and ip_val.ipv4_mapped is not None:
            mapped = ip_val.ipv4_mapped
            if _is_restricted_ip(mapped):
                raise ValueError(
                    f"federation_ssrf_blocked: IPv6-mapped private IP {ip_val} ({mapped})"
                )
    except ValueError as exc:
        if str(exc).startswith("federation_ssrf_blocked"):
            raise
        # hostname path — resolve DNS and check every address.
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as dns_err:
            raise ValueError(
                f"federation_ssrf_blocked: DNS resolution failed for {host!r}: {dns_err}"
            ) from dns_err
        for info in infos:
            ip_text = info[4][0]
            try:
                resolved = ipaddress.ip_address(ip_text)
            except ValueError:
                continue
            if _is_restricted_ip(resolved):
                raise ValueError(
                    f"federation_ssrf_blocked: DNS resolved to private/loopback IP "
                    f"{resolved} for host {host!r}"
                )
            # IPv6-mapped IPv4 check for DNS results too.
            if isinstance(resolved, ipaddress.IPv6Address) and resolved.ipv4_mapped is not None:
                mapped = resolved.ipv4_mapped
                if _is_restricted_ip(mapped):
                    raise ValueError(
                        f"federation_ssrf_blocked: DNS resolved to IPv6-mapped private IP "
                        f"{resolved} ({mapped}) for host {host!r}"
                    )


def _fetch_jwks_no_redirect(url: str, timeout: int = 5) -> bytes:
    """Fetch JWKS *url* with SSRF guard and redirect-following disabled."""
    _assert_safe_federation_url(url)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
            raise ValueError(
                f"federation_ssrf_blocked: redirect to {newurl!r} not allowed"
            )

    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "frostgate-federation/1"})
    with opener.open(req, timeout=timeout) as resp:
        return resp.read()


# ---------------------------------------------------------------------------
# JWKS cache — now uses SSRF-guarded fetch
# ---------------------------------------------------------------------------

class JWKSCache:
    def __init__(self) -> None:
        self._doc: dict[str, Any] | None = None
        self._exp = 0.0

    def get(self, url: str, ttl_seconds: int = 300) -> dict[str, Any]:
        now = time.time()
        if self._doc is not None and now < self._exp:
            return self._doc
        # FG-AUD-002: SSRF guard + no-redirect enforced in _fetch_jwks_no_redirect.
        raw = _fetch_jwks_no_redirect(url, timeout=5)
        payload = json.loads(raw.decode("utf-8"))
        self._doc = payload
        self._exp = now + ttl_seconds
        return payload


# ---------------------------------------------------------------------------
# Federation service
# ---------------------------------------------------------------------------

class FederationService:
    def __init__(self) -> None:
        self.cache = JWKSCache()

    def _decode_payload_unverified(self, jwt_token: str) -> dict[str, Any]:
        """Decode JWT payload WITHOUT verifying signature. Only used to extract 'iss' for routing."""
        parts = jwt_token.split(".")
        if len(parts) < 2:
            raise ValueError("federation_invalid_token")
        payload_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")))

    def _verify_signature(self, jwt_token: str, jwks: dict[str, Any], expected_issuer: str) -> dict[str, Any]:
        """Verify JWT signature using fetched JWKS. Raises ValueError on any failure.

        FG-AUD-001 patch: this replaces the previous no-op that only decoded base64.
        Supports RS256/RS384/RS512/PS256/ES256/ES384/ES512 via PyJWT.
        """
        try:
            import jwt as pyjwt
            from jwt import InvalidTokenError
            from jwt import algorithms as jwt_algorithms
        except ImportError as exc:
            raise RuntimeError(
                "PyJWT[cryptography] is required for federation JWT verification. "
                "Add 'PyJWT[cryptography]' to requirements.txt."
            ) from exc

        try:
            header = pyjwt.get_unverified_header(jwt_token)
        except Exception as exc:
            raise ValueError(f"federation_invalid_token_header: {exc}") from exc

        kid = header.get("kid")
        alg = header.get("alg", "")
        # Allowlist of permitted algorithms.
        allowed_algs = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
        if alg not in allowed_algs:
            raise ValueError(f"federation_unsupported_alg: {alg!r}")

        keys = jwks.get("keys", [])
        candidate = None
        for k in keys:
            if kid and k.get("kid") == kid:
                candidate = k
                break
        if candidate is None and not kid and keys:
            # No kid in header: pick first key whose kty matches.
            for k in keys:
                kty = k.get("kty", "")
                if alg.startswith(("RS", "PS")) and kty == "RSA":
                    candidate = k
                    break
                if alg.startswith("ES") and kty == "EC":
                    candidate = k
                    break
        if candidate is None:
            raise ValueError("federation_jwks_key_not_found")

        try:
            if alg.startswith(("RS", "PS")):
                public_key = jwt_algorithms.RSAAlgorithm.from_jwk(json.dumps(candidate))
            else:  # ES*
                public_key = jwt_algorithms.ECAlgorithm.from_jwk(json.dumps(candidate))
        except (ValueError, KeyError) as exc:
            raise ValueError(f"federation_jwk_parse_error: {exc}") from exc

        try:
            claims = pyjwt.decode(
                jwt_token,
                public_key,
                algorithms=[alg],
                options={
                    "require": ["exp", "iss"],
                    "verify_exp": True,
                    "verify_iss": True,
                },
                issuer=expected_issuer,
            )
        except InvalidTokenError as exc:
            raise ValueError(f"federation_token_invalid: {exc}") from exc

        return claims

    def validate_token(self, jwt_token: str) -> dict[str, Any]:
        """Decode, verify issuer, fetch JWKS (SSRF-guarded), and verify signature.

        FG-AUD-001 + FG-AUD-002 patches:
          - Previously: only decoded base64 payload, no signature verification.
          - Now: issuer checked against FG_FEDERATION_ISSUER (must be set),
            JWKS URL derived from *configured* issuer (not token's iss claim),
            signature verified cryptographically.
        """
        expected_issuer = (os.getenv("FG_FEDERATION_ISSUER") or "").strip()
        if not expected_issuer:
            raise ValueError(
                "federation_config_error: FG_FEDERATION_ISSUER must be configured "
                "before federation token validation is allowed"
            )

        # Unverified decode — only to confirm iss before fetching JWKS.
        unverified = self._decode_payload_unverified(jwt_token)
        issuer = str(unverified.get("iss", "")).strip()
        if issuer != expected_issuer:
            raise ValueError("federation_invalid_issuer")

        # JWKS URL: use the *configured* issuer, NOT the token's iss claim.
        # This prevents SSRF via attacker-supplied iss (FG-AUD-002).
        jwks_url = (os.getenv("FG_FEDERATION_JWKS_URL") or "").strip()
        if not jwks_url:
            jwks_url = expected_issuer.rstrip("/") + "/.well-known/jwks.json"

        jwks = self.cache.get(jwks_url)
        return self._verify_signature(jwt_token, jwks, expected_issuer)

    def map_roles(self, groups: list[str]) -> list[str]:
        raw = (os.getenv("FG_FEDERATION_GROUP_ROLE_MAP") or "").strip()
        mapping: dict[str, str] = {}
        if raw:
            for item in raw.split(","):
                if ":" in item:
                    g, role = item.split(":", 1)
                    mapping[g.strip()] = role.strip()
        return [mapping[g] for g in groups if g in mapping]
