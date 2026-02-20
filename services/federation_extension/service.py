from __future__ import annotations

import base64
import json
import os
import time
from typing import Any

import requests

from api.security.outbound_policy import sanitize_url_for_log, validate_target


class JWKSCache:
    def __init__(self) -> None:
        self._doc: dict[str, Any] | None = None
        self._exp = 0.0

    def get(self, url: str, ttl_seconds: int = 300) -> dict[str, Any]:
        now = time.time()
        if self._doc is not None and now < self._exp:
            return self._doc
        normalized_url, _ = validate_target(url)
        resp = requests.get(normalized_url, timeout=5, allow_redirects=False)
        if resp.status_code != 200:
            raise ValueError(f"jwks_fetch_failed:{resp.status_code}:{sanitize_url_for_log(url)}")
        payload = resp.json()
        self._doc = payload
        self._exp = now + ttl_seconds
        return payload


class FederationService:
    def __init__(self) -> None:
        self.cache = JWKSCache()

    def _decode_payload(self, jwt_token: str) -> dict[str, Any]:
        parts = jwt_token.split(".")
        if len(parts) < 2:
            raise ValueError("federation_invalid_token")
        payload_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")))

    def validate_token(self, jwt_token: str) -> dict[str, Any]:
        payload = self._decode_payload(jwt_token)
        issuer = str(payload.get("iss", ""))
        expected = (os.getenv("FG_FEDERATION_ISSUER") or "").strip()
        if expected and issuer != expected:
            raise ValueError("federation_invalid_issuer")
        return payload

    def map_roles(self, groups: list[str]) -> list[str]:
        raw = (os.getenv("FG_FEDERATION_GROUP_ROLE_MAP") or "").strip()
        mapping: dict[str, str] = {}
        if raw:
            for item in raw.split(","):
                if ":" in item:
                    g, role = item.split(":", 1)
                    mapping[g.strip()] = role.strip()
        return [mapping[g] for g in groups if g in mapping]
