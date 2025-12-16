from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Iterable, Set

from fastapi import Depends, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


@dataclass(frozen=True)
class Principal:
    key_id: str
    scopes: Set[str]


def _parse_scoped_keys_env() -> dict[str, Principal]:
    """
    Env format:
      FG_API_KEYS="key1|decisions:read,defend:write;key2|decisions:read"

    Notes:
      - No "|" means "legacy full access" (disable if you want strict).
      - Parsing happens ONCE at import. Restart service to apply env changes.
    """
    raw = os.getenv("FG_API_KEYS", "").strip()
    if not raw:
        return {}

    principals: dict[str, Principal] = {}
    for entry in raw.split(";"):
        entry = entry.strip()
        if not entry:
            continue

        if "|" not in entry:
            # Legacy: full access. If you want strict, raise RuntimeError instead.
            principals[entry] = Principal(
                key_id="legacy",
                scopes={"decisions:read", "defend:write"},
            )
            continue

        key, scopes_str = entry.split("|", 1)
        key = key.strip()
        scopes = {s.strip() for s in scopes_str.split(",") if s.strip()}
        principals[key] = Principal(key_id=key, scopes=scopes)

    return principals


# Parse ONCE (fast + consistent). Restart container to apply changes.
_PRINCIPALS = _parse_scoped_keys_env()


async def verify_api_key(api_key: str | None = Security(API_KEY_HEADER)) -> Principal:
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    p = _PRINCIPALS.get(api_key)
    if not p:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return p


def require_scope(scope: str) -> Callable:
    async def _dep(p: Principal = Depends(verify_api_key)) -> Principal:
        if scope not in p.scopes:
            raise HTTPException(status_code=403, detail=f"Missing scope: {scope}")
        return p

    return _dep


def require_any_scope(scopes: Iterable[str]) -> Callable:
    scopes_set = set(scopes)

    async def _dep(p: Principal = Depends(verify_api_key)) -> Principal:
        if not (p.scopes & scopes_set):
            raise HTTPException(
                status_code=403,
                detail=f"Missing required scope (any of): {sorted(scopes_set)}",
            )
        return p

    return _dep
