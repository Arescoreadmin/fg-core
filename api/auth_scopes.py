from __future__ import annotations

import os
import logging
from dataclasses import dataclass
from typing import Callable, Optional, Set

from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

log = logging.getLogger("frostgate.auth")

API_KEY_HEADER = APIKeyHeader(name="x-api-key", auto_error=False)

# Scopes are strings like: "decisions:read", "defend:write"
# Env format:
#   FG_API_KEYS="ADMIN_abc|decisions:read,defend:write;AGENT_xyz|decisions:read"
# Also support a legacy/global key:
#   FG_API_KEY="ADMIN_..."   (treated as all-scopes for MVP)
#   FG_ADMIN_KEY="ADMIN_..." (same)


@dataclass(frozen=True)
class Principal:
    key_id: str
    scopes: Set[str]
    is_admin: bool = False


def _parse_scoped_keys_env() -> dict[str, Principal]:
    raw = (os.getenv("FG_API_KEYS") or os.getenv("FG_SCOPED_KEYS") or "").strip()
    principals: dict[str, Principal] = {}

    if not raw:
        return principals

    entries = [e.strip() for e in raw.split(";") if e.strip()]
    for entry in entries:
        # "<key>|scope1,scope2"
        if "|" not in entry:
            # No scopes segment -> treat as invalid (fail closed)
            log.warning("Ignoring invalid FG_API_KEYS entry (missing '|'): %r", entry)
            continue

        key, scopes_str = entry.split("|", 1)
        key = key.strip()
        scopes = {s.strip() for s in scopes_str.split(",") if s.strip()}

        if not key:
            log.warning("Ignoring invalid FG_API_KEYS entry (empty key): %r", entry)
            continue

        principal = Principal(
            key_id=key,
            scopes=scopes,
            is_admin=key.startswith("ADMIN_"),
        )
        principals[key] = principal
        log.info("principal=%s scopes=%s", principal.key_id, sorted(principal.scopes))

    return principals


# Parse once at import for speed; you can restart container to reload env.
_PRINCIPALS = _parse_scoped_keys_env()


def _global_admin_key() -> Optional[str]:
    # Backwards compat + easy MVP admin
    return (
        (os.getenv("FG_ADMIN_KEY") or "").strip()
        or (os.getenv("FG_API_KEY") or "").strip()
    ) or None


async def verify_api_key(api_key: str | None = Depends(API_KEY_HEADER)) -> Principal:
    if not api_key:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Missing API key")

    # Global admin key: treat as admin with wildcard behavior (MVP)
    gk = _global_admin_key()
    if gk and api_key == gk:
        return Principal(key_id=api_key, scopes=set(["*"]), is_admin=True)

    principal = _PRINCIPALS.get(api_key)
    if principal is None:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    return principal


def _has_scope(p: Principal, scope: str) -> bool:
    if p.is_admin:
        return True
    if "*" in p.scopes:
        return True
    return scope in p.scopes


def require_scope(scope: str) -> Callable:
    async def _dep(p: Principal = Depends(verify_api_key)) -> Principal:
        if not _has_scope(p, scope):
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail=f"Missing scope: {scope}")
        return p
    return _dep


def require_any_scope(*scopes: str) -> Callable:
    needed = [s for s in scopes if s]
    async def _dep(p: Principal = Depends(verify_api_key)) -> Principal:
        if p.is_admin or "*" in p.scopes:
            return p
        for s in needed:
            if s in p.scopes:
                return p
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail=f"Missing scope: one of {', '.join(needed)}",
        )
    return _dep
