#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "api" / "auth_scopes" / "mapping.py"


def must_replace(text: str, old: str, new: str) -> str:
    if old not in text:
        raise SystemExit(f"Expected block not found:\n{old}")
    return text.replace(old, new, 1)


def main() -> int:
    text = TARGET.read_text(encoding="utf-8")

    text = must_replace(
        text,
        """def _ensure_default_config_for_tenant(
    sqlite_path: str, tenant_id: Optional[str]
) -> None:
""",
        """def _ensure_default_config_for_tenant(
    sqlite_path: str, tenant_id: str
) -> None:
""",
    )

    text = must_replace(
        text,
        """def mint_key(
    *scopes: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    tenant_id: Optional[str] = None,
    now: Optional[int] = None,
    secret: Optional[str] = None,
) -> str:
""",
        """def mint_key(
    *scopes: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    tenant_id: str,
    now: Optional[int] = None,
    secret: Optional[str] = None,
) -> str:
""",
    )

    text = must_replace(
        text,
        """def revoke_api_key(
    key_prefix: str,
    key_hash: Optional[str] = None,
    *,
    tenant_id: Optional[str] = None,
) -> bool:
""",
        """def revoke_api_key(
    key_prefix: str,
    tenant_id: str,
    key_hash: Optional[str] = None,
) -> bool:
""",
    )

    text = must_replace(
        text,
        """def rotate_api_key_by_prefix(
    key_prefix: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    tenant_id: Optional[str] = None,
    revoke_old: bool = True,
) -> dict:
""",
        """def rotate_api_key_by_prefix(
    key_prefix: str,
    tenant_id: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    revoke_old: bool = True,
) -> dict:
""",
    )

    text = must_replace(
        text,
        """def list_api_keys(
    tenant_id: Optional[str] = None,
    include_disabled: bool = False,
) -> list[dict]:
""",
        """def list_api_keys(
    tenant_id: str,
    include_disabled: bool = False,
) -> list[dict]:
""",
    )

    TARGET.write_text(text, encoding="utf-8")
    print(f"patched {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
