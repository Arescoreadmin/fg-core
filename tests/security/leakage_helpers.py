# tests/security/leakage_helpers.py
from __future__ import annotations

from typing import Dict, Optional



def auth_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def assert_status_in(resp, allowed: set[int], *, msg: Optional[str] = None) -> None:
    if resp.status_code not in allowed:
        detail = ""
        try:
            detail = f" body={resp.json()}"
        except Exception:
            detail = f" text={resp.text!r}"
        raise AssertionError(
            msg
            or f"Unexpected status={resp.status_code}, expected in {sorted(allowed)}.{detail}"
        )


def set_env(monkeypatch, name: str, value: str | None) -> None:
    if value is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, value)
