from __future__ import annotations

from fastapi import HTTPException

from api.config.ui import ui_enabled


def ui_enabled_guard() -> None:
    if not ui_enabled():
        raise HTTPException(status_code=404, detail="UI disabled")


__all__ = ["ui_enabled_guard"]
