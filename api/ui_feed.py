from __future__ import annotations

from fastapi import APIRouter, HTTPException

# Legacy UI: moved OFF /ui to prevent collisions with api/ui.py
# If this gets mounted by accident, it will not break /ui/token or /ui/feed.
router = APIRouter(prefix="/_legacy/ui", tags=["legacy-ui"], include_in_schema=False)


@router.get("/feed")
def legacy_ui_feed() -> None:
    # If you somehow hit this, you’re using the wrong UI implementation.
    raise HTTPException(
        status_code=410,
        detail="Legacy UI removed. Use /ui/feed from api/ui.py.",
    )
