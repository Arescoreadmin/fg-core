from __future__ import annotations

# NOTE:
# This file used to contain a /ui/feed route. That caused route ambiguity and patch drift.
# Canonical UI is now in api/ui.py ONLY.
# Keeping this file as a harmless stub prevents stale imports from exploding.

from fastapi import APIRouter

router = APIRouter(
    prefix="/_legacy/ui_feed", tags=["legacy-ui"], include_in_schema=False
)
