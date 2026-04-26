"""
Error contract helpers — Task 11.1

Provides a minimal helper for building structured HTTPException detail dicts
with stable error codes, human-readable messages, and optional operator action hints.

Usage:
    raise HTTPException(
        status_code=403,
        detail=api_error("ADMIN_GATEWAY_FORBIDDEN", "message", action="hint"),
    )
"""

from __future__ import annotations


def api_error(
    code: str,
    message: str,
    *,
    action: str | None = None,
) -> dict[str, str]:
    """Return a structured HTTPException detail dict.

    Args:
        code: Stable, uppercase error code (e.g. "ADMIN_GATEWAY_FORBIDDEN").
              Never changes meaning once published.
        message: Human-readable description. Must not contain secrets, stack
                 traces, or raw exception text.
        action: Optional operator action hint (e.g. "provide X-Header with...").

    Returns:
        Dict suitable for use as ``HTTPException(detail=api_error(...))``.
    """
    d: dict[str, str] = {"code": code, "message": message}
    if action is not None:
        d["action"] = action
    return d
