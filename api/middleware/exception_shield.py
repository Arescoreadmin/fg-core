from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Mapping

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from prometheus_client import Counter

log = logging.getLogger("frostgate.exception_shield")


class _NoopCounter:
    def inc(self) -> None:
        return


def _build_counter():
    try:
        return Counter(
            "frostgate_exception_shield_total",
            "Count of HTTPException/ExceptionGroup responses emitted by FGExceptionShieldMiddleware",
            ["status_code"],
        )
    except ValueError:
        return _NoopCounter()


EXCEPTION_SHIELD_COUNTER = _build_counter()

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_URL_USERINFO_RE = re.compile(r"://[^/@\s]+@")
_SLUG_RE = re.compile(r"[^a-z0-9_]")
_PROD_ENVS = {"prod", "production", "staging"}


# Invariants:
# - Preserve HTTPException headers exactly (plus X-Request-ID when available).
# - Never swallow non-HTTP errors (re-raise).
# - Never emit a second response after http.response.start has been sent.
class FGExceptionShieldMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def tracked_send(message):
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, tracked_send)
            return
        except HTTPException as exc:
            target_exc = exc
        except ExceptionGroup as exc_group:
            target_exc = _first_http_exception(exc_group)
            if target_exc is None:
                raise
        except Exception:
            raise

        if response_started:
            _log_event(
                status_code=target_exc.status_code,
                error_code=_stable_error_code(
                    target_exc.status_code, target_exc.detail
                ),
                scope=scope,
                request_id=_resolve_request_id(scope),
                event="exception_shield_response_started",
            )
            raise target_exc

        request_id = _resolve_request_id(scope)
        payload = _error_payload(target_exc.status_code, target_exc.detail, request_id)
        headers = _build_response_headers(target_exc.headers, request_id)

        _counter_inc(target_exc.status_code)
        _log_event(
            status_code=target_exc.status_code,
            error_code=payload["error_code"],
            scope=scope,
            request_id=request_id,
            event="exception_shield",
        )

        response = JSONResponse(
            status_code=target_exc.status_code,
            content=payload,
            headers=headers,
        )
        await response(scope, receive, send)


def _counter_inc(status_code: int) -> None:
    try:
        EXCEPTION_SHIELD_COUNTER.labels(status_code=str(status_code)).inc()
    except Exception:
        try:
            EXCEPTION_SHIELD_COUNTER.inc()
        except Exception:
            return


def _first_http_exception(exc_group: BaseException) -> HTTPException | None:
    if isinstance(exc_group, HTTPException):
        return exc_group

    nested = getattr(exc_group, "exceptions", None)
    if not isinstance(nested, tuple):
        return None

    for ex in nested:
        found = _first_http_exception(ex)
        if found is not None:
            return found
    return None


def _resolve_request_id(scope: dict[str, Any]) -> str | None:
    state = scope.get("state")
    if isinstance(state, dict):
        rid = state.get("request_id")
        if isinstance(rid, str) and rid.strip():
            return rid.strip()

    for raw_k, raw_v in scope.get("headers") or []:
        try:
            k = raw_k.decode("latin-1").lower()
        except Exception:
            continue
        if k == "x-request-id":
            try:
                v = raw_v.decode("latin-1").strip()
            except Exception:
                continue
            if v:
                return v
    return None


def _safe_detail(detail: Any) -> str:
    env = (os.getenv("FG_ENV") or "").strip().lower()
    if env in _PROD_ENVS and not isinstance(detail, str):
        return "error"

    if isinstance(detail, str):
        text = detail
    elif isinstance(detail, dict):
        try:
            text = json.dumps(detail, separators=(",", ":"), sort_keys=True)
        except Exception:
            text = "error"
    elif detail is None:
        text = "error"
    else:
        text = str(detail)

    text = _CTRL_RE.sub("", text).strip()
    text = _URL_USERINFO_RE.sub("://***@", text)
    if not text:
        return "error"
    return text[:256]


def _stable_error_code(status_code: int, detail: Any) -> str:
    slug_src = _safe_detail(detail).strip().lower().replace(" ", "_")
    slug = _SLUG_RE.sub("", slug_src)
    slug = slug.strip("_")[:64]
    if not slug:
        slug = "error"
    return f"E{int(status_code)}_{slug}"


def _error_payload(
    status_code: int, detail: Any, request_id: str | None
) -> dict[str, Any]:
    safe_detail = _safe_detail(detail)
    payload: dict[str, Any] = {
        "error_code": _stable_error_code(status_code, safe_detail),
        "detail": safe_detail,
    }
    if request_id:
        payload["request_id"] = request_id
    return payload


def _build_response_headers(
    exc_headers: Mapping[str, str] | None,
    request_id: str | None,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    if exc_headers:
        headers.update({str(k): str(v) for k, v in exc_headers.items()})

    has_request_id = any(k.lower() == "x-request-id" for k in headers)
    if request_id and not has_request_id:
        headers["X-Request-ID"] = request_id
    return headers


def _log_event(
    *,
    event: str,
    status_code: int,
    error_code: str,
    scope: dict[str, Any],
    request_id: str | None,
) -> None:
    payload = {
        "event": event,
        "status_code": int(status_code),
        "error_code": error_code,
        "path": str(scope.get("path") or ""),
        "method": str(scope.get("method") or ""),
        "request_id": request_id,
    }
    log.info(json.dumps(payload, separators=(",", ":"), sort_keys=True))
