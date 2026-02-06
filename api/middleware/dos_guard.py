from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from starlette.responses import JSONResponse

log = logging.getLogger("frostgate.security")

_BOUNDARY_RE = re.compile(r"^[0-9A-Za-z'()+_,\-./:=?]{1,200}$")


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    return int(v)


def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    return float(v)


def _env_csv(name: str, default: str = "") -> tuple[str, ...]:
    v = (os.getenv(name) or default).strip()
    if not v:
        return tuple()
    return tuple(p.strip() for p in v.split(",") if p.strip())


@dataclass(frozen=True)
class DoSGuardConfig:
    enabled: bool
    max_body_bytes: int
    max_query_bytes: int
    max_path_bytes: int
    max_headers_count: int
    max_headers_bytes: int
    max_header_line_bytes: int
    multipart_max_bytes: int
    multipart_max_parts: int
    request_timeout_sec: float
    max_concurrent_requests: int
    trusted_proxy_cidrs: tuple[str, ...]

    @classmethod
    def from_env(cls) -> "DoSGuardConfig":
        return cls(
            enabled=(
                os.getenv("FG_DOS_GUARD_ENABLED", "true").strip().lower()
                in {"1", "true", "yes", "on"}
            ),
            max_body_bytes=_env_int("FG_MAX_BODY_BYTES", 1024 * 1024),
            max_query_bytes=_env_int("FG_MAX_QUERY_BYTES", 8 * 1024),
            max_path_bytes=_env_int("FG_MAX_PATH_BYTES", 2 * 1024),
            max_headers_count=_env_int("FG_MAX_HEADERS_COUNT", 100),
            max_headers_bytes=_env_int("FG_MAX_HEADERS_BYTES", 16 * 1024),
            max_header_line_bytes=_env_int("FG_MAX_HEADER_LINE_BYTES", 8 * 1024),
            multipart_max_bytes=_env_int("FG_MULTIPART_MAX_BYTES", 5 * 1024 * 1024),
            multipart_max_parts=_env_int("FG_MULTIPART_MAX_PARTS", 50),
            request_timeout_sec=_env_float("FG_REQUEST_TIMEOUT_SEC", 15.0),
            max_concurrent_requests=_env_int("FG_MAX_CONCURRENT_REQUESTS", 100),
            trusted_proxy_cidrs=_env_csv(
                "FG_TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128"
            ),
        )


class _RejectRequest(Exception):
    def __init__(
        self, status_code: int, reason_code: str, details: dict[str, int | str]
    ):
        self.status_code = status_code
        self.reason_code = reason_code
        self.details = details
        super().__init__(reason_code)


class DoSGuardMiddleware:
    def __init__(self, app, config: Optional[DoSGuardConfig] = None):
        self.app = app
        self.config = config or DoSGuardConfig.from_env()
        self._semaphore = asyncio.Semaphore(max(1, self.config.max_concurrent_requests))

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not self.config.enabled:
            await self.app(scope, receive, send)
            return

        request_id = self._resolve_request_id(scope)
        tenant_id = self._resolve_tenant_id(scope)
        client_ip = self._resolve_client_ip(scope)

        try:
            self._enforce_scope_limits(scope)
            content_type, boundary = self._content_type(scope)
            if content_type == "multipart/form-data":
                self._validate_boundary(boundary)

            if self._content_length_exceeds(scope, content_type):
                limit = (
                    self.config.multipart_max_bytes
                    if content_type == "multipart/form-data"
                    else self.config.max_body_bytes
                )
                raise _RejectRequest(
                    413,
                    "body_too_large_content_length",
                    {
                        "content_length": int(
                            self._header(scope, b"content-length") or 0
                        ),
                        "limit": limit,
                    },
                )
        except _RejectRequest as e:
            await self._log_and_reject(
                scope, receive, send, e, request_id, client_ip, tenant_id
            )
            return

        if self._semaphore.locked():
            reject = _RejectRequest(
                429,
                "concurrency_limit_exceeded",
                {"max_concurrent_requests": self.config.max_concurrent_requests},
            )
            await self._log_and_reject(
                scope, receive, send, reject, request_id, client_ip, tenant_id
            )
            return

        await self._semaphore.acquire()
        started = False

        async def guarded_send(message):
            nonlocal started
            if message.get("type") == "http.response.start":
                started = True
            await send(message)

        body_seen = 0
        first_body_at: Optional[float] = None
        boundary_hits = 0
        needle = None
        trailing = b""
        content_type, boundary = self._content_type(scope)
        if content_type == "multipart/form-data" and boundary:
            needle = b"--" + boundary.encode("ascii", errors="ignore")

        async def guarded_receive():
            nonlocal body_seen, first_body_at, boundary_hits, trailing
            try:
                message = await asyncio.wait_for(
                    receive(), timeout=self.config.request_timeout_sec
                )
            except TimeoutError as ex:
                raise _RejectRequest(
                    408,
                    "request_timeout",
                    {"timeout_sec": self.config.request_timeout_sec},
                ) from ex
            if message.get("type") == "http.request":
                chunk = message.get("body", b"") or b""
                now = time.monotonic()
                if chunk and first_body_at is None:
                    first_body_at = now
                body_seen += len(chunk)
                body_limit = (
                    self.config.multipart_max_bytes
                    if content_type == "multipart/form-data"
                    else self.config.max_body_bytes
                )
                if body_seen > body_limit:
                    raise _RejectRequest(
                        413,
                        "body_too_large_stream",
                        {"received_bytes": body_seen, "limit": body_limit},
                    )

                if needle is not None:
                    scan = trailing + chunk
                    boundary_hits += scan.count(needle)
                    if boundary_hits > self.config.multipart_max_parts + 1:
                        raise _RejectRequest(
                            413,
                            "multipart_too_many_parts",
                            {
                                "parts_seen": boundary_hits - 1,
                                "limit": self.config.multipart_max_parts,
                            },
                        )
                    trailing = scan[-max(0, len(needle) - 1) :]
            return message

        try:
            await asyncio.wait_for(
                self.app(scope, guarded_receive, guarded_send),
                timeout=self.config.request_timeout_sec,
            )
        except TimeoutError:
            if not started:
                reject = _RejectRequest(
                    408,
                    "request_timeout",
                    {"timeout_sec": self.config.request_timeout_sec},
                )
                await self._log_and_reject(
                    scope, receive, send, reject, request_id, client_ip, tenant_id
                )
            return
        except _RejectRequest as e:
            if not started:
                await self._log_and_reject(
                    scope, receive, send, e, request_id, client_ip, tenant_id
                )
            return
        finally:
            self._semaphore.release()

    def _resolve_request_id(self, scope) -> str:
        rid = self._header(scope, b"x-request-id")
        if rid:
            return rid
        return str(uuid.uuid4())

    def _resolve_tenant_id(self, scope) -> Optional[str]:
        return self._header(scope, b"x-tenant-id")

    def _resolve_client_ip(self, scope) -> str:
        client = scope.get("client") or ("unknown", 0)
        host = str(client[0])
        xff = self._header(scope, b"x-forwarded-for")
        if not xff:
            return host
        try:
            proxy_ip = ipaddress.ip_address(host)
            for cidr in self.config.trusted_proxy_cidrs:
                if proxy_ip in ipaddress.ip_network(cidr, strict=False):
                    return xff.split(",", 1)[0].strip() or host
        except Exception:
            return host
        return host

    def _header(self, scope, key: bytes) -> Optional[str]:
        for name, value in scope.get("headers", []):
            if name == key:
                return value.decode("latin-1").strip()
        return None

    def _enforce_scope_limits(self, scope) -> None:
        path = scope.get("path", "")
        query_string = scope.get("query_string", b"") or b""
        headers = scope.get("headers", [])

        if len(path.encode("utf-8", errors="ignore")) > self.config.max_path_bytes:
            raise _RejectRequest(
                414,
                "path_too_long",
                {
                    "path_bytes": len(path.encode("utf-8", errors="ignore")),
                    "limit": self.config.max_path_bytes,
                },
            )

        if len(query_string) > self.config.max_query_bytes:
            raise _RejectRequest(
                414,
                "query_too_long",
                {
                    "query_bytes": len(query_string),
                    "limit": self.config.max_query_bytes,
                },
            )

        if len(headers) > self.config.max_headers_count:
            raise _RejectRequest(
                431,
                "too_many_headers",
                {"header_count": len(headers), "limit": self.config.max_headers_count},
            )

        total_header_bytes = 0
        for name, value in headers:
            line_len = len(name) + len(value) + 4
            if line_len > self.config.max_header_line_bytes:
                raise _RejectRequest(
                    431,
                    "header_line_too_large",
                    {
                        "header_line_bytes": line_len,
                        "limit": self.config.max_header_line_bytes,
                    },
                )
            total_header_bytes += line_len
            if total_header_bytes > self.config.max_headers_bytes:
                raise _RejectRequest(
                    431,
                    "headers_too_large",
                    {
                        "headers_bytes": total_header_bytes,
                        "limit": self.config.max_headers_bytes,
                    },
                )

    def _content_type(self, scope) -> tuple[str, Optional[str]]:
        content_type = self._header(scope, b"content-type") or ""
        parts = [p.strip() for p in content_type.split(";") if p.strip()]
        media_type = parts[0].lower() if parts else ""
        boundary = None
        for p in parts[1:]:
            if p.lower().startswith("boundary="):
                boundary = p.split("=", 1)[1].strip().strip('"')
                break
        return media_type, boundary

    def _validate_boundary(self, boundary: Optional[str]) -> None:
        if not boundary:
            raise _RejectRequest(400, "multipart_boundary_missing", {})
        if not _BOUNDARY_RE.match(boundary):
            raise _RejectRequest(
                400, "multipart_boundary_invalid", {"boundary_len": len(boundary)}
            )

    def _content_length_exceeds(self, scope, content_type: str) -> bool:
        content_length = self._header(scope, b"content-length")
        if not content_length:
            return False
        try:
            length = int(content_length)
        except ValueError:
            return False
        limit = (
            self.config.multipart_max_bytes
            if content_type == "multipart/form-data"
            else self.config.max_body_bytes
        )
        return length > limit

    async def _log_and_reject(
        self,
        scope,
        receive,
        send,
        reject: _RejectRequest,
        request_id: str,
        client_ip: str,
        tenant_id: Optional[str],
    ) -> None:
        log.warning(
            "security_event: dos_guard_reject",
            extra={
                "event_type": "dos_guard_reject",
                "request_id": request_id,
                "tenant_id": tenant_id,
                "client_ip": client_ip,
                "request_path": scope.get("path"),
                "request_method": scope.get("method"),
                "reason": reject.reason_code,
                "details": reject.details,
            },
        )
        response = JSONResponse(
            status_code=reject.status_code,
            content={"detail": "request rejected", "reason": reject.reason_code},
        )
        await response(scope, receive, send)


__all__ = ["DoSGuardConfig", "DoSGuardMiddleware"]
