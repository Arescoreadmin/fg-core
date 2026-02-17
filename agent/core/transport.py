from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit


SECRET_HEADERS = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "cookie",
    "set-cookie",
}
RETRYABLE_STATUSES = {408, 409, 425, 429, 500, 502, 503, 504}


@dataclass(frozen=True)
class TransportResponse:
    status_code: int
    json_body: dict[str, Any]
    headers: dict[str, str]


class TransportError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        retryable: bool,
        status_code: int | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.status_code = status_code


class TransportClient(Protocol):
    @property
    def pinned_endpoint(self) -> bool: ...

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        correlation_id: str | None,
    ) -> TransportResponse: ...


class SecureTransport:
    """Backwards-compat wrapper over an injected transport client."""

    def __init__(self, client: TransportClient) -> None:
        self._client = client

    @property
    def pinned_endpoint(self) -> bool:
        return self._client.pinned_endpoint

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        correlation_id: str | None,
    ) -> TransportResponse:
        return self._client.request(
            method,
            path,
            headers=headers,
            json_body=json_body,
            correlation_id=correlation_id,
        )


def ensure_correlation_id(correlation_id: str | None) -> str:
    return correlation_id or str(uuid.uuid4())


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    sanitized_headers = {}
    for key, value in headers.items():
        key_l = key.lower()
        if key_l in SECRET_HEADERS or key_l.startswith("proxy-"):
            sanitized_headers[key] = "[REDACTED]"
        else:
            sanitized_headers[key] = sanitize_value(value)
    return sanitized_headers


def sanitize_url(url: str) -> str:
    parsed = urlsplit(url)
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def sanitize_value(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._:-]", "_", value)[:256]
