from __future__ import annotations

import json
import logging
from typing import Any

import requests

from agent.core.transport import (
    RETRYABLE_STATUSES,
    TransportError,
    TransportResponse,
    ensure_correlation_id,
    sanitize_headers,
    sanitize_url,
)


class RequestsTransportClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 5.0,
        pinned_endpoint: bool = False,
        session: requests.Session | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._pinned_endpoint = bool(pinned_endpoint)
        self._session = session or requests.Session()

    @property
    def pinned_endpoint(self) -> bool:
        return self._pinned_endpoint

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        correlation_id: str | None,
    ) -> TransportResponse:
        corr_id = ensure_correlation_id(correlation_id)
        request_headers = dict(headers or {})
        request_headers["X-Correlation-ID"] = corr_id

        url = f"{self._base_url}{path}"
        logging.info(
            json.dumps(
                {
                    "event": "transport_request",
                    "method": method,
                    "url": sanitize_url(url),
                    "headers": sanitize_headers(request_headers),
                    "correlation_id": corr_id,
                },
                sort_keys=True,
            )
        )

        try:
            response = self._session.request(
                method=method,
                url=url,
                headers=request_headers,
                json=json_body,
                timeout=self._timeout,
                allow_redirects=False,
            )
        except requests.Timeout:
            raise TransportError("timeout", retryable=True) from None
        except requests.RequestException:
            raise TransportError("transport_error", retryable=True) from None

        if response.status_code in RETRYABLE_STATUSES:
            raise TransportError(
                "retryable_http_error",
                retryable=True,
                status_code=response.status_code,
            )
        if response.status_code >= 400:
            raise TransportError(
                "terminal_http_error",
                retryable=False,
                status_code=response.status_code,
            )

        try:
            body = response.json() if response.content else {}
        except ValueError as exc:
            raise TransportError(
                "invalid_json", retryable=False, status_code=response.status_code
            ) from exc
        return TransportResponse(
            status_code=response.status_code,
            json_body=body,
            headers={k: v for k, v in response.headers.items()},
        )
