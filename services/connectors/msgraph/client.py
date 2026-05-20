"""Bounded Microsoft Graph HTTP client.

Enforces: per-request timeout, scan total timeout, pagination limit,
exponential retry with Retry-After respect, and tenant validation on
every response.

RULE-SEC-001: access token never logged
RULE-SEC-003: no Graph secret in log output
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

import httpx

from services.connectors.msgraph.manifest import (
    GRAPH_BASE_URL,
    MAX_PAGES_PER_ENDPOINT,
    MAX_RECORDS_PER_PAGE,
    MAX_RETRIES,
    REQUEST_TIMEOUT_SECONDS,
    RETRY_AFTER_MAX_SECONDS,
    RETRY_BACKOFF_BASE_SECONDS,
    RETRY_ON_STATUS,
    SCAN_TOTAL_TIMEOUT_SECONDS,
    ScanTimeoutError,
)
from services.connectors.msgraph.tenant import TenantLock

log = logging.getLogger("frostgate.connectors.msgraph.client")

_SENSITIVE_HEADERS = frozenset({"authorization", "x-api-key"})


def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return headers with sensitive values masked for logging."""
    return {
        k: "[REDACTED]" if k.lower() in _SENSITIVE_HEADERS else v
        for k, v in headers.items()
    }


def _structure_hash(obj: Any) -> str:
    """sha256 of sorted top-level keys — proves completeness without storing content."""
    if isinstance(obj, dict):
        keys = sorted(obj.keys())
    elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
        keys = sorted(obj[0].keys())
    else:
        keys = []
    return hashlib.sha256(json.dumps(keys).encode()).hexdigest()


class GraphClient:
    """Read-only, bounded Graph HTTP client.

    All requests use the bearer token from CredentialContext.
    All responses are validated against the TenantLock.
    """

    def __init__(
        self,
        access_token: str,
        tenant_lock: TenantLock,
        *,
        scan_deadline: float | None = None,
    ) -> None:
        self._token = access_token
        self._lock = tenant_lock
        self._deadline = scan_deadline or (
            time.monotonic() + SCAN_TOTAL_TIMEOUT_SECONDS
        )
        self._pages_fetched: dict[str, int] = {}
        self._endpoints_called: list[str] = []
        self._record_counts: dict[str, int] = {}
        self._call_timestamps: dict[str, str] = {}
        self._structure_hashes: dict[str, str] = {}

    def _check_deadline(self) -> None:
        if time.monotonic() > self._deadline:
            raise ScanTimeoutError("Scan total timeout exceeded")

    def _remaining_seconds(self) -> float:
        return max(0.0, self._deadline - time.monotonic())

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "ConsistencyLevel": "eventual",
        }

    def _get_with_retry(self, url: str) -> dict[str, Any]:
        """Single GET with exponential retry on transient errors."""
        self._check_deadline()

        for attempt in range(MAX_RETRIES + 1):
            self._check_deadline()
            timeout = min(REQUEST_TIMEOUT_SECONDS, self._remaining_seconds())
            try:
                resp = httpx.get(
                    url,
                    headers=self._auth_headers(),
                    timeout=timeout,
                )
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempt == MAX_RETRIES:
                    raise
                wait = RETRY_BACKOFF_BASE_SECONDS * (2**attempt)
                log.warning(
                    "graph client: request error %s — retry %d in %ds",
                    exc,
                    attempt + 1,
                    wait,
                )
                time.sleep(min(wait, self._remaining_seconds()))
                continue

            if resp.status_code not in RETRY_ON_STATUS:
                resp.raise_for_status()
                return resp.json()

            if attempt == MAX_RETRIES:
                resp.raise_for_status()

            if resp.status_code == 429:
                retry_after = min(
                    int(
                        resp.headers.get(
                            "Retry-After", RETRY_BACKOFF_BASE_SECONDS * (2**attempt)
                        )
                    ),
                    RETRY_AFTER_MAX_SECONDS,
                )
                log.warning(
                    "graph client: throttled — waiting %ds (Retry-After)", retry_after
                )
                if retry_after > self._remaining_seconds():
                    log.warning(
                        "graph client: retry wait exceeds remaining scan time — skipping endpoint"
                    )
                    return {"value": [], "_throttled": True}
                time.sleep(retry_after)
            else:
                wait = RETRY_BACKOFF_BASE_SECONDS * (2**attempt)
                log.warning(
                    "graph client: HTTP %d — retry %d in %ds",
                    resp.status_code,
                    attempt + 1,
                    wait,
                )
                time.sleep(min(wait, self._remaining_seconds()))

        raise RuntimeError(f"All retries exhausted for {url}")

    def get_all(
        self,
        path: str,
        *,
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Paginated GET — returns all records up to MAX_PAGES * MAX_RECORDS.

        Records `truncated: true` in evidence if limit is hit.
        """
        url: str | None = f"{GRAPH_BASE_URL}{path}"
        if params:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{query}"

        all_records: list[dict[str, Any]] = []
        pages = 0
        truncated = False

        while url and pages < MAX_PAGES_PER_ENDPOINT:
            self._check_deadline()
            data = self._get_with_retry(url)
            if data.get("_throttled"):
                break

            self._lock.validate_response(data)

            records = data.get("value", [])
            all_records.extend(records[:MAX_RECORDS_PER_PAGE])
            pages += 1

            # Track manifest data
            endpoint_key = path
            self._pages_fetched[endpoint_key] = pages
            self._record_counts[endpoint_key] = len(all_records)
            if endpoint_key not in self._structure_hashes and records:
                self._structure_hashes[endpoint_key] = _structure_hash(records[0])

            url = data.get("@odata.nextLink") or None

        if url and pages >= MAX_PAGES_PER_ENDPOINT:
            truncated = True
            log.info(
                "graph client: %s truncated at %d pages", path, MAX_PAGES_PER_ENDPOINT
            )

        if path not in self._endpoints_called:
            self._endpoints_called.append(path)

        # Attach truncation metadata for evidence refs
        for rec in all_records:
            if isinstance(rec, dict):
                rec["_fg_truncated"] = truncated

        return all_records

    def get_one(self, path: str) -> dict[str, Any]:
        """Single-object GET (no pagination)."""
        url = f"{GRAPH_BASE_URL}{path}"
        self._check_deadline()
        data = self._get_with_retry(url)
        self._lock.validate_response(data)
        if path not in self._endpoints_called:
            self._endpoints_called.append(path)
        return data

    @property
    def pages_fetched(self) -> dict[str, int]:
        return dict(self._pages_fetched)

    @property
    def endpoints_called(self) -> list[str]:
        return list(self._endpoints_called)

    @property
    def record_counts(self) -> dict[str, int]:
        return dict(self._record_counts)

    @property
    def structure_hashes(self) -> dict[str, str]:
        return dict(self._structure_hashes)
