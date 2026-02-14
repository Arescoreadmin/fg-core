from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import ipaddress
import json
import logging
import os
import re
import socket
import time
import uuid
from typing import Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3 import PoolManager
from urllib3.util.retry import Retry


TRANSIENT_CODES = {"RATE_LIMITED", "ABUSE_CAP_EXCEEDED", "PLAN_LIMIT_EXCEEDED"}
FATAL_CODES = {"AUTH_REQUIRED", "SCOPE_DENIED", "COMMAND_TERMINAL", "RECEIPT_REPLAY"}

# request-id is a convenience, not a security boundary. Keep it tight-ish.
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_POLICY_LOGGED = False


def sanitize_request_id(request_id: str | None) -> str:
    candidate = (request_id or "").strip()
    if REQUEST_ID_RE.fullmatch(candidate):
        return candidate
    return str(uuid.uuid4())


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _normalize_fingerprint(pin: str) -> str:
    # Accept formats like:
    # - sha256/ABCDEF...
    # - AA:BB:CC...
    # - aa-bb-cc...
    normalized = pin.strip().lower().replace(":", "").replace("-", "")
    if normalized.startswith("sha256/"):
        normalized = normalized.split("/", 1)[1]
    return normalized


def _is_restricted_ip(ip_value: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip_value.is_loopback
        or ip_value.is_link_local
        or ip_value.is_private
        or ip_value.is_reserved
    )


def _matches_allowlist(host: str, allowlist: list[str]) -> bool:
    host_l = host.lower()
    host_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        host_ip = ipaddress.ip_address(host_l)
    except ValueError:
        host_ip = None

    for entry in allowlist:
        entry_l = entry.lower()

        # CIDR allowlist
        if "/" in entry_l:
            if host_ip is None:
                continue
            try:
                if host_ip in ipaddress.ip_network(entry_l, strict=False):
                    return True
            except ValueError:
                continue
            continue

        # wildcard suffix (*.example.com)
        if entry_l.startswith("*."):
            suffix = entry_l[1:]  # ".example.com"
            if host_l.endswith(suffix):
                return True
            continue

        # dot-suffix (.example.com)
        if entry_l.startswith("."):
            if host_l.endswith(entry_l):
                return True
            continue

        # exact host match
        if host_l == entry_l:
            return True

    return False


def _resolved_ips(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    infos = socket.getaddrinfo(host, None)
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        sockaddr = info[4]
        ip_text = sockaddr[0]
        try:
            ips.append(ipaddress.ip_address(ip_text))
        except ValueError:
            continue
    return ips


def _allowlist_matches_ip(
    ip_value: ipaddress.IPv4Address | ipaddress.IPv6Address, allowlist: list[str]
) -> bool:
    for entry in allowlist:
        entry_l = entry.lower()
        if "/" not in entry_l:
            continue
        try:
            if ip_value in ipaddress.ip_network(entry_l, strict=False):
                return True
        except ValueError:
            continue
    return False


def validate_core_base_url(base_url: str) -> dict:
    parsed = urlparse(base_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("FG_CORE_BASE_URL must be an absolute URL")

    scheme = parsed.scheme.lower()
    host = parsed.hostname
    if not host:
        raise ValueError("FG_CORE_BASE_URL must include host")

    insecure_override = os.getenv("FG_ALLOW_INSECURE_HTTP", "0") == "1"
    private_allowed = os.getenv("FG_ALLOW_PRIVATE_CORE", "0") == "1"
    allowlist = _split_csv(os.getenv("FG_CORE_HOST_ALLOWLIST"))
    pin_enabled = bool(_split_csv(os.getenv("FG_CORE_CERT_SHA256")))

    if scheme not in {"http", "https"}:
        raise ValueError("FG_CORE_BASE_URL scheme must be http or https")
    if scheme == "http" and not insecure_override:
        raise ValueError(
            "FG_CORE_BASE_URL insecure http:// blocked; set FG_ALLOW_INSECURE_HTTP=1 only for explicit dev override"
        )

    host_type = "hostname"
    allowlist_match = _matches_allowlist(host, allowlist)

    # If host is an IP literal, validate directly.
    try:
        ip_value = ipaddress.ip_address(host)
        host_type = "ip_literal"
        if _is_restricted_ip(ip_value) and not (
            private_allowed or _allowlist_matches_ip(ip_value, allowlist)
        ):
            raise ValueError(
                "FG_CORE_BASE_URL private/loopback/link-local IP blocked; set FG_ALLOW_PRIVATE_CORE=1 or FG_CORE_HOST_ALLOWLIST"
            )
        allowlist_match = allowlist_match or _allowlist_matches_ip(ip_value, allowlist)
    except ValueError as exc:
        # If we threw our own FG_CORE_* error above, bubble it.
        if str(exc).startswith("FG_CORE_BASE_URL"):
            raise

        # Otherwise treat as hostname and validate resolved IPs.
        try:
            resolved = _resolved_ips(host)
        except socket.gaierror:
            # DNS failure override is allowlist OR (https + pin enabled). Never for http.
            dns_override = allowlist_match or (scheme == "https" and pin_enabled)
            if not dns_override:
                raise ValueError(
                    "FG_CORE_BASE_URL hostname resolution failed and no allowlist/TLS-pin override is configured"
                )
            resolved = []

        for resolved_ip in resolved:
            ip_allowed = (
                private_allowed
                or allowlist_match
                or _allowlist_matches_ip(resolved_ip, allowlist)
            )
            if _is_restricted_ip(resolved_ip) and not ip_allowed:
                raise ValueError(
                    "FG_CORE_BASE_URL resolved to private/loopback/link-local IP; set FG_ALLOW_PRIVATE_CORE=1 or FG_CORE_HOST_ALLOWLIST"
                )
            allowlist_match = allowlist_match or _allowlist_matches_ip(
                resolved_ip, allowlist
            )

    decision = {
        "event": "core_endpoint_policy",
        "scheme": scheme,
        "insecure_override": insecure_override,
        "private_allowed": private_allowed,
        "allowlist_match": allowlist_match,
        "pin_enabled": pin_enabled,
        "host_type": host_type,
        "host": host,
    }

    global _POLICY_LOGGED
    if not _POLICY_LOGGED:
        logging.info(json.dumps(decision, sort_keys=True))
        _POLICY_LOGGED = True

    return decision


class FingerprintPinningAdapter(HTTPAdapter):
    """
    HTTPS-only adapter that uses urllib3's built-in assert_fingerprint support.
    Expects a SHA256 hex string (no colons).
    """

    def __init__(self, fingerprint: str, **kwargs):
        self._fingerprint = _normalize_fingerprint(fingerprint)
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["assert_fingerprint"] = self._fingerprint
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )


class CoreClientError(RuntimeError):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: dict | None,
        request_id: str | None,
        retry_after_seconds: float | None = None,
    ):
        super().__init__(f"{code}: {message}")
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}
        self.request_id = request_id
        self.retry_after_seconds = retry_after_seconds

    @property
    def transient(self) -> bool:
        return self.code in TRANSIENT_CODES or self.status_code >= 500


@dataclass
class CoreClient:
    base_url: str
    api_key: str
    tenant_id: str
    agent_id: str
    contract_version: str
    timeout: float = 10.0

    def __post_init__(self) -> None:
        decision = validate_core_base_url(self.base_url)
        self._insecure_override = bool(decision["insecure_override"])

        self._pins = [
            _normalize_fingerprint(pin)
            for pin in _split_csv(os.getenv("FG_CORE_CERT_SHA256"))
        ]

        self._session = requests.Session()
        self._retry = Retry(
            total=2,
            backoff_factor=0.1,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=_IDEMPOTENT_METHODS,
            raise_on_status=False,
        )

        # Default HTTPS adapter (no pin). We override per-request if pinning is enabled.
        self._session.mount("https://", HTTPAdapter(max_retries=self._retry))

        if self._insecure_override:
            self._session.mount("http://", HTTPAdapter(max_retries=self._retry))
        else:
            # Hard fail-closed: remove http adapter unless explicitly overridden.
            self._session.adapters.pop("http://", None)

    @classmethod
    def from_env(cls) -> "CoreClient":
        return cls(
            base_url=os.environ["FG_CORE_BASE_URL"].rstrip("/"),
            api_key=os.environ["FG_AGENT_KEY"],
            tenant_id=os.environ["FG_TENANT_ID"],
            agent_id=os.environ["FG_AGENT_ID"],
            contract_version=os.getenv("FG_CONTRACT_VERSION", "2025-01-01"),
        )

    def _headers(self, request_id: str | None = None) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "X-Contract-Version": self.contract_version,
            "X-Request-ID": sanitize_request_id(request_id),
            "Content-Type": "application/json",
        }

    def _request_once(
        self,
        method: str,
        path: str,
        *,
        payload: dict | None,
        params: dict | None,
        request_id: str | None,
        fingerprint: str | None,
    ) -> requests.Response:
        session = self._session
        created_session: requests.Session | None = None

        if fingerprint:
            created_session = requests.Session()
            created_session.mount(
                "https://",
                FingerprintPinningAdapter(
                    fingerprint=fingerprint, max_retries=self._retry
                ),
            )
            if self._insecure_override:
                created_session.mount("http://", HTTPAdapter(max_retries=self._retry))
            session = created_session

        try:
            return session.request(
                method,
                f"{self.base_url}{path}",
                headers=self._headers(request_id=request_id),
                json=payload,
                params=params,
                timeout=self.timeout,
            )
        finally:
            if created_session is not None:
                created_session.close()

    def _request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        params: dict | None = None,
        request_id: str | None = None,
    ) -> dict:
        if self._pins:
            last_ssl_error: requests.exceptions.SSLError | None = None
            resp: requests.Response | None = None

            for pin in self._pins:
                try:
                    resp = self._request_once(
                        method,
                        path,
                        payload=payload,
                        params=params,
                        request_id=request_id,
                        fingerprint=pin,
                    )
                    break
                except requests.exceptions.SSLError as exc:
                    last_ssl_error = exc

            if resp is None:
                if last_ssl_error is not None:
                    raise last_ssl_error
                raise requests.exceptions.SSLError("TLS fingerprint pinning failed")
        else:
            resp = self._request_once(
                method,
                path,
                payload=payload,
                params=params,
                request_id=request_id,
                fingerprint=None,
            )

        if resp.status_code >= 400:
            envelope = self._parse_error(resp)
            raise CoreClientError(
                resp.status_code,
                envelope["code"],
                envelope["message"],
                envelope.get("details"),
                envelope.get("request_id"),
                retry_after_seconds=self._retry_after_seconds(resp),
            )

        return resp.json() if resp.content else {}

    @staticmethod
    def _parse_error(resp: requests.Response) -> dict:
        try:
            data = resp.json()
        except Exception:
            data = {}
        return {
            "code": data.get("code", "UNKNOWN_ERROR"),
            "message": data.get("message", "Unknown error"),
            "details": data.get("details", {}),
            "request_id": data.get("request_id"),
        }

    @staticmethod
    def _retry_after_seconds(resp: requests.Response) -> float | None:
        value = resp.headers.get("Retry-After")
        if not value:
            return None
        try:
            return max(0.0, float(value))
        except ValueError:
            try:
                dt = parsedate_to_datetime(value)
                return max(0.0, dt.timestamp() - time.time())
            except Exception:
                return None

    def send_events(self, events: list[dict], request_id: str | None = None) -> dict:
        return self._request(
            "POST",
            "/v1/agent/events",
            payload={
                "tenant_id": self.tenant_id,
                "agent_id": self.agent_id,
                "events": events,
            },
            request_id=request_id,
        )

    def poll_commands(
        self, agent_id: str, cursor: Optional[str], request_id: str | None = None
    ) -> dict:
        params: dict[str, str] = {"agent_id": agent_id}
        if cursor:
            params["cursor"] = cursor
        return self._request(
            "GET", "/v1/agent/commands", params=params, request_id=request_id
        )

    def send_receipt(self, receipt: dict, request_id: str | None = None) -> dict:
        return self._request(
            "POST",
            "/v1/agent/receipts",
            payload={
                "tenant_id": self.tenant_id,
                "agent_id": self.agent_id,
                "receipt": receipt,
            },
            request_id=request_id,
        )
