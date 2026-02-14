from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from typing import Optional
from urllib.parse import urlparse
import uuid

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from urllib3.util.ssl_ import assert_fingerprint


TRANSIENT_CODES = {"RATE_LIMITED", "ABUSE_CAP_EXCEEDED", "PLAN_LIMIT_EXCEEDED"}
FATAL_CODES = {"AUTH_REQUIRED", "SCOPE_DENIED", "COMMAND_TERMINAL", "RECEIPT_REPLAY"}
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


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


def _allowlist_entries() -> list[str]:
    raw = os.getenv("FG_CORE_HOST_ALLOWLIST", "")
    return [x.strip().lower() for x in raw.split(",") if x.strip()]


def _sanitize_request_id(request_id: str | None) -> str:
    if not request_id:
        return str(uuid.uuid4())
    candidate = request_id.strip()
    return candidate if _REQUEST_ID_RE.fullmatch(candidate) else str(uuid.uuid4())


def _normalize_fingerprint(fp: str) -> str:
    value = fp.strip().lower()
    if value.startswith("sha256/"):
        value = value.split("/", 1)[1]
    return value.replace(":", "")


class PinningAdapter(HTTPAdapter):
    def __init__(self, fingerprints: list[str], *args, **kwargs):
        self._fingerprints = [_normalize_fingerprint(x) for x in fingerprints if x.strip()]
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        response = super().send(request, **kwargs)
        if request.url.startswith("https://") and self._fingerprints:
            cert_bin = response.raw.connection.sock.getpeercert(binary_form=True)
            matched = False
            for fp in self._fingerprints:
                try:
                    assert_fingerprint(cert_bin, fp)
                    matched = True
                    break
                except Exception:
                    continue
            if not matched:
                response.close()
                raise requests.exceptions.SSLError("TLS certificate pin mismatch")
        return response


@dataclass
class CoreClient:
    base_url: str
    api_key: str
    tenant_id: str
    agent_id: str
    contract_version: str
    timeout: float = 10.0

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        parsed = urlparse(self.base_url)
        self._allow_insecure = os.getenv("FG_ALLOW_INSECURE_HTTP", "0") == "1"
        self._allow_private = os.getenv("FG_ALLOW_PRIVATE_CORE", "0") == "1"
        self._allowlist = _allowlist_entries()
        self._fingerprints = [x for x in os.getenv("FG_CORE_CERT_SHA256", "").split(",") if x.strip()]

        if parsed.scheme not in {"https", "http"}:
            raise ValueError("FG_CORE_BASE_URL must use http or https")
        if parsed.scheme == "http" and not self._allow_insecure:
            raise ValueError("Insecure http is disabled by default")
        if not parsed.hostname:
            raise ValueError("FG_CORE_BASE_URL missing hostname")

        self._allowlist_match = self._is_host_allowlisted(parsed.hostname)
        self._validate_resolved_ips(parsed.hostname)

        retry = Retry(
            total=2,
            backoff_factor=0.1,
            allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
            status_forcelist=(429, 500, 502, 503, 504),
            raise_on_status=False,
        )
        self.session = requests.Session()
        self.session.mount(
            "https://",
            PinningAdapter(self._fingerprints, max_retries=retry),
        )
        if self._allow_insecure:
            self.session.mount("http://", HTTPAdapter(max_retries=retry))

        print(
            json.dumps(
                {
                    "event": "core_transport_policy",
                    "scheme": parsed.scheme,
                    "insecure_override": self._allow_insecure,
                    "private_allowed": self._allow_private,
                    "allowlist_match": self._allowlist_match,
                    "cert_pin_enabled": bool(self._fingerprints),
                },
                sort_keys=True,
            ),
            flush=True,
        )

    @classmethod
    def from_env(cls) -> "CoreClient":
        return cls(
            base_url=os.environ["FG_CORE_BASE_URL"].rstrip("/"),
            api_key=os.environ["FG_AGENT_KEY"],
            tenant_id=os.environ["FG_TENANT_ID"],
            agent_id=os.environ["FG_AGENT_ID"],
            contract_version=os.getenv("FG_CONTRACT_VERSION", "2025-01-01"),
        )

    def _is_host_allowlisted(self, hostname: str) -> bool:
        host = hostname.lower()
        for entry in self._allowlist:
            if "/" in entry:
                continue
            suffix = entry[2:] if entry.startswith("*.") else entry
            if host == suffix or host.endswith(f".{suffix}"):
                return True
        return False

    def _is_ip_allowlisted(self, ip: ipaddress._BaseAddress) -> bool:
        for entry in self._allowlist:
            if "/" not in entry:
                continue
            try:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _validate_resolved_ips(self, hostname: str) -> None:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_loopback or ip.is_link_local:
                if not (self._allowlist_match or self._is_ip_allowlisted(ip)):
                    raise ValueError(f"core host resolves to disallowed address: {ip}")
                continue
            if ip.is_private and not self._allow_private:
                if not (self._allowlist_match or self._is_ip_allowlisted(ip)):
                    raise ValueError(f"core host resolves to private address without override: {ip}")

    def _headers(self, request_id: str | None = None) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "X-Contract-Version": self.contract_version,
            "X-Request-ID": _sanitize_request_id(request_id),
            "Content-Type": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        params: dict | None = None,
        request_id: str | None = None,
    ) -> dict:
        resp = self.session.request(
            method,
            f"{self.base_url}{path}",
            headers=self._headers(request_id=request_id),
            json=payload,
            params=params,
            timeout=self.timeout,
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
        params = {"agent_id": agent_id}
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
