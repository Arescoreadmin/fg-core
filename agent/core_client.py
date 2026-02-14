from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import os
import uuid
from typing import Optional

import requests


TRANSIENT_CODES = {"RATE_LIMITED", "ABUSE_CAP_EXCEEDED", "PLAN_LIMIT_EXCEEDED"}
FATAL_CODES = {"AUTH_REQUIRED", "SCOPE_DENIED", "COMMAND_TERMINAL", "RECEIPT_REPLAY"}


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
            "X-Request-ID": request_id or str(uuid.uuid4()),
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
        resp = requests.request(
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
                return max(0.0, dt.timestamp() - __import__("time").time())
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
