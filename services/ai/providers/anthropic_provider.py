from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from services.ai.providers.base import (
    AI_PROVIDER_CALL_FAILED,
    AI_PROVIDER_CONFIG_MISSING,
    AI_PROVIDER_RESPONSE_INVALID,
    AI_PROVIDER_TIMEOUT,
    ProviderCallError,
    ProviderRequest,
    ProviderResponse,
)

log = logging.getLogger("frostgate.ai.anthropic")

_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"
_DEFAULT_MODEL = "claude-haiku-4-5-20251001"
_TIMEOUT_MIN = 5
_TIMEOUT_MAX = 120
_TIMEOUT_DEFAULT = 30


def _load_config() -> tuple[str, str, int]:
    """Returns (api_key, model, timeout_seconds). Raises ProviderCallError if unconfigured."""
    api_key = (os.getenv("FG_ANTHROPIC_API_KEY") or "").strip()
    if not api_key:
        raise ProviderCallError(
            AI_PROVIDER_CONFIG_MISSING, "Anthropic API key not configured"
        )
    model = (os.getenv("FG_ANTHROPIC_MODEL") or _DEFAULT_MODEL).strip()
    try:
        timeout = int(
            (os.getenv("FG_ANTHROPIC_TIMEOUT_SECONDS") or str(_TIMEOUT_DEFAULT)).strip()
        )
    except ValueError:
        timeout = _TIMEOUT_DEFAULT
    timeout = max(_TIMEOUT_MIN, min(_TIMEOUT_MAX, timeout))
    return api_key, model, timeout


class AnthropicProvider:
    def call(self, req: ProviderRequest) -> ProviderResponse:
        api_key, model, timeout = _load_config()

        messages: list[dict[str, Any]] = [{"role": "user", "content": req.prompt}]
        body: dict[str, Any] = {
            "model": model,
            "max_tokens": req.max_tokens,
            "messages": messages,
        }
        if req.system_prompt:
            body["system"] = req.system_prompt

        try:
            resp = httpx.post(
                _MESSAGES_URL,
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": _ANTHROPIC_VERSION,
                    "content-type": "application/json",
                },
                json=body,
                timeout=timeout,
            )
        except httpx.TimeoutException:
            log.warning(
                "anthropic_provider: request timed out",
                extra={"provider_id": "anthropic", "request_id": req.request_id},
            )
            raise ProviderCallError(AI_PROVIDER_TIMEOUT, "Anthropic provider timed out")
        except httpx.HTTPError as exc:
            log.warning(
                "anthropic_provider: HTTP transport error",
                extra={"provider_id": "anthropic", "request_id": req.request_id},
            )
            raise ProviderCallError(
                AI_PROVIDER_CALL_FAILED, "Anthropic provider transport error"
            ) from exc

        if resp.status_code != 200:
            log.warning(
                "anthropic_provider: non-200 status",
                extra={
                    "provider_id": "anthropic",
                    "status_code": resp.status_code,
                    "request_id": req.request_id,
                },
            )
            raise ProviderCallError(
                AI_PROVIDER_CALL_FAILED,
                f"Anthropic provider returned HTTP {resp.status_code}",
            )

        try:
            data = resp.json()
            content = data["content"]
            text = next(
                (block["text"] for block in content if block.get("type") == "text"),
                None,
            )
            if text is None:
                raise ValueError("no text block in response content")
        except (KeyError, ValueError, TypeError) as exc:
            log.warning(
                "anthropic_provider: invalid response structure",
                extra={"provider_id": "anthropic", "request_id": req.request_id},
            )
            raise ProviderCallError(
                AI_PROVIDER_RESPONSE_INVALID, "Invalid Anthropic response structure"
            ) from exc

        usage = data.get("usage") or {}
        return ProviderResponse(
            provider_id="anthropic",
            text=text,
            model=data.get("model", model),
            input_tokens=usage.get("input_tokens"),
            output_tokens=usage.get("output_tokens"),
            finish_reason=data.get("stop_reason"),
        )
