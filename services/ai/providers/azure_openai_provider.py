from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import quote

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

log = logging.getLogger("frostgate.ai.azure_openai")

_DEFAULT_API_VERSION = "2024-06-01"
_DEFAULT_MODEL = "azure_openai"
_TIMEOUT_MIN = 5
_TIMEOUT_MAX = 120
_TIMEOUT_DEFAULT = 30


def _load_config() -> tuple[str, str, str, str, str, int]:
    api_key = (os.getenv("FG_AZURE_AI_KEY") or "").strip()
    endpoint = (os.getenv("FG_AZURE_OPENAI_ENDPOINT") or "").strip().rstrip("/")
    deployment = (os.getenv("FG_AZURE_OPENAI_DEPLOYMENT") or "").strip()
    api_version = (
        os.getenv("FG_AZURE_OPENAI_API_VERSION") or _DEFAULT_API_VERSION
    ).strip()
    model = (os.getenv("FG_AZURE_OPENAI_MODEL") or deployment or _DEFAULT_MODEL).strip()
    if not api_key or not endpoint or not deployment:
        raise ProviderCallError(
            AI_PROVIDER_CONFIG_MISSING, "Azure OpenAI provider not configured"
        )
    try:
        timeout = int(
            (
                os.getenv("FG_AZURE_OPENAI_TIMEOUT_SECONDS") or str(_TIMEOUT_DEFAULT)
            ).strip()
        )
    except ValueError:
        timeout = _TIMEOUT_DEFAULT
    timeout = max(_TIMEOUT_MIN, min(_TIMEOUT_MAX, timeout))
    return api_key, endpoint, deployment, api_version, model, timeout


class AzureOpenAIProvider:
    def call(self, req: ProviderRequest) -> ProviderResponse:
        api_key, endpoint, deployment, api_version, model, timeout = _load_config()
        url = (
            f"{endpoint}/openai/deployments/{quote(deployment, safe='')}"
            f"/chat/completions?api-version={quote(api_version, safe='')}"
        )
        messages: list[dict[str, str]] = []
        if req.system_prompt:
            messages.append({"role": "system", "content": req.system_prompt})
        messages.append({"role": "user", "content": req.prompt})
        body: dict[str, Any] = {
            "messages": messages,
            "max_tokens": req.max_tokens,
        }

        try:
            resp = httpx.post(
                url,
                headers={"api-key": api_key, "content-type": "application/json"},
                json=body,
                timeout=timeout,
            )
        except httpx.TimeoutException:
            log.warning(
                "azure_openai_provider: request timed out",
                extra={"provider_id": "azure_openai", "request_id": req.request_id},
            )
            raise ProviderCallError(
                AI_PROVIDER_TIMEOUT, "Azure OpenAI provider timed out"
            )
        except httpx.HTTPError as exc:
            log.warning(
                "azure_openai_provider: HTTP transport error",
                extra={"provider_id": "azure_openai", "request_id": req.request_id},
            )
            raise ProviderCallError(
                AI_PROVIDER_CALL_FAILED, "Azure OpenAI provider transport error"
            ) from exc

        if resp.status_code != 200:
            log.warning(
                "azure_openai_provider: non-200 status",
                extra={
                    "provider_id": "azure_openai",
                    "status_code": resp.status_code,
                    "request_id": req.request_id,
                },
            )
            raise ProviderCallError(
                AI_PROVIDER_CALL_FAILED,
                f"Azure OpenAI provider returned HTTP {resp.status_code}",
            )

        try:
            data = resp.json()
            choice = data["choices"][0]
            text = choice["message"]["content"]
            if not isinstance(text, str) or not text:
                raise ValueError("empty response content")
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            log.warning(
                "azure_openai_provider: invalid response structure",
                extra={"provider_id": "azure_openai", "request_id": req.request_id},
            )
            raise ProviderCallError(
                AI_PROVIDER_RESPONSE_INVALID,
                "Invalid Azure OpenAI response structure",
            ) from exc

        usage = data.get("usage") or {}
        return ProviderResponse(
            provider_id="azure_openai",
            text=text,
            model=str(data.get("model") or model),
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
            finish_reason=choice.get("finish_reason"),
        )
