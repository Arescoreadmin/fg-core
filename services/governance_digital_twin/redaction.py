"""Redaction helpers for replay-safe Governance Digital Twin exports."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from typing import Any, cast


FORBIDDEN_FIELD_KEYS = frozenset(
    {
        "secret",
        "token",
        "password",
        "api_key",
        "auth_header",
        "authorization",
        "raw_prompt",
        "raw_vector",
        "embedding",
        "provider_payload",
        "private_key",
        "session",
        "cookie",
    }
)


class GovernanceDigitalTwinRedactionError(RuntimeError):
    """Raised when replay-safe redaction cannot safely process a payload."""


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", key.strip().lower()).strip("_")


def is_forbidden_key(key: str) -> bool:
    normalized = _normalize_key(key)
    return normalized in FORBIDDEN_FIELD_KEYS


def redact_forbidden_fields(
    payload: Any,
    *,
    warnings: list[str] | None = None,
    path: str = "root",
) -> Any:
    if is_dataclass(payload):
        payload = asdict(cast(Any, payload))

    if isinstance(payload, Mapping):
        redacted: dict[str, Any] = {}
        for raw_key, raw_value in payload.items():
            key = str(raw_key)
            next_path = f"{path}.{key}"
            if is_forbidden_key(key):
                if warnings is not None:
                    warnings.append(f"dropped forbidden field at {next_path}")
                continue
            redacted[key] = redact_forbidden_fields(
                raw_value,
                warnings=warnings,
                path=next_path,
            )
        return redacted

    if isinstance(payload, Sequence) and not isinstance(
        payload, (str, bytes, bytearray)
    ):
        return [
            redact_forbidden_fields(item, warnings=warnings, path=f"{path}[]")
            for item in payload
        ]

    if payload is None or isinstance(payload, (str, int, float, bool)):
        return payload

    raise GovernanceDigitalTwinRedactionError(
        f"unsupported replay-safe payload type at {path}: {type(payload)!r}"
    )


def assert_no_forbidden_fields(payload: Any) -> None:
    if isinstance(payload, Mapping):
        for raw_key, raw_value in payload.items():
            key = str(raw_key)
            if is_forbidden_key(key):
                raise GovernanceDigitalTwinRedactionError(
                    f"forbidden field remained after redaction: {key}"
                )
            assert_no_forbidden_fields(raw_value)
        return
    if isinstance(payload, Sequence) and not isinstance(
        payload, (str, bytes, bytearray)
    ):
        for item in payload:
            assert_no_forbidden_fields(item)
