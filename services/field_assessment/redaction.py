"""Credential and secret redaction for scan payloads.

Walks raw_payload recursively, redacting values whose key names match
sensitive patterns (password, api_key, token, …) or whose string values
match known secret formats (Bearer tokens, AWS keys, JWTs, PEM headers).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

REDACT_SENTINEL = "[REDACTED]"

_MAX_REDACT_DEPTH = 20

# Key names whose values must always be redacted, regardless of value content.
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|secret|api[_\-]?key|apikey"
    r"|token|bearer|credential|auth[_\-]?header"
    r"|private[_\-]?key|access[_\-]?key|client[_\-]?secret"
    r"|refresh[_\-]?token|service[_\-]?account[_\-]?key"
    r"|pem|pkcs|x509|cert(?:ificate)?[_\-]?key"
    r"|oauth[_\-]?token|id[_\-]?token|session[_\-]?key"
    r"|encryption[_\-]?key|signing[_\-]?key"
    r"|hmac[_\-]?secret|jwt[_\-]?secret"
    r")\b"
)

# Value-level patterns — applied only to string values with sensitive content.
_SECRET_VALUE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)^bearer\s+[A-Za-z0-9\-._~+/]+=*$"),
    re.compile(r"(?i)^basic\s+[A-Za-z0-9+/]+=*$"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS AKID
    re.compile(r"ghp_[A-Za-z0-9]{36}"),  # GitHub PAT
    re.compile(r"ghs_[A-Za-z0-9]{36}"),  # GitHub app token
    re.compile(r"sk-[A-Za-z0-9]{48}"),  # OpenAI key
    re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}={0,2}"),  # Long base64 blob
    re.compile(r"-----BEGIN [A-Z ]+(?:KEY|CERTIFICATE)-----"),  # PEM header
    # JWT: three base64url segments separated by dots, middle starts with eyJ
    re.compile(r"[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
]


@dataclass
class RedactionResult:
    payload: dict[str, Any]
    redacted_paths: list[str] = field(default_factory=list)

    @property
    def redacted_count(self) -> int:
        return len(self.redacted_paths)


def _sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY_RE.search(str(key)))


def _sensitive_value(value: str) -> bool:
    return any(p.search(value) for p in _SECRET_VALUE_PATTERNS)


def _walk_dict(
    obj: dict[str, Any],
    paths: list[str],
    prefix: str,
    depth: int,
) -> dict[str, Any]:
    if depth > _MAX_REDACT_DEPTH:
        return obj
    out: dict[str, Any] = {}
    for k, v in obj.items():
        path = f"{prefix}.{k}" if prefix else str(k)
        if _sensitive_key(str(k)):
            out[k] = REDACT_SENTINEL
            paths.append(path)
        elif isinstance(v, dict):
            out[k] = _walk_dict(v, paths, path, depth + 1)
        elif isinstance(v, list):
            out[k] = _walk_list(v, paths, path, depth + 1)
        elif isinstance(v, str) and _sensitive_value(v):
            out[k] = REDACT_SENTINEL
            paths.append(path)
        else:
            out[k] = v
    return out


def _walk_list(
    lst: list[Any],
    paths: list[str],
    prefix: str,
    depth: int,
) -> list[Any]:
    if depth > _MAX_REDACT_DEPTH:
        return lst
    out: list[Any] = []
    for i, item in enumerate(lst):
        path = f"{prefix}[{i}]"
        if isinstance(item, dict):
            out.append(_walk_dict(item, paths, path, depth + 1))
        elif isinstance(item, list):
            out.append(_walk_list(item, paths, path, depth + 1))
        elif isinstance(item, str) and _sensitive_value(item):
            out.append(REDACT_SENTINEL)
            paths.append(path)
        else:
            out.append(item)
    return out


def redact_payload(payload: dict[str, Any]) -> RedactionResult:
    """Redact secrets from *payload* and return the sanitised copy with a path list."""
    paths: list[str] = []
    sanitised = _walk_dict(payload, paths, "", 0)
    return RedactionResult(payload=sanitised, redacted_paths=paths)
