from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RedactionResult:
    text: str
    redacted: bool
    warnings: list[str]


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "email_redacted",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "phone_redacted",
        re.compile(
            r"\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b"
        ),
    ),
    ("ssn_redacted", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card_redacted", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("ip_redacted", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    (
        "jwt_redacted",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b"),
    ),
    ("bearer_token_redacted", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}")),
    (
        "api_key_redacted",
        re.compile(r"(?i)\b(?:x-api-key|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+"),
    ),
    ("secret_redacted", re.compile(r"(?i)\b(?:sk|rk|pk)_[A-Za-z0-9]{10,}\b")),
    ("hex_api_key_redacted", re.compile(r"\b[A-Fa-f0-9]{32,64}\b")),
    (
        "address_redacted",
        re.compile(
            r"\b\d{1,6}\s+[A-Za-z0-9.\- ]+\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b",
            re.IGNORECASE,
        ),
    ),
)

_REDACTED = "[REDACTED]"


def redact_pii(text: str) -> RedactionResult:
    value = text
    warnings: list[str] = []
    redacted = False

    for warning, pattern in _PATTERNS:
        value_next, count = pattern.subn(_REDACTED, value)
        if count > 0:
            redacted = True
            warnings.append(warning)
            value = value_next

    deduped = sorted(set(warnings))
    return RedactionResult(text=value, redacted=redacted, warnings=deduped)
