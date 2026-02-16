from __future__ import annotations

import unicodedata
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PIIRedactionResult:
    text: str
    redacted: bool
    findings: list[str]


_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    (
        "phone",
        re.compile(
            r"\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b"
        ),
    ),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("api_key", re.compile(r"\b(?:sk|pk|api|key)_[A-Za-z0-9]{16,}\b", re.I)),
    # conservative address heuristic; only obvious street-address style strings
    (
        "address",
        re.compile(
            r"\b\d{1,6}\s+[A-Za-z]+(?:\s+[A-Za-z]+){0,2}\s(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Boulevard|Blvd)\b",
            re.I,
        ),
    ),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("bearer", re.compile(r"\bBearer\s+[A-Za-z0-9._\-+/=]{16,}\b", re.I)),
    ("auth_header", re.compile(r"\bAuthorization\s*:\s*[^\n\r]+", re.I)),
    ("x_api_key_header", re.compile(r"\bX-Api-Key\s*:\s*[^\n\r]+", re.I)),
]


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def redact_pii(text: str) -> PIIRedactionResult:
    sanitized = normalize_text(text)
    findings: list[str] = []
    for label, pattern in _PATTERNS:
        if pattern.search(sanitized):
            findings.append(label)
            sanitized = pattern.sub(f"[REDACTED_{label.upper()}]", sanitized)
    return PIIRedactionResult(
        text=sanitized,
        redacted=bool(findings),
        findings=sorted(set(findings)),
    )
