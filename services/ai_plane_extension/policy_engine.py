from __future__ import annotations

import re

_SECRET_PATTERNS = [
    re.compile(r"(?i)api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{8,}"),
    re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
]
_PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
]
_OUTPUT_DENY_PATTERNS = [
    re.compile(r"(?i)BEGIN PRIVATE KEY"),
]


def evaluate_input(prompt: str, denylist: list[str]) -> tuple[bool, str | None]:
    for pat in _SECRET_PATTERNS:
        if pat.search(prompt):
            return False, "AI_INPUT_POLICY_BLOCKED"
    for pat in _PII_PATTERNS:
        if pat.search(prompt):
            return False, "AI_INPUT_POLICY_BLOCKED"
    low = prompt.lower()
    for term in denylist:
        if term and term.lower() in low:
            return False, "AI_INPUT_POLICY_BLOCKED"
    return True, None


def evaluate_output(output: str) -> tuple[bool, str | None]:
    for pat in _OUTPUT_DENY_PATTERNS:
        if pat.search(output):
            return False, "AI_OUTPUT_POLICY_BLOCKED"
    return True, None
