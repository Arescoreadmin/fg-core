"""
FrostGate Control Plane - Error Detail Sanitizer

Strips credentials, tokens, stack traces, and other secrets from error strings
before they are stored in audit logs or returned in API error responses.

INVARIANT: No known secret pattern must survive sanitize_error_detail().

Covers:
  - Credentials embedded in URLs (scheme://user:password@host)
  - Token/key/secret in query strings (?token=xyz)
  - Authorization header values (Bearer, Basic, etc.)
  - X-API-Key header values
  - Cookie / Set-Cookie values containing session/auth tokens
  - JWT-shaped tokens (three base64url segments)
  - Python traceback frames and blocks
  - PEM private key blocks
"""
from __future__ import annotations

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Compiled strip patterns — order matters: most specific first.
# Each entry is (compiled_pattern, replacement_string).
# ---------------------------------------------------------------------------
_SANITIZE_PATTERNS: list[tuple[re.Pattern, str]] = [
    # 1. PEM private key blocks (must come first — multiline)
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?"
            r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.IGNORECASE,
        ),
        "[REDACTED-PRIVATE-KEY]",
    ),
    # 2. Python "Traceback (most recent call last):" block
    (
        re.compile(
            r"Traceback \(most recent call last\):[\s\S]*?(?=\n\n|\n[A-Z]|\Z)",
            re.MULTILINE,
        ),
        "[REDACTED-TRACEBACK]",
    ),
    # 3. Python traceback individual frames
    (
        re.compile(r'File "[^"]+", line \d+,? in \w[^\n]*'),
        "[REDACTED-TRACEBACK-FRAME]",
    ),
    # 4. JWT-shaped tokens (three base64url segments, min 10 chars each)
    (
        re.compile(
            r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ),
        "[REDACTED-JWT]",
    ),
    # 5. URLs with embedded credentials: scheme://user:password@host/...
    (
        re.compile(
            r"[a-zA-Z][a-zA-Z0-9+\-.]*://[^\s@/:\"'<>]+:[^\s@/:\"'<>]+@[^\s\"'<>]+",
            re.IGNORECASE,
        ),
        "[REDACTED-URL-CREDS]",
    ),
    # 6. Token/key/secret/password in query strings or key=value pairs
    #    Matches: ?api_key=xxx  &token=xxx  ?secret=xxx  etc.
    (
        re.compile(
            r"(?i)([?&])"
            r"(api[_-]?key|access[_-]?key|token|secret|password|passwd|pw|"
            r"auth|bearer|credential|private[_-]?key|client[_-]?secret)"
            r"([=:])[^\s&\"'<>#]+"
        ),
        r"\1\2\3[REDACTED]",
    ),
    # 7. Authorization header values: "Authorization: Bearer xxx"
    (
        re.compile(
            r"(?i)(Authorization\s*[:=]\s*)"
            r"(Bearer|Basic|Token|Digest|AWS4-HMAC-SHA256|ApiKey|Hawk)\s+\S+"
        ),
        r"\1\2 [REDACTED]",
    ),
    # 8. X-API-Key header values
    (
        re.compile(r"(?i)(X-API-Key\s*[:=]\s*)\S+"),
        r"\1[REDACTED]",
    ),
    # 9. Cookie / Set-Cookie values containing session/auth token fields
    (
        re.compile(
            r"(?i)((?:Cookie|Set-Cookie)\s*:\s*[^;\"'\n]*?"
            r"(?:session|token|auth|key|csrf|sid)\s*=\s*)[^\s;,\"'\n]+"
        ),
        r"\1[REDACTED]",
    ),
]


def sanitize_error_detail(text: Optional[str]) -> Optional[str]:
    """
    Strip credentials, tokens, URLs with secrets, and stack traces from
    error detail strings.

    Safe to call on None — returns None unchanged.
    Always apply before storing error detail in audit logs or returning
    it in any API response, even in non-production environments.

    This function is intentionally conservative: it may over-redact
    in edge cases. Under-redaction is a security defect; over-redaction
    is a cosmetic issue.
    """
    if text is None:
        return None

    result = str(text)
    for pattern, replacement in _SANITIZE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result
