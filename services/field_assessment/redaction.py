"""Credential and secret redaction for scan payloads.

Walks raw_payload recursively, redacting values whose key names match
sensitive patterns (password, api_key, token, secret, bearer, …) or whose
string values match known secret formats (Bearer tokens, AWS AKIDs, GitHub
PATs, OpenAI keys, JWTs, PEM headers, Vault tokens, Databricks tokens, …).

JSON-in-JSON: string values that deserialise as JSON objects/arrays are
walked recursively so secrets inside stringified payloads (e.g. Terraform
state, CloudFormation outputs) are also caught.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

REDACT_SENTINEL = "[REDACTED]"

_MAX_REDACT_DEPTH = 20

# ---------------------------------------------------------------------------
# Key-name patterns — substring match (no word-boundary anchors so that
# "private_key_id", "access_key_secret", etc. are all caught).
# ---------------------------------------------------------------------------
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)"
    r"(password|passwd"
    r"|secret"
    r"|api[_\-]?key|apikey"
    r"|token"
    r"|bearer"
    r"|credential"
    r"|auth[_\-]?header"
    r"|private[_\-]?key"
    r"|access[_\-]?key"
    r"|client[_\-]?secret"
    r"|oauth[_\-]?token|id[_\-]?token"
    r"|session[_\-]?key"
    r"|encryption[_\-]?key|signing[_\-]?key"
    r"|hmac[_\-]?secret|jwt[_\-]?secret"
    # Cloud / infra specific
    r"|role[_\-]?arn"  # AWS assumed-role ARN
    r"|external[_\-]?id"  # AWS cross-account external ID
    r"|kms[_\-]?key"  # AWS / GCP KMS
    r"|connection[_\-]?string"  # Azure / DB connection strings
    r"|sas[_\-]?token"  # Azure SAS tokens
    r"|storage[_\-]?key"  # Azure / GCP storage
    r"|service[_\-]?account[_\-]?key"  # GCP SA JSON key
    r"|pem|pkcs|x509"
    r"|cert(?:ificate)?[_\-]?key"
    r")"
)

# ---------------------------------------------------------------------------
# Value-level patterns — applied to string values only.
# ---------------------------------------------------------------------------
_SECRET_VALUE_PATTERNS: list[re.Pattern[str]] = [
    # HTTP auth headers
    re.compile(r"(?i)^bearer\s+[A-Za-z0-9\-._~+/]+=*$"),
    re.compile(r"(?i)^basic\s+[A-Za-z0-9+/]+=*$"),
    # AWS
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS Access Key ID
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),  # AWS STS token
    # GitHub
    re.compile(r"ghp_[A-Za-z0-9]{36}"),  # GitHub PAT
    re.compile(r"ghs_[A-Za-z0-9]{36}"),  # GitHub app token
    re.compile(r"gho_[A-Za-z0-9]{36}"),  # GitHub OAuth
    # OpenAI / Anthropic
    re.compile(r"sk-[A-Za-z0-9]{48}"),  # OpenAI
    re.compile(r"sk-ant-[A-Za-z0-9\-]{40,}"),  # Anthropic
    # Stripe
    re.compile(r"sk_live_[A-Za-z0-9]{24,}"),  # Stripe live secret
    re.compile(r"rk_live_[A-Za-z0-9]{24,}"),  # Stripe restricted key
    # Databricks
    re.compile(r"dapi[a-f0-9]{32}"),  # Databricks token
    # HashiCorp Vault
    re.compile(r"s\.[A-Za-z0-9]{20,}"),  # Vault token
    # Database / connection URIs
    re.compile(r"(?i)(postgres|mysql|redis|mongodb(?:\+srv)?)://[^:]+:[^@]+@"),
    re.compile(r"DefaultEndpointProtocol=https;AccountName="),  # Azure storage
    # PEM / certificate headers
    re.compile(r"-----BEGIN [A-Z ]+(?:KEY|CERTIFICATE|PRIVATE)-----"),
    # JWT: header.payload.signature — middle segment starts with eyJ (base64 of "{")
    re.compile(r"[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
    # Properly padded base64 blob ≥40 chars (GCP service-account keys, etc.)
    # Anchored ^ … $ so hex hashes (no +/) and short strings don't match.
    re.compile(r"^[A-Za-z0-9+/]{40,}={1,2}$"),
]

# Minimum length for a string value before we apply value-pattern scanning.
_MIN_VALUE_SCAN_LEN = 8


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
    if len(value) < _MIN_VALUE_SCAN_LEN:
        return False
    return any(p.search(value) for p in _SECRET_VALUE_PATTERNS)


def _try_parse_json(value: str) -> dict[str, Any] | list[Any] | None:
    """Try to deserialise *value* as JSON object or array; return None on failure."""
    stripped = value.strip()
    if not stripped or stripped[0] not in ("{", "["):
        return None
    try:
        parsed = json.loads(stripped)
    except (ValueError, json.JSONDecodeError):
        return None
    if isinstance(parsed, (dict, list)):
        return parsed  # type: ignore[return-value]
    return None


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
            # For scalar values under a sensitive key: redact directly.
            # For dicts/lists: walk into them so non-sensitive sibling fields
            # (e.g. region, client_email) are preserved alongside the secrets.
            if isinstance(v, dict):
                out[k] = _walk_dict(v, paths, path, depth + 1)
            elif isinstance(v, list):
                out[k] = _walk_list(v, paths, path, depth + 1)
            else:
                out[k] = REDACT_SENTINEL
                paths.append(path)
        elif isinstance(v, dict):
            out[k] = _walk_dict(v, paths, path, depth + 1)
        elif isinstance(v, list):
            out[k] = _walk_list(v, paths, path, depth + 1)
        elif isinstance(v, str):
            if _sensitive_value(v):
                out[k] = REDACT_SENTINEL
                paths.append(path)
            else:
                # JSON-in-JSON: string values containing serialised JSON are
                # also walked so secrets inside Terraform state, CloudFormation
                # outputs, Helm values, etc. are caught.
                parsed = _try_parse_json(v)
                if parsed is not None:
                    before = len(paths)
                    walked: Any
                    if isinstance(parsed, dict):
                        walked = _walk_dict(parsed, paths, path, depth + 1)
                    else:
                        walked = _walk_list(parsed, paths, path, depth + 1)
                    if len(paths) > before:
                        # Re-serialise only when something was redacted.
                        out[k] = json.dumps(walked, separators=(",", ":"))
                    else:
                        out[k] = v
                else:
                    out[k] = v
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
        elif isinstance(item, str):
            if _sensitive_value(item):
                out.append(REDACT_SENTINEL)
                paths.append(path)
            else:
                parsed = _try_parse_json(item)
                if parsed is not None:
                    before = len(paths)
                    walked: Any
                    if isinstance(parsed, dict):
                        walked = _walk_dict(parsed, paths, path, depth + 1)
                    else:
                        walked = _walk_list(parsed, paths, path, depth + 1)
                    if len(paths) > before:
                        out.append(json.dumps(walked, separators=(",", ":")))
                    else:
                        out.append(item)
                else:
                    out.append(item)
        else:
            out.append(item)
    return out


def redact_payload(payload: dict[str, Any]) -> RedactionResult:
    """Redact secrets from *payload* and return the sanitised copy with a path list."""
    paths: list[str] = []
    sanitised = _walk_dict(payload, paths, "", 0)
    return RedactionResult(payload=sanitised, redacted_paths=paths)
