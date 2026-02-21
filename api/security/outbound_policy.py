from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Mapping
from urllib.parse import urljoin, urlsplit, urlunsplit

from api.config.env import is_production_env

MAX_REDIRECT_HOPS = 3
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")


class OutboundPolicyError(ValueError):
    """Raised when outbound request policy is violated."""


def sanitize_header_value(value: str) -> str:
    text = str(value)
    for idx, ch in enumerate(text):
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            text = text[:idx]
            break
    text = _CONTROL_CHAR_RE.sub("", text).strip()
    return text[:256]


def sanitize_url_for_log(url: str) -> str:
    cleaned = _CONTROL_CHAR_RE.sub("", str(url))
    try:
        parsed = urlsplit(cleaned)
    except Exception:
        return "<malformed-url>"
    if not parsed.scheme or not parsed.hostname:
        return "<malformed-url>"
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host if parsed.port is None else f"{host}:{parsed.port}"
    safe_path = sanitize_header_value(parsed.path or "/")
    return urlunsplit((parsed.scheme, netloc, safe_path, "", ""))


def sanitize_outbound_headers(headers: Mapping[str, str]) -> dict[str, str]:
    clean: dict[str, str] = {}
    for k, v in headers.items():
        key = str(k).strip()
        if not _HEADER_NAME_RE.match(key):
            raise OutboundPolicyError("invalid_header_name")
        clean[key] = sanitize_header_value(str(v))
    return clean


def _parse_url(url: str):
    cleaned = _CONTROL_CHAR_RE.sub("", str(url))
    try:
        parsed = urlsplit(cleaned)
    except Exception as exc:
        raise OutboundPolicyError("malformed_url") from exc
    if parsed.scheme not in {"http", "https"}:
        raise OutboundPolicyError("scheme_not_allowed")
    if not parsed.hostname:
        raise OutboundPolicyError("host_required")
    if parsed.username is not None or parsed.password is not None:
        raise OutboundPolicyError("userinfo_not_allowed")
    return parsed


def _resolve_host(host: str) -> list[str]:
    try:
        info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise OutboundPolicyError("dns_resolution_failed") from exc
    ips = sorted({entry[4][0] for entry in info})
    if not ips:
        raise OutboundPolicyError("dns_no_addresses")
    return ips


def _is_ip_blocked(ip_raw: str) -> bool:
    ip = ipaddress.ip_address(ip_raw)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_unspecified,
            ip.is_reserved,
        )
    )


def validate_target(url: str, *, allow_private: bool = False) -> tuple[str, list[str]]:
    parsed = _parse_url(url)
    if is_production_env() and parsed.scheme != "https":
        raise OutboundPolicyError("https_required_in_production")
    ips = _resolve_host(parsed.hostname)
    if not allow_private and any(_is_ip_blocked(ip) for ip in ips):
        raise OutboundPolicyError("resolved_ip_blocked")
    rebound_ips = _resolve_host(parsed.hostname)
    if rebound_ips != ips:
        raise OutboundPolicyError("dns_rebinding_detected")
    normalized_url = urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "/", "", "")
    )
    return normalized_url, ips


async def safe_post_with_redirects(
    client: object,
    url: str,
    *,
    json_body: dict,
    headers: Mapping[str, str],
    timeout: float,
    allow_private: bool = False,
    max_redirect_hops: int = MAX_REDIRECT_HOPS,
) -> object:
    current_url = url
    clean_headers = sanitize_outbound_headers(headers)
    for hop in range(max_redirect_hops + 1):
        normalized_url, _ = validate_target(current_url, allow_private=allow_private)
        response = await client.post(
            normalized_url,
            json=json_body,
            headers=clean_headers,
            timeout=timeout,
            follow_redirects=False,
        )
        status = getattr(response, "status_code", None)
        if status is None:
            status = getattr(response, "status", 0)
        if 300 <= status < 400:
            location = (getattr(response, "headers", {}) or {}).get("Location")
            if not location:
                raise OutboundPolicyError("redirect_location_missing")
            if hop >= max_redirect_hops:
                raise OutboundPolicyError("redirect_hop_limit_exceeded")
            current_url = urljoin(normalized_url, location)
            continue
        return response
    raise OutboundPolicyError("redirect_hop_limit_exceeded")
