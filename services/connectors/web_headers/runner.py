"""Web Security Headers connector — inspects HTTP security headers for target URLs.

Redirect safety: follow_redirects=False is set on the httpx client. Each redirect
Location is revalidated through SafeTargetValidationService before following, so
a redirect chain cannot reach private infrastructure even if the initial URL is public.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from services.connectors.safe_target_validator import SafeTargetValidationService

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_MAX_REDIRECT_HOPS = 5
_validator = SafeTargetValidationService()

_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
]

_HSTS_MIN_MAX_AGE = 15_768_000  # 6 months in seconds


def _normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def _follow_redirects_safely(
    client: httpx.Client, initial_url: str
) -> tuple[httpx.Response, str | None]:
    """Follow redirects manually, re-validating every hop through the validator.

    Returns (final_response, rejection_reason).
    rejection_reason is non-None if a redirect was blocked; in that case
    final_response is the response that issued the blocked redirect.
    """
    current_url = initial_url
    for _ in range(_MAX_REDIRECT_HOPS):
        resp = client.head(current_url, follow_redirects=False)
        if resp.status_code not in (301, 302, 303, 307, 308):
            return resp, None

        location = resp.headers.get("location", "")
        if not location:
            return resp, None

        # Resolve relative redirect URLs against current URL.
        next_url = urljoin(current_url, location)

        result = _validator.validate(next_url, target_type="url")
        if not result.ok:
            return resp, (
                f"redirect to {next_url!r} blocked: "
                f"[{result.rejection_code}] {result.rejection_reason}"
            )
        current_url = next_url

    # Exceeded hop limit — treat as non-redirect final response.
    resp = client.head(current_url, follow_redirects=False)
    return resp, None


def _check_hsts(value: str | None) -> list[dict]:
    if not value:
        return [
            {
                "type": "missing_hsts",
                "severity": "high",
                "title": "Missing HSTS Header",
                "description": "Strict-Transport-Security header is absent; browsers may downgrade to HTTP.",
            }
        ]
    findings = []
    max_age = 0
    for directive in value.split(";"):
        directive = directive.strip().lower()
        if directive.startswith("max-age="):
            try:
                max_age = int(directive.split("=", 1)[1])
            except ValueError:
                pass
    if max_age < _HSTS_MIN_MAX_AGE:
        findings.append(
            {
                "type": "hsts_short_maxage",
                "severity": "medium",
                "title": f"HSTS max-age Too Short ({max_age}s)",
                "description": f"HSTS max-age={max_age} is below the recommended {_HSTS_MIN_MAX_AGE}s (6 months).",
            }
        )
    if "includesubdomains" not in value.lower():
        findings.append(
            {
                "type": "hsts_no_subdomains",
                "severity": "low",
                "title": "HSTS Missing includeSubDomains",
                "description": "HSTS does not cover subdomains, leaving them open to downgrade attacks.",
            }
        )
    return findings


def _check_csp(value: str | None) -> list[dict]:
    if not value:
        return [
            {
                "type": "missing_csp",
                "severity": "medium",
                "title": "Missing Content-Security-Policy",
                "description": "No CSP header found; XSS attack surface is unrestricted.",
            }
        ]
    findings = []
    if "'unsafe-inline'" in value:
        findings.append(
            {
                "type": "csp_unsafe_inline",
                "severity": "medium",
                "title": "CSP Allows unsafe-inline",
                "description": "CSP permits inline scripts/styles, weakening XSS protection.",
            }
        )
    if "'unsafe-eval'" in value:
        findings.append(
            {
                "type": "csp_unsafe_eval",
                "severity": "medium",
                "title": "CSP Allows unsafe-eval",
                "description": "CSP permits eval(), which is exploitable in XSS attacks.",
            }
        )
    if "default-src *" in value or "script-src *" in value:
        findings.append(
            {
                "type": "csp_wildcard_source",
                "severity": "high",
                "title": "CSP Wildcard Source Allowed",
                "description": "CSP permits loading resources from any origin (*), negating XSS protection.",
            }
        )
    return findings


def _check_x_frame(value: str | None) -> list[dict]:
    if not value:
        return [
            {
                "type": "missing_x_frame_options",
                "severity": "medium",
                "title": "Missing X-Frame-Options",
                "description": "No X-Frame-Options header; page may be embeddable in iframes (clickjacking risk).",
            }
        ]
    return []


def _check_x_content_type(value: str | None) -> list[dict]:
    if not value or value.strip().lower() != "nosniff":
        return [
            {
                "type": "missing_x_content_type",
                "severity": "low",
                "title": "Missing X-Content-Type-Options: nosniff",
                "description": "Browser may MIME-sniff responses, enabling content injection attacks.",
            }
        ]
    return []


def _check_referrer_policy(value: str | None) -> list[dict]:
    if not value:
        return [
            {
                "type": "missing_referrer_policy",
                "severity": "low",
                "title": "Missing Referrer-Policy",
                "description": "No Referrer-Policy set; full URL may leak in Referer headers to third parties.",
            }
        ]
    unsafe = {"unsafe-url", "no-referrer-when-downgrade"}
    if value.strip().lower() in unsafe:
        return [
            {
                "type": "referrer_policy_unsafe",
                "severity": "low",
                "title": f"Referrer-Policy Too Permissive ({value})",
                "description": "Referrer-Policy leaks full URLs to external origins.",
            }
        ]
    return []


def _check_permissions_policy(value: str | None) -> list[dict]:
    if not value:
        return [
            {
                "type": "missing_permissions_policy",
                "severity": "low",
                "title": "Missing Permissions-Policy",
                "description": "No Permissions-Policy header; browser features (camera, microphone, geolocation) may be accessible to embedded content.",
            }
        ]
    return []


def _check_plain_http(url: str, response_url: str) -> list[dict]:
    parsed_response = urlparse(response_url)
    if parsed_response.scheme == "http":
        return [
            {
                "type": "plain_http",
                "severity": "high",
                "title": "Site Served Over Plain HTTP",
                "description": f"{url} is served over HTTP with no HTTPS redirect.",
            }
        ]
    return []


def scan_target(url: str) -> dict[str, Any]:
    normalized = _normalize_url(url)

    # Validate the initial URL before opening any connection (Layer 1 + 2 + 3–5).
    pre_check = _validator.validate(normalized, target_type="url")
    if not pre_check.ok:
        return {
            "url": normalized,
            "final_url": None,
            "status_code": None,
            "headers_present": [],
            "headers_missing": list(_SECURITY_HEADERS),
            "score": 0,
            "findings": [],
            "error": f"target blocked by scanner policy: [{pre_check.rejection_code}] {pre_check.rejection_reason}",
            "blocked": True,
            "rejection_code": pre_check.rejection_code,
        }

    findings: list[dict] = []
    headers_found: dict[str, str] = {}
    error = None

    try:
        # follow_redirects=False — every redirect hop is manually revalidated.
        with httpx.Client(
            timeout=_TIMEOUT, follow_redirects=False, verify=True
        ) as client:
            resp, redirect_block = _follow_redirects_safely(client, normalized)
            if redirect_block:
                return {
                    "url": normalized,
                    "final_url": None,
                    "status_code": resp.status_code,
                    "headers_present": [],
                    "headers_missing": list(_SECURITY_HEADERS),
                    "score": 0,
                    "findings": [],
                    "error": redirect_block,
                    "blocked": True,
                    "rejection_code": "UNSAFE_REDIRECT",
                }

            final_url = str(resp.url)
            for h in _SECURITY_HEADERS:
                val = resp.headers.get(h)
                if val:
                    headers_found[h] = val

            findings.extend(_check_plain_http(normalized, final_url))
            findings.extend(_check_hsts(headers_found.get("strict-transport-security")))
            findings.extend(_check_csp(headers_found.get("content-security-policy")))
            findings.extend(_check_x_frame(headers_found.get("x-frame-options")))
            findings.extend(
                _check_x_content_type(headers_found.get("x-content-type-options"))
            )
            findings.extend(
                _check_referrer_policy(headers_found.get("referrer-policy"))
            )
            findings.extend(
                _check_permissions_policy(headers_found.get("permissions-policy"))
            )

            score = max(0, 100 - len(findings) * 12)

            return {
                "url": normalized,
                "final_url": final_url,
                "status_code": resp.status_code,
                "headers_present": list(headers_found.keys()),
                "headers_missing": [
                    h for h in _SECURITY_HEADERS if h not in headers_found
                ],
                "score": score,
                "findings": findings,
                "error": None,
                "blocked": False,
            }
    except httpx.ConnectError:
        error = f"Connection refused or DNS resolution failed for {normalized}"
    except httpx.TimeoutException:
        error = f"Request timed out for {normalized}"
    except Exception as exc:
        error = str(exc)

    return {
        "url": normalized,
        "final_url": None,
        "status_code": None,
        "headers_present": [],
        "headers_missing": list(_SECURITY_HEADERS),
        "score": 0,
        "findings": [],
        "error": error,
        "blocked": False,
    }


def run(targets: list[str]) -> dict[str, Any]:
    results = []
    all_findings: list[dict] = []
    for target in targets:
        result = scan_target(target)
        results.append(result)
        for f in result["findings"]:
            all_findings.append({**f, "target": target})

    reachable = [r for r in results if r["error"] is None]
    avg_score = (
        int(sum(r["score"] for r in reachable) / len(reachable)) if reachable else 0
    )

    return {
        "targets": results,
        "findings": all_findings,
        "summary": {
            "total_targets": len(targets),
            "reachable": len(reachable),
            "avg_security_score": avg_score,
            "total_findings": len(all_findings),
        },
    }
