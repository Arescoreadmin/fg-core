"""
SafeTargetValidationService — centralized SSRF and private-range protection.

All scanners MUST call this service before connecting to any user-supplied target.
No scanner may bypass it. No scanner-specific exceptions. No environment-variable
bypasses. No localhost exceptions. No metadata exceptions.

Validation layers:
  1. Input normalization (hostname, URL, CIDR, IPv4, IPv6)
  2. DNS resolution — hostnames resolved to IPs before any check
  3. Private range blocking (RFC1918, RFC4193, RFC3927, loopback, multicast,
     link-local, CGNAT, documentation, future-use, broadcast)
  4. Cloud metadata endpoint protection (169.254.169.254 and equivalents)
  5. DNS rebinding protection — ALL resolved IPs must pass; first-safe/second-unsafe
     is a hard failure
  6. CIDR host validation — every host in a small CIDR is validated individually

Redirect containment is handled by the calling runner, not this service. Callers
must invoke validate() on every redirect Location value before following.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    normalized: str  # canonical form of the validated target
    target_type: str  # "ip" | "hostname" | "cidr" | "url"
    resolved_ips: list[str]  # all IPs resolved (empty for unresolved CIDRs)
    rejection_reason: str | None
    rejection_code: str | None


# ---------------------------------------------------------------------------
# Blocked IPv4 networks (all RFC-reserved, private, documentation, or special-use)
# ---------------------------------------------------------------------------
_BLOCKED_IPV4_NETWORKS: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in (
        "0.0.0.0/8",  # This network (RFC1122 §3.2.1.3)
        "10.0.0.0/8",  # Private (RFC1918)
        "100.64.0.0/10",  # Shared Address Space / CGNAT (RFC6598)
        "127.0.0.0/8",  # Loopback (RFC1122)
        "169.254.0.0/16",  # Link-local / APIPA (RFC3927) — includes metadata
        "172.16.0.0/12",  # Private (RFC1918)
        "192.0.0.0/24",  # IETF Protocol Assignments (RFC6890)
        "192.0.2.0/24",  # Documentation TEST-NET-1 (RFC5737)
        "192.88.99.0/24",  # 6to4 relay anycast deprecated (RFC7526)
        "192.168.0.0/16",  # Private (RFC1918)
        "198.18.0.0/15",  # Benchmarking (RFC2544)
        "198.51.100.0/24",  # Documentation TEST-NET-2 (RFC5737)
        "203.0.113.0/24",  # Documentation TEST-NET-3 (RFC5737)
        "224.0.0.0/4",  # Multicast (RFC1112)
        "233.252.0.0/24",  # Documentation MCAST-TEST (RFC6676)
        "240.0.0.0/4",  # Reserved / Future use (RFC1112)
        "255.255.255.255/32",  # Limited broadcast
    )
)

# ---------------------------------------------------------------------------
# Blocked IPv6 networks
# ---------------------------------------------------------------------------
_BLOCKED_IPV6_NETWORKS: tuple[ipaddress.IPv6Network, ...] = tuple(
    ipaddress.IPv6Network(cidr)
    for cidr in (
        "::/128",  # Unspecified (RFC4291)
        "::1/128",  # Loopback (RFC4291)
        "::ffff:0:0/96",  # IPv4-mapped (RFC4291) — may embed private IPv4
        "::ffff:0:0:0/96",  # IPv4-translated (RFC6145)
        "64:ff9b::/96",  # IPv4/IPv6 translation (RFC6052)
        "64:ff9b:1::/48",  # IPv4/IPv6 translation local (RFC8215)
        "100::/64",  # Discard prefix (RFC6666)
        "2001::/23",  # IETF protocol assignments (RFC2928) — covers Teredo, etc.
        "2001:db8::/32",  # Documentation (RFC3849)
        "2002::/16",  # 6to4 (RFC3056) — maps to IPv4, potentially private
        "fc00::/7",  # Unique local (RFC4193)
        "fe80::/10",  # Link-local (RFC4291)
        "ff00::/8",  # Multicast (RFC4291)
    )
)

# Explicit cloud metadata IPs beyond the link-local range.
_CLOUD_METADATA_IPS: frozenset[str] = frozenset(
    {
        "169.254.169.254",  # AWS IMDSv1/v2, Azure IMDS, GCP metadata, DigitalOcean, OCI, Hetzner
        "169.254.0.1",  # Some legacy cloud hypervisors
        "100.100.100.200",  # Alibaba Cloud ECS metadata (RFC6598 range)
        "fd00:ec2::254",  # AWS IPv6 IMDSv2
    }
)

# Cloud metadata hostnames — rejected regardless of resolved IP.
_CLOUD_METADATA_HOSTNAMES: frozenset[str] = frozenset(
    {
        "metadata.google.internal",
        "metadata.gce.internal",
        "metadata.azure.com",
        "metadata.azure.internal",
        "instance-data",  # DigitalOcean legacy
        "169.254.169.254",  # Explicit IP-as-hostname
        "100.100.100.200",  # Alibaba explicit
    }
)

# Maximum number of hosts to validate individually in a CIDR (≤ /28 = 16 hosts).
_MAX_CIDR_HOSTS_INLINE = 16


def _blocked_ipv4(addr: ipaddress.IPv4Address) -> tuple[bool, str]:
    for net in _BLOCKED_IPV4_NETWORKS:
        if addr in net:
            return True, f"{addr} is in blocked range {net}"
    if str(addr) in _CLOUD_METADATA_IPS:
        return True, f"{addr} is a cloud metadata endpoint"
    return False, ""


def _blocked_ipv6(addr: ipaddress.IPv6Address) -> tuple[bool, str]:
    # Check IPv4-mapped first — a mapped private address is still private.
    if addr.ipv4_mapped is not None:
        blocked, reason = _blocked_ipv4(addr.ipv4_mapped)
        if blocked:
            return True, f"IPv6-mapped address embeds blocked IPv4: {reason}"
    for net in _BLOCKED_IPV6_NETWORKS:
        if addr in net:
            return True, f"{addr} is in blocked range {net}"
    if str(addr) in _CLOUD_METADATA_IPS:
        return True, f"{addr} is a cloud metadata endpoint"
    return False, ""


def _blocked_ip_str(ip_str: str) -> tuple[bool, str]:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"cannot parse {ip_str!r} as IP address"
    if isinstance(addr, ipaddress.IPv4Address):
        return _blocked_ipv4(addr)
    return _blocked_ipv6(addr)  # type: ignore[arg-type]


def _default_dns_resolve(hostname: str) -> list[str]:
    """Resolve hostname to all IP addresses. Raises OSError on failure."""
    try:
        results = socket.getaddrinfo(
            hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise OSError(str(exc)) from exc
    seen: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in results:
        ip = sockaddr[0]
        if ip not in seen:
            seen.append(ip)
    return seen


class SafeTargetValidationService:
    """
    Central scanner trust gate.

    Every call to validate() enforces all 6 validation layers.
    Injectable DNS resolver for deterministic unit tests.
    """

    def __init__(
        self,
        *,
        dns_resolver: Callable[[str], list[str]] | None = None,
    ) -> None:
        self._resolve: Callable[[str], list[str]] = dns_resolver or _default_dns_resolve

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(
        self, target: str, *, target_type: str | None = None
    ) -> ValidationResult:
        """
        Validate a single target string.

        target_type is auto-detected when omitted:
          - starts with http:// or https:// → url
          - contains / that forms valid CIDR → cidr
          - valid bare IP address → ip
          - everything else → hostname
        """
        target = (target or "").strip()
        if not target:
            return self._reject(
                "", "unknown", [], "EMPTY_TARGET", "empty target string"
            )

        detected = target_type or self._detect_type(target)
        if detected == "url":
            return self._validate_url(target)
        if detected == "cidr":
            return self._validate_cidr(target)
        if detected == "ip":
            return self._validate_ip(target)
        return self._validate_hostname(target)

    # ------------------------------------------------------------------
    # Type detection
    # ------------------------------------------------------------------

    def _detect_type(self, target: str) -> str:
        if target.startswith(("http://", "https://")):
            return "url"
        # Try CIDR before IP so 10.0.0.0/8 is correctly detected.
        if "/" in target:
            try:
                ipaddress.ip_network(target, strict=False)
                return "cidr"
            except ValueError:
                return "url"
        try:
            ipaddress.ip_address(target)
            return "ip"
        except ValueError:
            return "hostname"

    # ------------------------------------------------------------------
    # Layer validators
    # ------------------------------------------------------------------

    def _validate_ip(self, target: str) -> ValidationResult:
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            return self._reject(
                target, "ip", [], "INVALID_IP", f"{target!r} is not a valid IP address"
            )

        normalized = str(addr)
        if isinstance(addr, ipaddress.IPv4Address):
            blocked, reason = _blocked_ipv4(addr)
        else:
            blocked, reason = _blocked_ipv6(addr)  # type: ignore[arg-type]

        if blocked:
            return self._reject(normalized, "ip", [normalized], "BLOCKED_IP", reason)

        return ValidationResult(
            ok=True,
            normalized=normalized,
            target_type="ip",
            resolved_ips=[normalized],
            rejection_reason=None,
            rejection_code=None,
        )

    def _validate_hostname(self, target: str) -> ValidationResult:
        hostname = target.lower().rstrip(".")

        # Layer 4: cloud metadata hostname check (before DNS, no resolution needed).
        if hostname in _CLOUD_METADATA_HOSTNAMES:
            return self._reject(
                hostname,
                "hostname",
                [],
                "CLOUD_METADATA_HOSTNAME",
                f"{hostname!r} is a cloud metadata hostname",
            )

        # Layer 2: DNS resolution.
        try:
            resolved = self._resolve(hostname)
        except OSError as exc:
            return self._reject(
                hostname,
                "hostname",
                [],
                "DNS_RESOLUTION_FAILED",
                f"DNS resolution failed for {hostname!r}: {exc}",
            )

        if not resolved:
            return self._reject(
                hostname,
                "hostname",
                [],
                "DNS_NO_RECORDS",
                f"DNS returned no records for {hostname!r}",
            )

        # Layer 5: DNS rebinding — every resolved IP must be safe.
        for ip_str in resolved:
            blocked, reason = _blocked_ip_str(ip_str)
            if blocked:
                return self._reject(
                    hostname,
                    "hostname",
                    resolved,
                    "DNS_REBINDING_OR_PRIVATE",
                    f"{hostname!r} resolves to blocked address — {reason}",
                )

        return ValidationResult(
            ok=True,
            normalized=hostname,
            target_type="hostname",
            resolved_ips=resolved,
            rejection_reason=None,
            rejection_code=None,
        )

    def _validate_cidr(self, target: str) -> ValidationResult:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return self._reject(
                target,
                "cidr",
                [],
                "INVALID_CIDR",
                f"{target!r} is not a valid CIDR notation",
            )

        normalized = str(net)

        # Layer 6: validate every host if small CIDR; network + broadcast if large.
        if net.num_addresses <= _MAX_CIDR_HOSTS_INLINE:
            for addr in net.hosts():
                if isinstance(addr, ipaddress.IPv4Address):
                    blocked, reason = _blocked_ipv4(addr)
                else:
                    blocked, reason = _blocked_ipv6(addr)  # type: ignore[arg-type]
                if blocked:
                    return self._reject(
                        normalized,
                        "cidr",
                        [],
                        "BLOCKED_CIDR_HOST",
                        f"{normalized} contains blocked address {addr}: {reason}",
                    )
        else:
            # Large CIDR — check network address; also check if the network
            # itself is entirely within a blocked range.
            if isinstance(net, ipaddress.IPv4Network):
                blocked, reason = _blocked_ipv4(net.network_address)
                if not blocked:
                    blocked, reason = _blocked_ipv4(net.broadcast_address)
            else:
                blocked, reason = _blocked_ipv6(net.network_address)  # type: ignore[arg-type]
            if blocked:
                return self._reject(
                    normalized,
                    "cidr",
                    [],
                    "BLOCKED_CIDR_NETWORK",
                    f"{normalized} is in a blocked range: {reason}",
                )

        return ValidationResult(
            ok=True,
            normalized=normalized,
            target_type="cidr",
            resolved_ips=[],
            rejection_reason=None,
            rejection_code=None,
        )

    def _validate_url(self, target: str) -> ValidationResult:
        try:
            parsed = urlparse(target)
        except Exception as exc:
            return self._reject(
                target, "url", [], "INVALID_URL", f"cannot parse URL: {exc}"
            )

        if parsed.scheme not in ("http", "https"):
            return self._reject(
                target,
                "url",
                [],
                "INVALID_URL_SCHEME",
                f"URL scheme {parsed.scheme!r} is not http or https",
            )

        hostname = parsed.hostname
        if not hostname:
            return self._reject(
                target,
                "url",
                [],
                "MISSING_URL_HOSTNAME",
                f"URL {target!r} has no hostname",
            )

        # IP literal in URL — validate directly.
        try:
            addr = ipaddress.ip_address(hostname)
            if isinstance(addr, ipaddress.IPv4Address):
                blocked, reason = _blocked_ipv4(addr)
            else:
                blocked, reason = _blocked_ipv6(addr)  # type: ignore[arg-type]
            if blocked:
                return self._reject(
                    target, "url", [hostname], "BLOCKED_IP_IN_URL", reason
                )
            return ValidationResult(
                ok=True,
                normalized=target,
                target_type="url",
                resolved_ips=[hostname],
                rejection_reason=None,
                rejection_code=None,
            )
        except ValueError:
            pass

        # Hostname in URL — full hostname validation (DNS + rebinding).
        h_result = self._validate_hostname(hostname)
        if not h_result.ok:
            return ValidationResult(
                ok=False,
                normalized=target,
                target_type="url",
                resolved_ips=h_result.resolved_ips,
                rejection_reason=h_result.rejection_reason,
                rejection_code=h_result.rejection_code,
            )

        return ValidationResult(
            ok=True,
            normalized=target,
            target_type="url",
            resolved_ips=h_result.resolved_ips,
            rejection_reason=None,
            rejection_code=None,
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _reject(
        normalized: str,
        target_type: str,
        resolved_ips: list[str],
        code: str,
        reason: str,
    ) -> ValidationResult:
        return ValidationResult(
            ok=False,
            normalized=normalized,
            target_type=target_type,
            resolved_ips=resolved_ips,
            rejection_reason=reason,
            rejection_code=code,
        )
