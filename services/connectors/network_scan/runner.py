"""Network Scan connector — pure-Python port scanner with TLS inspection."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any


# Ports to probe: common services + AI model server ports
_PROBE_PORTS: list[int] = [
    21,  # FTP
    22,  # SSH
    23,  # Telnet
    25,  # SMTP
    80,  # HTTP
    443,  # HTTPS
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8000,  # HTTP alt / FastAPI / Uvicorn
    8080,  # HTTP alt
    8443,  # HTTPS alt
    8888,  # Jupyter
    9200,  # Elasticsearch
    11434,  # Ollama
    7860,  # Gradio
    5000,  # Flask / MLflow
    6006,  # TensorBoard
]

_UNSAFE_EXPOSED = {3389, 5900, 23, 21}
_PLAIN_HTTP = {80, 8080, 8000, 5000}
_AI_PORTS = {8000, 8888, 11434, 7860, 6006}
_PORT_TIMEOUT = 2.0
_TLS_TIMEOUT = 5.0
_MAX_WORKERS = 30
_MAX_HOSTS = 50


def _probe_port(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=_PORT_TIMEOUT):
            return True
    except Exception:
        return False


def _check_tls(host: str) -> dict[str, Any]:
    result: dict[str, Any] = {"valid": False, "expired": False, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=_TLS_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not isinstance(cert, dict):
                    result["valid"] = True
                else:
                    expire_str = cert.get("notAfter", "")
                    if isinstance(expire_str, str) and expire_str:
                        import time

                        expire_ts = ssl.cert_time_to_seconds(expire_str)
                        result["expired"] = expire_ts < time.time()
                        result["days_until_expiry"] = max(
                            0, int((expire_ts - time.time()) / 86400)
                        )
                    result["valid"] = True
    except ssl.SSLCertVerificationError as exc:
        result["error"] = str(exc)[:120]
    except ssl.SSLError as exc:
        result["error"] = str(exc)[:120]
    except Exception:
        pass
    return result


def _expand_targets(raw_hosts: list[str]) -> list[str]:
    hosts: list[str] = []
    for entry in raw_hosts:
        entry = entry.strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
            # Only expand small subnets inline (≤ /28 = 16 hosts)
            if net.num_addresses <= 16:
                hosts.extend(str(ip) for ip in net.hosts())
            else:
                hosts.append(str(net.network_address))
        except ValueError:
            hosts.append(entry)
    return hosts[:_MAX_HOSTS]


def _scan_host(host: str) -> dict[str, Any]:
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
        futures = {ex.submit(_probe_port, host, port): port for port in _PROBE_PORTS}
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass

    open_ports.sort()
    tls_info: dict[str, Any] = {}
    if 443 in open_ports:
        tls_info = _check_tls(host)

    return {
        "host": host,
        "open_ports": open_ports,
        "tls": tls_info,
    }


def run_network_scan(
    *,
    target_hosts: list[str],
    engagement_id: str,
) -> dict[str, Any]:
    """Run a port scan and TLS check against the provided target hosts.

    Returns a raw payload compatible with source_type=network_scan.
    Required top-level key: hosts (list).
    """
    scan_initiated_at = datetime.now(timezone.utc).isoformat()

    expanded = _expand_targets(target_hosts)
    host_results: list[dict[str, Any]] = []
    for host in expanded:
        try:
            host_results.append(_scan_host(host))
        except Exception:
            host_results.append(
                {"host": host, "open_ports": [], "tls": {}, "error": "scan_failed"}
            )

    findings: list[dict[str, Any]] = []

    # Finding: unsafe services exposed
    unsafe_hosts = [
        h["host"]
        for h in host_results
        if any(p in _UNSAFE_EXPOSED for p in h.get("open_ports", []))
    ]
    if unsafe_hosts:
        findings.append(
            {
                "finding_type": "network.unsafe_services_exposed",
                "severity": "critical",
                "title": f"Unsafe services exposed to network ({len(unsafe_hosts)} hosts)",
                "description": (
                    f"Ports associated with unsafe protocols (RDP 3389, VNC 5900, Telnet 23, "
                    f"FTP 21) are open on {len(unsafe_hosts)} host(s). These services "
                    "are frequently targeted for lateral movement and credential attacks."
                ),
                "control_id": "NIST-AI-RMF-MANAGE-2.2",
                "affected_count": len(unsafe_hosts),
                "recommendation": (
                    "Close or firewall-restrict RDP, VNC, Telnet, and FTP ports. "
                    "Replace with VPN-gated access or zero-trust network access."
                ),
            }
        )

    # Finding: HTTP without TLS
    plain_http_hosts = [
        h["host"]
        for h in host_results
        if any(p in _PLAIN_HTTP for p in h.get("open_ports", []))
        and 443 not in h.get("open_ports", [])
    ]
    if plain_http_hosts:
        findings.append(
            {
                "finding_type": "network.plain_http_services",
                "severity": "high",
                "title": f"Services exposed over unencrypted HTTP ({len(plain_http_hosts)} hosts)",
                "description": (
                    f"{len(plain_http_hosts)} host(s) expose services over plain HTTP "
                    "without a corresponding HTTPS endpoint. Traffic can be intercepted."
                ),
                "control_id": "NIST-AI-RMF-MANAGE-2.4",
                "affected_count": len(plain_http_hosts),
                "recommendation": (
                    "Enable TLS on all HTTP services. Redirect port 80 to 443. "
                    "Use certificates from a trusted CA."
                ),
            }
        )

    # Finding: expired or invalid TLS
    bad_tls_hosts = [
        h["host"]
        for h in host_results
        if h.get("tls", {}).get("expired") or h.get("tls", {}).get("error")
    ]
    if bad_tls_hosts:
        findings.append(
            {
                "finding_type": "network.invalid_tls_certificates",
                "severity": "high",
                "title": f"Expired or invalid TLS certificates ({len(bad_tls_hosts)} hosts)",
                "description": (
                    f"{len(bad_tls_hosts)} host(s) have expired, self-signed, or otherwise "
                    "invalid TLS certificates. Clients may bypass certificate validation, "
                    "enabling man-in-the-middle attacks."
                ),
                "control_id": "NIST-AI-RMF-MANAGE-2.4",
                "affected_count": len(bad_tls_hosts),
                "recommendation": (
                    "Renew expired certificates. Use certificates from a trusted public CA. "
                    "Implement automated certificate renewal (e.g. Let's Encrypt / ACME)."
                ),
            }
        )

    # Finding: exposed AI model server ports
    ai_exposed_hosts = [
        h["host"]
        for h in host_results
        if any(p in _AI_PORTS for p in h.get("open_ports", []))
    ]
    if ai_exposed_hosts:
        findings.append(
            {
                "finding_type": "network.ai_ports_exposed",
                "severity": "medium",
                "title": f"AI model server ports accessible ({len(ai_exposed_hosts)} hosts)",
                "description": (
                    f"Ports commonly used by AI model servers (Ollama 11434, Gradio 7860, "
                    f"Jupyter 8888, etc.) are open on {len(ai_exposed_hosts)} host(s). "
                    "Unprotected model endpoints can expose proprietary models or enable "
                    "adversarial probing."
                ),
                "control_id": "NIST-AI-RMF-GOVERN-6.2",
                "affected_count": len(ai_exposed_hosts),
                "recommendation": (
                    "Restrict AI model server ports behind authentication and network controls. "
                    "Do not expose model inference endpoints to the public internet without auth."
                ),
            }
        )

    scan_completed_at = datetime.now(timezone.utc).isoformat()

    return {
        "scan_id": uuid.uuid4().hex,
        "scan_type": "network_scan_v1",
        "schema_version": "1.0",
        "engagement_id": engagement_id,
        "scan_initiated_at": scan_initiated_at,
        "scan_completed_at": scan_completed_at,
        "scan_status": "completed",
        "hosts": host_results,
        "summary": {
            "total_hosts": len(host_results),
            "hosts_with_open_ports": sum(
                1 for h in host_results if h.get("open_ports")
            ),
            "total_open_ports": sum(len(h.get("open_ports", [])) for h in host_results),
        },
        "findings": findings,
    }
