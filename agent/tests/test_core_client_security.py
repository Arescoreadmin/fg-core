import uuid

import pytest
import requests

from agent.core_client import CoreClient, sanitize_request_id, validate_core_base_url


def test_reject_http_base_url_by_default(monkeypatch):
    monkeypatch.delenv("FG_ALLOW_INSECURE_HTTP", raising=False)
    with pytest.raises(ValueError):
        validate_core_base_url("http://core.example")


def test_allow_http_only_when_explicit_override(monkeypatch):
    monkeypatch.setenv("FG_ALLOW_INSECURE_HTTP", "1")
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("8.8.8.8", 0))])
    policy = validate_core_base_url("http://core.example")
    assert policy["scheme"] == "http"
    assert policy["insecure_override"] is True


def test_loopback_and_link_local_rejected_by_default(monkeypatch):
    monkeypatch.delenv("FG_ALLOW_PRIVATE_CORE", raising=False)
    monkeypatch.delenv("FG_CORE_HOST_ALLOWLIST", raising=False)
    with pytest.raises(ValueError):
        validate_core_base_url("https://127.0.0.1")
    with pytest.raises(ValueError):
        validate_core_base_url("https://169.254.1.9")
    with pytest.raises(ValueError):
        validate_core_base_url("https://[::1]")
    with pytest.raises(ValueError):
        validate_core_base_url("https://[fe80::1]")


def test_private_core_allowed_via_flag_or_allowlist(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("10.1.2.3", 0))])
    monkeypatch.setenv("FG_ALLOW_PRIVATE_CORE", "1")
    policy = validate_core_base_url("https://core.internal")
    assert policy["private_allowed"] is True

    monkeypatch.delenv("FG_ALLOW_PRIVATE_CORE", raising=False)
    monkeypatch.setenv("FG_CORE_HOST_ALLOWLIST", "10.0.0.0/8")
    policy = validate_core_base_url("https://core.internal")
    assert policy["allowlist_match"] is True


def test_hostname_allowlist_suffix_match(monkeypatch):
    monkeypatch.setenv("FG_CORE_HOST_ALLOWLIST", "*.svc.cluster.local")
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: (_ for _ in ()).throw(__import__("socket").gaierror("dns fail")))
    policy = validate_core_base_url("https://api.svc.cluster.local")
    assert policy["allowlist_match"] is True


def test_cert_pin_mismatch_fails_closed(monkeypatch):
    monkeypatch.setenv("FG_AGENT_KEY", "k")
    monkeypatch.setenv("FG_TENANT_ID", "t")
    monkeypatch.setenv("FG_AGENT_ID", "a")
    monkeypatch.setenv("FG_CORE_BASE_URL", "https://core.example")
    monkeypatch.setenv("FG_CORE_CERT_SHA256", "sha256/aa,bb")

    client = CoreClient.from_env()
    attempts: list[str | None] = []

    def fake_once(self, method, path, *, payload, params, request_id, fingerprint):
        attempts.append(fingerprint)
        raise requests.exceptions.SSLError("pin mismatch")

    monkeypatch.setattr(CoreClient, "_request_once", fake_once)
    with pytest.raises(requests.exceptions.SSLError):
        client._request("GET", "/v1/agent/commands")

    assert attempts == ["aa", "bb"]


def test_sanitize_invalid_request_id():
    unsafe = "bad\nheader"
    sanitized = sanitize_request_id(unsafe)
    assert sanitized != unsafe
    uuid.UUID(sanitized)
    assert sanitize_request_id(" req.id-1 ") == "req.id-1"


def test_hostname_resolving_to_loopback_rejected_by_default(monkeypatch):
    monkeypatch.delenv("FG_ALLOW_PRIVATE_CORE", raising=False)
    monkeypatch.delenv("FG_CORE_HOST_ALLOWLIST", raising=False)
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("127.0.0.1", 0))])
    with pytest.raises(ValueError):
        validate_core_base_url("https://core.internal")


def test_hostname_resolving_to_private_rejected_by_default(monkeypatch):
    monkeypatch.delenv("FG_ALLOW_PRIVATE_CORE", raising=False)
    monkeypatch.delenv("FG_CORE_HOST_ALLOWLIST", raising=False)
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("10.0.0.5", 0))])
    with pytest.raises(ValueError):
        validate_core_base_url("https://core.internal")


def test_hostname_private_allowed_with_flag(monkeypatch):
    monkeypatch.setenv("FG_ALLOW_PRIVATE_CORE", "1")
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("10.0.0.5", 0))])
    policy = validate_core_base_url("https://core.internal")
    assert policy["private_allowed"] is True


def test_dns_failure_only_allowed_for_allowlist_or_pin(monkeypatch):
    monkeypatch.delenv("FG_CORE_HOST_ALLOWLIST", raising=False)
    monkeypatch.delenv("FG_CORE_CERT_SHA256", raising=False)
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: (_ for _ in ()).throw(__import__("socket").gaierror("dns fail")))
    with pytest.raises(ValueError):
        validate_core_base_url("https://core.internal")

    monkeypatch.setenv("FG_CORE_HOST_ALLOWLIST", "*.internal")
    policy = validate_core_base_url("https://core.internal")
    assert policy["allowlist_match"] is True

    monkeypatch.delenv("FG_CORE_HOST_ALLOWLIST", raising=False)
    monkeypatch.setenv("FG_CORE_CERT_SHA256", "aa")
    policy = validate_core_base_url("https://core.internal")
    assert policy["pin_enabled"] is True

    with pytest.raises(ValueError):
        validate_core_base_url("http://core.internal")


def test_http_transport_only_mounted_with_override(monkeypatch):
    monkeypatch.setenv("FG_AGENT_KEY", "k")
    monkeypatch.setenv("FG_TENANT_ID", "t")
    monkeypatch.setenv("FG_AGENT_ID", "a")
    monkeypatch.setenv("FG_CORE_BASE_URL", "https://core.example")
    monkeypatch.delenv("FG_ALLOW_INSECURE_HTTP", raising=False)
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("8.8.8.8", 0))])
    client = CoreClient.from_env()
    assert "http://" not in client._session.adapters

    monkeypatch.setenv("FG_ALLOW_INSECURE_HTTP", "1")
    monkeypatch.setenv("FG_CORE_BASE_URL", "http://core.example")
    client2 = CoreClient.from_env()
    assert "http://" in client2._session.adapters
