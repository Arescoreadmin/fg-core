from unittest.mock import patch

import pytest
import requests
from requests.adapters import HTTPAdapter

from agent.core_client import CoreClient, PinningAdapter


def _addr(ip):
    return [(None, None, None, None, (ip, 0))]


def test_reject_http_by_default(monkeypatch):
    monkeypatch.delenv("FG_ALLOW_INSECURE_HTTP", raising=False)
    with pytest.raises(ValueError):
        CoreClient("http://core.example", "k", "t", "a", "2025-01-01")


def test_allow_http_with_override(monkeypatch):
    monkeypatch.setenv("FG_ALLOW_INSECURE_HTTP", "1")
    with patch("socket.getaddrinfo", return_value=_addr("8.8.8.8")):
        CoreClient("http://core.example", "k", "t", "a", "2025-01-01")


def test_reject_loopback_and_link_local_by_default(monkeypatch):
    monkeypatch.setenv("FG_ALLOW_INSECURE_HTTP", "1")
    with patch("socket.getaddrinfo", return_value=_addr("127.0.0.1")):
        with pytest.raises(ValueError):
            CoreClient("http://localhost", "k", "t", "a", "2025-01-01")
    with patch("socket.getaddrinfo", return_value=_addr("169.254.1.10")):
        with pytest.raises(ValueError):
            CoreClient("http://core", "k", "t", "a", "2025-01-01")


def test_allow_private_via_flag_or_allowlist(monkeypatch):
    monkeypatch.setenv("FG_ALLOW_INSECURE_HTTP", "1")
    monkeypatch.setenv("FG_ALLOW_PRIVATE_CORE", "1")
    with patch("socket.getaddrinfo", return_value=_addr("10.0.0.9")):
        CoreClient("http://core.internal", "k", "t", "a", "2025-01-01")

    monkeypatch.setenv("FG_ALLOW_PRIVATE_CORE", "0")
    monkeypatch.setenv("FG_CORE_HOST_ALLOWLIST", "10.0.0.0/8")
    with patch("socket.getaddrinfo", return_value=_addr("10.0.0.9")):
        CoreClient("http://core.internal", "k", "t", "a", "2025-01-01")


def test_hostname_suffix_allowlist_match(monkeypatch):
    monkeypatch.setenv("FG_ALLOW_INSECURE_HTTP", "1")
    monkeypatch.setenv("FG_CORE_HOST_ALLOWLIST", "*.svc.cluster.local")
    with patch("socket.getaddrinfo", return_value=_addr("10.1.2.3")):
        CoreClient("http://core.svc.cluster.local", "k", "t", "a", "2025-01-01")


class _Sock:
    def __init__(self, cert):
        self._cert = cert

    def getpeercert(self, binary_form=False):
        return self._cert


class _Conn:
    def __init__(self, cert):
        self.sock = _Sock(cert)


class _Raw:
    def __init__(self, cert):
        self.connection = _Conn(cert)


class _Resp:
    def __init__(self, cert):
        self.raw = _Raw(cert)
        self.closed = False

    def close(self):
        self.closed = True


def test_cert_pin_mismatch_fails_closed():
    adapter = PinningAdapter(["sha256/" + "00" * 32])
    with patch.object(HTTPAdapter, "send", return_value=_Resp(b"abc")):
        with pytest.raises(requests.exceptions.SSLError):
            adapter.send(type("R", (), {"url": "https://core"})())


def test_invalid_request_id_sanitized(monkeypatch):
    monkeypatch.setenv("FG_ALLOW_INSECURE_HTTP", "1")
    with patch("socket.getaddrinfo", return_value=_addr("8.8.8.8")):
        client = CoreClient("http://core", "k", "t", "a", "2025-01-01")
    headers = client._headers(" bad\nvalue\t!")
    assert headers["X-Request-ID"] != "badvalue!"
