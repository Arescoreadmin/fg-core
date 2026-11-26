from unittest.mock import patch

import pytest
import requests

from agent.core_client import CoreClient, FingerprintPinningAdapter as PinningAdapter


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


def _self_signed_cert(tmp_path):
    """Write a throwaway self-signed cert for 127.0.0.1; return paths + pin."""
    import datetime
    import hashlib
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fg855-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pin = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return cert_path, key_path, pin


class _TLSServer:
    """Local HTTPS server on 127.0.0.1 that counts requests it served."""

    def __init__(self, cert_path, key_path):
        import http.server
        import ssl
        import threading

        served = self.served = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                served.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(cert_path), str(key_path))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.httpd.server_address[1]}/probe"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


def _pinned_session(pin):
    session = requests.Session()
    session.mount("https://", PinningAdapter(pin))
    return session


def test_pinning_adapter_enforces_fingerprint_in_tls_handshake():
    # FG-855-REPAIR-001: the adapter takes one fingerprint string and hands it
    # to urllib3 (assert_fingerprint), which checks the peer certificate during
    # the TLS handshake. The former test passed a pin list and mocked send().
    adapter = PinningAdapter("sha256/" + "AB:" * 31 + "AB")
    assert adapter.poolmanager.connection_pool_kw["assert_fingerprint"] == "ab" * 32


def test_cert_pin_mismatch_fails_closed(tmp_path):
    cert_path, key_path, _pin = _self_signed_cert(tmp_path)
    with _TLSServer(cert_path, key_path) as server:
        # The CA check passes (verify trusts this cert), so only the pin fails.
        with pytest.raises(requests.exceptions.SSLError):
            _pinned_session("sha256/" + "00" * 32).get(
                server.url, verify=str(cert_path), timeout=5
            )
    assert server.served == [], "no request may reach a server with a wrong pin"


def test_cert_pin_match_allows_request(tmp_path):
    # Positive control: proves the mismatch test fails because of the pin.
    cert_path, key_path, pin = _self_signed_cert(tmp_path)
    with _TLSServer(cert_path, key_path) as server:
        resp = _pinned_session("sha256/" + pin).get(
            server.url, verify=str(cert_path), timeout=5
        )
    assert resp.status_code == 200
    assert server.served == ["/probe"]


def test_invalid_request_id_sanitized(monkeypatch):
    monkeypatch.setenv("FG_ALLOW_INSECURE_HTTP", "1")
    with patch("socket.getaddrinfo", return_value=_addr("8.8.8.8")):
        client = CoreClient("http://core", "k", "t", "a", "2025-01-01")
    headers = client._headers(" bad\nvalue\t!")
    assert headers["X-Request-ID"] != "badvalue!"
