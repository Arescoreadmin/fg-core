"""DEP-REMEDIATE-005 — behavioural regression tests for the agent ``requests`` pin.

Dependabot alerts #1 (GHSA-9hjg-9r4m-mvj7 / CVE-2024-47081, .netrc credential
leak via malicious URL, fixed in 2.32.4) and #2 (GHSA-gc5v-m9x4-r6x2 /
CVE-2026-25645, predictable temp-file reuse in ``extract_zipped_paths``, fixed
in 2.33.0) are exercised against the installed library, together with the
agent transport properties the upgrade must preserve: TLS verification,
no redirect following, credentials only to the configured Core host, and
Authorization stripping on cross-host redirects.

The four advisory tests fail against requests 2.32.3 and pass on >= 2.33.0
(verified by shadowing the library); the three transport tests pass on both
and guard behaviour the upgrade must not change. The pin itself is enforced by
``tools/ci/dep_remediation_final_inventory.py``.
"""

from __future__ import annotations

import base64
import io
import os
import stat
import tempfile
import zipfile
from pathlib import Path

import pytest
import requests
from requests.adapters import BaseAdapter
from requests.utils import extract_zipped_paths, get_netrc_auth

from agent.core_client import CoreClient

REPO = Path(__file__).resolve().parents[2]


def _vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split(".")[:3])


def test_agent_pin_and_installed_requests_are_outside_both_advisories():
    pins = [
        line.strip()
        for line in (REPO / "agent/requirements.txt").read_text().splitlines()
        if line.strip().lower().startswith("requests")
    ]
    assert len(pins) == 1 and pins[0].startswith("requests=="), pins
    pinned = pins[0].split("==", 1)[1]
    for version in (pinned, requests.__version__):
        assert _vtuple(version) >= (2, 33, 0), version


# --- Alert #1: .netrc credentials must not be sent to an attacker host -------


@pytest.fixture()
def netrc_for_core(tmp_path, monkeypatch):
    path = tmp_path / "netrc"
    path.write_text("machine core.example login agent password s3cret\n")
    path.chmod(0o600)
    monkeypatch.setenv("NETRC", str(path))
    return path


def test_netrc_lookup_uses_real_hostname_not_userinfo(netrc_for_core):
    # Positive control: the genuine host still resolves its .netrc entry.
    assert get_netrc_auth("https://core.example/v1/x") == ("agent", "s3cret")
    # CVE-2024-47081: "core.example:@evil.example" has hostname evil.example;
    # vulnerable versions split the netloc on ":" and returned core.example's
    # credentials for a request that goes to evil.example.
    assert get_netrc_auth("https://core.example:@evil.example/") is None


def test_session_does_not_attach_netrc_auth_for_malicious_url(netrc_for_core):
    session = requests.Session()
    assert session.trust_env is True  # the agent keeps the library default
    good = session.prepare_request(requests.Request("GET", "https://core.example/"))
    assert good.headers["Authorization"].startswith("Basic ")
    evil = session.prepare_request(
        requests.Request("GET", "https://core.example:@evil.example/")
    )
    # requests turns the URL's own userinfo ("core.example", empty password)
    # into Basic auth; what must never appear is the .netrc secret.
    sent = base64.b64decode(evil.headers["Authorization"].split(" ", 1)[1])
    assert sent == b"core.example:"
    assert b"s3cret" not in sent and b"agent" not in sent


# --- Alert #2: extract_zipped_paths must not reuse a planted temp file -------


def test_extract_zipped_paths_ignores_planted_file_and_uses_private_tempfile(
    tmp_path, monkeypatch
):
    shared = tmp_path / "shared-tmp"
    shared.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(shared))
    # Vulnerable versions extracted to <tempdir>/<member basename> and reused
    # any file already there, so a local attacker could pre-plant content.
    planted = shared / "ca.pem"
    planted.write_bytes(b"ATTACKER")

    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("certs/ca.pem", b"GENUINE")
    member_path = str(archive / "certs" / "ca.pem")

    first = extract_zipped_paths(member_path)
    second = extract_zipped_paths(member_path)
    try:
        assert first != str(planted) and second != str(planted)
        assert first != second
        for extracted in (first, second):
            assert Path(extracted).read_bytes() == b"GENUINE"
            assert stat.S_IMODE(os.stat(extracted).st_mode) == 0o600
        assert planted.read_bytes() == b"ATTACKER"
    finally:
        for extracted in {first, second} - {str(planted)}:
            Path(extracted).unlink(missing_ok=True)


def test_extract_zipped_paths_passthrough_for_real_and_unknown_paths(tmp_path):
    real = tmp_path / "real.pem"
    real.write_bytes(b"x")
    assert extract_zipped_paths(str(real)) == str(real)
    missing = str(tmp_path / "nope" / "ca.pem")
    assert extract_zipped_paths(missing) == missing


# --- Transport properties the upgrade must preserve ---------------------------


class _RecordingAdapter(BaseAdapter):
    """Returns a cross-host 302 from core.example, 200 elsewhere; records calls."""

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[dict] = []

    def send(self, request, **kwargs):
        self.calls.append(
            {"url": request.url, "headers": dict(request.headers), **kwargs}
        )
        resp = requests.Response()
        resp.request = request
        resp.url = request.url
        resp.raw = io.BytesIO(b"")
        resp._content = b""
        if request.url.startswith("https://core.example"):
            resp.status_code = 302
            resp.headers["Location"] = "https://evil.example/collect"
        else:
            resp.status_code = 200
        return resp

    def close(self) -> None:
        pass


def test_requests_strips_authorization_on_cross_host_redirect():
    session = requests.Session()
    adapter = _RecordingAdapter()
    session.mount("https://", adapter)
    session.get(
        "https://core.example/v1/x", headers={"Authorization": "Bearer t"}, timeout=1
    )
    assert [c["url"] for c in adapter.calls] == [
        "https://core.example/v1/x",
        "https://evil.example/collect",
    ]
    assert adapter.calls[0]["headers"]["Authorization"] == "Bearer t"
    assert "Authorization" not in adapter.calls[1]["headers"]


def test_agent_core_client_verifies_tls_and_never_follows_redirects(monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("8.8.8.8", 0))]
    )
    monkeypatch.delenv("FG_CORE_CERT_SHA256", raising=False)
    # requests (trust_env) substitutes an operator CA bundle for verify=True;
    # isolate the default case, then check the bundle case separately.
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
    client = CoreClient("https://core.example", "device-key", "t", "a", "2025-01-01")
    adapter = _RecordingAdapter()
    client._session.mount("https://", adapter)

    client._request("GET", "/v1/agent/commands")

    assert len(adapter.calls) == 1, adapter.calls  # the 302 was not followed
    call = adapter.calls[0]
    assert call["url"] == "https://core.example/v1/agent/commands"
    assert call["verify"] is True
    assert call["timeout"] == client.timeout
    assert call["headers"]["Authorization"] == "Bearer device-key"

    # With an operator CA bundle, verification stays on against that bundle.
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/etc/ssl/certs/corp-ca.pem")
    client._request("GET", "/v1/agent/commands")
    assert len(adapter.calls) == 2
    assert adapter.calls[1]["verify"] == "/etc/ssl/certs/corp-ca.pem"
