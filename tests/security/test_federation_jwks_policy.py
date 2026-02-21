from __future__ import annotations

import io
from urllib.error import HTTPError

import pytest

from services.federation_extension.service import JWKSCache


def test_jwks_fetch_disables_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class FakeResp:
        status = 200

        def read(self) -> bytes:
            return b'{"keys": []}'

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class FakeOpener:
        def open(self, req, timeout=0):
            captured["url"] = req.full_url
            captured["timeout"] = timeout
            return FakeResp()

    monkeypatch.setattr(
        "services.federation_extension.service.validate_target",
        lambda u: (u, ["93.184.216.34"]),
    )
    monkeypatch.setattr(
        "services.federation_extension.service.urllib.request.build_opener",
        lambda *args, **kwargs: FakeOpener(),
    )

    payload = JWKSCache().get("https://issuer.example/.well-known/jwks.json")
    assert payload == {"keys": []}
    assert captured["timeout"] == 5


def test_jwks_redirect_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeOpener:
        def open(self, req, timeout=0):
            raise HTTPError(req.full_url, 302, "Found", hdrs={}, fp=io.BytesIO())

    monkeypatch.setattr(
        "services.federation_extension.service.validate_target",
        lambda u: (u, ["93.184.216.34"]),
    )
    monkeypatch.setattr(
        "services.federation_extension.service.urllib.request.build_opener",
        lambda *args, **kwargs: FakeOpener(),
    )

    with pytest.raises(ValueError, match="jwks_fetch_failed:302"):
        JWKSCache().get("https://issuer.example/.well-known/jwks.json")
