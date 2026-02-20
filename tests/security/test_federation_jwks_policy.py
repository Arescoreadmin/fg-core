from __future__ import annotations

from types import SimpleNamespace

import pytest

from services.federation_extension.service import JWKSCache


def test_jwks_fetch_disables_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class Resp(SimpleNamespace):
        status_code = 200

        def json(self):
            return {"keys": []}

    def fake_get(url: str, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return Resp()

    monkeypatch.setattr("services.federation_extension.service.validate_target", lambda u: (u, ["93.184.216.34"]))
    monkeypatch.setattr("services.federation_extension.service.requests.get", fake_get)

    payload = JWKSCache().get("https://issuer.example/.well-known/jwks.json")
    assert payload == {"keys": []}
    assert captured["allow_redirects"] is False
    assert captured["timeout"] == 5
