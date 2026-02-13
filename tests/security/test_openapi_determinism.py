from __future__ import annotations

from scripts.contracts_gen_core import generate_openapi
from scripts.openapi_canonical import render_openapi


def test_openapi_generation_is_deterministic_with_env_noise(monkeypatch) -> None:
    first = render_openapi(generate_openapi())

    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_DB_URL", "sqlite:///tmp/evil.db")
    monkeypatch.setenv("FG_ADMIN_ENABLED", "1")
    monkeypatch.setenv("FG_AUTH_ALLOW_FALLBACK", "true")
    monkeypatch.setenv("FG_OIDC_ISSUER", "https://example.invalid")
    monkeypatch.setenv("FG_SERVICE", "mutated-service-name")

    second = render_openapi(generate_openapi())

    assert first == second
    assert "mutated-service-name" not in second
    assert "example.invalid" not in second
    assert '"url": "https://example.invalid"' not in second
