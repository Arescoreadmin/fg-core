from __future__ import annotations

import socket

import pytest

from api.main import build_contract_app, build_runtime_app


def test_contract_build_is_pure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FG_DB_URL", raising=False)
    monkeypatch.delenv("FG_OIDC_ISSUER", raising=False)

    def _boom(*args, **kwargs):
        raise AssertionError("unexpected side effect")

    monkeypatch.setattr("api.db.get_engine", _boom)
    monkeypatch.setattr(socket.socket, "connect", _boom)

    app = build_contract_app()
    assert app.router.on_startup == []
    import warnings

    warnings.filterwarnings("ignore", category=DeprecationWarning)
    openapi = app.openapi()
    assert "paths" in openapi


def test_runtime_build_enforces_prod_runtime_requirements(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FG_ENV", "prod")
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_DB_BACKEND", "postgres")
    monkeypatch.delenv("FG_DB_URL", raising=False)

    with pytest.raises(Exception):
        from fastapi.testclient import TestClient

        with TestClient(build_runtime_app()):
            pass
