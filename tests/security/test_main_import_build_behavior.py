from __future__ import annotations

import asyncio
import importlib
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _restore_api_main_after_test(monkeypatch: pytest.MonkeyPatch):
    yield
    monkeypatch.delenv("FG_CONTRACTS_GEN", raising=False)
    monkeypatch.delenv("FG_IMPORT_BUILD_MODE", raising=False)
    monkeypatch.delenv("FG_BUILD_APP_ON_IMPORT", raising=False)
    sys.modules.pop("api.main", None)


@pytest.fixture
def reload_api_main(monkeypatch: pytest.MonkeyPatch):
    def _reload(*, contract_gen: bool = False, import_mode: str | None = None):
        monkeypatch.setenv("FG_ENV", "dev")
        monkeypatch.setenv("FG_AUTH_ENABLED", "0")
        monkeypatch.setenv("FG_RL_ENABLED", "0")
        monkeypatch.setenv("FG_SQLITE_PATH", "state/test-main-import.db")

        if contract_gen:
            monkeypatch.setenv("FG_CONTRACTS_GEN", "1")
        else:
            monkeypatch.delenv("FG_CONTRACTS_GEN", raising=False)

        if import_mode is None:
            monkeypatch.delenv("FG_IMPORT_BUILD_MODE", raising=False)
        else:
            monkeypatch.setenv("FG_IMPORT_BUILD_MODE", import_mode)

        monkeypatch.delenv("FG_BUILD_APP_ON_IMPORT", raising=False)

        sys.modules.pop("api.main", None)
        return importlib.import_module("api.main")

    return _reload


def test_import_api_main_does_not_build_runtime_app_by_default(reload_api_main) -> None:
    main = reload_api_main()

    assert main._RUNTIME_APP is None
    assert main.app is not None


def test_build_app_still_fails_closed_when_invariant_raises(
    reload_api_main, monkeypatch
):
    main = reload_api_main()

    def _boom() -> None:
        raise RuntimeError("Route scope invariant failed: synthetic")

    monkeypatch.setattr(main, "assert_prod_invariants", _boom)

    app = main.build_app()

    async def _startup_only() -> None:
        async with app.router.lifespan_context(app):
            pass

    with pytest.raises(RuntimeError, match="Route scope invariant failed"):
        asyncio.run(_startup_only())


def test_contract_generation_context_binds_contract_app(reload_api_main) -> None:
    main = reload_api_main(contract_gen=True)

    assert main.app is not None
    assert hasattr(main.app, "router")
    assert main.build_contract_app().title


def test_builders_do_not_crash_when_optional_billing_router_is_missing(
    reload_api_main,
) -> None:
    main = reload_api_main(contract_gen=True)

    assert hasattr(main, "billing_router")
    assert main.billing_router is None

    runtime_app = main.build_app(auth_enabled=False)
    contract_app = main.build_contract_app()

    with TestClient(runtime_app) as runtime_client:
        assert runtime_client.get("/health").status_code == 200

    with TestClient(contract_app) as contract_client:
        assert contract_client.get("/health").status_code == 200


def test_optional_router_requires_apirouter_instance(reload_api_main, monkeypatch) -> None:
    main = reload_api_main(contract_gen=True)

    class _FakeModule:
        router = object()

    monkeypatch.setattr("builtins.__import__", lambda *args, **kwargs: _FakeModule)

    assert main._optional_router("api.billing") is None


def test_build_app_ignores_invalid_optional_router_value(reload_api_main, monkeypatch) -> None:
    main = reload_api_main(contract_gen=False)
    monkeypatch.setattr(main, "billing_router", object())

    app = main.build_app(auth_enabled=False)
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
