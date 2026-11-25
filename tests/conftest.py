from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

# Set deterministic, writable defaults before importing modules that may touch DB paths.
os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_API_KEY", "ci-test-key-00000000000000000000000000000000")
os.environ.setdefault("FG_KEY_PEPPER", "ci-test-pepper")
os.environ.setdefault("FG_STATE_DIR", "/tmp/frostgate/state")
os.environ.setdefault("FG_SQLITE_PATH", "/tmp/frostgate/fg-conftest.db")
os.environ.setdefault("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
os.environ.setdefault(
    "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
)

import pytest


def _load_app_modules():
    try:
        from api.db import dispose_engine_cache, init_db, reset_engine_cache
        from api.main import build_app as _build_app

        return init_db, reset_engine_cache, _build_app, dispose_engine_cache
    except Exception:
        return None


def _setenv(key: str, val: str) -> None:
    os.environ[str(key)] = str(val)


def pytest_configure() -> None:
    os.environ.setdefault("FG_API_KEY", "ci-test-key-00000000000000000000000000000000")
    os.environ.setdefault("FG_KEY_PEPPER", "ci-test-pepper")
    os.environ.setdefault("FG_ENV", "test")
    os.environ.setdefault("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    os.environ.setdefault(
        "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )


@pytest.fixture(scope="session", autouse=True)
def _test_env_defaults() -> None:
    os.environ.setdefault("FG_API_KEY", "ci-test-key-00000000000000000000000000000000")
    os.environ.setdefault("FG_KEY_PEPPER", "ci-test-pepper")
    os.environ.setdefault("FG_ENV", "test")
    os.environ.setdefault("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    os.environ.setdefault(
        "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )


@pytest.fixture(autouse=True)
def _restore_env():
    before = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(before)


_CI_TEST_KEY = "ci-test-key-00000000000000000000000000000000"


def _require_api_key() -> str:
    api_key = os.environ.get("FG_API_KEY", "").strip()
    return api_key or _CI_TEST_KEY


@pytest.fixture(autouse=True, scope="session")
def _session_env(tmp_path_factory: pytest.TempPathFactory):
    """
    Ensure a deterministic sqlite path + schema exists even for tests that call mint_key()
    before building an app.
    """
    db_path = str(tmp_path_factory.mktemp("fg-session") / "fg-session.db")
    _setenv("FG_ENV", "test")
    _setenv("FG_SQLITE_PATH", db_path)
    _setenv("FG_API_KEY", _require_api_key())
    _setenv("FG_KEY_PEPPER", "ci-test-pepper")
    _setenv("FG_UI_TOKEN_GET_ENABLED", "1")
    _setenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    _setenv("FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

    loaded = _load_app_modules()
    if loaded is None:
        yield
        return

    init_db, reset_engine_cache, _, _ = loaded
    reset_engine_cache()
    init_db(sqlite_path=db_path)

    yield


def _app_reuse_key(auth_enabled: bool) -> tuple:
    # Every FG_* setting except the per-test database path: any difference in
    # the environment the app is built from gets its own app.
    env = tuple(
        sorted(
            (k, v)
            for k, v in os.environ.items()
            if k.startswith("FG_") and k != "FG_SQLITE_PATH"
        )
    )
    return (bool(auth_enabled), env)


def _reuse_or_build_app(cache: dict, build, auth_enabled: bool):
    """Return a cached app for an identical build environment, reset to its
    just-built state; otherwise build one and cache it.

    Building the full app (1270 routes) costs ~1s per test.  Reuse is opt-in
    via ``module_app_cache``.  Per-test isolation is kept: the caller still
    creates a fresh database, and every reuse clears dependency overrides,
    discards the middleware stack (so middleware with in-memory state, such as
    the DoS guard, is re-instantiated on the next request) and restores
    ``app.state`` from a snapshot taken right after the build, with fresh
    copies of mutable containers.
    """
    import copy

    def _fresh(state: dict) -> dict:
        # The live containers (e.g. the UI key-scope cache) are mutated by
        # requests, so the snapshot and every restore must hold copies.
        return {
            k: copy.copy(v) if isinstance(v, (dict, list, set)) else v
            for k, v in state.items()
        }

    key = _app_reuse_key(auth_enabled)
    entry = cache.get(key)
    if entry is None:
        app = build()
        cache[key] = (app, _fresh(app.state._state))
        return app
    app, snapshot = entry
    app.dependency_overrides.clear()
    app.middleware_stack = None
    app.state._state.clear()
    app.state._state.update(_fresh(snapshot))
    return app


@pytest.fixture(scope="module")
def module_app_cache() -> Iterator[dict]:
    """Opt-in: share one built app per test module (``build_app(reuse_from=...)``)."""
    cache: dict = {}
    yield cache
    cache.clear()


@pytest.fixture()
def build_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Factory fixture so tests can build an app with controlled env.
    """

    def _factory(
        auth_enabled: bool = True,
        sqlite_path: str | None = None,
        dev_events_enabled: bool = False,
        api_key: str | None = None,
        ui_token_get_enabled: bool = True,
        reuse_from: dict | None = None,
    ):
        api_key_value = api_key or _require_api_key()
        db_path = sqlite_path or str(tmp_path / "fg-test.db")

        monkeypatch.setenv("FG_SQLITE_PATH", db_path)
        monkeypatch.setenv("FG_ENV", "test")
        monkeypatch.setenv("FG_AUTH_ENABLED", "1" if auth_enabled else "0")
        monkeypatch.setenv("FG_API_KEY", api_key_value)
        monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
        for _gw in (
            "FG_INTERNAL_GATEWAY_SECRET",
            "FG_ADMIN_GATEWAY_INTERNAL_TOKEN",
            "FG_INTERNAL_AUTH_SECRET",
        ):
            monkeypatch.delenv(_gw, raising=False)
        monkeypatch.setenv("FG_DEV_EVENTS_ENABLED", "1" if dev_events_enabled else "0")
        monkeypatch.setenv(
            "FG_UI_TOKEN_GET_ENABLED", "1" if ui_token_get_enabled else "0"
        )
        monkeypatch.setenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
        monkeypatch.setenv(
            "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
        )
        # P1.3: capability enforcement is strict by default; integration tests
        # that test non-capability behaviour use audit-only mode so they are not
        # blocked by capability checks. Capability enforcement correctness is
        # covered by tests/security/test_capability_enforcement.py.
        monkeypatch.setenv("FG_ENTITLEMENT_ENFORCEMENT", "false")
        import api.entitlements as _ent

        monkeypatch.setattr(_ent, "ENFORCEMENT_STRICT", False)

        loaded = _load_app_modules()
        if loaded is None:
            pytest.skip("app/db dependencies unavailable in this environment")
        init_db, reset_engine_cache, _build_app, _ = loaded
        reset_engine_cache()
        init_db(sqlite_path=db_path)

        if reuse_from is None:
            app = _build_app()
        else:
            app = _reuse_or_build_app(reuse_from, _build_app, auth_enabled)
        # L14-ASSESSMENT-ASSURANCE-001: QA decisions require a named human
        # reviewer.  Inert unless a test sends the X-Test-Human-Actor header
        # (see tests/_assurance_actors.py); all other requests resolve normally.
        from tests._assurance_actors import install_human_actors

        install_human_actors(app)
        return app

    yield _factory

    # Dispose pool connections without clearing _ENGINE/_SessionLocal.
    # This closes DBAPI connections (preventing __del__ races under
    # filterwarnings=error) while leaving the engine reference intact so
    # fixture-less tests that call _sessionmaker() directly can inherit
    # the last valid engine rather than creating a new one against a
    # potentially stale or deleted FG_SQLITE_PATH.
    loaded = _load_app_modules()
    if loaded is not None:
        _, _, _, dispose_engine_cache = loaded
        dispose_engine_cache()


@pytest.fixture
def fresh_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """
    Compatibility fixture for tests that expect `fresh_db` to be a sqlite DB path (str).
    These tests insert rows via sqlite3 directly, so we must create schema in that file.
    """
    db_path = str(tmp_path / "fg-fresh.db")

    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_API_KEY", _require_api_key())
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_UI_TOKEN_GET_ENABLED", "1")
    monkeypatch.setenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    monkeypatch.setenv(
        "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )

    loaded = _load_app_modules()
    if loaded is None:
        pytest.skip("app/db dependencies unavailable in this environment")
    init_db, reset_engine_cache, _, _ = loaded
    reset_engine_cache()
    init_db(sqlite_path=db_path)

    yield db_path

    # Dispose pool connections — same rationale as build_app teardown.
    loaded = _load_app_modules()
    if loaded is not None:
        _, _, _, dispose_engine_cache = loaded
        dispose_engine_cache()


@pytest.fixture
def app(build_app):
    """
    Default app fixture.
    If FG_SQLITE_PATH was already set by a prior fixture (e.g., fresh_db),
    build the app against that same sqlite file so inserts and API reads match.
    """
    sqlite_path = os.environ.get("FG_SQLITE_PATH")
    return build_app(auth_enabled=True, sqlite_path=sqlite_path)
