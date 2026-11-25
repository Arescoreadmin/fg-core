"""Isolation guarantees of opt-in app reuse (``build_app(reuse_from=...)``).

The security lane's MSP suites share one built app per module to avoid
rebuilding 1270 routes per test.  Reuse must never carry per-test state.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient


def test_reuse_returns_app_reset_to_its_built_state(
    build_app: Any, monkeypatch: Any
) -> None:
    cache: dict = {}
    first = build_app(auth_enabled=True, reuse_from=cache)
    TestClient(first).get("/health")
    assert first.middleware_stack is not None

    sentinel = object()
    first.dependency_overrides[sentinel] = lambda: None
    first.state.leaked_by_previous_test = True
    if hasattr(first.state, "_ui_key_scopes_cache"):
        first.state._ui_key_scopes_cache["k"] = "cached-scopes"

    second = build_app(auth_enabled=True, reuse_from=cache)
    assert second is first
    assert sentinel not in second.dependency_overrides
    # Middleware (and any in-memory state it holds) is rebuilt on next request.
    assert second.middleware_stack is None
    assert not hasattr(second.state, "leaked_by_previous_test")
    if hasattr(second.state, "_ui_key_scopes_cache"):
        assert second.state._ui_key_scopes_cache == {}
    assert TestClient(second).get("/health").status_code == 200


def test_reuse_builds_a_new_app_for_a_different_environment(
    build_app: Any, monkeypatch: Any
) -> None:
    cache: dict = {}
    first = build_app(auth_enabled=True, reuse_from=cache)
    assert build_app(auth_enabled=False, reuse_from=cache) is not first
    monkeypatch.setenv("FG_REUSE_KEY_PROBE", "1")
    assert build_app(auth_enabled=True, reuse_from=cache) is not first


def test_without_reuse_every_build_is_new(build_app: Any) -> None:
    assert build_app(auth_enabled=True) is not build_app(auth_enabled=True)
