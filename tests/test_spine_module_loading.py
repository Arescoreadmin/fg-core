from __future__ import annotations

from api.config.spine_modules import load_spine_modules


def test_spine_modules_load_with_flags(monkeypatch) -> None:
    monkeypatch.setenv("FG_GRACEFUL_SHUTDOWN_ENABLED", "1")
    monkeypatch.setenv("FG_ADMIN_API_ENABLED", "1")

    modules = load_spine_modules()

    assert modules.connection_tracking_middleware is not None
    assert modules.get_shutdown_manager is not None
    assert modules.admin_router is not None
