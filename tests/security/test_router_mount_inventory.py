from __future__ import annotations

from api.main import build_app


def test_build_app_mounts_required_router_paths() -> None:
    app = build_app()
    paths = {getattr(route, "path", "") for route in app.routes}
    required = {
        "/defend",
        "/ingest",
        "/feed/live",
        "/decisions",
        "/stats",
        "/config/versions",
        "/billing/invoices",
        "/audit/exams",
        "/admin/connectors/status",
        "/planes",
        "/evidence/runs",
    }
    missing = sorted(p for p in required if p not in paths)
    assert not missing, f"missing mounted routes: {missing}"
