import importlib


def test_api_surface_smoke_imports() -> None:
    modules = [
        "api.admin",
        "api.control_plane_v2",
        "api.decisions",
        "api.dev_events",
        "api.ingest",
        "api.keys",
        "api.schemas",
        "api.stats",
        "api.ui_dashboards",
    ]

    loaded = [importlib.import_module(name) for name in modules]

    assert all(module is not None for module in loaded)
