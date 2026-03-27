import importlib


def test_import() -> None:
    module = importlib.import_module("api.control_plane_v2")
    assert module is not None
