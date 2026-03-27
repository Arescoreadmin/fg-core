import importlib


def test_import() -> None:
    module = importlib.import_module("api.admin")
    assert module is not None
