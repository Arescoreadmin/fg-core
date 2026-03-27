import importlib


def test_import() -> None:
    module = importlib.import_module("api.keys")
    assert module is not None
