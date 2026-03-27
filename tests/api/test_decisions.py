import importlib


def test_import() -> None:
    module = importlib.import_module("api.decisions")
    assert module is not None
