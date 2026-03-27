import importlib


def test_import() -> None:
    module = importlib.import_module("api.ingest")
    assert module is not None
