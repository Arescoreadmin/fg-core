from __future__ import annotations

import importlib
import sys


def test_core_contract_generation_context_import_keeps_builders_available(
    monkeypatch,
) -> None:
    monkeypatch.setenv("FG_CONTRACTS_GEN", "1")
    monkeypatch.setenv("FG_ENV", "prod")

    sys.modules.pop("api.main", None)
    mod = importlib.import_module("api.main")

    assert hasattr(mod, "build_contract_app")
    assert getattr(mod, "app", None) is not None

