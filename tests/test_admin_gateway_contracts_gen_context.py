from __future__ import annotations

import importlib


def test_contract_generation_context_avoids_side_effects_and_allows_import():
    """
    Contract generation imports build_app and should not:
    - auto-create app at import time
    - enforce prod-only runtime requirements
    """
    mod = importlib.import_module("admin_gateway.main")
    assert hasattr(mod, "build_app")
    # In contract-gen context, module-level `app` should be None (or not built).
    # The test suite sets AG_CONTRACTS_GEN=1 via pytest-env or Makefile env.
    assert getattr(mod, "app", None) is None


def test_build_app_still_builds_when_called_explicitly_in_contract_context():
    from admin_gateway.main import build_app

    app = build_app()
    assert app.title
