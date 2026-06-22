"""Container-boundary regression tests for Admin Gateway identity runtime."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_admin_gateway_imports_when_core_api_package_is_unavailable() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = """
import importlib.abc
import sys

class BlockCoreApi(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == \"api\" or fullname.startswith(\"api.\"):
            raise ModuleNotFoundError(\"Core api package is outside Admin Gateway image\")
        return None

sys.meta_path.insert(0, BlockCoreApi())
from admin_gateway.asgi import app
from admin_gateway.routers import identity
assert app is not None
assert identity.router.prefix == \"/identity\"
assert not any(name == \"api\" or name.startswith(\"api.\") for name in sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
