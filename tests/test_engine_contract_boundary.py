from __future__ import annotations

import ast
import builtins
import importlib
import sys
from pathlib import Path


ENGINE_DIR = Path("engine")
BLOCKED_PREFIXES = ("api", "fastapi", "starlette")


def _is_blocked(module: str) -> bool:
    return any(
        module == prefix or module.startswith(f"{prefix}.")
        for prefix in BLOCKED_PREFIXES
    )


def test_engine_has_no_api_imports():
    offenders: list[str] = []
    for path in ENGINE_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if _is_blocked(alias.name):
                        offenders.append(f"{path}:{alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module and _is_blocked(node.module):
                    offenders.append(f"{path}:{node.module}")

    assert not offenders, f"Engine imports forbidden modules: {', '.join(offenders)}"


def test_engine_imports_without_web_stack():
    original_import = builtins.__import__

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if _is_blocked(name):
            raise ImportError(f"Blocked import: {name}")
        return original_import(name, globals, locals, fromlist, level)

    modules_to_clear = [
        key
        for key in list(sys.modules.keys())
        if key == "engine" or key.startswith("engine.")
    ]
    removed = {
        key: sys.modules.pop(key) for key in modules_to_clear if key in sys.modules
    }

    blocked_cached = [key for key in list(sys.modules.keys()) if _is_blocked(key)]
    removed.update(
        {key: sys.modules.pop(key) for key in blocked_cached if key in sys.modules}
    )

    try:
        builtins.__import__ = guarded_import
        importlib.import_module("engine.rules")
        importlib.import_module("engine.tied")
        importlib.import_module("engine.roe")
        importlib.import_module("engine.persona")
        importlib.import_module("engine.types")
    finally:
        builtins.__import__ = original_import
        sys.modules.update(removed)
