from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Services are not allowed to import API router/bootstrap modules.
FORBIDDEN = {
    "api.main",
    "api.middleware",
    "api.admin",
    "api.connectors_control_plane",
}


def _iter_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
    return imports


def main() -> int:
    violations: list[str] = []
    for py in (ROOT / "services").rglob("*.py"):
        rel = py.relative_to(ROOT)
        for name in _iter_imports(py):
            if any(name == f or name.startswith(f + ".") for f in FORBIDDEN):
                violations.append(f"{rel}: forbidden import {name}")
    if violations:
        for v in violations:
            print(v)
        return 1
    print("plane boundaries: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
