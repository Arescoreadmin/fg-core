# ruff: noqa: E402
from __future__ import annotations

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.ci.route_checks import is_public_path, iter_route_records


def _auth_module_uses_get_db() -> bool:
    auth_path = Path("api/auth.py")
    tree = ast.parse(auth_path.read_text(encoding="utf-8"), filename=str(auth_path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "Depends":
            continue
        if not node.args:
            continue
        dep = node.args[0]
        if isinstance(dep, ast.Name) and dep.id == "get_db":
            return True
    return False


def main() -> int:
    api_root = Path("api")
    violations = [
        r
        for r in iter_route_records(api_root)
        if not is_public_path(r.full_path) and r.route_has_db_dependency
    ]

    if _auth_module_uses_get_db():
        print("api/auth.py must not depend on get_db for auth dependencies.")
        return 1

    if violations:
        print("Found non-public routes using Depends(get_db):")
        for v in violations:
            print(f"- {v.file_path}:{v.function_name} [{v.method} {v.full_path}]")
        return 1

    print("OK: no non-public routes use Depends(get_db).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
