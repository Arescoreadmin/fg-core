from __future__ import annotations

import re
from pathlib import Path


FORBIDDEN_PATTERNS = [
    re.compile(r"from\s+engine\.evaluate\s+import"),
    re.compile(r"import\s+engine\.evaluate"),
    re.compile(r"engine\.evaluate\s*\("),
]


def test_no_engine_evaluate_imports_in_api() -> None:
    violations: list[str] = []
    for path in Path("api").rglob("*.py"):
        if path.name == "__init__.py":
            continue
        content = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_PATTERNS:
            if pattern.search(content):
                violations.append(str(path))
                break

    assert not violations, (
        "Forbidden engine.evaluate usage in api/: " + ", ".join(sorted(violations))
    )
