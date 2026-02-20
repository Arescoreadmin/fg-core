from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGETS = [ROOT / "api" / "security_alerts.py", ROOT / "api" / "tripwires.py", ROOT / "api" / "security"]
PATTERN = re.compile(r"except\s+Exception(?:\s+as\s+\w+)?:\s*\n\s*(pass|continue)\b", re.MULTILINE)


def _files() -> list[Path]:
    files: list[Path] = []
    for target in TARGETS:
        if target.is_dir():
            files.extend(sorted(target.rglob("*.py")))
        elif target.exists():
            files.append(target)
    return files


def main() -> int:
    violations: list[str] = []
    for path in _files():
        rel = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8")
        if PATTERN.search(text):
            violations.append(str(rel))
    if violations:
        for rel in violations:
            print(f"forbidden exception swallowing: {rel}")
        return 1
    print("security exception swallowing: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
