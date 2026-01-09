from __future__ import annotations
from pathlib import Path
import sys

REQUIRED = [
    ("env =", "pytest-env section (env =) missing"),
    ("FG_ENV=test", "FG_ENV=test missing"),
    ("markers =", "markers section missing"),
    ("smoke:", "smoke marker missing"),
    ("contract:", "contract marker missing"),
]

def main() -> int:
    p = Path("pytest.ini")
    if not p.exists():
        print("ERROR: pytest.ini missing", file=sys.stderr)
        return 2
    t = p.read_text("utf-8")
    if "INI" in t:
        print("ERROR: pytest.ini contains heredoc garbage 'INI'", file=sys.stderr)
        return 2
    for needle, msg in REQUIRED:
        if needle not in t:
            print(f"ERROR: {msg}", file=sys.stderr)
            return 2
    print("pytest.ini guard: OK")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
