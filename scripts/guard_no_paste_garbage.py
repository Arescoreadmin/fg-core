from __future__ import annotations

from pathlib import Path
import re
import sys

WATCH = [
    Path("Makefile"),
    Path("pytest.ini"),
    Path("pyproject.toml"),
]

# Only high-signal patterns that indicate terminal output got pasted into a file.
BAD = [
    r"^INTERNALERROR>",
    r"^Traceback \(most recent call last\):",
    r"^/bin/bash: line \d+:",
    r"^bash: .*: command not found$",
    r"^make: \*\*\*",
    r"\bPYint\(",
    r"tomllib\.TOMLDecodeError",
]

RX = re.compile("|".join(f"(?:{p})" for p in BAD), re.MULTILINE)


def main() -> int:
    hits: list[str] = []
    for p in WATCH:
        if not p.exists():
            continue
        s = p.read_text("utf-8", errors="replace")
        if RX.search(s):
            hits.append(str(p))
    if hits:
        print("ERROR: paste-garbage detected in:", file=sys.stderr)
        for h in hits:
            print(f" - {h}", file=sys.stderr)
        return 2
    print("paste-garbage guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
