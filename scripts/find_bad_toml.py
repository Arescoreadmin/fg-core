from __future__ import annotations

from pathlib import Path
import tomllib


def main() -> None:
    roots = [Path(".")]
    tomls = sorted(
        {p for r in roots for p in r.rglob("*.toml")} | {Path("pyproject.toml")}
    )
    bad = []
    for p in tomls:
        if not p.exists() or p.is_dir():
            continue
        try:
            tomllib.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            bad.append((p, e))

    if not bad:
        print("All TOML files parsed OK.")
        return

    print("Broken TOML files:")
    for p, e in bad:
        print(f"\n- {p}\n  {type(e).__name__}: {e}")
        # Try to show nearby lines if we can parse position like "line X, column Y"
        msg = str(e)
        import re

        m = re.search(r"line (\d+), column (\d+)", msg)
        if m:
            line = int(m.group(1))
            start = max(1, line - 5)
            end = line + 5
            lines = p.read_text(encoding="utf-8").splitlines()
            for i in range(start, min(end, len(lines)) + 1):
                prefix = ">>" if i == line else "  "
                print(f"{prefix} {i:4d}  {lines[i - 1]}")
    raise SystemExit(2)


if __name__ == "__main__":
    main()
