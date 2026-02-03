#!/usr/bin/env python3
from __future__ import annotations

import difflib
import sys
from pathlib import Path

from scripts.contracts_gen_core import generate_openapi, render_openapi

CONTRACT_PATH = Path("contracts/core/openapi.json")


def main() -> int:
    if not CONTRACT_PATH.exists():
        print(f"❌ Missing core OpenAPI contract at {CONTRACT_PATH}", file=sys.stderr)
        return 1

    expected = CONTRACT_PATH.read_text(encoding="utf-8")
    generated = render_openapi(generate_openapi())

    if expected != generated:
        diff = difflib.unified_diff(
            expected.splitlines(),
            generated.splitlines(),
            fromfile=str(CONTRACT_PATH),
            tofile="generated",
            lineterm="",
        )
        print("❌ Core OpenAPI contract drift detected:", file=sys.stderr)
        print("\n".join(diff), file=sys.stderr)
        return 1

    print("✅ Core OpenAPI contract matches committed version")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
