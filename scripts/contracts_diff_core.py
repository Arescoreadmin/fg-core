#!/usr/bin/env python3
from __future__ import annotations

import difflib
import os
import sys
from pathlib import Path

from scripts.contracts_gen_core import generate_openapi, render_openapi

CONTRACT_PATH = Path("contracts/core/openapi.json")


def main() -> int:
    if not CONTRACT_PATH.exists():
        print(f"❌ Missing core OpenAPI contract at {CONTRACT_PATH}", file=sys.stderr)
        return 1

    expected = CONTRACT_PATH.read_text(encoding="utf-8")
    prior_env = os.environ.get("FG_ENV")
    os.environ["FG_ENV"] = "prod"
    try:
        generated = render_openapi(generate_openapi())
    finally:
        if prior_env is None:
            os.environ.pop("FG_ENV", None)
        else:
            os.environ["FG_ENV"] = prior_env

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
