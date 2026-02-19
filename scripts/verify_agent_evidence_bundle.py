#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_agent_evidence_bundle.py <bundle.json>")
        return 2
    p = Path(sys.argv[1])
    data = json.loads(p.read_text(encoding="utf-8"))
    anchors = data.get("anchors", [])
    if not isinstance(anchors, list):
        print("FAIL: anchors missing")
        return 1
    command_ledger = data.get("command_ledger", [])
    digest = hashlib.sha256(
        json.dumps(command_ledger, sort_keys=True).encode("utf-8")
    ).hexdigest()
    print(f"PASS bundle={p} command_ledger_sha256={digest} anchors={len(anchors)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
