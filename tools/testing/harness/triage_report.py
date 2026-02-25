#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

BUCKET_RULES: list[tuple[str, str, str]] = [
    ("contract drift", r"contract|openapi|schema|snapshot", "make fg-contract"),
    ("duplicate routes", r"duplicate route|route conflict", "python tools/ci/check_route_inventory.py"),
    ("plane registry mismatch", r"plane registry|ownership_map", "python tools/ci/check_plane_registry.py"),
    ("auth scope mismatch", r"scope|forbidden|permission", "pytest -q tests/security/test_scope_enforcement.py"),
    ("tenant isolation breach", r"tenant|cross-tenant|isolation", "pytest -q tests/security/test_tenant_binding_global.py"),
    ("RLS missing", r"rls|row level security", "python tools/ci/check_agent_phase2_rls.py"),
    ("migration unsafe", r"migration|ddl|sql", "make test-pg-migrations-replay"),
    ("evidence hash mismatch", r"sha256|hash mismatch|attestation", "python tools/verify_bundle.py"),
    ("flaky test suspected", r"flaky|intermittent|rerun", "pytest --lf -q"),
]


def _classify(lines: list[str]) -> dict[str, object]:
    joined = "\n".join(lines).lower()
    for bucket, pattern, command in BUCKET_RULES:
        if re.search(pattern, joined):
            relevant = [line for line in lines if re.search(pattern, line.lower())][:8]
            return {
                "bucket": bucket,
                "top_lines": relevant,
                "next_command": command,
            }

    return {
        "bucket": "unclassified",
        "top_lines": lines[:8],
        "next_command": "make fg-fast",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic triage output from test logs")
    parser.add_argument("--log", required=True, help="Path to lane log file")
    parser.add_argument("--out", required=True, help="Path to write triage JSON")
    args = parser.parse_args()

    log_path = Path(args.log)
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    report = _classify(lines)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
