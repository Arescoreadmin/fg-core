from __future__ import annotations
from pathlib import Path

MAKEFILE = Path("Makefile")

TARGETS = {
    "guard-scripts",
    "contracts-gen",
    "contracts-gen-prod",
    "contracts-core-gen",
    "contracts-core-diff",
    "artifact-contract-check",
    "contract-authority-check",
    "verify-spine-modules",
    "verify-schemas",
    "verify-drift",
    "align-score",
    "prod-profile-check",
    "gap-audit",
    "release-gate",
    "generate-scorecard",
    "fg-contract",
    "fg-contract-prod",
    "bp-s0-001-gate",
    "bp-s0-005-gate",
    "bp-c-001-gate",
    "bp-c-002-gate",
    "bp-c-003-gate",
    "bp-c-004-gate",
    "bp-c-005-gate",
    "bp-c-006-gate",
    "bp-m1-006-gate",
    "bp-m2-001-gate",
    "bp-m2-002-gate",
    "bp-m2-003-gate",
    "bp-m3-001-gate",
    "bp-m3-003-gate",
    "bp-m3-004-gate",
    "bp-m3-005-gate",
    "bp-m3-006-gate",
    "bp-m3-007-gate",
    "bp-d-000-gate",
}

txt = MAKEFILE.read_text()

out_lines = []
changed = 0
for line in txt.splitlines(True):
    # Only touch exact target definition lines like: target: prereqs...
    # Skip pattern rules, variables, etc.
    stripped = line.lstrip()
    if not stripped or stripped.startswith("#") or ":" not in line:
        out_lines.append(line)
        continue

    # Match "name:" at beginning of line (allow no leading spaces in Makefile targets typically)
    # We keep it conservative: only if the line starts with the target name exactly.
    for t in TARGETS:
        prefix = f"{t}:"
        if line.startswith(prefix):
            if " venv" in line or "\tvenv" in line or " _require-venv" in line:
                out_lines.append(line)
            else:
                # insert venv right after colon
                out_lines.append(line.replace(prefix, f"{prefix} venv", 1))
                changed += 1
            break
    else:
        out_lines.append(line)

MAKEFILE.write_text("".join(out_lines))
print(f"updated {changed} target(s)")
