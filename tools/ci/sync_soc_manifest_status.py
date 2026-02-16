# tools/ci/sync_soc_manifest_status.py
"""
2026-02-16: SOC manifest status sync tool

Change:
- Added tools/ci/sync_soc_manifest_status.py to sync tools/ci/soc_findings_manifest.json
  statuses based on gate outcomes.

Purpose:
- Keep SOC finding statuses deterministic and CI-verifiable.
- Support soc-manifest-sync (--write) and soc-manifest-verify (--fail-on-unresolved-p0).

Validation:
- make soc-invariants
- make security-regression-gates
- make soc-manifest-verify
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / "tools/ci/soc_findings_manifest.json"

NON_FINAL = {"open", "todo", "partial", "unknown"}
FINAL = {"mitigated", "waived"}


def _run_gate(gate: str) -> tuple[bool, str]:
    # gate is a Makefile target name
    proc = subprocess.run(
        ["make", gate],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    ok = proc.returncode == 0
    out = (proc.stdout or "") + (proc.stderr or "")
    return ok, out.strip()


def _evidence_ok(evidence: list[str]) -> tuple[bool, list[str]]:
    missing = []
    for rel in evidence:
        if not (REPO / rel).exists():
            missing.append(rel)
    return (len(missing) == 0), missing


def main(argv: list[str]) -> int:
    write = "--write" in argv
    fail_on_unresolved_p0 = "--fail-on-unresolved-p0" in argv

    data: Any = json.loads(MANIFEST.read_text(encoding="utf-8"))
    findings = data.get("findings", data)

    updated = 0
    failures: list[str] = []

    for f in findings:
        fid = f.get("id")
        sev = f.get("severity")
        status = f.get("status")
        gate = f.get("gate")
        evidence = f.get("evidence", [])

        if status in FINAL:
            continue

        ev_ok, missing = _evidence_ok(evidence)
        if not ev_ok:
            msg = f"{fid} missing evidence: {missing}"
            failures.append(msg)
            continue

        if not gate:
            failures.append(f"{fid} has no gate field (cannot verify)")
            continue

        gate_ok, _ = _run_gate(gate)
        if gate_ok:
            f["status"] = "mitigated"
            updated += 1
        else:
            if sev == "P0" and fail_on_unresolved_p0:
                failures.append(f"{fid} P0 remains {status} (gate {gate} failed)")

    if write and updated:
        MANIFEST.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    # Fail if any P0 still non-final when strict mode enabled
    if fail_on_unresolved_p0:
        for f in findings:
            if f.get("severity") == "P0" and f.get("status") in NON_FINAL:
                failures.append(f"{f.get('id')} is P0 but status={f.get('status')}")

    if failures:
        print("SOC manifest sync: FAILED")
        for x in failures:
            print(" -", x)
        return 1

    print(f"SOC manifest sync: OK (updated={updated}, write={write})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
