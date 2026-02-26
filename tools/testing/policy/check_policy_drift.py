#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

POLICY_FILES = {
    "tools/testing/policy/invariants.yaml",
    "tools/testing/policy/path_to_invariants.yaml",
    "tools/testing/policy/flaky_tests.yaml",
    "tools/testing/policy/runtime_baselines.yaml",
    "tools/testing/policy/runtime_budgets.yaml",
}


def changed_files(base_ref: str) -> list[str]:
    proc = subprocess.run(
        ["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"],
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    if proc.returncode != 0:
        raise SystemExit("unable to compute changed files")
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _event_json(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def enforce_policy_drift(base_ref: str, event_path: Path, allow_flag: bool) -> tuple[bool, list[str]]:
    changed = changed_files(base_ref)
    touched = sorted(set(changed).intersection(POLICY_FILES))
    if not touched:
        return False, []

    if not allow_flag:
        event = _event_json(event_path)
        pr = event.get("pull_request") if isinstance(event, dict) else None
        if not isinstance(pr, dict):
            return True, touched
        body = ""
        labels: list[str] = []
        body = str(pr.get("body") or "")
        labels_raw = pr.get("labels") or []
        labels = [str(lbl.get("name") if isinstance(lbl, dict) else "") for lbl in labels_raw]
        body_l = body.lower()
        explicit_justification = "## policy change justification" in body_l
        narrative_justification = (
            len(body.strip()) >= 40
            and "policy" in body_l
            and any(tok in body_l for tok in ("because", "reason", "rationale", "impact"))
        )
        justification = explicit_justification or narrative_justification
        label_ok = "policy-change-approved" in labels
        if not (justification or label_ok):
            raise SystemExit(
                "policy files changed without justification narrative/section or policy-change-approved label"
            )
    return True, touched


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base-ref", default="main")
    p.add_argument("--event-path", default="")
    p.add_argument("--allow-policy-change", action="store_true")
    p.add_argument("--out", default="artifacts/testing/policy-drift.json")
    args = p.parse_args()

    event_path = Path(args.event_path) if args.event_path else Path("/nonexistent")
    changed, touched = enforce_policy_drift(args.base_ref, event_path, args.allow_policy_change)
    payload = {"policy_changed": changed, "files": touched}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
