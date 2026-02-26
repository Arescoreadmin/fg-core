from __future__ import annotations

from pathlib import Path

import yaml


POLICY_PATH = Path("tools/testing/policy/flaky_tests.yaml")


def load_quarantine_nodeids(path: Path = POLICY_PATH) -> list[str]:
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    nodeids = sorted({str(entry["nodeid"]).strip() for entry in data if entry.get("nodeid")})
    return [n for n in nodeids if n]


def pytest_addopts_for_lane(lane: str) -> str:
    # Quarantined tests must not run in PR-required lanes.
    if lane not in {"fg-fast", "fg-contract", "fg-security", "required-tests-gate", "policy-validate"}:
        return ""
    nodeids = load_quarantine_nodeids()
    if not nodeids:
        return ""
    deselects = [f"--deselect={nodeid}" for nodeid in nodeids]
    return " ".join(deselects)


def ensure_new_suspects_have_policy_entries(report_path: Path, policy_path: Path = POLICY_PATH) -> None:
    import json

    report = json.loads(report_path.read_text(encoding="utf-8"))
    suspects = {entry["nodeid"] for entry in report.get("newly_suspected", [])}
    policy_nodeids = set(load_quarantine_nodeids(policy_path))
    missing = sorted(suspects - policy_nodeids)
    if missing:
        raise SystemExit(f"missing quarantine policy entries for suspected flakes: {missing}")
