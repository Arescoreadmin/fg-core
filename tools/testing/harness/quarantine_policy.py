from __future__ import annotations

import re
from pathlib import Path

POLICY_PATH = Path("tools/testing/policy/flaky_tests.yaml")
_NODEID_RE = re.compile(r'^\s*-?\s*nodeid\s*:\s*["\']?(.*?)["\']?\s*$')


def _parse_nodeids_fallback(text: str) -> list[str]:
    nodeids: list[str] = []
    for line in text.splitlines():
        m = _NODEID_RE.match(line)
        if m:
            value = m.group(1).strip()
            if value:
                nodeids.append(value)
    return sorted(set(nodeids))


def load_quarantine_nodeids(path: Path = POLICY_PATH) -> list[str]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")

    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text) or []
        nodeids = sorted(
            {
                str(entry["nodeid"]).strip()
                for entry in data
                if isinstance(entry, dict) and entry.get("nodeid")
            }
        )
        return [n for n in nodeids if n]
    except Exception:
        # Minimal hermetic fallback for environments without PyYAML (e.g. tools_minimal tests).
        return _parse_nodeids_fallback(text)


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
