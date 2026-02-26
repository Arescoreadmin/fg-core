#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable

import yaml

from tools.testing.harness.quarantine_policy import ensure_new_suspects_have_policy_entries


def _load_quarantine(path: Path) -> dict[str, dict[str, object]]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return {entry["nodeid"]: entry for entry in data}


def _parse_failures(junit_path: Path) -> list[str]:
    text = junit_path.read_text(encoding="utf-8", errors="replace")
    nodeids: set[str] = set()
    for line in text.splitlines():
        if "classname=" in line and "name=" in line:
            cls = line.split("classname=\"")[1].split("\"")[0]
            name = line.split("name=\"")[1].split("\"")[0]
            nodeids.add(f"{cls}::{name}")
    return sorted(nodeids)


def detect_flakes(nodeids: Iterable[str], outcomes: dict[str, list[str]]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for nodeid in sorted(set(nodeids)):
        series = outcomes.get(nodeid, [])
        if {"pass", "fail"}.issubset(set(series)):
            findings.append({"nodeid": nodeid, "outcomes": series, "classification": "flake-suspected"})
    return findings


def build_report(new_flakes: list[dict[str, object]], quarantine: dict[str, dict[str, object]]) -> dict[str, object]:
    return {
        "newly_suspected": new_flakes,
        "quarantined": [quarantine[k] for k in sorted(quarantine)],
        "trends": {
            "newly_suspected_count": len(new_flakes),
            "quarantined_count": len(quarantine),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--junit", required=True)
    parser.add_argument("--quarantine", default="tools/testing/policy/flaky_tests.yaml")
    parser.add_argument("--out", default="artifacts/testing/flake-report.json")
    args = parser.parse_args()

    failures = _parse_failures(Path(args.junit))
    # Deterministic fail-closed default: if no rerun outcomes provided, mark all as unresolved failures.
    outcomes = {nodeid: ["fail", "fail", "fail"] for nodeid in failures}
    quarantine = _load_quarantine(Path(args.quarantine))
    report = build_report(detect_flakes(failures, outcomes), quarantine)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    ensure_new_suspects_have_policy_entries(out_path, Path(args.quarantine))
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
