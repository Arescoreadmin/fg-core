#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

import yaml


def load(path: Path) -> dict[str, object]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {"lanes": {}}


def save(path: Path, payload: dict[str, object]) -> None:
    path.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")


def update_baseline(path: Path, lane: str, duration_seconds: int, branch: str, event: str) -> None:
    if branch != "main" or event not in {"schedule", "workflow_dispatch", "push"}:
        raise SystemExit("baseline updates allowed only on main protected workflows")
    doc = load(path)
    lanes = doc.setdefault("lanes", {})
    lanes[lane] = int(duration_seconds)
    doc["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    save(path, doc)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--baseline", default="tools/testing/policy/runtime_baselines.yaml")
    p.add_argument("--lane", required=True)
    p.add_argument("--duration", required=True, type=int)
    p.add_argument("--branch", required=True)
    p.add_argument("--event", required=True)
    args = p.parse_args()
    update_baseline(Path(args.baseline), args.lane, args.duration, args.branch, args.event)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
