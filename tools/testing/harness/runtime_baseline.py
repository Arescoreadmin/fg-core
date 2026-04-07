#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
from datetime import datetime, timezone
from pathlib import Path

yaml = importlib.import_module("yaml")


def _as_dict(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    return {}


def _as_iterable(value: object) -> list[object]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return []


def load(path: Path) -> dict[str, object]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {"lanes": {}}


def save(path: Path, payload: dict[str, object]) -> None:
    path.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")


def update_baseline(
    path: Path, lane: str, duration_seconds: int, branch: str, event: str
) -> None:
    if branch != "main" or event not in {"schedule", "workflow_dispatch", "push"}:
        raise SystemExit("baseline updates allowed only on main protected workflows")
    doc = load(path)
    lanes = _as_dict(doc.setdefault("lanes", {}))
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
    update_baseline(
        Path(args.baseline), args.lane, args.duration, args.branch, args.event
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
