from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class LaneBudget:
    max_seconds: int
    warn_pct: int
    fail_pct: int


def load_runtime_budgets(path: Path) -> dict[str, object]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "global_pr_budget_seconds" not in data:
        raise SystemExit("invalid runtime budget policy")
    return data


def enforce_lane_budget(
    lane: str,
    duration_seconds: int,
    budget_doc: dict[str, object],
    baseline_seconds: int,
) -> tuple[bool, str]:
    lane_cfg = (budget_doc.get("lanes") or {}).get(lane)
    if not lane_cfg:
        return True, ""
    max_seconds = int(lane_cfg["max_seconds"])
    fail_pct = int(lane_cfg["fail_pct"])
    if duration_seconds > max_seconds:
        return (
            False,
            f"lane={lane} exceeded max_seconds={max_seconds} actual={duration_seconds}",
        )
    allowed = int(baseline_seconds * (1 + (fail_pct / 100.0)))
    if baseline_seconds > 0 and duration_seconds > allowed:
        return (
            False,
            f"lane={lane} regression exceeds fail_pct={fail_pct} baseline={baseline_seconds} actual={duration_seconds}",
        )
    return True, ""


def load_runtime_baselines(path: Path) -> dict[str, int]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    lanes = data.get("lanes") or {}
    return {str(k): int(v) for k, v in lanes.items()}
