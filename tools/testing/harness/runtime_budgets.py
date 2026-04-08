from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

yaml = importlib.import_module("yaml")


@runtime_checkable
class _SupportsInt(Protocol):
    def __int__(self) -> int: ...


def _as_dict(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    return {}


def _as_iterable(value: object) -> list[object]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return []


def _to_int(value: object) -> int:
    if isinstance(value, (str, bytes, bytearray, _SupportsInt)):
        return int(value)
    raise TypeError(
        f"int() argument must be a string, bytes-like, or number, not {type(value).__name__}"
    )


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
    lane_cfg = _as_dict(_as_dict(budget_doc).get("lanes")).get(lane)
    if not lane_cfg:
        return True, ""
    lane_cfg_dict = _as_dict(lane_cfg)
    max_seconds = _to_int(lane_cfg_dict["max_seconds"])
    fail_pct = _to_int(lane_cfg_dict["fail_pct"])
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
    lanes = _as_dict(_as_dict(data).get("lanes"))
    return {str(k): _to_int(v) for k, v in lanes.items()}
