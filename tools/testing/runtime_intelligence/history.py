"""Rolling history for gate runtime results. Schema-version aware. Max 100 runs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import RollingStats
from .statistics import compute_rolling_stats

HISTORY_SCHEMA_VERSION = "1.0"
MAX_HISTORY_RUNS = 100


@dataclass
class RuntimeHistory:
    schema_version: str
    gate: str
    runs: list[
        dict[str, Any]
    ]  # list of {duration_seconds, passed, failed, collected, commit_sha, recorded_at}


def _gate_from_stem(stem: str) -> str:
    """Strip the '-history' suffix added by the filename convention."""
    return stem.removesuffix("-history")


def load_history(path: Path) -> RuntimeHistory:
    gate = _gate_from_stem(path.stem)
    if not path.exists():
        return RuntimeHistory(schema_version=HISTORY_SCHEMA_VERSION, gate=gate, runs=[])
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != HISTORY_SCHEMA_VERSION:
        # Schema mismatch: start fresh (forward-only migration)
        return RuntimeHistory(schema_version=HISTORY_SCHEMA_VERSION, gate=gate, runs=[])
    return RuntimeHistory(
        schema_version=data["schema_version"],
        gate=data.get("gate", gate),
        runs=data.get("runs", []),
    )


def append_result(
    history: RuntimeHistory,
    entry: dict[str, Any],
    max_runs: int = MAX_HISTORY_RUNS,
) -> RuntimeHistory:
    runs = list(history.runs) + [entry]
    if len(runs) > max_runs:
        runs = runs[-max_runs:]
    return RuntimeHistory(
        schema_version=history.schema_version, gate=history.gate, runs=runs
    )


def save_history(history: RuntimeHistory, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "schema_version": history.schema_version,
        "gate": history.gate,
        "runs": history.runs,
    }
    path.write_text(
        json.dumps(data, sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def rolling_stats_for_history(
    history: RuntimeHistory, last_n: int = 30
) -> RollingStats:
    recent = history.runs[-last_n:] if len(history.runs) >= last_n else history.runs
    durations = [r["duration_seconds"] for r in recent if "duration_seconds" in r]
    return compute_rolling_stats(durations)


def baseline_collected_for_history(
    history: RuntimeHistory, last_n: int = 30
) -> int | None:
    """Median collected-test count from recent history, or None if no data."""
    recent = history.runs[-last_n:] if len(history.runs) >= last_n else history.runs
    counts = [int(r["collected"]) for r in recent if "collected" in r]
    if not counts:
        return None
    counts.sort()
    return counts[len(counts) // 2]
