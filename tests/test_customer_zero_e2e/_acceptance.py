"""Acceptance matrix recorder — L14-CUSTOMER-ZERO-E2E-001.

Statuses (never inflated):
  PASS                — real authority, real route, real behaviour (no synthetic shortcut)
  SYNTHETIC_EXECUTED  — real authorities executed over synthetic data / provenance
  PARTIAL             — works, with a recorded product limitation
  FAIL                — observed behaviour violates the expected control (a finding)
  NOT_TESTED          — not executable in this environment; never implied to work
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

STATUSES = ("PASS", "SYNTHETIC_EXECUTED", "PARTIAL", "FAIL", "NOT_TESTED")
AREAS = (
    "backend_workflow",
    "browser_ui",
    "evidence_integrity",
    "report_correctness",
    "security",
    "operational_readiness",
    "commercial_readiness",
)


@dataclass
class Step:
    step_id: str
    area: str
    capability: str
    executed_path: str
    expected: str
    actual: str
    status: str
    evidence: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    blocking: str = "none"  # none | P0 | P1 | P2
    follow_up: str | None = None


class Acceptance:
    def __init__(self) -> None:
        self.steps: list[Step] = []

    def record(self, **kw: Any) -> Step:
        step = Step(**kw)
        assert step.status in STATUSES, step.status
        assert step.area in AREAS, step.area
        assert not any(s.step_id == step.step_id for s in self.steps), step.step_id
        self.steps.append(step)
        return step

    def by_id(self, step_id: str) -> Step:
        return next(s for s in self.steps if s.step_id == step_id)

    def to_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for s in self.steps:
            counts[s.status] = counts.get(s.status, 0) + 1
        return {
            "schema": "fg.customer_zero_acceptance.v1",
            "work_item": "L14-CUSTOMER-ZERO-E2E-001",
            "environment": "isolated SQLite test app (build_app); synthetic data only",
            "status_counts": dict(sorted(counts.items())),
            "steps": [asdict(s) for s in self.steps],
        }

    def write(self, name: str = "acceptance_matrix.json") -> Path | None:
        out = os.getenv("FG_CUSTOMER_ZERO_OUT")
        if not out:
            return None
        d = Path(out)
        d.mkdir(parents=True, exist_ok=True)
        path = d / name
        path.write_text(json.dumps(self.to_dict(), indent=2, default=str))
        return path
