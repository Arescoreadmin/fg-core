from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


@dataclass
class AnchorCadencePolicy:
    every_n_events: int = 50
    every_minutes: int = 10
    max_unanchored_events: int = 200


@dataclass
class AnchorCadenceState:
    queued_events: int = 0
    last_anchor_at: datetime | None = None

    def should_anchor(self, policy: AnchorCadencePolicy, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        if self.queued_events >= policy.max_unanchored_events:
            return True
        if self.queued_events >= policy.every_n_events:
            return True
        if self.last_anchor_at is None:
            return False
        return now - self.last_anchor_at >= timedelta(minutes=policy.every_minutes)

    def mark_event(self) -> None:
        self.queued_events += 1

    def mark_anchored(self, at: datetime | None = None) -> None:
        self.last_anchor_at = at or datetime.now(UTC)
        self.queued_events = 0
