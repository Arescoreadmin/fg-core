"""CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001 — Operator runtime watchdog.

This module implements the runtime and cost monitoring watchdog for the third
Customer-Zero trust ceremony (CUSTOMER-ZERO-TRUST-003).

DESIGN CONSTRAINTS (NON-NEGOTIABLE)
-------------------------------------
1. The watchdog is TIME-BASED (wall clock), not cost-based. Cloud billing is
   delayed and cannot serve as a real-time cost cap.
2. The watchdog does NOT provide a guaranteed dollar cap. It provides a
   time-based control that, combined with the confirmed hourly rate, allows
   the operator to estimate accrued cost — but actual billing may differ.
3. The watchdog emits WARNINGS only. It cannot prevent an operator from
   continuing after a stop signal. The operator bears responsibility for
   executing teardown.
4. No cloud API calls. No network requests. No credential access.

USAGE
-----
  from services.governance.run3_operator_watchdog import OperatorWatchdog

  watchdog = OperatorWatchdog(
      max_runtime_minutes=120,
      teardown_reserve_minutes=15,
      hourly_rate_usd_estimate=None,  # None if pricing unverified
  )
  watchdog.start()
  # ... at each checkpoint:
  status = watchdog.check()
  if status.should_stop:
      # INITIATE TEARDOWN IMMEDIATELY
      ...

IMPORTANT LIMITATION
--------------------
Cloud billing is delayed. An operator can estimate accrued cost from
  estimated_cost = elapsed_hours * confirmed_hourly_rate
but the provider's billed amount may not appear in their billing dashboard
for minutes to hours after the resources are destroyed. This watchdog uses
estimated_cost_usd_accrued which is a LOWER BOUND ESTIMATE only.

Do NOT claim that this watchdog provides a guaranteed dollar cap.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import Any


# ---------------------------------------------------------------------------
# Watchdog state
# ---------------------------------------------------------------------------


@dataclass
class WatchdogStatus:
    """Current watchdog status snapshot."""

    elapsed_minutes: float
    max_runtime_minutes: int
    teardown_reserve_minutes: int
    effective_max_minutes: int  # max_runtime - teardown_reserve
    runtime_percent: float
    should_warn: bool  # >= 75% of effective max
    should_stop: bool  # >= 100% of effective max
    past_hard_deadline: bool  # >= 100% of max_runtime (including teardown reserve)
    estimated_cost_usd_accrued: str | None  # None if hourly rate unverified
    billing_disclaimer: str
    checkpoint_name: str
    status_code: str  # OK | WARN_75 | STOP_EFFECTIVE_MAX | HARD_STOP

    def to_dict(self) -> dict[str, Any]:
        return {
            "elapsed_minutes": self.elapsed_minutes,
            "max_runtime_minutes": self.max_runtime_minutes,
            "teardown_reserve_minutes": self.teardown_reserve_minutes,
            "effective_max_minutes": self.effective_max_minutes,
            "runtime_percent": self.runtime_percent,
            "should_warn": self.should_warn,
            "should_stop": self.should_stop,
            "past_hard_deadline": self.past_hard_deadline,
            "estimated_cost_usd_accrued": self.estimated_cost_usd_accrued,
            "billing_disclaimer": self.billing_disclaimer,
            "checkpoint_name": self.checkpoint_name,
            "status_code": self.status_code,
        }


@dataclass
class WatchdogCheckpoint:
    """Record of a named checkpoint transition."""

    name: str
    elapsed_minutes: float
    status_code: str
    timestamp_utc: str
    estimated_cost_usd_accrued: str | None


# ---------------------------------------------------------------------------
# Watchdog implementation
# ---------------------------------------------------------------------------


class OperatorWatchdog:
    """Runtime and cost watchdog for the Customer-Zero trust ceremony.

    BILLING DISCLAIMER: This watchdog uses wall-clock time to estimate accrued
    cost. Cloud billing is delayed — the operator's provider account may not
    reflect the actual billed amount until after teardown. estimated_cost_usd_accrued
    is a LOWER BOUND ESTIMATE only, not a guaranteed billing cap.
    """

    BILLING_DISCLAIMER = (
        "IMPORTANT: estimated_cost_usd_accrued is a lower-bound ESTIMATE based on "
        "elapsed time and confirmed hourly rate. Cloud billing is delayed — "
        "actual provider billing may differ and will not appear in your HCP "
        "account until after teardown. This watchdog does NOT provide a "
        "guaranteed dollar cap."
    )

    def __init__(
        self,
        max_runtime_minutes: int,
        teardown_reserve_minutes: int,
        hourly_rate_usd_estimate: float | None = None,
        warn_at_pct: float = 0.75,
    ) -> None:
        """
        Args:
            max_runtime_minutes: The authorized maximum runtime INCLUDING teardown.
                                 Must be set before provisioning.
            teardown_reserve_minutes: Minutes reserved for teardown within max_runtime.
                                      The effective paid window is max_runtime - teardown_reserve.
            hourly_rate_usd_estimate: Current confirmed HCP hourly rate (USD).
                                      None if pricing is unverified.
            warn_at_pct: Warn threshold as fraction of effective max (default 0.75).
        """
        if max_runtime_minutes <= 0:
            raise ValueError("max_runtime_minutes must be > 0")
        if teardown_reserve_minutes < 0:
            raise ValueError("teardown_reserve_minutes must be >= 0")
        if teardown_reserve_minutes >= max_runtime_minutes:
            raise ValueError("teardown_reserve_minutes must be < max_runtime_minutes")
        if warn_at_pct <= 0 or warn_at_pct >= 1:
            raise ValueError("warn_at_pct must be between 0 and 1 (exclusive)")

        self.max_runtime_minutes = max_runtime_minutes
        self.teardown_reserve_minutes = teardown_reserve_minutes
        self.effective_max_minutes = max_runtime_minutes - teardown_reserve_minutes
        self.warn_at_pct = warn_at_pct
        self.hourly_rate_usd: Decimal | None = (
            Decimal(str(hourly_rate_usd_estimate))
            if hourly_rate_usd_estimate is not None
            else None
        )

        self._start_time: float | None = None
        self._ceremony_start_utc: str | None = None
        self._checkpoints: list[WatchdogCheckpoint] = []

    @property
    def is_started(self) -> bool:
        return self._start_time is not None

    def start(self, *, allow_restart: bool = False) -> str:
        """Record ceremony start time.

        Returns the ceremony start timestamp (UTC ISO-8601).
        Raises RuntimeError if already started and allow_restart is False.
        """
        if self._start_time is not None and not allow_restart:
            raise RuntimeError(
                "Watchdog already started. To restart, call start(allow_restart=True). "
                "WARNING: restarting resets elapsed time accounting."
            )
        self._start_time = time.monotonic()
        self._ceremony_start_utc = datetime.now(UTC).isoformat()
        self._checkpoints = []
        return self._ceremony_start_utc

    def elapsed_minutes(self) -> float:
        """Return elapsed minutes since start. Raises if not started."""
        if self._start_time is None:
            raise RuntimeError("Watchdog not started. Call start() first.")
        return (time.monotonic() - self._start_time) / 60.0

    def _estimate_cost(self, elapsed_min: float) -> str | None:
        if self.hourly_rate_usd is None:
            return None
        elapsed_hours = Decimal(str(elapsed_min)) / Decimal("60")
        cost = (elapsed_hours * self.hourly_rate_usd).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        return str(cost)

    def check(self, checkpoint_name: str = "checkpoint") -> WatchdogStatus:
        """Check current watchdog status at a named ceremony checkpoint.

        Records the checkpoint and returns a WatchdogStatus.
        Should be called at every ceremony checkpoint transition.
        """
        if self._start_time is None:
            raise RuntimeError("Watchdog not started. Call start() first.")

        elapsed = self.elapsed_minutes()
        pct = (
            elapsed / self.effective_max_minutes
            if self.effective_max_minutes > 0
            else 1.0
        )
        should_warn = pct >= self.warn_at_pct
        should_stop = pct >= 1.0
        past_hard = elapsed >= self.max_runtime_minutes
        estimated_cost = self._estimate_cost(elapsed)

        if past_hard:
            code = "HARD_STOP"
        elif should_stop:
            code = "STOP_EFFECTIVE_MAX"
        elif should_warn:
            code = "WARN_75"
        else:
            code = "OK"

        self._checkpoints.append(
            WatchdogCheckpoint(
                name=checkpoint_name,
                elapsed_minutes=elapsed,
                status_code=code,
                timestamp_utc=datetime.now(UTC).isoformat(),
                estimated_cost_usd_accrued=estimated_cost,
            )
        )

        return WatchdogStatus(
            elapsed_minutes=elapsed,
            max_runtime_minutes=self.max_runtime_minutes,
            teardown_reserve_minutes=self.teardown_reserve_minutes,
            effective_max_minutes=self.effective_max_minutes,
            runtime_percent=pct * 100,
            should_warn=should_warn,
            should_stop=should_stop,
            past_hard_deadline=past_hard,
            estimated_cost_usd_accrued=estimated_cost,
            billing_disclaimer=self.BILLING_DISCLAIMER,
            checkpoint_name=checkpoint_name,
            status_code=code,
        )

    def ceremony_summary(self) -> dict[str, Any]:
        """Return a summary of all recorded checkpoints."""
        if self._start_time is None:
            return {"error": "Watchdog not started"}
        total_elapsed = self.elapsed_minutes()
        return {
            "ceremony_start_utc": self._ceremony_start_utc,
            "total_elapsed_minutes": total_elapsed,
            "max_runtime_minutes": self.max_runtime_minutes,
            "teardown_reserve_minutes": self.teardown_reserve_minutes,
            "effective_max_minutes": self.effective_max_minutes,
            "billing_disclaimer": self.BILLING_DISCLAIMER,
            "total_estimated_cost_usd": self._estimate_cost(total_elapsed),
            "hourly_rate_used": str(self.hourly_rate_usd)
            if self.hourly_rate_usd
            else None,
            "checkpoints": [
                {
                    "name": cp.name,
                    "elapsed_minutes": cp.elapsed_minutes,
                    "status_code": cp.status_code,
                    "timestamp_utc": cp.timestamp_utc,
                    "estimated_cost_usd_accrued": cp.estimated_cost_usd_accrued,
                }
                for cp in self._checkpoints
            ],
        }
