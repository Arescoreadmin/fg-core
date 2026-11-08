"""Scanner execution checkpoint contract — L14-SCAN-AUTH-HARDENING-001.

Runners that perform outbound I/O over multiple targets accept an optional
``checkpoint`` callable.  The runner calls it immediately BEFORE each
meaningful outbound work boundary (next target, next redirect hop).  The
checkpoint re-reads authoritative authorization, cancellation and
emergency-stop state and signals the runner by raising:

* ``ScanTargetDenied``   — this one target (or redirect destination) is not
                           authorized.  The runner must skip it, record it as
                           DENIED, and may continue with other targets.
* ``ScanCheckpointHalt`` — authorization, cancellation, or emergency-stop state
                           no longer permits ANY new outbound work.  The runner
                           must stop starting new work immediately, keep what
                           it already collected, and report CANCELLED coverage.

This module is deliberately dependency-free so connector packages do not need
to import Field Assessment internals.  The authoritative implementation lives
in ``services/field_assessment/scan_execution_guard.py``.

Not standalone: this contract only has meaning when wired to the canonical
scan authorization authority (``services/field_assessment/scan_authorization``).
"""

from __future__ import annotations

from typing import Callable, Optional


class ScanCheckpointHalt(Exception):
    """No further outbound work is permitted for this scan job."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}" if detail else reason_code)


class ScanTargetDenied(Exception):
    """A single target or redirect destination is outside the authorized scope."""

    def __init__(self, reason_code: str, target: str) -> None:
        self.reason_code = reason_code
        self.target = target
        super().__init__(f"{reason_code}: {target}")


# checkpoint(phase, target) — phase is e.g. "target" or "redirect".
ScanCheckpoint = Callable[[str, Optional[str]], None]


def interruption_record(
    halt: ScanCheckpointHalt, *, phase: str, remaining: int
) -> dict:
    """Serializable description of why collection stopped early."""
    return {
        "reason_code": halt.reason_code,
        "phase": phase,
        "remaining_targets_not_started": remaining,
    }
