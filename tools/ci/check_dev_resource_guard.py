#!/usr/bin/env python3
"""FrostGate AI development resource preflight guard.

Reads /proc/meminfo and counts active rg processes to determine
whether it is safe to begin a heavy operation phase.

Usage:
    python tools/ci/check_dev_resource_guard.py              # preflight check
    python tools/ci/check_dev_resource_guard.py --report     # verbose diagnostics
    python tools/ci/check_dev_resource_guard.py --phase mypy # label the phase

    # Testable overrides (inject mocked system state):
    python tools/ci/check_dev_resource_guard.py --meminfo-path /tmp/fake_meminfo
    python tools/ci/check_dev_resource_guard.py --mock-rg-count 5

Exit codes:
    0 — resources within acceptable bounds
    1 — resource pressure too high; defer heavy work
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

_MEMINFO_PATH = "/proc/meminfo"
_MIN_AVAILABLE_GIB = 6.0
_WARN_AVAILABLE_GIB = 8.0
_MAX_RG_PROCS = 20
_WARN_RG_PROCS = 10
_MAX_SWAP_UTILIZATION = 0.80


class ResourceSnapshot(NamedTuple):
    available_gib: float
    swap_free_gib: float
    swap_total_gib: float
    rg_process_count: int


def _read_meminfo(path: str = _MEMINFO_PATH) -> dict[str, int]:
    result: dict[str, int] = {}
    try:
        for line in Path(path).read_text().splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                parts = val.split()
                result[key.strip()] = int(parts[0]) if parts else 0
    except FileNotFoundError:
        pass
    return result


def _count_rg_processes() -> int:
    try:
        out = subprocess.run(
            ["pgrep", "-c", "rg"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        raw = out.stdout.strip()
        return int(raw) if raw.isdigit() else 0
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        return 0


_MEMINFO_UNAVAILABLE = -1.0  # sentinel: /proc/meminfo not present on this platform


def snapshot(
    meminfo_path: str = _MEMINFO_PATH,
    rg_count: int | None = None,
) -> ResourceSnapshot:
    meminfo = _read_meminfo(meminfo_path)
    if rg_count is None:
        rg_count = _count_rg_processes()

    if not meminfo:
        # /proc/meminfo absent (non-Linux host) — cannot enforce RAM thresholds
        return ResourceSnapshot(
            available_gib=_MEMINFO_UNAVAILABLE,
            swap_free_gib=_MEMINFO_UNAVAILABLE,
            swap_total_gib=_MEMINFO_UNAVAILABLE,
            rg_process_count=rg_count,
        )

    available_kib = meminfo.get("MemAvailable", 0)
    swap_free_kib = meminfo.get("SwapFree", 0)
    swap_total_kib = meminfo.get("SwapTotal", 0)

    return ResourceSnapshot(
        available_gib=available_kib / (1024 * 1024),
        swap_free_gib=swap_free_kib / (1024 * 1024),
        swap_total_gib=swap_total_kib / (1024 * 1024),
        rg_process_count=rg_count,
    )


def evaluate(snap: ResourceSnapshot) -> tuple[bool, list[str]]:
    """Return (ok, messages). ok=False means defer heavy work immediately."""
    messages: list[str] = []
    ok = True

    if snap.available_gib == _MEMINFO_UNAVAILABLE:
        messages.append(
            "INFO: /proc/meminfo unavailable — RAM check skipped (non-Linux host)"
        )
    elif snap.available_gib < _MIN_AVAILABLE_GIB:
        messages.append(
            f"CRITICAL: available RAM {snap.available_gib:.1f} GiB"
            f" < {_MIN_AVAILABLE_GIB:.0f} GiB minimum — stop heavy work"
        )
        ok = False
    elif snap.available_gib < _WARN_AVAILABLE_GIB:
        messages.append(
            f"WARNING: available RAM {snap.available_gib:.1f} GiB"
            f" < {_WARN_AVAILABLE_GIB:.0f} GiB recommended — defer if possible"
        )

    if snap.swap_total_gib > 0:
        swap_used_gib = snap.swap_total_gib - snap.swap_free_gib
        utilization = swap_used_gib / snap.swap_total_gib
        if utilization > _MAX_SWAP_UTILIZATION:
            messages.append(
                f"WARNING: swap {swap_used_gib:.1f}/{snap.swap_total_gib:.1f} GiB"
                f" ({utilization:.0%} used) — treat as low RAM"
            )

    if snap.rg_process_count >= _MAX_RG_PROCS:
        messages.append(
            f"CRITICAL: {snap.rg_process_count} active rg processes"
            f" >= {_MAX_RG_PROCS} limit — stop issuing searches"
        )
        ok = False
    elif snap.rg_process_count >= _WARN_RG_PROCS:
        messages.append(
            f"WARNING: {snap.rg_process_count} active rg processes"
            f" >= {_WARN_RG_PROCS} advisory limit"
        )

    return ok, messages


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="FrostGate AI development resource preflight guard."
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Always print full resource diagnostics.",
    )
    parser.add_argument(
        "--phase",
        default="heavy",
        help="Phase label for log output (default: heavy).",
    )
    parser.add_argument(
        "--meminfo-path",
        default=_MEMINFO_PATH,
        help=f"Path to meminfo file (default: {_MEMINFO_PATH}). Override for testing.",
    )
    parser.add_argument(
        "--mock-rg-count",
        type=int,
        default=None,
        help="Inject a fixed rg process count instead of calling pgrep. For testing.",
    )
    args = parser.parse_args(argv)

    snap = snapshot(meminfo_path=args.meminfo_path, rg_count=args.mock_rg_count)
    ok, messages = evaluate(snap)

    has_warnings = any(m.startswith("WARNING") for m in messages)

    if args.report or messages:
        print(f"[resource-guard] phase={args.phase}")
        if snap.available_gib == _MEMINFO_UNAVAILABLE:
            print("  available RAM : unavailable (/proc/meminfo absent)")
            print("  swap          : unavailable")
        else:
            print(f"  available RAM : {snap.available_gib:.1f} GiB")
            print(
                f"  swap          : {snap.swap_free_gib:.1f} free / {snap.swap_total_gib:.1f} GiB total"
            )
        print(f"  rg processes  : {snap.rg_process_count}")
        for msg in messages:
            print(f"  {msg}")

    if not ok:
        print(
            f"[resource-guard] BLOCKED — defer {args.phase!r} phase until resources recover",
            file=sys.stderr,
        )
        return 1

    if has_warnings:
        print(f"[resource-guard] WARN — proceed with caution for {args.phase!r} phase")
    elif not messages:
        if args.report:
            print(f"[resource-guard] OK — safe to begin {args.phase!r} phase")
        else:
            print("[resource-guard] OK")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
