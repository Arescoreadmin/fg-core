"""
Report generation load-test harness.

Measures report job enqueue + lifecycle latency under concurrent load.
Uses an injected fake generator — no real LLM or provider calls are made.

Default safe profile: 5 jobs, concurrency 2, 10 ms simulated duration.

CLI usage:
    python tools/load/report_generation_load.py --help
    python tools/load/report_generation_load.py --jobs 5 --concurrency 2
    python tools/load/report_generation_load.py --jobs 20 --concurrency 4 --artifact /tmp/load_result.json

Importable API:
    from tools.load.report_generation_load import run_load_test, LoadMetrics
    metrics = asyncio.run(run_load_test(total_jobs=5, concurrency=2))
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

from api.report_jobs import (
    REPORT_GENERATION_FAILED,
    REPORT_GENERATION_TIMEOUT,
    ReportJobState,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class JobRecord:
    """Lifecycle record for a single simulated report job."""

    job_id: str
    tenant_id: str
    enqueue_time_ms: float
    start_time_ms: float | None = None
    end_time_ms: float | None = None
    state: ReportJobState = ReportJobState.QUEUED
    reason: str | None = None

    @property
    def enqueue_latency_ms(self) -> float:
        """Wall-clock time from run start until job was enqueued (ms)."""
        return self.enqueue_time_ms

    @property
    def completion_latency_ms(self) -> float | None:
        """Wall-clock time from job start until terminal state (ms)."""
        if self.start_time_ms is None or self.end_time_ms is None:
            return None
        return self.end_time_ms - self.start_time_ms


@dataclass
class LoadMetrics:
    """Aggregate metrics collected over a full load-test run."""

    total_jobs: int
    concurrency: int
    queued_count: int = 0
    succeeded_count: int = 0
    failed_count: int = 0
    timeout_count: int = 0
    enqueue_latencies_ms: list[float] = field(default_factory=list)
    completion_latencies_ms: list[float] = field(default_factory=list)
    total_duration_ms: float = 0.0

    def to_dict(self) -> dict:
        """Serialise metrics to a plain dict suitable for JSON output."""

        def _percentile(data: list[float], p: float) -> float | None:
            if not data:
                return None
            s = sorted(data)
            idx = max(0, int(len(s) * p / 100) - 1)
            return s[idx]

        def _stats(data: list[float]) -> dict:
            if not data:
                return {"min": None, "max": None, "avg": None, "p95": None}
            return {
                "min": min(data),
                "max": max(data),
                "avg": sum(data) / len(data),
                "p95": _percentile(data, 95),
            }

        return {
            "total_jobs": self.total_jobs,
            "concurrency": self.concurrency,
            "queued_count": self.queued_count,
            "succeeded_count": self.succeeded_count,
            "failed_count": self.failed_count,
            "timeout_count": self.timeout_count,
            "enqueue_latency_ms": _stats(self.enqueue_latencies_ms),
            "completion_latency_ms": _stats(self.completion_latencies_ms),
            "total_duration_ms": self.total_duration_ms,
        }


# ---------------------------------------------------------------------------
# Default fake generator factory
# ---------------------------------------------------------------------------


def _make_default_generator(
    simulated_duration_s: float,
    failure_rate: float,
) -> Callable[[str, str], Awaitable[None]]:
    """
    Return an async callable that simulates a report generation job.

    - Waits ``simulated_duration_s`` to mimic I/O-bound work.
    - Raises ``RuntimeError(REPORT_GENERATION_FAILED)`` with probability
      ``failure_rate`` (0.0 = never fail, 1.0 = always fail).
    - Uses only stdlib — no real providers, no DB, no network.
    """

    async def _fake_generator(job_id: str, tenant_id: str) -> None:  # noqa: ARG001
        if simulated_duration_s > 0:
            await asyncio.sleep(simulated_duration_s)
        if failure_rate > 0.0 and random.random() < failure_rate:
            raise RuntimeError(REPORT_GENERATION_FAILED)

    return _fake_generator


# ---------------------------------------------------------------------------
# Per-job runner
# ---------------------------------------------------------------------------


async def _run_job(
    job_id: str,
    tenant_id: str,
    generator: Callable[[str, str], Awaitable[None]],
    record: JobRecord,
    run_start: float,
) -> None:
    """
    Execute one simulated report job and update *record* in place.

    State machine: QUEUED → RUNNING → SUCCEEDED | FAILED
    ``asyncio.TimeoutError`` maps to ``REPORT_GENERATION_TIMEOUT``.
    All other exceptions map to ``REPORT_GENERATION_FAILED`` (or the
    exception message if it is non-empty).
    """
    t_start = time.perf_counter()
    record.start_time_ms = (t_start - run_start) * 1000
    record.state = ReportJobState.RUNNING

    try:
        await generator(job_id, tenant_id)
        record.state = ReportJobState.SUCCEEDED
    except asyncio.TimeoutError:
        record.state = ReportJobState.FAILED
        record.reason = REPORT_GENERATION_TIMEOUT
    except Exception as exc:
        record.state = ReportJobState.FAILED
        record.reason = str(exc) if str(exc) else REPORT_GENERATION_FAILED
    finally:
        record.end_time_ms = (time.perf_counter() - run_start) * 1000


# ---------------------------------------------------------------------------
# Main harness
# ---------------------------------------------------------------------------


async def run_load_test(
    total_jobs: int = 5,
    concurrency: int = 2,
    tenant_id: str = "test-tenant-load",
    simulated_duration_s: float = 0.01,
    failure_rate: float = 0.0,
    generator: Callable[[str, str], Awaitable[None]] | None = None,
    artifact_path: Path | None = None,
) -> LoadMetrics:
    """
    Run a load test against the report job lifecycle.

    Parameters
    ----------
    total_jobs:
        Number of report jobs to simulate.
    concurrency:
        Maximum jobs executing simultaneously.
    tenant_id:
        Tenant identifier stamped on every job record.
    simulated_duration_s:
        How long the fake generator sleeps to simulate work.
    failure_rate:
        Fraction of jobs that should fail (0.0–1.0).  Only applies when
        the default generator is used; custom generators control their own
        failure behaviour.
    generator:
        Async callable ``(job_id, tenant_id) -> None``.  If *None*, the
        default fake generator is used — no real provider calls are made.
    artifact_path:
        If provided, write a JSON metrics artifact to this path.

    Returns
    -------
    LoadMetrics
        Aggregate timing and count metrics for the completed run.
    """
    if generator is None:
        generator = _make_default_generator(simulated_duration_s, failure_rate)

    metrics = LoadMetrics(total_jobs=total_jobs, concurrency=concurrency)
    records: list[JobRecord] = []

    semaphore = asyncio.Semaphore(concurrency)
    run_start = time.perf_counter()

    async def _bounded_run(record: JobRecord) -> None:
        async with semaphore:
            await _run_job(
                record.job_id, record.tenant_id, generator, record, run_start
            )

    # Enqueue all jobs, recording the enqueue time relative to run start.
    tasks: list[asyncio.Task] = []
    for _ in range(total_jobs):
        t_enqueue = time.perf_counter()
        job_id = str(uuid.uuid4())
        record = JobRecord(
            job_id=job_id,
            tenant_id=tenant_id,
            enqueue_time_ms=(t_enqueue - run_start) * 1000,
            state=ReportJobState.QUEUED,
        )
        records.append(record)
        metrics.queued_count += 1
        metrics.enqueue_latencies_ms.append(record.enqueue_time_ms)
        tasks.append(asyncio.create_task(_bounded_run(record)))

    # Wait for all jobs to reach a terminal state.
    await asyncio.gather(*tasks)

    metrics.total_duration_ms = (time.perf_counter() - run_start) * 1000

    # Aggregate outcomes.
    for rec in records:
        if rec.state == ReportJobState.SUCCEEDED:
            metrics.succeeded_count += 1
        elif rec.state == ReportJobState.FAILED:
            if rec.reason == REPORT_GENERATION_TIMEOUT:
                metrics.timeout_count += 1
            else:
                metrics.failed_count += 1

        latency = rec.completion_latency_ms
        if latency is not None:
            metrics.completion_latencies_ms.append(latency)

    if artifact_path is not None:
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(
            json.dumps(metrics.to_dict(), indent=2), encoding="utf-8"
        )

    return metrics


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="report_generation_load",
        description=(
            "Report generation load-test harness. "
            "Simulates report job enqueue + lifecycle under concurrent load. "
            "No real LLM or provider calls are made."
        ),
    )
    p.add_argument(
        "--jobs",
        type=int,
        default=5,
        metavar="N",
        help="Total number of report jobs to simulate (default: 5).",
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=2,
        metavar="N",
        help="Maximum concurrent jobs (default: 2).",
    )
    p.add_argument(
        "--tenant",
        default="test-tenant-load",
        metavar="ID",
        help="Tenant ID to stamp on all job records (default: test-tenant-load).",
    )
    p.add_argument(
        "--duration",
        type=float,
        default=0.01,
        metavar="S",
        help="Simulated generation duration in seconds (default: 0.01).",
    )
    p.add_argument(
        "--failure-rate",
        type=float,
        default=0.0,
        metavar="F",
        dest="failure_rate",
        help="Fraction of jobs that should fail, 0.0–1.0 (default: 0.0).",
    )
    p.add_argument(
        "--artifact",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write JSON metrics artifact to this path (optional).",
    )
    return p


def _main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    metrics = asyncio.run(
        run_load_test(
            total_jobs=args.jobs,
            concurrency=args.concurrency,
            tenant_id=args.tenant,
            simulated_duration_s=args.duration,
            failure_rate=args.failure_rate,
            artifact_path=args.artifact,
        )
    )

    result = metrics.to_dict()
    print(json.dumps(result, indent=2))

    if args.artifact:
        print(f"\nArtifact written to: {args.artifact}")


if __name__ == "__main__":
    _main()
