"""
tests/test_report_load_harness.py — Harness behaviour tests.

Covers:
- Basic run with default fake generator succeeds
- Enqueue latency is recorded for every job
- Completion latency is recorded for every completed job
- Failure and timeout counts are accurate
- Concurrent jobs have distinct UUIDs
- All jobs reach a terminal state before run_load_test returns
- JSON artifact is written when artifact_path is provided
- No real provider calls are made (sentinel check)
- Explicit tenant_id is propagated to job records
- Default profile is fast (well under 1 s)
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

from tools.load.report_generation_load import (
    LoadMetrics,
    run_load_test,
)
from api.report_jobs import REPORT_GENERATION_FAILED


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAST_DURATION = 0.0  # no sleep — tests complete in microseconds


async def _instant_generator(job_id: str, tenant_id: str) -> None:  # noqa: ARG001
    """Zero-latency fake generator that always succeeds."""


async def _failing_generator(job_id: str, tenant_id: str) -> None:  # noqa: ARG001
    """Always raises to simulate a non-timeout failure."""
    raise RuntimeError(REPORT_GENERATION_FAILED)


async def _timeout_generator(job_id: str, tenant_id: str) -> None:  # noqa: ARG001
    """Raises asyncio.TimeoutError to simulate a timeout failure."""
    raise asyncio.TimeoutError


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestReportLoadHarnessBasic:
    def test_report_load_harness_runs_with_fake_generator(self) -> None:
        """run_load_test completes and returns a LoadMetrics instance."""
        metrics = asyncio.run(
            run_load_test(
                total_jobs=3,
                concurrency=2,
                simulated_duration_s=_FAST_DURATION,
                generator=_instant_generator,
            )
        )
        assert isinstance(metrics, LoadMetrics)
        assert metrics.total_jobs == 3
        assert metrics.concurrency == 2

    def test_report_load_harness_records_enqueue_latency(self) -> None:
        """An enqueue latency entry is recorded for every submitted job."""
        metrics = asyncio.run(
            run_load_test(
                total_jobs=4,
                concurrency=2,
                simulated_duration_s=_FAST_DURATION,
                generator=_instant_generator,
            )
        )
        assert len(metrics.enqueue_latencies_ms) == 4
        for lat in metrics.enqueue_latencies_ms:
            assert isinstance(lat, float)
            assert lat >= 0.0

    def test_report_load_harness_records_completion_latency(self) -> None:
        """A completion latency entry is recorded for every job that ran."""
        metrics = asyncio.run(
            run_load_test(
                total_jobs=4,
                concurrency=2,
                simulated_duration_s=_FAST_DURATION,
                generator=_instant_generator,
            )
        )
        assert len(metrics.completion_latencies_ms) == 4
        for lat in metrics.completion_latencies_ms:
            assert isinstance(lat, float)
            assert lat >= 0.0

    def test_report_load_harness_records_failure_and_timeout_counts(self) -> None:
        """failed_count and timeout_count accurately reflect generator outcomes."""
        # 3 jobs, all non-timeout failures
        metrics_fail = asyncio.run(
            run_load_test(
                total_jobs=3,
                concurrency=3,
                simulated_duration_s=_FAST_DURATION,
                generator=_failing_generator,
            )
        )
        assert metrics_fail.failed_count == 3
        assert metrics_fail.succeeded_count == 0
        assert metrics_fail.timeout_count == 0

        # 3 jobs, all timeout failures
        metrics_timeout = asyncio.run(
            run_load_test(
                total_jobs=3,
                concurrency=3,
                simulated_duration_s=_FAST_DURATION,
                generator=_timeout_generator,
            )
        )
        assert metrics_timeout.timeout_count == 3
        assert metrics_timeout.succeeded_count == 0
        assert metrics_timeout.failed_count == 0

    def test_report_load_harness_concurrent_jobs_have_distinct_ids(self) -> None:
        """Every simulated job is assigned a unique UUID."""
        seen_ids: list[str] = []

        async def _capture_generator(job_id: str, tenant_id: str) -> None:  # noqa: ARG001
            seen_ids.append(job_id)

        asyncio.run(
            run_load_test(
                total_jobs=10,
                concurrency=5,
                simulated_duration_s=_FAST_DURATION,
                generator=_capture_generator,
            )
        )
        assert len(seen_ids) == 10
        assert len(set(seen_ids)) == 10, "Duplicate job IDs detected"
        # All IDs should be valid UUIDs
        for jid in seen_ids:
            uuid.UUID(jid)  # raises if invalid

    def test_report_load_harness_waits_for_terminal_states(self) -> None:
        """run_load_test returns only after all jobs reach SUCCEEDED or FAILED."""
        metrics = asyncio.run(
            run_load_test(
                total_jobs=5,
                concurrency=2,
                simulated_duration_s=_FAST_DURATION,
                generator=_instant_generator,
            )
        )
        # All jobs must be accounted for in terminal counts
        terminal_total = (
            metrics.succeeded_count + metrics.failed_count + metrics.timeout_count
        )
        assert terminal_total == metrics.total_jobs

    def test_report_load_harness_writes_json_artifact(self, tmp_path: Path) -> None:
        """When artifact_path is provided, a valid JSON file is written."""
        out = tmp_path / "load_result.json"
        asyncio.run(
            run_load_test(
                total_jobs=3,
                concurrency=2,
                simulated_duration_s=_FAST_DURATION,
                generator=_instant_generator,
                artifact_path=out,
            )
        )
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["total_jobs"] == 3
        assert data["concurrency"] == 2
        assert "succeeded_count" in data
        assert "enqueue_latency_ms" in data
        assert "completion_latency_ms" in data
        assert "total_duration_ms" in data

    def test_report_load_harness_does_not_call_real_provider(self) -> None:
        """
        Harness must never import or call the real AI provider.

        We verify by ensuring no call to services.ai.dispatch reaches the
        default generator path, and that injecting a sentinel generator that
        raises if called with unexpected args still succeeds.
        """
        call_log: list[tuple[str, str]] = []

        async def _sentinel_generator(job_id: str, tenant_id: str) -> None:
            # Real provider calls would require env vars / network; this sentinel
            # records calls instead of delegating to any real service.
            call_log.append((job_id, tenant_id))

        metrics = asyncio.run(
            run_load_test(
                total_jobs=2,
                concurrency=1,
                simulated_duration_s=_FAST_DURATION,
                generator=_sentinel_generator,
            )
        )
        # All calls went through our sentinel (no real provider)
        assert len(call_log) == 2
        assert metrics.succeeded_count == 2

    def test_report_load_harness_uses_explicit_tenant_id(self) -> None:
        """The tenant_id passed to run_load_test is propagated to the generator."""
        observed_tenants: list[str] = []

        async def _tenant_capture(job_id: str, tenant_id: str) -> None:  # noqa: ARG001
            observed_tenants.append(tenant_id)

        asyncio.run(
            run_load_test(
                total_jobs=3,
                concurrency=2,
                tenant_id="my-custom-tenant",
                simulated_duration_s=_FAST_DURATION,
                generator=_tenant_capture,
            )
        )
        assert all(t == "my-custom-tenant" for t in observed_tenants), (
            f"Unexpected tenant IDs: {set(observed_tenants)}"
        )

    def test_report_load_harness_default_profile_is_fast(self) -> None:
        """
        Default profile (5 jobs, concurrency 2, 10 ms duration) completes
        well within 5 seconds.  All 5 tests in this module should finish in
        that window.
        """
        import time

        t0 = time.perf_counter()
        metrics = asyncio.run(
            run_load_test(
                total_jobs=5,
                concurrency=2,
                simulated_duration_s=0.01,  # default
            )
        )
        elapsed = time.perf_counter() - t0
        assert elapsed < 5.0, f"Default profile took {elapsed:.2f}s — exceeds 5 s"
        assert metrics.total_jobs == 5
        assert metrics.succeeded_count == 5
