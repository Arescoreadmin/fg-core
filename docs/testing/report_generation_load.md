# Report Generation Load-Test Harness

## Purpose

Provides a repeatable, deterministic way to measure the report job enqueue
and lifecycle latency under concurrent load.  The harness is self-contained:
it never calls a real LLM, provider, or database.

## What is Measured

| Metric | Description |
|---|---|
| `enqueue_latency_ms` | Wall-clock time from run start until each job was enqueued (min/max/avg/p95) |
| `completion_latency_ms` | Wall-clock time from job start until terminal state (min/max/avg/p95) |
| `total_duration_ms` | End-to-end wall clock time for the entire run |
| `queued_count` | Number of jobs submitted |
| `succeeded_count` | Jobs that completed without error |
| `failed_count` | Jobs that raised a non-timeout exception |
| `timeout_count` | Jobs that raised `asyncio.TimeoutError` |

## Default Safe Command

```bash
PYTHONPATH=. python tools/load/report_generation_load.py
```

Runs 5 jobs at concurrency 2 with a 10 ms simulated duration.
Completes in well under 1 second.

## Optional Heavier Command

```bash
PYTHONPATH=. python tools/load/report_generation_load.py \
  --jobs 100 \
  --concurrency 10 \
  --duration 0.05 \
  --failure-rate 0.1 \
  --artifact /tmp/fg_load_report.json
```

All flags:

| Flag | Default | Description |
|---|---|---|
| `--jobs N` | 5 | Total simulated jobs |
| `--concurrency N` | 2 | Max concurrent jobs |
| `--tenant ID` | `test-tenant-load` | Tenant ID stamped on records |
| `--duration S` | 0.01 | Simulated generation duration (seconds) |
| `--failure-rate F` | 0.0 | Fraction of jobs to fail (0.0–1.0) |
| `--artifact PATH` | none | Write JSON metrics to this file |

## Output Artifact Path

Pass `--artifact <path>` to write a JSON file, for example:

```
artifacts/load/report_generation_YYYYMMDD.json
```

The artifact is not committed to the repository; it is local scratch output.

## How to Interpret Metrics

- **`enqueue_latency_ms` p95 < 1 ms** — healthy; high values indicate event-loop contention during enqueueing.
- **`completion_latency_ms`** — dominated by `simulated_duration_s`; with the default 10 ms setting, p95 should be under 100 ms even at high concurrency.
- **`failed_count > 0`** — non-zero only when `--failure-rate > 0` or a custom generator raises.
- **`timeout_count > 0`** — only when `asyncio.TimeoutError` is raised by the generator.
- **`total_duration_ms`** — for a queue of N jobs at concurrency C and duration D, expect roughly `(N / C) * D * 1000` ms.

## Safety Note

**No real provider calls are made.**  The default generator uses only
`asyncio.sleep`.  This harness is not a replacement for production
observability or integration-level benchmarks; it validates harness
correctness and concurrency behaviour only.
