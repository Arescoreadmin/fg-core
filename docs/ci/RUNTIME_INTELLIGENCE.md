# Runtime Intelligence

Advisory CI telemetry package for gate timing, regression detection, and GitHub step summaries.

## Package location

`tools/testing/runtime_intelligence/`

## Modules

| Module | Purpose |
|--------|---------|
| `models.py` | Frozen dataclasses: `RuntimeResult`, `RuntimeMetadata`, `RollingStats`, `Regression`, `SlowTest`, `SlowFixture` |
| `serializer.py` | Deterministic JSON (`sort_keys=True`, `ensure_ascii=True`) |
| `fingerprints.py` | Stable, secret-free environment/dependency/commit fingerprints |
| `statistics.py` | Pure stdlib: `percentile()`, `compute_rolling_stats()` |
| `history.py` | Rolling per-gate history (max 100 runs, schema-version aware) |
| `regression.py` | Severity-driven regression detection (advisory, never fails builds) |
| `profiler.py` | Parse pytest `--durations` output into `SlowTest`/`SlowFixture` |
| `parser.py` | Parse `fg_fast_duration.json` and JUnit XML into `RuntimeResult` |
| `recorder.py` | Write `RuntimeResult` JSON artifact to disk |
| `github_summary.py` | GitHub Actions step summary markdown (no PII) |
| `cli.py` | Entry point: `tools/testing/runtime_intelligence/cli.py` |

## CLI usage

```bash
# Record fg-fast result and update history (advisory — never fails build)
make runtime-record

# Dry-run: parse and print summary without writing
make runtime-summary

# Direct invocation
.venv/bin/python tools/testing/runtime_intelligence/cli.py \
    --gate fg-fast \
    --artifact-dir artifacts/ci/runtime \
    --history-dir artifacts/ci/runtime/history

# Parse JUnit XML
.venv/bin/python tools/testing/runtime_intelligence/cli.py \
    --gate fg-security \
    --junit artifacts/ci/junit-security.xml

# Dry-run with GitHub step summary
.venv/bin/python tools/testing/runtime_intelligence/cli.py \
    --gate fg-fast \
    --dry-run \
    --github-summary
```

## Design principles

- Advisory only: all errors are non-fatal (exit 0)
- No secrets: fingerprints never include env vars, tokens, or DB URLs
- No external dependencies: stdlib only (except dataclasses)
- Deterministic output: `sort_keys=True`, stable hash inputs
