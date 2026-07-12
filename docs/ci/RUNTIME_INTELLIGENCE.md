# Runtime Intelligence

Advisory CI telemetry package for gate timing, regression detection, and GitHub step summaries.
Introduced in PR-CI-02; integrated into live CI execution in PR-CI-02.1.

## Package location

`tools/testing/runtime_intelligence/`

## Modules

| Module | Purpose |
|--------|---------|
| `models.py` | Frozen dataclasses: `RuntimeResult`, `RuntimeMetadata`, `RollingStats`, `Regression`, `SlowTest`, `SlowFixture` |
| `serializer.py` | Deterministic JSON (`sort_keys=True`, `ensure_ascii=True`) |
| `fingerprints.py` | Stable, secret-free fingerprints: environment, dependency, commit, manifest, selector |
| `statistics.py` | Pure stdlib: `percentile()`, `compute_rolling_stats()` |
| `history.py` | Rolling per-gate history (max 100 runs, schema-version aware) |
| `regression.py` | Severity-driven regression detection (advisory, never fails builds) |
| `profiler.py` | Parse pytest `--durations` output into `SlowTest`/`SlowFixture` with ownership |
| `parser.py` | Parse JUnit XML + duration JSON → complete `RuntimeResult` via `merge_artifacts()` |
| `ownership.py` | Map test paths → (plane, module_id, owner) via `ownership_map.yaml` |
| `recorder.py` | Write `RuntimeResult` JSON artifact to disk |
| `github_summary.py` | GitHub Actions step summary markdown with fixtures and manifest fingerprint |
| `cli.py` | Entry point: auto-detects JUnit, merges sources, records history |

## Runtime pipeline (PR-CI-02.1)

```
pytest --junitxml artifacts/ci/junit/{gate}.xml
      │
      ├─ JUnit XML  ──────────┐
      │   collected            │
      │   passed               ├──► merge_artifacts() ──► RuntimeResult
      │   failed               │         │
      │   node_ids             │         ├── manifest_fingerprint
      │   manifest_fingerprint │         ├── selector_fingerprint
      │                        │         └── ownership (SlowFixture)
      └─ fg_fast_duration.json ┘
          wall-clock duration
```

Every gate emits a complete `RuntimeResult`. No placeholder counts.

## CLI usage

```bash
# Per-gate record targets (called automatically by fg-fast/fg-security/fg-full)
make fg-fast-record       # reads artifacts/ci/junit/fg-fast.xml + fg_fast_duration.json
make fg-security-record   # reads artifacts/ci/junit/fg-security.xml
make fg-full-record       # reads artifacts/ci/junit/fg-full.xml

# Compat alias (fg-fast)
make runtime-record

# Dry-run: parse and print summary without writing
make runtime-summary

# Direct invocation with auto-detection
.venv/bin/python tools/testing/runtime_intelligence/cli.py \
    --gate fg-fast \
    --artifact-dir artifacts/ci/runtime \
    --history-dir artifacts/ci/runtime/history

# Explicit JUnit path + selector fingerprint
.venv/bin/python tools/testing/runtime_intelligence/cli.py \
    --gate fg-security \
    --junit artifacts/ci/junit/fg-security.xml \
    --selector 'tests/security -m "not slow"'
```

## Artifact merge strategy

| Source | Provides | Priority |
|--------|----------|----------|
| JUnit XML | collected, passed, failed, skipped, node_ids, manifest_fingerprint, slowest_tests | **Primary** |
| `fg_fast_duration.json` | wall-clock duration | **Override** for duration_seconds |
| History baseline | baseline_collected for regression detection | Supporting |

## Failure behaviour (advisory — never fails CI)

| Condition | Behaviour |
|-----------|-----------|
| Missing JUnit | Print warning to stderr, fall back to duration-only |
| Malformed XML | Print warning to stderr, fall back to duration-only |
| Missing profiler | Empty `slowest_fixtures`, continue |
| Missing ownership map | Empty `plane`/`module`/`owner` on fixtures, continue |
| Both sources missing | Print advisory to stderr, exit 0 |

## Design principles

- **Advisory only**: all errors exit 0; telemetry never blocks builds
- **No secrets**: fingerprints never include env vars, tokens, or DB URLs
- **No external dependencies**: stdlib only (except optional `pyyaml` for ownership)
- **Deterministic output**: `sort_keys=True`, stable hash inputs, `PYTHONHASHSEED=0`
- **Complete RuntimeResult**: collected = actual tests run, never 0 when tests executed
