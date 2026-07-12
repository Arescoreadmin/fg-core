# Runtime Artifacts

All artifacts emitted by the runtime intelligence package.

## Artifact index

| Artifact | Path | Format | Gate |
|----------|------|--------|------|
| Gate result | `artifacts/ci/runtime/<gate>.json` | JSON (RuntimeResult) | any |
| fg-fast result | `artifacts/ci/runtime/fg-fast.json` | JSON (RuntimeResult) | fg-fast |
| fg-security result | `artifacts/ci/runtime/fg-security.json` | JSON (RuntimeResult) | fg-security |
| fg-contract result | `artifacts/ci/runtime/fg-contract.json` | JSON (RuntimeResult) | fg-contract |
| fg-full result | `artifacts/ci/runtime/fg-full.json` | JSON (RuntimeResult) | fg-full |
| History file | `artifacts/ci/runtime/history/<gate>-history.json` | JSON (RuntimeHistory) | per-gate |
| fg-fast budget | `artifacts/ci/fg_fast_duration.json` | JSON (legacy) | fg-fast (existing) |

## Gate result format

```json
{
  "collected": 398,
  "duration_seconds": 312.4,
  "failed": 0,
  "meta": {
    "commit_sha": "abc123def456789...",
    "completed_at": "2026-01-01T00:05:00Z",
    "dependency_fingerprint": "aabb1122ccdd3344",
    "duration_seconds": 312.4,
    "environment_fingerprint": "1122aabb3344ccdd",
    "gate": "fg-fast",
    "job": "local",
    "python_version": "3.12.3",
    "runner_os": "local",
    "schema_version": "1.0",
    "started_at": "2026-01-01T00:00:00Z",
    "workflow": "local"
  },
  "passed": 396,
  "skipped": 2,
  "slowest_fixtures": [],
  "slowest_tests": [],
  "warnings": 0,
  "xfailed": 0
}
```

## Producing artifacts

```bash
# Via Makefile (advisory, never fails build)
make runtime-record

# Direct
.venv/bin/python tools/testing/runtime_intelligence/cli.py --gate fg-fast
```

## Consuming artifacts

- Regression detection reads the history file
- GitHub step summary reads the gate result
- Future: upload via `actions/upload-artifact` for cross-job availability
