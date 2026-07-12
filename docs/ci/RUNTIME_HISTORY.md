# Runtime History

Per-gate rolling history of CI run durations and test counts.

## Storage location

`artifacts/ci/runtime/history/<gate>-history.json`

Example: `artifacts/ci/runtime/history/fg-fast-history.json`

## Schema (v1.0)

```json
{
  "schema_version": "1.0",
  "gate": "fg-fast",
  "runs": [
    {
      "duration_seconds": 312.4,
      "passed": 396,
      "failed": 0,
      "collected": 398,
      "commit_sha": "abc123def456",
      "gate": "fg-fast"
    }
  ]
}
```

## Rotation policy

- Maximum **100 runs** per gate file (`MAX_HISTORY_RUNS = 100`)
- On append: oldest entries are dropped when count exceeds limit
- Entries are stored in chronological order (newest last)

## Rolling window sizes

| Operation | Window |
|-----------|--------|
| `rolling_stats_for_history()` default | 30 runs |
| Regression baseline | last 30 runs (median) |
| History file max | 100 runs |

## Schema evolution

- `schema_version` field is checked on load
- On mismatch (e.g., `"99.0"` vs `"1.0"`): history is reset to empty
- This is a **forward-only migration** strategy — no backfill
- Bump `HISTORY_SCHEMA_VERSION` in `history.py` when the `runs` entry shape changes

## Artifact notes

- Files are gitignored (`artifacts/` is not committed)
- In CI: artifacts should be uploaded/downloaded between jobs via `actions/upload-artifact`
- History files are human-readable JSON (sorted keys, 2-space indent)
