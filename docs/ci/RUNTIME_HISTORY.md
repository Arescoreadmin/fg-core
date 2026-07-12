# Runtime History

Per-gate rolling history of CI run durations and test counts.

## Storage location

`artifacts/ci/runtime/history/<gate>-history.json`

Example: `artifacts/ci/runtime/history/fg-fast-history.json`

## Schema (v1.0) — updated PR-CI-02.1

```json
{
  "schema_version": "1.0",
  "gate": "fg-fast",
  "runs": [
    {
      "duration_seconds": 450.0,
      "passed": 396,
      "failed": 0,
      "collected": 398,
      "skipped": 2,
      "commit_sha": "abc123def456",
      "gate": "fg-fast",
      "manifest_fingerprint": "4ab8d2cf1a3b5e70",
      "selector_fingerprint": "e7f3a1b2c4d5e6f7"
    }
  ]
}
```

`manifest_fingerprint` enables cross-run comparability: two runs with the same fingerprint
ran against the same test suite. Runs with different fingerprints should not be regressed
against each other (test suite changed).

`selector_fingerprint` identifies which pytest expression was used. Two runs with different
selector fingerprints are not directly comparable.

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
