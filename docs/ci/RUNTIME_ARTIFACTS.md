# Runtime Artifacts

All artifacts emitted by the runtime intelligence package. Updated in PR-CI-02.1 to reflect
canonical JUnit XML integration and complete `RuntimeResult` population.

## Artifact index

| Artifact | Path | Format | Written by |
|----------|------|--------|-----------|
| JUnit — fg-fast | `artifacts/ci/junit/fg-fast.xml` | JUnit XML | `fg-fast-pytest` |
| JUnit — fg-security | `artifacts/ci/junit/fg-security.xml` | JUnit XML | `fg-security-pytest` |
| JUnit — fg-full | `artifacts/ci/junit/fg-full.xml` | JUnit XML | `fg-full-pytest` |
| Gate result — fg-fast | `artifacts/ci/runtime/fg-fast.json` | JSON (RuntimeResult) | `fg-fast-record` |
| Gate result — fg-security | `artifacts/ci/runtime/fg-security.json` | JSON (RuntimeResult) | `fg-security-record` |
| Gate result — fg-full | `artifacts/ci/runtime/fg-full.json` | JSON (RuntimeResult) | `fg-full-record` |
| Gate result — fg-contract | `artifacts/ci/runtime/fg-contract.json` | JSON (RuntimeResult) | `fg-contract-record` |
| History | `artifacts/ci/runtime/history/<gate>-history.json` | JSON (RuntimeHistory) | per-gate record |
| fg-fast budget | `artifacts/ci/fg_fast_duration.json` | JSON (legacy) | `fg-fast-pytest` |

## Gate result format (complete)

```json
{
  "collected": 398,
  "duration_seconds": 450.0,
  "failed": 0,
  "manifest_fingerprint": "4ab8d2cf1a3b5e70",
  "selector_fingerprint": "e7f3a1b2c4d5e6f7",
  "meta": {
    "commit_sha": "abc123def456789...",
    "completed_at": "2026-01-01T00:07:30Z",
    "dependency_fingerprint": "aabb1122ccdd3344",
    "duration_seconds": 450.0,
    "environment_fingerprint": "1122aabb3344ccdd",
    "gate": "fg-fast",
    "job": "fg-fast",
    "python_version": "3.12.3",
    "runner_os": "Linux",
    "schema_version": "1.0",
    "started_at": "2026-01-01T00:00:00Z",
    "workflow": "testing-module"
  },
  "passed": 396,
  "skipped": 2,
  "slowest_fixtures": [
    {
      "duration_seconds": 2.7,
      "module": "identity_plane",
      "name": "identity_fixture",
      "owner": "team-identity",
      "plane": "identity"
    }
  ],
  "slowest_tests": [
    {
      "duration_seconds": 8.5,
      "node_id": "tests.foo.test_e",
      "phase": "call"
    }
  ],
  "warnings": 0,
  "xfailed": 0
}
```

## Merge strategy

The CLI merges sources automatically (PR-CI-02.1):

```
JUnit XML (authoritative for counts + manifest)
  + fg_fast_duration.json (authoritative for wall-clock duration)
  → complete RuntimeResult
```

- `manifest_fingerprint`: SHA-256[:16] of sorted node IDs from JUnit. Never empty when `collected > 0`.
- `selector_fingerprint`: SHA-256[:16] of the pytest selector expression (e.g. `-m "smoke or contract or security"`).
- `duration_seconds`: wall-clock time from `fg_fast_duration.json` overrides pytest's internal time.

## Producing artifacts

```bash
make fg-fast-record       # writes artifacts/ci/runtime/fg-fast.json
make fg-security-record   # writes artifacts/ci/runtime/fg-security.json
make fg-full-record       # writes artifacts/ci/runtime/fg-full.json
make runtime-record       # compat alias for fg-fast-record
```

These targets are called automatically at the end of `fg-fast`, `fg-security`, and `fg-full` via `|| true`.

## Consuming artifacts

- Regression detection reads history files
- GitHub step summary renders gate results and fixtures
- Future PR-CI-03: cross-gate comparison via `manifest_fingerprint` and `selector_fingerprint`
