# Test Classification Report

Generated: 2026-07-10

## Total Test Suite

- **20,219 tests** collected (pytest collects tests/, backend/tests/)

## By Marker

| Marker | Count | % of Total | Used By |
|--------|-------|-----------|---------|
| `smoke` | 236 | 1.2% | fg-fast-pytest |
| `contract` | 145 | 0.7% | fg-fast-pytest |
| `security` | 17 | 0.1% | fg-fast-pytest |
| `smoke or contract or security` | 398 | 2.0% | fg-fast-pytest (combined) |
| `integration` | 12 | 0.1% | excluded from fast lanes |
| `slow` | 0 | — | excluded from fg-security-pytest |
| `postgres` | 0 | — | postgres-only |
| **unmarked** | 19,809 | 97.98% | fg-full-pytest only |

## Lane Test Selection

### fg-fast-pytest
- Filter: `-m "smoke or contract or security"`
- Count: **398 tests**
- Hard max: 930s; nominal max: 900s
- Baseline guard: `_FG_FAST_BASELINE_COUNT = 398` in `tests/tools/test_fg_fast_budget_and_triage.py`

### fg-security-pytest
- Path: `tests/security/ -m "not slow"`
- Estimated count: ~701 tests
- Estimated duration: ~21 min in CI
- Note: Only 17 tests in this directory carry `@pytest.mark.security`. The selection is path-based, not marker-based.

### fg-full-pytest
- Filter: none — all tests
- Count: **20,219 tests**
- Estimated duration: 35+ min in CI

## Cross-Lane Overlap

### tests/security/ covered by multiple lanes

The `tests/security/` directory runs in:
1. `fg-security-pytest` (via `make fg-security` in fg-security job, fg-required fg-security lane, lane_runner fg-fast)
2. `ci.yml hardening` job: `pytest tests/security -q` (same 701 tests — full duplicate)
3. `fg-full-pytest` (all tests, superset)

**Action:** `ci.yml` hardening job's `pytest tests/security -q` is redundant when the dedicated `fg-security` job runs. Consider removing or conditioning it.

## Tests Implying Security by Name but Missing Marker

The `tests/security/` directory has ~701 tests but only 17 carry `@pytest.mark.security`.
The remaining ~684 tests in `tests/security/` are security tests by location but not by marker.

**Impact on fg-fast-pytest:** `-m security` only picks up 17 tests. The 684 unmarked security tests are NOT included in fg-fast-pytest.

**Impact on fg-security-pytest:** The path filter `tests/security/` correctly catches all 701 tests regardless of marker.

**Recommendation:** This is not a defect — the current design intentionally separates the "fast 398" from the "full security 701". Adding `@pytest.mark.security` to all tests/security/ would include them in fg-fast-pytest, which would break the 930s budget. The current split is correct.

## Parallelization Safety Assessment

Security tests use:
- `monkeypatch.setenv` — per-test scope, reverted by root conftest `_restore_env` autouse fixture. Parallel-SAFE.
- `FG_SQLITE_PATH` via `monkeypatch.setenv` pointing to `tmp_path` per-test dirs. Parallel-SAFE (unique paths).
- Global default: `FG_SQLITE_PATH=/tmp/frostgate/fg-conftest.db` — shared across workers. Parallel-UNSAFE if DB is mutable.
- FastAPI TestClient — in-process, parallel-SAFE.

**Conclusion:** Security tests are mostly parallel-safe, but the shared default SQLite path `/tmp/frostgate/fg-conftest.db` requires each worker to use a unique path. With `pytest-xdist`, tests using `tmp_path` fixtures are safe; tests that don't override `FG_SQLITE_PATH` would share the global DB.

## Machine-readable data

See `artifacts/ci/test_classification.json` and `artifacts/ci/test_lane_overlap.json`
