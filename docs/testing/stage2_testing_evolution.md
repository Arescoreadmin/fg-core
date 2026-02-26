# Stage 2 Testing Evolution — Test Intelligence + Control Tower

## A) File tree + module boundaries

- `tools/testing/harness/triage_taxonomy.py`: authoritative failure category enum.
- `tools/testing/harness/triage_report.py`: deterministic triage v2 generation.
- `tools/testing/harness/flake_detect.py`: flake suspect analysis + report writer.
- `tools/testing/harness/runtime_budgets.py`: runtime policy load/enforcement.
- `tools/testing/harness/runtime_baseline.py`: baseline update gate (main-only protected workflows).
- `tools/testing/harness/quarantine_policy.py`: execution-time quarantine enforcement helpers.
- `services/testing_control_tower_store.py`: DB-backed run metadata persistence service.
- `tools/testing/security/check_invariant_coverage.py`: invariant coverage guard.
- `tools/testing/policy/flaky_tests.yaml`: quarantine policy.
- `tools/testing/policy/runtime_budgets.yaml`: PR runtime budget policy.
- `tools/testing/policy/invariants.yaml`: invariant registry.
- `tools/testing/policy/path_to_invariants.yaml`: protected-path-to-invariant mapping.
- `schemas/testing/*.schema.json`: Control Tower API contracts.
- `migrations/20260226_stage2_testing_control_tower.sql`: persisted run metadata schema + RLS.
- `tests/tools/test_triage_v2.py`: taxonomy mapping, confidence, determinism.
- `tests/tools/test_flake_detection.py`: flake oscillation behavior.
- `tests/tools/test_quarantine_policy.py`: quarantine schema enforcement.
- `tests/tools/test_runtime_budgets.py`: budget hard-fail semantics.
- `tests/tools/test_invariant_registry.py`: critical invariant/path mapping failures.

## B) Control Tower API contracts

### `POST /control/testing/runs/register` (internal)
- Requires `control-plane:admin` + `x-fg-internal-token`.
- Persists run summary + artifact hashes through `services/testing_control_tower_store.py`.

### `GET /control/testing/runs?limit=50`
- Response schema: `schemas/testing/control_tower_run_list_response.schema.json`

### `GET /control/testing/runs/{run_id}`
- Response schema: `schemas/testing/control_tower_run.schema.json`

### `GET /control/testing/runs/{run_id}`
- Tenant-bound read; returns 404 if run is outside tenant scope.

### `GET /control/testing/runs/{run_id}/artifacts`
- Response body includes `artifact_hashes` + `artifact_paths` from run schema.

## C) DB schema + migration

See `migrations/20260226_stage2_testing_control_tower.sql`:
- `testing_runs`: canonical run metadata; no raw logs.
- `testing_run_artifacts`: metadata-only artifact catalog (path/hash/type/size).
- `testing_flake_registry`: flake quarantine/trend registry.
- `testing_invariant_registry`: invariant ownership and enforcement mapping.
- Indexes:
  - `(tenant_id, started_at DESC)` for run listing.
  - `(lane, status)` for dashboard filters.
  - `(tenant_id, run_id)` for artifact listing.
- RLS policies: tenant bound by `current_setting('app.tenant_id', true)` on all tables.

## D) Implementation details (code-level)

### Triage V2
- `tools/testing/harness/triage_report.py::_classify(lines, lane)`:
  - deterministic first-match taxonomy rule application.
  - produces category/confidence/evidence/suggested_fix fields.
  - computes `stable_hash` over sorted JSON payload.
  - defaults to `UNKNOWN` with confidence `0.0` only when no pattern matches.

### Flake detect + quarantine
- `tools/testing/harness/flake_detect.py::detect_flakes(nodeids, outcomes)`:
  - flags oscillating pass/fail series only.
- `tools/testing/harness/flake_detect.py::build_report(...)`:
  - emits deterministic `flake-report.json` structure.

### Runtime budgets
- `tools/testing/harness/runtime_budgets.py::enforce_lane_budget(...)`:
  - fails when lane runtime exceeds `max_seconds`.
  - fails when runtime exceeds baseline by `fail_pct`.

### Invariant registry
- `tools/testing/security/check_invariant_coverage.py::validate_critical_coverage(...)`:
  - hard-fail if critical invariant has no tests.
- `validate_path_mapping(...)`:
  - hard-fail if protected changed path lacks invariant mapping.

## E) CI workflow / make targets changes required

- Add nightly lane in workflow:
  - `fg-full`
  - `fg-flake-detect`
  - migration replay/rollback
  - evidence replay verification
  - vulnerability scan (critical fail)
- Add required PR jobs:
  - runtime budget check (`tools/testing/harness/runtime_budgets.py`)
  - invariant coverage check (`tools/testing/security/check_invariant_coverage.py`)
  - triage artifact generation per lane with hard-fail if missing
- Publish deterministic artifacts under `artifacts/testing/`:
  - `{lane}.log`
  - `{lane}.metadata.json`
  - `triage/{lane}.json`
  - `flake-report.json`

## F) Tests added

- `tests/tools/test_triage_v2.py`
  - each taxonomy category fixture maps correctly with confidence >= 0.8.
  - output deterministic and excerpt limited to <= 30 lines.
  - `UNKNOWN` only for unmatched signatures.
- `tests/tools/test_flake_detection.py`
  - oscillation -> flake-suspected.
  - consistent failures are not marked flake.
- `tests/tools/test_quarantine_policy.py`
  - quarantine YAML loads and includes SLA metadata.
- `tests/tools/test_runtime_budgets.py`
  - over-max runtime fails.
  - fail_pct regression fails.
- `tests/tools/test_invariant_registry.py`
  - critical invariant missing test coverage fails.
  - protected path without mapping fails.

## G) Acceptance criteria

- Triage V2 outputs one of authoritative enum categories with deterministic `stable_hash` and actionable fix hints.
- Unknown failures are categorized as `UNKNOWN` only when no known pattern matches.
- Flake report always contains suspected/new/quarantined counts and deterministic ordering.
- PR lane runtime hard-fails above policy budget and on fail_pct regression.
- Critical invariants cannot exist without enforcing tests.
- Protected-area changes cannot pass without path-to-invariant mapping coverage.
- Testing run metadata tables are tenant-isolated by RLS policies.


## Additional hardening shipped
- Quarantine enforcement is execution-time via `PYTEST_ADDOPTS --deselect` injection in both `fg_required.py` and `lane_runner.py` for required lanes.
- Runtime baseline updates are blocked off-main/non-protected events by `runtime_baseline.py`.
- Invariant guard now checks changed API route modules (`APIRouter(prefix=...)`) are mapped in `path_to_invariants.yaml`.
- Triage includes `triage_schema_version: "2.0"` for backward-compatible UI parsing.
