# FrostGate Spine Invariants

These invariants are non-negotiable requirements that must hold before new
modules are added. Each invariant lists its enforcement mechanism and the
command to validate it.

## INV-001 — Spine Module Loading (Fail-Closed)
- **Description:** When a spine module is enabled, the import must succeed;
  missing modules are a hard failure in production.
- **Enforcement:** Startup validation + spine module verification script.
- **Command:** `make verify-spine-modules` and `pytest tests/test_spine_module_loading.py -q`

## INV-002 — API Contract Authority
- **Description:** The committed OpenAPI contract is authoritative; generated
  OpenAPI must match exactly.
- **Enforcement:** Contract diff gate in CI.
- **Command:** `make contracts-core-diff`

## INV-003 — Schema Registry Completeness
- **Description:** All API/event/artifact schemas must live in the registry and
  declare a valid version.
- **Enforcement:** Schema registry verifier.
- **Command:** `make verify-schemas`

## INV-004 — Drift Detection Gate
- **Description:** API contract drift, schema/code reference drift, and version
  mismatches must fail CI.
- **Enforcement:** Drift verifier in `fg-fast`.
- **Command:** `make verify-drift`

## INV-005 — Policy Enforcement (OPA Fail-Closed)
- **Description:** When enforcement is enabled, OPA failures deny requests and
  production cannot disable enforcement without explicit risk acceptance.
- **Enforcement:** Startup validation + pipeline enforcement logic.
- **Command:** `FG_ENV=prod FG_OPA_ENFORCE=1 FG_OPA_URL=http://localhost:8181 python -c "from api.config.startup_validation import validate_startup_config; r=validate_startup_config(fail_on_error=True, log_results=False); assert not r.has_errors"`

## INV-006 — Tenant Isolation (DB)
- **Description:** Postgres RLS policies and tenant isolation must be enforced.
- **Enforcement:** Migration assertions gate.
- **Command:** `make db-postgres-assert`

## INV-007 — Migration Discipline (Postgres)
- **Description:** Postgres must run migrations; schema_migrations must match
  committed migration set.
- **Enforcement:** Migration assert in core DB init + CI db-postgres-verify.
- **Command:** `make db-postgres-verify`

## INV-008 — Evidence Append-Only
- **Description:** Evidence tables are append-only and enforce immutability.
- **Enforcement:** Migration assertions for append-only triggers.
- **Command:** `make db-postgres-assert`

## INV-009 — Evidence Hash Chain Integrity
- **Description:** Decision evidence must remain tamper-evident via hash chain.
- **Enforcement:** Evidence chain verification and anchor tests.
- **Command:** `pytest tests/test_merkle_anchor.py -q`

## INV-010 — Event/Artifact Schema Versioning
- **Description:** Schema versions in code must match registry schema versions.
- **Enforcement:** Drift verification.
- **Command:** `make verify-drift`
