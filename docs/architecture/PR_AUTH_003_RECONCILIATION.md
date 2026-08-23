# PR-AUTH-003C — Identity Backfill Reconciliation & Closure Proof

**Phase:** 3 of 3 in the AUTH-003 identity backfill sequence
**Status:** ships with PR-AUTH-003C
**Depends on:** PR-AUTH-001 (#650), PR-AUTH-002 (#652), PR-AUTH-003A (#653), PR-AUTH-003B (#654)
**Normative source:** `docs/architecture/IDENTITY_AUTHORITY_DATA_MODEL.md`

---

## What each phase does

| PR | File | Effect |
|---|---|---|
| AUTH-001 | `migrations/postgres/0179_fg_principals.sql`, `0180_fg_external_identities.sql`, `api/db_models_principal.py` | Creates the canonical cross-tenant identity tables. Zero rows written. |
| AUTH-002 | `migrations/postgres/0181_tenant_users_principal_id.sql` | Adds `tenant_users.principal_id UUID NULL REFERENCES fg_principals(id)`. Zero rows changed. |
| AUTH-003A | `api/identity_backfill_preflight.py` | Reads legacy `tenant_users`, classifies every row, groups READY rows by canonical triple. Zero writes. Guard: BYPASSRLS/superuser connection required (RLS on `tenant_users` from migration 0099 otherwise silently omits blocking rows). |
| AUTH-003B | `api/identity_backfill_writer.py` | For each `PrincipalGroup`: INSERT `fg_principals`, INSERT `fg_external_identities`, UPDATE `tenant_users.principal_id`. Refuses to run if preflight is not `ready_for_backfill`. Idempotent. |
| **AUTH-003C** | `api/identity_backfill_reconciliation.py` | Zero-write reconciliation. Emits 13-category classification, deterministic fingerprint, and `migration_closed` boolean. |

---

## What `migration_closed` means

`ReconciliationReport.migration_closed` is `True` iff **all** of the following hold:

1. Every `tenant_users` row that would have been READY under AUTH-003A has a
   populated `principal_id`.
2. Every populated `tenant_users.principal_id` matches an
   `fg_external_identities` row that resolves to the same principal.
3. `fg_external_identities` holds exactly one row per canonical triple.
4. No canonical triple is split across multiple principals in `tenant_users`.
5. No principal or external identity is orphaned.
6. Every `fg_principals.lifecycle_state` matches the derived value
   (`any(active)` → `active`, else `suspended`) from its linked
   `tenant_users` rows.
7. Every `fg_principals.primary_email` matches the AUTH-003B source
   attribution rule (email of the first-sorted linked `tenant_users` row).
8. A dry-run of AUTH-003B against the current DB reports zero writes required.

If any of these fail, the corresponding blocking category increments and
`migration_closed` is `False`.

### What `migration_closed` does NOT mean

- It does **not** cut over the runtime auth path. The auth code still reads
  `tenant_users.identity_*` columns; a separate AUTH cutover PR moves auth to
  `principal_id`.
- It does **not** drop legacy columns. `tenant_users.identity_*` and
  `uq_tenant_users_bound_identity` remain as shadow authorities pending
  post-cutover cleanup.
- It does **not** add any constraints. See below.

---

## Why there is no migration 0182

`tenant_users.principal_id` remains **nullable** after AUTH-003C. This is
intentional and load-bearing:

- **UNBOUND memberships legitimately have NULL `principal_id`.** Rows with
  `identity_binding_status != 'bound'` are not migration targets. They exist
  as pending invitations, deactivated memberships, or portal-adjacent records
  whose canonical principal has not yet been established.
- A global `NOT NULL` constraint would violate the UNBOUND lifecycle by
  requiring every membership to point at a principal — which is a category
  error for the AUTH model established in `IDENTITY_AUTHORITY_DATA_MODEL.md`.
- A partial constraint (`NOT NULL WHERE identity_binding_status = 'bound'`)
  is possible but belongs to a **separate hardening PR** (HARD-001). AUTH-003C
  proves the closure with the current schema; the constraint is a downstream
  hardening step.

**Rule for downstream PRs:** any PR that flips `principal_id` to `NOT NULL`
(global or partial) must be titled `HARD-*` (constraint hardening), must have
its own preflight for existing UNBOUND rows, and must be reviewed against this
document.

---

## Legacy mutation detection is best-effort

The reconciliation compares each MIGRATED_CONSISTENT row's current
`(identity_provider, identity_issuer, identity_subject)` against the
matching `fg_external_identities.(provider, provider_issuer, provider_subject)`.
Divergence → `LEGACY_MUTATION_DETECTED`.

**Limitation:** this only detects mutations that happened **after AUTH-003B ran**.
The migration snapshot is not preserved in the schema, so pre-migration
changes are indistinguishable from correct migration.

If pre-migration snapshot proof becomes a requirement, a future migration
would need to add a `principal_backfill_source_snapshot` table (out of scope
for AUTH-003C).

---

## Read-only guarantee

Reconciliation is provably zero-write:

- No `INSERT`, `UPDATE`, or `DELETE` statements in
  `api/identity_backfill_reconciliation.py`.
- The `run_backfill(conn, dry_run=True)` call is delegated; AUTH-003B's dry-run
  path is already covered by its own tests (Group C in
  `test_pr_auth_003b_principal_backfill_writer.py`).
- Tests J1–J4 in `test_pr_auth_003c_identity_reconciliation.py` verify
  `tenant_users`, `fg_principals`, `fg_external_identities`, and `principal_id`
  values are unchanged before/after reconciliation.
- Test group M verifies the module does not import auth, session, or RBAC
  modules — reconciliation cannot affect the runtime auth path.

---

## Production proof procedure

For each production environment:

1. **Connect with elevated credentials.** The reconciliation inherits AUTH-003A's
   BYPASSRLS/superuser guard.
   ```bash
   export FG_DB_MIGRATION_URL="postgresql://postgres:...@host/railway"
   ```
2. **Run the reconciliation tool.**
   ```bash
   python tools/identity/pr_auth_003_reconcile.py \
     --json-out artifacts/auth003c/<env>-<UTC-timestamp>.json
   ```
3. **Assert the exit code is 0** (`migration_closed=True`).
4. **Assert the fingerprint is stable** — rerun immediately, confirm identical
   fingerprint.
5. **Attach the JSON evidence artifact** to the migration closure record for
   this environment.
6. **If exit code is non-zero:** inspect `findings` in the JSON output; each
   entry carries a blocking classification, a sanitized `canonical_key_hash`
   (never the raw subject), and a human-readable reason. Resolve each blocking
   finding, rerun preflight → writer → reconciliation.

Do NOT declare AUTH cutover green without a `migration_closed=True`
fingerprint from each environment (dev → staging → production).

---

## What comes after AUTH-003C

1. **HARD-001** (separate PR) — optionally add a partial `NOT NULL` constraint
   scoped to `identity_binding_status = 'bound'` rows via a `CHECK` constraint
   or triggered validation. Requires its own preflight to prove zero violating
   rows.
2. **AUTH cutover** (separate PR) — auth path stops reading
   `tenant_users.identity_*` and starts reading `principal_id` →
   `fg_external_identities` → `fg_principals`. This PR is where session
   issuance changes and where legacy columns become truly shadow.
3. **Legacy column removal** (separate PR) — drop
   `tenant_users.identity_provider`, `identity_issuer`, `identity_subject`,
   `identity_binding_status`, `identity_email`, `identity_type` and the
   `uq_tenant_users_bound_identity` partial index. Only after AUTH cutover has
   been proven in production.

Each of these steps is a distinct, independently reviewable PR.
