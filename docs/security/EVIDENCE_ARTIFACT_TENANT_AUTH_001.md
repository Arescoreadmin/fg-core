# EVIDENCE-ARTIFACT-TENANT-AUTH-001: tenant ownership for evidence artifacts

Baseline: `main` `7acd62cb` (#870 merged), with 93 open CodeQL alerts and 0 dismissed. This is not a CodeQL finding. CodeQL #100–#105 were path-injection alerts, and they are fixed. This work closes the authorization gap their fix left: **filesystem containment is not tenant authorization.**

## Affected endpoints

| Route | Scope | Accepts `artifact_path` | Reads or hashes the file | Persists |
|---|---|---|---|---|
| `POST /evidence/anchors` | `compliance:read` | yes (body) | SHA-256, returned to the caller | `evidence_anchor_records` row and anchor receipt file in the caller's tenant |
| `POST /evidence/runs/register` | `admin:write` | yes (body) | SHA-256, returned to the caller | `evidence_runs` row in the caller's tenant |

These are the only places that turn a caller path into a read, hash, registration or ownership claim. They are also the only users of `services/artifact_paths.py`. Internally, `scripts/generate_ai_plane_evidence.py` calls `EvidenceIndexService.register_run` directly. No console or UI code calls either route.

## Root cause and verified exploit (unmodified `main` `7acd62cb`, synthetic data)

`FG_ARTIFACTS_DIR` is shared by every tenant. It holds:
- `decision_evidence/<sequential decision id>.json` for all tenants;
- `anchor_receipts/`;
- by default, `audit_exports/` and `audit_packets/`;
- platform files such as `ai_plane_evidence.json`.

Both routes checked only that the path resolved inside that root. Tenant A created decision evidence through the real producer, `emit_decision_evidence`. Then tenant B, with its own key:

| Scenario | Result on `main` |
|---|---|
| B anchors A's evidence | **200, A's SHA-256 returned, and an anchor record stored in tenant B** |
| B registers A's evidence | **200, A's SHA-256 returned, and an evidence run stored in tenant B** |
| B walks `decision_evidence/1..5.json` | 200 with a hash for each id that exists, 404 for the rest: **ids are enumerable** |
| Foreign vs absent vs unowned in-root file | Four different responses. The 404 echoed the requested path in `reason`. |
| B anchors an in-root symlink to A's file | 200, A's hash |
| B registers or anchors `ai_plane_evidence.json` | 200: **B claims platform evidence as its own** |
| B sets `X-Tenant-Id: tenant-a` | Rejected by `require_bound_tenant` (an existing control, which held) |
| A anchors its own evidence after the file was altered | 200 with the new hash: the record and the file disagree silently |
| Path outside the root | 400 (#869 containment, which held) |

Information exposed: whether other tenants' artifacts exist, how many decisions they have, and the fingerprints of their artifacts. The routes also created unauthorized records: anchors and runs in tenant B claiming provenance over tenant A's or the platform's evidence. File contents were never returned. Neither route writes a security audit event, so nothing was logged.

## Canonical ownership authority

| Existing record | Binds tenant ↔ artifact path? | Records the fingerprint? | Used here |
|---|---|---|---|
| `decision_evidence_artifacts` (`DecisionEvidenceArtifact`, written by `emit_decision_evidence` from `/defend`, ingest and dev events) | **Yes**: `tenant_id` and `storage_path` (resolved at write time) | **Yes**: `evidence_sha256` of the exact bytes written | **Yes** |
| `evidence_anchor_records`, `evidence_runs` | Records a tenant's *claim*. These are the outputs being protected, not an owner authority. | n/a | No: it would be circular |
| Audit exports (`FG_AUDIT_EXPORT_DIR`) | No record; only a digest-named tenant directory | Manifest only | No: a filename is not authority |
| Billing, field-assessment, audit-packet files | Their own feature tables | varies | Not wired up (see compatibility) |

`decision_evidence_artifacts` is the producer's own authoritative record. Postgres also enforces RLS on it (`migrations/postgres/0003_tenant_rls.sql`), so it is reused as is. **No new table, no migration, and no second registry.**

## Authorization design (`services/artifact_paths.py`)

1. **Containment** (unchanged from #869): realpath, then strictly inside `realpath(FG_ARTIFACTS_DIR)`. Otherwise 400 `EVIDENCE_ARTIFACT_PATH_INVALID`, decided from the string alone.
2. **Ownership**, `authorize_tenant_artifact(db, tenant_id, raw)`:
   - The tenant comes from the bound credential (`require_bound_tenant`), never the request body.
   - The resolved path must equal a `decision_evidence_artifacts.storage_path` whose `tenant_id` is the caller's.
   - This lookup happens **before the file is opened**.
3. **Integrity**, `hash_authorized_artifact`:
   - The file is hashed in chunks and must equal the recorded `evidence_sha256`. Otherwise 409 `EVIDENCE_ARTIFACT_INTEGRITY_MISMATCH`.
   - So an anchor always carries the fingerprint the producer recorded, even if the file is swapped between check and read.
   - An owned but deleted file is treated like an unknown one.
4. **One refusal**: foreign, unknown, unowned, owner-record-deleted and missing files all return the same 404:
   - anchors: `evidence_anchor_artifact_not_found`, the existing code, now without the `reason` path echo;
   - runs: `EVIDENCE_ARTIFACT_NOT_FOUND`.
   - None of them reads a file or logs a path or hash.
5. **Provenance**:
   - Anchor and run rows now store the **canonical resolved path** of the authorized artifact.
   - Responses add `artifact_ref`, for example `decision_evidence:42`, naming the owner record.
   - Tenant scoping, anchor receipts (schema unchanged) and listing are unchanged.

### Shared platform artifacts

`PLATFORM_ARTIFACT_GRANTS` is a code-defined map. Each grant is keyed by the artifact's path relative to the root, and records:
- the owning platform authority;
- the `plane_id`/`artifact_type` it may be registered as;
- the permitted operations.

Today there is one grant: `ai_plane_evidence.json`, owned by `services.ai_plane_extension`, operation `register_run`.

- **Only an internal caller can present a grant**, through the `platform_authority=` argument of `EvidenceIndexService.register_run`. The HTTP route never passes it, so a tenant cannot self-declare an artifact shared.
- Anchoring a platform artifact has no grant, so it is refused.
- A wrong owner, wrong type, wrong plane, or a removed grant is refused.
- Adding or revoking a grant is a reviewed code change. There is no runtime revocation switch; that would be a new operational dependency, and it isn't needed for the one grant that exists.
- The platform producer keeps its degraded-safe behaviour: a not-yet-written platform artifact is recorded as `"missing"`.

## Threat model

| Threat | Control |
|---|---|
| Foreign artifact hash or registration | Owner lookup by bound tenant before any read |
| Enumeration and existence oracle | One 404 for every non-owned case; no read before authorization |
| Caller tenant override | `require_bound_tenant` (existing); ownership uses only the bound tenant |
| Traversal, absolute paths, symlinks out of root | Containment (existing) |
| In-root symlink to a foreign artifact | Realpath before lookup, so it resolves to the foreign path and the lookup fails |
| File swapped or mutated after creation, or a TOCTOU swap | Fingerprint must equal the recorded `evidence_sha256` |
| Tenant claims platform evidence | Grants only through the internal argument, never over HTTP |
| Path or hash leakage in errors or logs | Fixed error bodies; no logging on denial (tested) |
| Concurrent or duplicate anchors | Anchors are append-only per tenant and owner-checked. Duplicates by the owner are allowed, as before. |

## Compatibility

- **Owned decision evidence**: anchors and registers as before.
- **Arbitrary in-root files and other features' artifacts** are now refused, because no owner record covers them. That includes audit exports, billing evidence, field-assessment files, audit packets and stray files. No in-repo caller relies on this. An adapter per producer, using that producer's own owner table, is the way to add one; a path rule is not.
- **Registering an unwritten tenant artifact** now returns 404 instead of storing `"missing"`. That is a contract change, and the tests are updated to match.
- **AI-plane evidence generator**: unchanged behaviour, through the platform grant.
- **Historical anchor and run rows and anchor receipts**: unchanged; there is no migration. Rows created before this change may reference artifacts their tenant did not own. They cannot be told apart reliably after the fact, so they stay as recorded (reconciliation below).
- **Decision evidence created under a different `FG_ARTIFACTS_DIR`**: its stored path is outside the current root, so it is refused (400), as with #869.

### Reconciling historical records (operator)

Run this read-only query on Postgres to list anchors whose path has no owner record in the same tenant:

```sql
SELECT a.id, a.tenant_id, a.anchored_at_utc FROM evidence_anchor_records a
LEFT JOIN decision_evidence_artifacts d
  ON d.storage_path = a.artifact_path AND d.tenant_id = a.tenant_id
WHERE d.id IS NULL;
```

Use the same query on `evidence_runs`. Rows returned are **unprovable**: treat them as quarantined and do not use them as provenance. Records are append-only by design, so do not delete them. Record the review in the SOC log.

## Remaining risks

- A tenant that owns an artifact can still anchor it repeatedly. That is by design.
- Platform grants are trusted by code review. Any core-API code could pass `platform_authority`.
- Other artifact families are not anchorable until they get owner adapters.
- `evidence_runs` accepts any `plane_id`/`artifact_type` label for a tenant's own decision evidence, as before.

## Rollback

Revert the PR. The routes accept any in-root file again, and the new tests fail. There is no schema or data change to undo.
