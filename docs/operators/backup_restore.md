# FrostGate Production Backup and Restore Runbook

## 1. Purpose

This runbook proves and documents the FrostGate production database backup and recovery path.
It must be executed before the design-partner launch (Launch DoD L4) and rehearsed quarterly
thereafter. It provides the only documented path for recovering production data after data loss.

This document closes `FG-LR-003` and is required evidence for `L4`.

## 2. Scope

Covers the FrostGate production PostgreSQL database hosted on Railway (project: `frostgate-core`,
environment: `production`, service: `Postgres`). Does not cover Redis (ephemeral session store —
no recovery required) or Vercel deployments (stateless).

## 3. Safety Rules

1. **Never restore over the production database.** The scratch target must have a separate name,
   separate credentials, and separate connection string from production.
2. **Never point a live production service at the scratch database.**
3. **Never commit credentials, connection strings, passwords, or dump files to git.**
4. **Never copy raw connection strings into any tracked file.** Use placeholders.
5. **Never expose secrets in documentation, terminal captures, logs, or screenshots.**
6. **Destroy the scratch database immediately after all evidence is captured.**
7. **Use read-only production access wherever possible.** `pg_dump` is read-only by nature.

## 4. Prerequisites

| Requirement | Detail |
|-------------|--------|
| Railway role | Admin or member with variable access on `frostgate-core` project |
| Railway CLI | `railway` v5.30.1 or later; authenticated as `admin@arescore.ai` |
| Docker | Docker 29.x or later; pulls `pgvector/pgvector:pg18` and `postgres:18` |
| pg_dump version | Must match server major version (PostgreSQL 18); use `pgvector/pgvector:pg18` image |
| Network | Outbound TCP to `<PROD_PROXY_HOST>:<PROD_PROXY_PORT>` (Railway public proxy) |
| Scratch target | Local Docker container named `frostgate-restore-proof-YYYYMMDD` on port 5433 |
| Evidence storage | `docs/governance/status/L04_evidence_manifest.md` (committed, sanitized) |
| Dump storage | `/tmp/frostgate-restore-proof-YYYYMMDD.dump` (never committed) |

## 5. Railway Plan and Backup Posture

| Item | Value | Source |
|------|-------|--------|
| Railway project | `frostgate-core` | `railway status` |
| Railway plan tier | **hobby** | GraphQL `subscriptionType` field |
| Automatic database backups | **None** | `subscriptionPlanLimit.volumes.maxBackupsCount = 0` |
| Backup mechanism | Manual `pg_dump` via Docker | This runbook |
| Backup frequency | Before each client engagement (see `first_client_prep.md`); quarterly restore drill |
| Backup retention | Operator-controlled; dump file retained in secure off-git storage |
| Restore capability | `pg_restore` (custom-format dump) into isolated scratch PostgreSQL |
| Plan upgrade required | Yes for Railway automatic backups; Pro plan required for `maxBackupsCount > 0` |

**Note:** The Railway Hobby plan (`maxBackupsCount: 0`) provides no automatic database backups.
Manual `pg_dump` before each client engagement is the current production backup strategy.
Upgrading to Railway Pro is required to enable automatic backups (T5/infra decision).

## 6. Recovery Objectives

| Metric | Value | Type |
|--------|-------|------|
| RPO (Recovery Point Objective) | Time since last manual `pg_dump` | Measured (pre-engagement cadence) |
| RTO (Recovery Target Objective) | < 15 minutes for a 1.7 MB database | Measured (4s restore + validation) |
| Restore duration (2026-07-30 drill) | ~4 seconds | Measured |
| Validation duration (2026-07-30 drill) | ~18 seconds | Measured |
| Database size (2026-07-30) | 1.7 MB (compressed custom format) | Measured |

RPO is bounded by the backup cadence. With pre-engagement `pg_dump` only, data added between
the last dump and a failure event is at risk. Upgrading to Railway Pro automatic backups would
provide a verified automated RPO (Railway Pro: backups every 6 hours, 7-day retention).

## 7. Restore Procedure

### 7.1 Phase 0: Record start timestamp

```bash
date -u +"%Y-%m-%dT%H:%M:%SZ"
# Record as DRILL_START
```

### 7.2 Phase 1: Get production credentials (never print to stdout)

```bash
# Get production password — stored only in shell variable, never echoed
PROD_PASS="$(railway variables --service Postgres --json 2>/dev/null \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['PGPASSWORD'])" 2>/dev/null)"

# Write to temp pgpass file (not committed, deleted after use)
printf '%s:%s:%s:%s:%s\n' \
  "<PROD_PROXY_HOST>" "<PROD_PROXY_PORT>" "railway" "postgres" "$PROD_PASS" \
  > /tmp/.fg_pgpass_tmp
chmod 600 /tmp/.fg_pgpass_tmp
```

Replace `<PROD_PROXY_HOST>` and `<PROD_PROXY_PORT>` with values from
`railway variables --service Postgres` (field: `DATABASE_PUBLIC_URL`).
**Do not commit these values.**

### 7.3 Phase 2: Take pg_dump of production

```bash
DUMP_FILE="/tmp/frostgate-restore-proof-$(date +%Y%m%d).dump"

docker run --rm \
  -v /tmp/.fg_pgpass_tmp:/root/.pgpass:ro \
  -v /tmp:/output \
  pgvector/pgvector:pg18 \
  pg_dump \
    --no-password \
    -h <PROD_PROXY_HOST> \
    -p <PROD_PROXY_PORT> \
    -U postgres \
    -d railway \
    --format=custom \
    --no-acl \
    --no-owner \
    -f /output/frostgate-restore-proof-$(date +%Y%m%d).dump

rm -f /tmp/.fg_pgpass_tmp
```

**Required:** Use `pgvector/pgvector:pg18` (not `postgres:16` or earlier). The production
server runs PostgreSQL 18.4; pg_dump must match the server major version.

### 7.4 Phase 3: Create scratch database

```bash
SCRATCH_NAME="frostgate-restore-proof-$(date +%Y%m%d)"
SCRATCH_PASS="scratch-$(openssl rand -hex 8)-not-production"

docker run -d \
  --name "$SCRATCH_NAME" \
  -e POSTGRES_PASSWORD="$SCRATCH_PASS" \
  -e POSTGRES_DB=restore_proof \
  -e POSTGRES_USER=restore_user \
  -p 5433:5432 \
  pgvector/pgvector:pg18

sleep 10
docker ps --filter "name=$SCRATCH_NAME" --format "{{.Status}}"
```

Confirm:
- Container name contains date stamp (not `production`, not `railway`)
- Port 5433 (not 5432, which production uses internally on Railway)
- No Railway production service references this container

### 7.5 Phase 4: Restore dump into scratch

```bash
date -u +"%Y-%m-%dT%H:%M:%SZ"  # RESTORE_START

docker run --rm \
  -e PGPASSWORD="$SCRATCH_PASS" \
  -v "$DUMP_FILE":/restore.dump:ro \
  --network host \
  pgvector/pgvector:pg18 \
  pg_restore \
    --no-password \
    -h 127.0.0.1 \
    -p 5433 \
    -U restore_user \
    -d restore_proof \
    --no-owner \
    --no-acl \
    --exit-on-error \
    /restore.dump

date -u +"%Y-%m-%dT%H:%M:%SZ"  # RESTORE_END
```

Exit code must be 0. Any non-zero exit is a restore failure — see Section 10.

## 8. Integrity Validation

Run each query against the scratch database and compare to production source counts
(recorded in Section 9 below for each drill):

```bash
# Overall dataset counts
docker run --rm \
  -e PGPASSWORD="$SCRATCH_PASS" \
  --network host \
  pgvector/pgvector:pg18 \
  psql -h 127.0.0.1 -p 5433 -U restore_user -d restore_proof --no-password -tA -c \
  "SELECT
    (SELECT COUNT(*) FROM fa_engagements) AS fa_engagements,
    (SELECT COUNT(*) FROM fa_normalized_findings) AS findings,
    (SELECT COUNT(*) FROM fa_evidence) AS evidence,
    (SELECT COUNT(*) FROM fa_engagement_audit_events) AS audit_events,
    (SELECT COUNT(*) FROM fa_scan_results) AS scan_results,
    (SELECT COUNT(*) FROM tenants) AS tenants,
    (SELECT COUNT(*) FROM portal_remediation_audit_events) AS remediation_audit_events"

# Per-engagement counts for ENG-RESTORE-PROOF-01 (use the engagement ID on record
# in the sanitized evidence manifest — never hard-code customer engagement IDs here)
docker run --rm \
  -e PGPASSWORD="$SCRATCH_PASS" \
  --network host \
  pgvector/pgvector:pg18 \
  psql -h 127.0.0.1 -p 5433 -U restore_user -d restore_proof --no-password -tA -c \
  "SELECT
    (SELECT COUNT(*) FROM fa_engagements WHERE id = '<ENG_ID>') AS eng_count,
    (SELECT COUNT(*) FROM fa_normalized_findings WHERE engagement_id = '<ENG_ID>') AS findings,
    (SELECT COUNT(*) FROM fa_evidence WHERE engagement_id = '<ENG_ID>') AS evidence,
    (SELECT COUNT(*) FROM fa_engagement_audit_events WHERE engagement_id = '<ENG_ID>') AS audit_events,
    (SELECT COUNT(*) FROM fa_scan_results WHERE engagement_id = '<ENG_ID>') AS scan_results"

# Schema state
docker run --rm \
  -e PGPASSWORD="$SCRATCH_PASS" \
  --network host \
  pgvector/pgvector:pg18 \
  psql -h 127.0.0.1 -p 5433 -U restore_user -d restore_proof --no-password -tA -c \
  "SELECT MAX(version) FROM schema_migrations;
   SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';"
```

Replace `<ENG_ID>` with the engagement ID recorded in `docs/governance/status/L04_evidence_manifest.md`.

**L4 requires exact count agreement** across all tables for the selected engagement.
Any mismatch must be investigated before marking L4 complete.

## 9. Evidence Checklist

Complete for each drill and record in `docs/governance/status/L04_evidence_manifest.md`:

| Field | Value |
|-------|-------|
| Backup source | Production `frostgate-core` Railway Postgres, `railway` database |
| Dump timestamp | `pg_dump` start time (UTC) |
| Dump file location | `/tmp/frostgate-restore-proof-YYYYMMDD.dump` (not committed) |
| Dump size | MB |
| Restore target | `frostgate-restore-proof-YYYYMMDD` (local Docker) |
| Restore start | UTC |
| Restore end | UTC |
| Restore duration | seconds |
| Validation start | UTC |
| Validation complete | UTC |
| Source row counts | `fa_engagements`, `findings`, `evidence`, `audit_events`, `scan_results`, `tenants` |
| Restored row counts | Same tables |
| Count agreement | PASS / FAIL |
| Migration version | `schema_migrations.MAX(version)` |
| PostgreSQL version | From `SELECT version()` |
| Table count | From `information_schema.tables WHERE table_schema='public'` |
| ENG-RESTORE-PROOF-01 counts match | PASS / FAIL |
| Production writes performed | None confirmed |
| Production service pointed at scratch | None confirmed |
| Operator | admin@arescore.ai |
| Result | PASS / FAIL / BLOCKED |
| Scratch cleanup | PENDING / DONE |

## 10. Failure Handling

| Failure mode | Diagnosis | Resolution |
|--------------|-----------|------------|
| `pg_dump: server version mismatch` | pg_dump client < server version | Switch to `pgvector/pgvector:pg18` image |
| `extension "vector" is not available` | Scratch image missing pgvector | Use `pgvector/pgvector:pg18` (not `postgres:18`) |
| Railway connection refused | Railway proxy down or wrong host/port | Check `railway status`; verify `DATABASE_PUBLIC_URL` |
| pg_restore non-zero exit | Schema incompatibility, extension mismatch, or corrupt dump | Inspect stderr; re-dump if corrupt; fix extension issue |
| Count mismatch | Partial restore or data written between dump and count | Re-run dump and restore; do not mark L4 complete |
| `railway variables` empty | CLI not authenticated | `railway login` |
| Docker pull fails | No internet / registry unavailable | Pre-pull images; retry |

**Stop condition:** If the restore cannot be completed without touching production data, altering
production credentials, or pointing a live service at scratch — stop and report BLOCKED.

## 11. Cleanup

After all evidence is captured and recorded:

```bash
# Remove scratch container
docker stop frostgate-restore-proof-YYYYMMDD
docker rm frostgate-restore-proof-YYYYMMDD

# Remove dump file (never committed)
rm -f /tmp/frostgate-restore-proof-YYYYMMDD.dump

# Confirm no container with 'restore-proof' name is running
docker ps --filter "name=restore-proof"
```

**Do not destroy the scratch container until:**
- All row-count comparisons are recorded
- The evidence manifest is committed to the branch
- `EXECUTION_STATE.md` is updated

## 12. Launch DoD Mapping

This runbook directly satisfies:

| DoD Item | Blocker | Exit criteria |
|----------|---------|---------------|
| **L4** | `FG-LR-003` | `pg_dump` of production restored into isolated scratch; row-count verification of a known engagement passes; this runbook exists |

**L4 may be marked PASS only when all of the following are true:**
1. A real production backup (pg_dump) was taken from the live production database.
2. The dump was restored into a named, isolated scratch target with separate credentials.
3. No production application service was pointed at the scratch target.
4. Row counts for at least one known engagement match exactly between source and restored.
5. This runbook exists and the evidence manifest references dated restore evidence.

**L4 may not be marked PASS based solely on automatic backups being enabled** — a restore must
be executed and validated, not assumed.

## 13. Last Verified

| Field | Value |
|-------|-------|
| Date | 2026-07-30 |
| Result | PASS |
| Evidence reference | `docs/governance/status/L04_evidence_manifest.md` |
| Operator | admin@arescore.ai |
| Next required rehearsal | 2026-10-30 (quarterly) or before second client engagement |
| Drill duration | ~22 seconds (dump + restore + validation) |
| Database size | 1.7 MB (compressed) |
