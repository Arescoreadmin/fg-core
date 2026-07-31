# FrostGate Backup Automation

Companion to `backup_restore.md` (the proven method). This document is the
operator's guide to `scripts/backup/fg_backup.sh` — the automation that runs
on top of that method.

## 1. Architecture at a glance

```
   +----------------------+       +---------------------------+
   |  fg_backup.sh backup |----+->| docker run pgvector:pg18  |
   +----------------------+    |  |    pg_dump --format=custom|
              |                |  +---------------------------+
              |                |
              v                |
   +----------------------+    |  +----------------------------+
   | .manifest.json (SHA) |    +->| optional openssl enc AES-  |
   +----------------------+       |   256-CBC pbkdf2 iter=600k |
              |                   +----------------------------+
              v
   +----------------------+       +----------------------------+
   | offsite provider     |------>| local | s3 | r2 | b2       |
   +----------------------+       +----------------------------+
              |
              v
   +----------------------+
   | retention pruning    |
   +----------------------+
```

The script never modifies production. Every subcommand reads from production
in `pg_dump`/`psql` mode; the restore subcommand always targets an isolated
local Docker scratch container (never Railway).

## 2. Why full logical dumps and not true incrementals

Railway Hobby exposes only a public proxy for the internal PostgreSQL
service, with no access to:
- WAL streaming / archiving (`archive_command`, `pg_receivewal`)
- Base-backup streaming (`pg_basebackup`)
- Replication slots

Given those constraints:
- **pg_dump always produces a full logical dump.** It has no native
  incremental mode.
- **The production database is 1.7 MB.** T1 measured pg_dump at ~2 minutes
  wall time — dominated by network + Docker image cache, not data.
- **Building a custom incremental pipeline** (change-data capture, WAL
  shipping via a bastion, filesystem snapshots) is meaningful complexity
  with real failure modes.

Recommendation: run full dumps at short intervals. Hourly is easily within
budget; daily meets the current RPO target with headroom. Revisit if the
database grows past ~200 MB or if Railway Pro (with WAL access) is adopted.

## 3. Configuration reference

All configuration flows through env vars parsed by
`scripts/backup/backup_config.sh`. That file also documents defaults inline.
The most-touched knobs:

| Variable | Default | Notes |
|----------|---------|-------|
| `FG_BACKUP_DB_URL` | *(required)* | `postgresql://user:pass@host:port/db` |
| `FG_BACKUP_DIR` | `/var/lib/frostgate/backups` | Local storage root, mode 0700 |
| `FG_BACKUP_OFFSITE_PROVIDER` | `local` | `local` \| `s3` \| `r2` \| `b2` \| `none` |
| `FG_BACKUP_OFFSITE_LOCAL_PATH` | `${FG_BACKUP_DIR}/offsite` | Where the local provider copies |
| `FG_BACKUP_ENCRYPT` | `false` | Set `true` to enable AES-256-CBC |
| `FG_BACKUP_ENCRYPTION_KEY` | *(none)* | Required when `FG_BACKUP_ENCRYPT=true` |
| `FG_BACKUP_RETAIN_HOURLY` | 24 | Keep N newest in the ≤48h bucket |
| `FG_BACKUP_RETAIN_DAILY` | 30 | ≤14 days bucket |
| `FG_BACKUP_RETAIN_WEEKLY` | 12 | ≤90 days bucket |
| `FG_BACKUP_RETAIN_MONTHLY` | 12 | ≤730 days bucket |
| `FG_BACKUP_RETAIN_YEARLY` | 7 | >730 days bucket |
| `FG_BACKUP_RPO_WARN_HOURS` | 25 | `status` flips to warning past this |
| `FG_BACKUP_OPERATOR` | `unknown@frostgate.local` | Recorded in manifests |
| `FG_BACKUP_JSON_OUTPUT` | `false` | Emit JSON to stdout when true |

## 4. Daily / weekly / monthly workflow

### 4.1 Daily

Run `fg_backup.sh backup --type scheduled`. Recommended cron:

```
0 * * * * /opt/frostgate/scripts/backup/fg_backup.sh backup --type scheduled >>/var/log/fg_backup.log 2>&1
```

(Hourly is well within pg_dump budget for a 1.7 MB database and satisfies
any reasonable RPO.)

### 4.2 Before a client engagement

`fg_backup.sh backup --type pre-engagement` — replaces the manual pg_dump
called for in `first_client_prep.md §0`.

### 4.3 Before a migration or deploy

`fg_backup.sh backup --type pre-migration` or `--type pre-deploy`. The
manifest records the `backup_type`, so rollback tooling can filter for the
right recovery point.

### 4.4 Weekly

- `fg_backup.sh list` — confirm the ledger looks sane.
- `fg_backup.sh prune --dry-run` — confirm nothing important is about to
  drop. Then run without `--dry-run` if you want to force a compaction (the
  daily backup already prunes as part of its run).
- `fg_backup.sh status` — check the RPO/RTO snapshot.

### 4.5 Monthly

- `fg_backup.sh drill` — restores the most recent backup into a scratch
  container, compares row counts with production, and appends evidence to
  `docs/governance/status/restore_drill_evidence_YYYYMMDD.md`.

## 5. Failure handling

| Symptom | Diagnosis | Fix |
|---------|-----------|-----|
| `pg_dump: server version mismatch` | Wrong Docker image | Confirm `FG_BACKUP_DOCKER_IMAGE=pgvector/pgvector:pg18` |
| `FG_BACKUP_ENCRYPT=true but ... KEY is empty` | Encryption misconfigured | Set `FG_BACKUP_ENCRYPTION_KEY` or disable encryption |
| `offsite upload skipped: credentials not configured` | S3 provider without creds | Populate `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` or set `FG_BACKUP_OFFSITE_PROVIDER=local` |
| `status` returns `warning` with age > RPO | Backup cron stopped | Check systemd/cron, run `fg_backup.sh backup --type manual`, then investigate |
| `verify` FAIL on `checksum_match` | Storage corruption or tampering | Do not restore from this file. Re-take a fresh backup, escalate per `disaster_recovery.md §7` |
| `restore` returns FAIL with mismatched counts | Restore is not authoritative | Re-run `backup` then re-run `restore`; if it still fails, escalate |

Non-zero exit codes are:

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Generic failure (see stderr) |
| 2 | Configuration error (missing var, unknown provider, bad flag, encryption without key) |
| 3 | Missing dependency (`docker`, `sha256sum`, `openssl`) |
| 4 | Runtime failure of dump/restore/scratch |
| 5 | Offsite provider hard failure |
| 6 | Post-backup verification failed |
| 7 | Restore count mismatch |

## 6. Key rotation

1. Generate a new AES key: `openssl rand -hex 32`.
2. Perform a fresh `fg_backup.sh backup --type manual` under the new key.
3. Confirm `fg_backup.sh verify <new-file>` returns all PASS.
4. Retain the old key for at least the retention window of the oldest
   backup you still need (see `FG_BACKUP_RETAIN_*`).
5. Decryption steps for old backups: see `disaster_recovery.md §4`.

Never commit any encryption key. Store in your secrets manager only.

## 7. Offsite storage setup

### 7.1 Local (default)

Set `FG_BACKUP_OFFSITE_LOCAL_PATH` to a path on a different volume, ideally
one that is shipped elsewhere by an out-of-band job (rsync, rclone,
snapshot).

### 7.2 S3-compatible (AWS S3, Cloudflare R2, Backblaze B2)

```
export FG_BACKUP_OFFSITE_PROVIDER=r2
export FG_BACKUP_S3_BUCKET=frostgate-backups
export FG_BACKUP_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com
export FG_BACKUP_S3_PREFIX=frostgate/backups
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
```

Alternative: pre-configure an `rclone` remote and set
`FG_BACKUP_RCLONE_REMOTE=<name>`. The script prefers `rclone` when
available.

If credentials are missing the provider intentionally returns success with
a "skipped: credentials not configured" message, so scheduled backups do
not fail while offsite is being wired up. The manifest records
`offsite_uploaded: false` in that case — monitor for it.

## 8. Retention model

Filenames encode both the type and timestamp:

```
frostgate_YYYYMMDD_HHMMSS_<type>.dump[.enc]
```

Prune categorises backups by age:

| Bucket | Age window | Default retained |
|--------|-----------|------------------|
| hourly | < 48 h | 24 |
| daily | < 14 d | 30 |
| weekly | < 90 d | 12 |
| monthly | < 2 y | 12 |
| yearly | ≥ 2 y | 7 |

The **single newest successful backup is always protected** regardless of
its bucket, so retention math can never delete your only recovery point.

Manifests are removed together with the archive they describe. Encrypted
archives (`.dump.enc`) are treated the same as `.dump` for retention.

## 9. Restore drill evidence

`fg_backup.sh drill` appends a dated block to
`docs/governance/status/restore_drill_evidence_YYYYMMDD.md`. Multiple
drills on the same day append to the same file (no overwrite). This file
is the operator's audit trail for L4 quarterly rehearsal.

## 10. Cross-references

- `docs/operators/backup_restore.md` — the underlying proven method (do not
  change)
- `docs/operators/disaster_recovery.md` — full DR procedure and escalation
- `docs/operators/backup_schedule.md` — schedule reference card
- `docs/operators/first_client_prep.md §0` — pre-engagement backup step
- `docs/governance/status/L04_evidence_manifest.md` — L4 evidence
