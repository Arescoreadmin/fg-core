# FrostGate Disaster Recovery Procedure

Companion to `backup_restore.md` (the proven method) and
`backup_automation.md` (the automation layer). This document is the
step-by-step procedure operators execute when production data is lost or
suspected corrupted.

## 1. Recovery objectives

| Metric | Target | Notes |
|--------|--------|-------|
| RPO | ≤ 25 h with the daily schedule; ≤ 1 h with the hourly schedule | Bounded by cron cadence |
| RTO | ≤ 15 min for the current 1.7 MB database | Measured (T1 drill: 3.5 min) |
| Verification window | ≤ 5 min after restore | Count comparison + smoke |

These targets apply while the database remains under ~10 MB. Revisit if
the database exceeds ~200 MB.

## 2. Trigger classification

| Class | Example | Action |
|-------|---------|--------|
| **Data loss** | Dropped table, accidental DELETE, purge misfire | §3 full restore |
| **Corruption** | pg_dump/pg_restore reports errors, tests fail on schema | §3 with pre-corruption backup |
| **Service outage** | Railway down, container OOM loop | §5 escalation only; data likely intact |
| **Rollback after bad migration** | New migration produces errors | §4 targeted restore into scratch first |
| **Compromise / suspected tamper** | Unauthorized DB access | §6 security response |

## 3. Full recovery procedure

### 3.1 Prepare

1. Announce a maintenance window; put the Console into read-only if
   available.
2. Stop upstream writers (Railway API + admin_gateway workers). Do not
   restart until §3.6.
3. Record incident start time: `date -u +"%Y-%m-%dT%H:%M:%SZ"`.

### 3.2 Identify the backup

```
fg_backup.sh list
fg_backup.sh status
```

Choose the most recent backup whose manifest has
`verification_status: "verified"` and predates the incident.

### 3.3 Verify before you rely on it

```
fg_backup.sh verify /var/lib/frostgate/backups/frostgate_YYYYMMDD_HHMMSS_<type>.dump
```

All lines must be `PASS`. Any `FAIL` — try the next-oldest verified
backup.

### 3.4 Decrypt if needed

If the backup is `.dump.enc`:

```
export FG_BACKUP_ENCRYPTION_KEY='<key from secrets manager>'
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
  -pass env:FG_BACKUP_ENCRYPTION_KEY \
  -in frostgate_YYYYMMDD_HHMMSS_<type>.dump.enc \
  -out /tmp/restore.dump
sha256sum /tmp/restore.dump
```

Compare the resulting SHA-256 to the decrypted checksum recorded when the
backup was originally taken (kept in your secrets manager or key
rotation log).

### 3.5 Restore into scratch first

```
fg_backup.sh restore /var/lib/frostgate/backups/frostgate_YYYYMMDD_HHMMSS_<type>.dump
```

This spins up a local scratch container, restores, and compares counts to
production. Do not proceed until the JSON report shows `"status": "PASS"`.
The scratch container is destroyed automatically.

### 3.6 Promote scratch data to production

For Railway Hobby (no in-place restore path), the promotion sequence is:

1. `railway service create postgres-restore-YYYYMMDD` (new service).
2. Restore the dump into that service using the same
   `docker run pgvector/pgvector:pg18 pg_restore` procedure documented in
   `backup_restore.md §7.5`, but pointed at the new service's connection
   string.
3. Point the API + admin_gateway at the new service via
   `DATABASE_URL` variable swap in Railway.
4. Re-run `fg_backup.sh status` — confirm `backup_status: "ok"`.
5. Take a fresh `fg_backup.sh backup --type post-recovery` (recorded as a
   generic `manual` type until a `post-recovery` alias lands).
6. Restart workers, remove the read-only lock.
7. Retire the old service after 7 days if no anomalies observed.

### 3.7 Post-recovery close-out

- Update `docs/governance/status/EXECUTION_STATE.md` with the incident
  timeline and result.
- Append a full drill-style block to
  `docs/governance/status/restore_drill_evidence_YYYYMMDD.md` even though
  it was a live event.
- File a follow-up ticket for anything that went wrong during recovery.

## 4. Targeted restore (single table / engagement)

Use the scratch container from `fg_backup.sh restore ...`, then use
`pg_dump -t <table>` + `pg_restore -t <table>` to extract only the object
of interest into production. Never bulk-swap the production database for a
targeted restore.

## 5. Escalation

| Failure | Owner | Channel |
|---------|-------|---------|
| pg_dump/pg_restore version mismatch | Ops on-call | Fix locally |
| Checksum FAIL on the latest verified backup | Founder + ops | Slack #ops, phone if unread in 15 min |
| Restore count mismatch (`fg_backup.sh restore` returns 7) | Founder | Phone immediately — treat as data-loss event |
| Railway service create failure | Railway support ticket | Cite plan tier, project id, service id |
| Suspected security compromise | Founder + security lead | §6 |

## 6. Security response

If tampering is suspected:

1. Do not overwrite existing backups on the offsite provider.
2. Take a forensic snapshot of the entire `FG_BACKUP_DIR` (tarball, chain
   of custody).
3. Rotate every credential in the top-5 blast-radius list (T3 rotation
   procedure, see `secret_rotation.md` when it lands as part of T14).
4. Restore into a fresh Railway project (not the compromised one); the
   compromised project stays intact for forensic access.
5. Preserve container logs (`docker logs frostgate-restore-*`) even after
   the restore drill destroys the scratch container — pipe logs to a
   separate log file before cleanup.

## 7. Communication template

**Subject:** FrostGate incident — production data recovery in progress

**Body:**

> At <UTC timestamp>, FrostGate detected <trigger>. Production writes are
> paused while we restore from backup <backup file, redacted to filename
> only>. Expected duration: 15 minutes for the restore itself, plus up to
> 30 minutes for validation and service swap.
>
> No customer data has been exposed. This is a recovery from a
> point-in-time backup taken at <manifest.timestamp>. Data written between
> that timestamp and the incident is being re-established from external
> sources where possible.
>
> Next update in 30 minutes or when service is restored, whichever comes
> first.

## 8. Cross-references

- `docs/operators/backup_restore.md` — manual procedure (source of truth)
- `docs/operators/backup_automation.md` — automation configuration
- `docs/operators/backup_schedule.md` — schedule reference
- `docs/governance/status/L04_evidence_manifest.md` — L4 evidence
