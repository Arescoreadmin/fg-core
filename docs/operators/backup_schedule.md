# FrostGate Backup Schedule — Reference Card

Print / keep in the operator runbook. Details live in
`backup_automation.md`; this is a one-page cheat sheet.

## Cadence

| When | Command | Type | Owner |
|------|---------|------|-------|
| Every hour (recommended) or daily | `fg_backup.sh backup --type scheduled` | scheduled | cron |
| Before every client engagement | `fg_backup.sh backup --type pre-engagement` | pre-engagement | operator running `first_client_prep.md` |
| Before every prod deploy | `fg_backup.sh backup --type pre-deploy` | pre-deploy | deploy pipeline |
| Before every Alembic migration | `fg_backup.sh backup --type pre-migration` | pre-migration | migration author |
| Before scheduled maintenance | `fg_backup.sh backup --type pre-maintenance` | pre-maintenance | operator |
| Ad hoc | `fg_backup.sh backup --type manual` | manual | operator |

## Verification

| When | Command |
|------|---------|
| After every backup (automatic) | built-in — sets `verification_status: "verified"` in manifest |
| Weekly spot-check | `fg_backup.sh verify <newest file>` |
| Monthly | `fg_backup.sh drill` |
| Quarterly (L4) | full `backup_restore.md` §7 drill, evidence into `L04_evidence_manifest.md` |

## Monitoring

- `fg_backup.sh status` — JSON summary; `backup_status` field is
  `ok` / `warning` / `critical`.
- Alert when `backup_status != "ok"`.
- Alert when `latest_backup_age_hours > FG_BACKUP_RPO_WARN_HOURS` (25 by
  default).
- Alert when `last_drill_date` is older than 35 days.

## Retention default at a glance

| Bucket | Age window | Kept |
|--------|-----------|------|
| hourly | < 48 h | 24 |
| daily | < 14 d | 30 |
| weekly | < 90 d | 12 |
| monthly | < 2 y | 12 |
| yearly | ≥ 2 y | 7 |

Newest backup is always protected regardless of retention math.

## Cron example (Railway sidecar or ops host)

```
# hourly scheduled backup
0 * * * * FG_BACKUP_OPERATOR="ops@frostgate.ai" /opt/frostgate/scripts/backup/fg_backup.sh backup --type scheduled >>/var/log/fg_backup.log 2>&1

# monthly drill on the 1st at 03:00 UTC
0 3 1 * * FG_BACKUP_OPERATOR="ops@frostgate.ai" /opt/frostgate/scripts/backup/fg_backup.sh drill >>/var/log/fg_backup.log 2>&1
```
