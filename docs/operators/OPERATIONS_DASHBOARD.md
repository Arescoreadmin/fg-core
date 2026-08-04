# Operations Dashboard

Quick-reference for answering "Is FrostGate healthy?" in under 30 seconds.

Update this page after every incident, drill, rotation, or constraint change.
All live values must be read from authoritative sources — never estimate.

---

## Production

| Signal | Value | Source |
|---|---|---|
| API deployment SHA | `—` | Railway → frostgate-api → Deployments → latest SHA |
| Portal deployment SHA | `—` | Railway → frostgate-portal → Deployments → latest SHA |
| DB migration version | `—` | `psql $DB_URL -c "SELECT version_num FROM alembic_version ORDER BY 1 DESC LIMIT 1"` |
| Runtime role | `—` | Railway → frostgate-api → Variables → `FG_RUNTIME_ROLE` |
| Last successful backup | `—` | `scripts/backup/fg_backup.sh status` → `latest_backup` |
| Last restore drill | `—` | `docs/governance/status/` → most recent `restore_drill_evidence_YYYYMMDD.md` |

---

## Capacity (check at start of each engagement)

| Signal | Healthy | Source |
|---|---|---|
| API memory | < 70% RSS | Railway → frostgate-api → Metrics |
| DB connections | < 80% pool | Railway → Postgres → Metrics → active connections |
| Redis memory | < 80% | Railway → Redis → Metrics |
| Queue depth | 0 pending > 5 min | Railway → worker → logs: `pending_jobs` |

---

## Operations

| Signal | Value | Source |
|---|---|---|
| Active tenants | `—` | `psql $DB_URL -c "SELECT COUNT(*) FROM tenants WHERE lifecycle_state='active'"` |
| Active engagements | `—` | `psql $DB_URL -c "SELECT COUNT(*) FROM fa_engagements WHERE status NOT IN ('completed','cancelled')"` |
| Active portal users | `—` | `psql $DB_URL -c "SELECT COUNT(*) FROM portal_sessions WHERE expires_at > now()"` |
| Failed jobs (24h) | `—` | Railway → worker → logs: filter `job_failed` |
| Pending scan jobs | `—` | `psql $DB_URL -c "SELECT COUNT(*) FROM fa_scan_jobs WHERE status='pending'"` |

---

## Security

| Signal | Last completed | Evidence |
|---|---|---|
| Key rotation (FG_SIGNING_SECRET) | `—` | Rotation manifest in `docs/governance/status/` |
| Key rotation (FG_KEY_PEPPER) | `—` | Rotation manifest in `docs/governance/status/` |
| Evidence signing verification | `—` | `scripts/backup/fg_backup.sh verify-manifest <manifest>` |
| Incident drill (T8) | `—` | `docs/operators/t8_incident_drill.md` evidence block |
| Restore drill | `—` | `docs/governance/status/restore_drill_evidence_YYYYMMDD.md` |

---

## Launch

| Signal | Current value |
|---|---|
| Stage | Stage 1 — Design Partner |
| Open constraints | C1 (backup secrets + first drill), C4 (T8/T9/T10/T13 operator execution) |
| Next gate | C1 close → T8 → T9 → T10 → T13 → launch constraints removed |
| Decision authority | jcosat (LDR-2026-001, 2026-08-04) |
| LDR | `docs/governance/status/LAUNCH_DECISION_RECORD.md` |

---

## How to use

1. **Before client onboarding:** verify Production SHA matches the expected branch, DB migration is at HEAD, last backup < 25h, no open security signals.
2. **After an incident:** fill in the Security row for incident drill with date + result. Update Launch constraints if one closed.
3. **Monthly:** run the restore drill workflow (`restore-drill` → Run workflow), download the evidence artifact, update Last restore drill date.
4. **After each key rotation:** update the Security table with the rotation date.
