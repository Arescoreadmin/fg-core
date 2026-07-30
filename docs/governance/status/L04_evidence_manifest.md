# Launch DoD L4 — Restore Drill Evidence Manifest

**DoD item:** L4  
**Blocker closed:** FG-LR-003  
**Runbook:** `docs/operators/backup_restore.md`

---

## 2026-07-30 Restore Drill

### Platform

| Field | Value |
|-------|-------|
| Railway project | frostgate-core |
| Railway plan tier | hobby |
| Automatic Railway backups | None (`maxBackupsCount: 0` on hobby plan) |
| Backup mechanism | Manual `pg_dump` via Docker (`pgvector/pgvector:pg18`) |
| Production DB engine | PostgreSQL 18.4 (Debian 18.4-1.pgdg13+1) |
| Production DB service | Postgres — Online — sfo region — 148 MB / 500 MB volume |
| Production database name | railway |

### Timing

| Event | Timestamp (UTC) |
|-------|----------------|
| Drill start | 2026-07-30T20:08:46Z |
| pg_dump complete | 2026-07-30T20:10:43Z |
| Scratch container ready | 2026-07-30T20:11:42Z |
| Restore start | 2026-07-30T20:11:42Z |
| Restore complete | 2026-07-30T20:11:46Z |
| Validation start | 2026-07-30T20:11:53Z |
| Validation complete | 2026-07-30T20:12:11Z |
| Restore duration | ~4 seconds |
| Validation duration | ~18 seconds |

### Dump

| Field | Value |
|-------|-------|
| Dump format | pg_dump custom format (`--format=custom`) |
| Dump size | 1.7 MB (compressed) |
| Dump file | `/tmp/frostgate-restore-proof-20260730.dump` (not committed) |
| pg_dump image | `pgvector/pgvector:pg18` (PostgreSQL 18.4) |

### Scratch Target

| Field | Value |
|-------|-------|
| Scratch name | `frostgate-restore-proof-20260730` |
| Type | Local Docker container (`pgvector/pgvector:pg18`) |
| Local port | 5433 (isolated from production port 5432 internal) |
| Credentials | Separate from production (never committed) |
| Network | Host-only local; no Railway internal network |
| Production service pointed at scratch | None |
| Safe to destroy | Yes |

### Schema State

| Field | Source | Restored |
|-------|--------|----------|
| PostgreSQL version | 18.4 (Debian) | 18.4 (Debian) |
| Migration version | 0168 | 0168 |
| Public table count | 372 | 372 |

### Overall Dataset Counts

| Table | Source (production) | Restored (scratch) | Result |
|-------|--------------------|--------------------|--------|
| fa_engagements | 7 | 7 | PASS |
| fa_normalized_findings | 59 | 59 | PASS |
| fa_evidence | 0 | 0 | PASS |
| fa_engagement_audit_events | 264 | 264 | PASS |
| fa_scan_results | 37 | 37 | PASS |
| tenants | 6 | 6 | PASS |
| portal_remediation_audit_events | 0 | 0 | PASS |

### Known Engagement Verification

**Alias:** ENG-RESTORE-PROOF-01  
**Engagement:** 2026-06-01 dry-run engagement, `default` tenant (3rd engagement by creation date)  
**Engagement ID:** Recorded in non-committed operator notes; alias maps only to the operator.

| Table | Source | Restored | Result |
|-------|--------|----------|--------|
| fa_engagements | 1 | 1 | PASS |
| fa_normalized_findings | 22 | 22 | PASS |
| fa_evidence | 0 | 0 | PASS |
| fa_engagement_audit_events | 28 | 28 | PASS |
| fa_scan_results | 12 | 12 | PASS |

### Safety Confirmation

| Check | Status |
|-------|--------|
| No production writes during drill | CONFIRMED — pg_dump is read-only |
| No live service pointed at scratch | CONFIRMED — local Docker, not Railway |
| No credentials committed | CONFIRMED — temp pgpass file created/destroyed in-session |
| No dump file committed | CONFIRMED — dump at /tmp, git-ignored |
| No customer data committed | CONFIRMED — counts only; no raw rows |

### Result

```
L4: PASS
FG-LR-003: CLOSED
```

### Operator

admin@arescore.ai

### Scratch Cleanup

Scratch container `frostgate-restore-proof-20260730` and dump file `/tmp/frostgate-restore-proof-20260730.dump`
to be destroyed after this branch is reviewed and merged.

---

## Next Rehearsal

**Required by:** 2026-10-30 (quarterly) or before the second client engagement, whichever is first.

**Trigger for unscheduled rehearsal:**
- Any Railway plan change
- Any database migration adding new critical tables
- Any major production incident affecting data
