
## Drill 2026-08-06T10:42:54Z

- Backup file: `frostgate_20260806_104220_manual.dump.enc`
- Result: PASS
- Operator: ops@frostgate.ai

```json
[fg_backup] decrypting /tmp/fg-backups/frostgate_20260806_104220_manual.dump.enc → /tmp/.fg_restore.xJHufJ.dump (in tmpfs)
[fg_backup] creating scratch container: frostgate-restore-20260806-7ce3a27c on 127.0.0.1:5434
[fg_backup] pg_restore into scratch
{
  "backup_file": "/tmp/fg-backups/frostgate_20260806_104220_manual.dump.enc",
  "expected_counts": {
    "fa_engagement_audit_events": "346",
    "fa_engagements": "17",
    "fa_normalized_findings": "101",
    "fa_scan_results": "56",
    "migration_version": "0172",
    "tenants": "17"
  },
  "expected_counts_source": "manifest",
  "mismatches": [],
  "scratch_container": "frostgate-restore-20260806-7ce3a27c",
  "scratch_counts": {
    "fa_engagement_audit_events": "346",
    "fa_engagements": "17",
    "fa_normalized_findings": "101",
    "fa_scan_results": "56",
    "migration_version": "0172",
    "tenants": "17"
  },
  "status": "PASS"
}
```

