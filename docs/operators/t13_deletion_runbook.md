# T13 Deletion Runbook — DPA Data Purge Procedure

**DoD L11:** The deletion runbook covers all three DPA triggers — day-90 retention expiry, early deletion within 5 business days of request (DPA §5), deletion within 10 business days of termination (DPA §10) — each with a named trigger, owner, and deadline; executed once against test data, respecting lifecycle locks and legal holds.

**Owner:** Founder (Jason Cosat) — sole operator at Stage 1.
**Authority:** `docs/operators/letters/3_data_handling_notice.md` (client-facing commitment), retention policy `docs/observability/retention_policy.md`.

---

## 1. DPA Trigger Reference

### Trigger 1 — Day-90 Retention Expiry

| Field | Value |
|---|---|
| **Trigger condition** | 90 days have elapsed since the engagement's `created_at` timestamp (or date of first data collection, whichever is earlier). |
| **Owner** | Founder |
| **Deadline** | Purge must be complete by day 91. Do not wait for a client request — this is an automatic obligation. |
| **How it surfaces** | Check the `fa_engagements` table for rows where `created_at < NOW() - INTERVAL '90 days'` and `status != 'purged'`. Run this check monthly. |

### Trigger 2 — Early Deletion Request (DPA §5)

| Field | Value |
|---|---|
| **Trigger condition** | Client submits a deletion request via email to jason@frostgate.ai. The data handling notice commits to a response within 5 business days. |
| **Owner** | Founder |
| **Deadline** | Purge and written confirmation to the client within 5 business days of receiving the request. |
| **How it surfaces** | Email from client requesting deletion. Log receipt date immediately. |

### Trigger 3 — Termination Deletion (DPA §10)

| Field | Value |
|---|---|
| **Trigger condition** | The engagement or client relationship ends (engagement status `closed` or `cancelled`, or explicit termination notice from the client). |
| **Owner** | Founder |
| **Deadline** | Purge must complete within 10 business days of the termination date. |
| **How it surfaces** | Engagement status transitions to `closed` or `cancelled` in the console; or founder receives written termination notice. |

---

## 2. Pre-Purge Checks

Before executing any deletion, complete all of the following checks. Do not proceed if any check blocks.

### 2.1 Lifecycle lock check

Evidence tables (`fa_scan_results`, `fa_document_analyses`, `fa_field_observations`) carry a `lifecycle_state` column. Evidence in state `locked` has been incorporated into a signed report. Evidence in state `legal_hold` is under an active legal hold.

Run against production (substitute actual `ENGAGEMENT_ID` and `TENANT_ID`):

```sql
SELECT evidence_type, COUNT(*) as count, lifecycle_state
FROM (
  SELECT 'scan_result' AS evidence_type, lifecycle_state
    FROM fa_scan_results WHERE engagement_id = '<ENGAGEMENT_ID>'
  UNION ALL
  SELECT 'document_analysis', lifecycle_state
    FROM fa_document_analyses WHERE engagement_id = '<ENGAGEMENT_ID>'
  UNION ALL
  SELECT 'observation', lifecycle_state
    FROM fa_field_observations WHERE engagement_id = '<ENGAGEMENT_ID>'
) combined
GROUP BY evidence_type, lifecycle_state;
```

- **`locked` state:** Allowed to purge once the signed report has been delivered. Confirm the report was delivered before proceeding.
- **`legal_hold` state:** Do NOT purge. Check `fa_legal_holds` for the active hold record. Contact the client or legal counsel before proceeding. Purge is suspended until the hold is lifted.

### 2.2 Legal hold table check

```sql
SELECT * FROM fa_legal_holds
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>'
  AND lifted_at IS NULL;
```

If any row is returned with `lifted_at IS NULL`, there is an active legal hold. **Stop. Do not purge.**

### 2.3 Report delivery confirmation

Confirm the final report was delivered to the client before purging. Check:

```sql
SELECT delivery_type, delivered_at, delivered_to
FROM fa_report_delivery_events
WHERE engagement_id = '<ENGAGEMENT_ID>'
ORDER BY delivered_at DESC
LIMIT 5;
```

If no delivery event exists and the engagement is in `closed` status, escalate to the founder before proceeding.

### 2.4 Audit log preservation

The audit log (`fa_engagement_audit_events`, `fa_scan_audit_events`, `fa_evidence_lifecycle_events`) must be preserved for 7 years per `docs/observability/retention_policy.md §Tier 4`. These tables are NOT included in the purge. Confirm this understanding before running the deletion queries.

---

## 3. Deletion Procedure

Execute in this order. Each step is a separate SQL transaction. Do not combine into a single transaction — if a step fails, investigate before continuing.

**Substitution:** replace `<ENGAGEMENT_ID>` and `<TENANT_ID>` with the actual values throughout.

### Step 1 — Evidence links

```sql
DELETE FROM fa_evidence_links
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>';
```

### Step 2 — Evidence provenance

```sql
DELETE FROM fa_evidence_provenance
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>';
```

### Step 3 — Evidence report links

```sql
DELETE FROM fa_evidence_report_links
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>';
```

### Step 4 — Scan results and associated data

```sql
DELETE FROM fa_scan_results
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>'
  AND lifecycle_state != 'legal_hold';

DELETE FROM fa_quarantined_scans
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>';

DELETE FROM fa_scan_jobs
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>';
```

### Step 5 — Document analyses and observations

```sql
DELETE FROM fa_document_analyses
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>'
  AND lifecycle_state != 'legal_hold';

DELETE FROM fa_field_observations
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>'
  AND lifecycle_state != 'legal_hold';
```

### Step 6 — Findings and artifacts

```sql
DELETE FROM fa_normalized_findings
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>';

DELETE FROM fa_artifacts
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>'
  AND legal_hold = FALSE;

DELETE FROM fa_verified_targets
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>';
```

### Step 7 — Report versions and delivery events

```sql
DELETE FROM fa_report_delivery_events
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>';

DELETE FROM fa_report_versions
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>';
```

### Step 8 — Governance workflows

```sql
DELETE FROM governance_workflows
WHERE engagement_id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>';
```

### Step 9 — Engagement record (last)

Mark the engagement as purged rather than deleting the row. This preserves the engagement ID in audit records without retaining client data.

```sql
UPDATE fa_engagements
SET status = 'purged',
    client_name = '[PURGED]',
    client_domain = '[PURGED]',
    assessor_id = '[PURGED]',
    engagement_metadata = '{}'
WHERE id = '<ENGAGEMENT_ID>'
  AND tenant_id = '<TENANT_ID>';
```

**Do not DELETE the `fa_engagements` row.** Audit log events reference the engagement ID.

---

## 4. Post-Purge Verification

Run confirmation queries to verify the data is gone:

```sql
-- Scan results
SELECT COUNT(*) FROM fa_scan_results
WHERE engagement_id = '<ENGAGEMENT_ID>';
-- Expected: 0 (or count of items still under legal_hold)

-- Findings
SELECT COUNT(*) FROM fa_normalized_findings
WHERE engagement_id = '<ENGAGEMENT_ID>';
-- Expected: 0

-- Report versions
SELECT COUNT(*) FROM fa_report_versions
WHERE engagement_id = '<ENGAGEMENT_ID>';
-- Expected: 0

-- Engagement status
SELECT status, client_name FROM fa_engagements
WHERE id = '<ENGAGEMENT_ID>';
-- Expected: status='purged', client_name='[PURGED]'
```

Confirm the audit log tables still have entries (they should NOT have been deleted):

```sql
SELECT COUNT(*) FROM fa_engagement_audit_events
WHERE engagement_id = '<ENGAGEMENT_ID>';
-- Expected: > 0 (audit events preserved)
```

---

## 5. Test Execution

**This section must be completed once before the first client engagement.**

### 5.1 Create a disposable test tenant and engagement

1. In the console, provision a new tenant with the naming convention `fg-t13-purge-test-YYYYMMDD`.
2. Create a minimal engagement under that tenant: submit one scan result, one observation, and generate a report. The engagement does not need to be fully realistic — it only needs real rows in the relevant tables.
3. Note the test engagement ID and tenant ID.

```
Test tenant:      fg-t13-purge-test-___________
Test engagement:  ____________________________
```

### 5.2 Verify data exists before purge

Run the pre-purge count query:

```sql
SELECT
  (SELECT COUNT(*) FROM fa_scan_results WHERE engagement_id = '<TEST_ENGAGEMENT_ID>') AS scan_results,
  (SELECT COUNT(*) FROM fa_field_observations WHERE engagement_id = '<TEST_ENGAGEMENT_ID>') AS observations,
  (SELECT COUNT(*) FROM fa_report_versions WHERE engagement_id = '<TEST_ENGAGEMENT_ID>') AS report_versions,
  (SELECT COUNT(*) FROM fa_engagement_audit_events WHERE engagement_id = '<TEST_ENGAGEMENT_ID>') AS audit_events;
```

Record pre-purge counts:

| Table | Pre-purge count |
|---|---|
| fa_scan_results | |
| fa_field_observations | |
| fa_report_versions | |
| fa_engagement_audit_events | |

### 5.3 Execute purge

Run Steps 1–9 of the deletion procedure with the test engagement ID and tenant ID.

### 5.4 Verify data is gone

Run the post-purge verification queries. Record results:

| Table | Post-purge count | Expected |
|---|---|---|
| fa_scan_results | | 0 |
| fa_normalized_findings | | 0 |
| fa_report_versions | | 0 |
| fa_engagement_audit_events | | > 0 (preserved) |
| fa_engagements status | | 'purged' |

---

## 6. Evidence Record

| Field | Value |
|---|---|
| Drill date | |
| Operator | |
| DPA trigger type simulated | Day-90 (Trigger 1) |
| Test tenant used | |
| Test engagement ID | |
| Pre-purge: scan_results count | |
| Pre-purge: observations count | |
| Pre-purge: report_versions count | |
| Pre-purge: audit_events count | |
| Post-purge: scan_results count | |
| Post-purge: findings count | |
| Post-purge: report_versions count | |
| Post-purge: audit_events count (must be > 0) | |
| Engagement status after purge | |
| Legal hold check result | No active holds |
| Lifecycle lock check result | |
| Purge completed within deadline | [ ] Yes |

---

## Cross-references

- `docs/operators/letters/3_data_handling_notice.md` — client-facing DPA commitments
- `docs/observability/retention_policy.md` — retention period definitions and immutability requirements
- `docs/governance/audits/client_launch_readiness/LAUNCH_DEFINITION_OF_DONE.md` — L11 DoD definition
