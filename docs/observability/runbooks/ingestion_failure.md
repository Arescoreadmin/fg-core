# Runbook: FrostgateIngestionFailureHigh

**Alert:** `FrostgateIngestionFailureHigh`
**Severity:** Critical
**Metric:** `frostgate_ingestion_requests_total`
**Threshold:** Failure rate > 5% over 5 minutes

## Immediate actions
1. Check which tenant and doc type is failing: `sum by (tenant_id, doc_type, status) (rate(frostgate_ingestion_requests_total[5m]))`
2. Review ingestion pipeline logs for parse errors, schema violations, or storage failures
3. Check DB connectivity: `frostgate_db_connectivity_failures_total`
4. Check ingestion queue depth: `frostgate_ingestion_queue_depth`

## Resolution
- For parse errors: validate source document format against ingest schema
- For storage failures: check disk/DB capacity
- For schema violations: check policy version compatibility
