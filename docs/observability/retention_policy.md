# Telemetry Retention Policy

Recommended retention periods for each telemetry type. "Recommended" means
this is the minimum defensible posture for FrostGate deployments. Regulated
buyers may require longer retention — this document identifies which tiers
are subject to regulatory floors.

---

## Quick reference

| Data type | Recommended retention | Regulatory floor | Immutable? |
|---|---|---|---|
| Structured application logs | 90 days | None (operational) | No |
| Distributed traces | 30 days | None (operational) | No |
| Prometheus metrics (TSDB) | 1 year | None (operational) | No |
| Audit log entries | 7 years | SOC 2, HIPAA, FedRAMP | **Yes** |
| Audit export archives | 7 years | SOC 2, HIPAA, FedRAMP | **Yes** |
| Security incident logs | 3 years | SOC 2 CC7 | No (but don't delete during active incident) |
| Provenance validation records | 7 years | Customer contract dependent | **Yes** |

---

## Tier 1: Operational logs (90 days)

FrostGate structured logs (JSON to stdout) contain per-request operational data:
`request_id`, `trace_id`, `tenant_id`, `duration_ms`, `status_code`.

**Why 90 days:** sufficient for incident investigation lookback (most incidents
are identified within days; 90 days covers a full quarterly review cycle).

**What to do after 90 days:** delete or archive to cold storage. These logs are
not compliance evidence — retaining them beyond 90 days increases exposure under
data minimization requirements (GDPR, CCPA) without adding security value.

**Exception:** if an active security incident investigation is underway, do not
expire logs in scope. Preserve until the incident is formally closed.

---

## Tier 2: Distributed traces (30 days)

OTel spans stored in Grafana Tempo, Jaeger, or equivalent.

**Why 30 days:** traces are used for debugging recent issues. Trace storage is
expensive (full payload per request); 30 days covers typical SRE lookback for
post-incident reviews and SLO burn-rate analysis.

**Sampling interaction:** at `FG_OTEL_SAMPLE_RATIO=0.1` (10% sampling), 30 days
of traces is effectively 3 days of full-fidelity data at 10% volume. For
air-gapped or regulated environments using 100% sampling, 30 days is more
expensive — consider 14 days in those cases.

**What traces contain:** `tenant_id`, `trace_id`, `span_id`, span attributes
(`tenant.id`, `doc.type`, `provider.id`, `policy.version`). No document content,
no credentials (enforced by `check_safe_telemetry.py` CI gate).

---

## Tier 3: Prometheus metrics (1 year)

Prometheus TSDB raw data, or equivalent remote_write destination.

**Why 1 year:** enables year-over-year SLO trending, capacity planning, and
compliance reporting (SOC 2 availability metrics require historical data).
Most cloud Prometheus services default to 13 months; match or exceed that.

**Storage estimate:** FrostGate emits approximately 19 metric families. At
typical cardinality (10–50 label combinations per metric, 15s scrape interval),
expect ~50K samples/minute. Prometheus compresses aggressively; 1 year typically
fits in 5–15 GB depending on cardinality.

**Downsampling:** after 30 days, downsample to 5-minute resolution. After 90
days, downsample to 1-hour resolution. Keep raw 15s resolution for the most
recent 30 days to support incident investigations. Grafana Mimir and Thanos
both support automated downsampling rules.

---

## Tier 4: Audit log entries (7 years, immutable)

The audit log store contains per-event records of regulated operations:
document ingestion, policy evaluation, audit export generation, tenant key
operations. These are not part of FrostGate's metrics or tracing stack —
they live in the audit log store with an independent retention path.

**Why 7 years:** SOC 2 Type II requires 1 year. HIPAA requires 6 years. FedRAMP
High requires 3 years. 7 years covers all three and aligns with typical enterprise
contract terms for regulated industries. Some GovCon contracts require 10 years —
check your specific contract.

**Immutability requirement:** audit log entries must not be modifiable after
creation. Implement at the storage layer (e.g. AWS S3 Object Lock, write-once
append-only Postgres partitions, Worm storage). Application-layer immutability
is insufficient.

**Chain of custody:** each audit log entry is hash-chained (Merkle anchor). A
gap in the chain is a forensic signal. Do not delete individual entries to
"clean up" — this breaks the chain. Delete entire time-range partitions only
during authorized retention expiry procedures, after the retention floor has
been met.

---

## Tier 5: Audit export archives (7 years, immutable)

When a tenant or auditor requests an audit export, the generated archive (JSONL
with hash chain) is itself a compliance artifact. Retain the export alongside
the source audit log entries.

**Format:** JSONL + SHA-256 manifest. The `frostgate_audit_export_total` metric
counts export generation events; the actual export files live in object storage.

**Access logging:** every read access to an audit export archive should itself be
logged (who accessed it, when, for what purpose). This is required for SOC 2
CC6.1 and HIPAA 164.312(b).

---

## Tier 6: Security incident logs (3 years)

If FrostGate is involved in a security incident (auth bypass attempt, anomalous
API usage, PII exposure), the logs from the incident window should be preserved
for 3 years regardless of the standard 90-day operational log expiry.

**How to preserve:** copy the relevant log range to a separate immutable archive
bucket at incident declaration time. Do not rely on the operational log pipeline
to retain them.

---

## Regulatory mapping

| Regulation | Relevant tier | Key requirement |
|---|---|---|
| SOC 2 Type II | Tiers 3, 4, 5, 6 | 1-year availability metrics; 1-year audit log minimum |
| HIPAA | Tiers 4, 5 | 6-year audit log retention; BAA on log store |
| FedRAMP Moderate | Tiers 4, 5, 6 | 3-year audit log; FIPS-compliant storage |
| FedRAMP High | Tiers 4, 5, 6 | 3-year audit log; stricter access controls |
| GDPR / CCPA | Tiers 1, 2 | Data minimization — don't retain operational logs longer than necessary |
| PCI DSS | Tiers 1, 4, 6 | 1-year log retention; 3-month immediate access |

---

## Implementation checklist

- [ ] Prometheus TSDB `--storage.tsdb.retention.time=365d` (or remote_write equivalent)
- [ ] Grafana Tempo / Jaeger retention set to 30 days maximum
- [ ] Log shipper TTL / index lifecycle set to 90 days for operational index
- [ ] Separate immutable index / bucket for audit log entries (7-year retention)
- [ ] S3 Object Lock or equivalent enabled on audit archive bucket
- [ ] Access logging enabled on audit archive bucket
- [ ] Incident log preservation procedure documented in runbook
- [ ] Retention policy reviewed annually by compliance officer
