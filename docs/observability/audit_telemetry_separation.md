# Audit Event Telemetry Separation

## Why this document exists

FrostGate uses the same Prometheus + OTel + structured-log stack for both
**operational observability** (is the system healthy?) and **compliance evidence**
(did this regulated operation happen, and can we prove it?). These two concerns
share infrastructure today but must remain logically and legally separate.

This document defines the boundary so it cannot be crossed accidentally.

---

## The two planes

### Operational telemetry

| Type | Examples | Purpose |
|---|---|---|
| Metrics | `frostgate_ingestion_requests_total`, `frostgate_provider_latency_seconds` | Capacity, SLO monitoring, alerting |
| Traces | OTel spans, `frostgate.ingestion` span | Debugging, latency profiling |
| Structured logs | Per-request log lines with `trace_id`, `duration_ms` | On-call investigation |

**Retention:** 30–90 days (see `docs/observability/retention_policy.md`).
**Mutability:** can be sampled, dropped, aggregated, and expired without legal consequence.
**Evidentiary value:** none — these are probabilistic aggregates, not records of fact.

### Audit telemetry

| Type | Examples | Purpose |
|---|---|---|
| Audit log entries | Document ingested, policy evaluated, export generated | Compliance evidence, forensic investigation |
| Merkle-anchored audit chain | Per-event hash chain | Tamper detection, chain of custody |
| Audit export records | JSONL export with `frostgate_audit_export_total` | Regulatory submission |

**Retention:** 7 years minimum (SOC 2, HIPAA, FedRAMP). See `docs/observability/retention_policy.md`.
**Mutability:** immutable. No sampling. No aggregation that loses individual records.
**Evidentiary value:** high — these are the legal record of what FrostGate did.

---

## What `frostgate_audit_export_total` measures — and what it does not

`frostgate_audit_export_total` tracks the **operational health of the audit export pipeline**:
- How many export jobs ran
- Whether they succeeded or failed
- How long they took

It does **not** contain audit records, document hashes, or provenance chains.
It answers "is the audit export system working?" not "what was in the audit export?"

The actual audit records live in the audit log store (outside the metrics stack).

---

## Rules: what must not cross the boundary

### Audit data must never appear in operational telemetry

| Prohibited | Reason |
|---|---|
| Document content in metric labels | Unbounded cardinality + retention mismatch |
| Document hashes in span attributes | OTel trace retention is short; audit hashes need 7-year retention |
| Tenant PII in structured log `extra=` | Operational logs expire; PII retention requires separate policy |
| Raw policy decisions in Prometheus counters | Aggregation destroys evidentiary precision |
| Audit event contents in Grafana dashboards | Operational dashboards may be accessible to non-compliance personnel |

### Operational telemetry must never be mistaken for audit evidence

- An OTel span for `frostgate.ingestion` is **not** an audit record of that ingestion.
- A Prometheus counter increment is **not** a legally defensible record of the event it counts.
- Structured log lines are not immutable — they can be dropped by a misconfigured log router.

If a compliance officer or auditor asks "did this document get ingested?", the answer
comes from the audit log, not from Prometheus or Grafana.

---

## Infrastructure sharing guidance

Sharing Prometheus / Grafana / Jaeger between audit-adjacent and operational metrics
is **acceptable today** under these conditions:

1. No audit record content (hashes, document IDs, policy decisions) flows into the
   shared Prometheus TSDB.
2. The audit log store has an independent retention/backup policy enforced at the
   storage layer, not just at the application layer.
3. Access controls on Grafana dashboards are scoped: operational dashboards should
   not expose audit chain details even if both are routed to the same backend.
4. Audit export telemetry (`frostgate_audit_export_*`) is labeled clearly as
   operational health metrics, not as audit records.

In air-gapped or GovCon deployments, separate the metrics backends entirely to
eliminate any risk of cross-contamination. See `docs/observability/deployment_topology.md`.

---

## Separation checklist for new features

When adding a new pipeline stage that touches regulated data:

- [ ] Does the OTel span for this stage include any document content, PII, or
      cryptographic material as attributes? (Must not.)
- [ ] Does any new metric label carry a per-document or per-user identifier? (Must not.)
- [ ] If a new audit record type is introduced, is its retention path separate from
      the operational log pipeline?
- [ ] Is the new pipeline stage's operational health metric named distinctly from
      the audit record it generates? (e.g. `frostgate_ingestion_requests_total`
      for health, not `frostgate_ingestion_events_total` which sounds like a record count.)
- [ ] Has the compliance officer been notified if the new stage changes what gets
      recorded in the audit chain?
