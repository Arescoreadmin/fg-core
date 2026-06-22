"""Centralized Prometheus metrics registry for FrostGate.

All metric definitions live here so dashboards, alert rules, and instrumented
code share a single source of truth for label names and bucket boundaries.

Metrics are registered on import; repeated imports are safe (CollectorRegistry
de-dupes by name). Test isolation uses the `REGISTRY` reset mechanism in pytest
conftest when needed.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

_LATENCY_BUCKETS = (
    0.001,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
)

# ---------------------------------------------------------------------------
# Provider metrics
# ---------------------------------------------------------------------------

PROVIDER_REQUESTS = Counter(
    "frostgate_provider_requests_total",
    "Total provider routing requests by provider and outcome",
    ["provider_id", "status"],
)

PROVIDER_LATENCY = Histogram(
    "frostgate_provider_latency_seconds",
    "Provider response latency in seconds",
    ["provider_id"],
    buckets=_LATENCY_BUCKETS,
)

PROVIDER_FAILURES = Counter(
    "frostgate_provider_failures_total",
    "Provider hard failures (timeouts, errors, unavailability)",
    ["provider_id", "failure_type"],
)

# ---------------------------------------------------------------------------
# Retrieval pipeline metrics
# ---------------------------------------------------------------------------

RETRIEVAL_REQUESTS = Counter(
    "frostgate_retrieval_requests_total",
    "Total retrieval requests by mode and outcome",
    ["mode", "status"],
)

RETRIEVAL_LATENCY = Histogram(
    "frostgate_retrieval_latency_seconds",
    "Retrieval pipeline latency in seconds",
    ["mode"],
    buckets=_LATENCY_BUCKETS,
)

RETRIEVAL_CHUNK_COUNT = Histogram(
    "frostgate_retrieval_chunks_returned",
    "Number of chunks returned per retrieval request",
    ["mode"],
    buckets=(0, 1, 2, 5, 10, 20, 50, 100),
)

# ---------------------------------------------------------------------------
# Ingestion pipeline metrics
# ---------------------------------------------------------------------------

INGESTION_REQUESTS = Counter(
    "frostgate_ingestion_requests_total",
    "Total ingestion requests by tenant and outcome",
    ["tenant_id", "doc_type", "status"],
)

INGESTION_LATENCY = Histogram(
    "frostgate_ingestion_latency_seconds",
    "Ingestion pipeline latency in seconds",
    ["doc_type"],
    buckets=_LATENCY_BUCKETS,
)

INGESTION_BYTES = Counter(
    "frostgate_ingestion_bytes_total",
    "Total bytes ingested by document type",
    ["doc_type"],
)

# ---------------------------------------------------------------------------
# Audit pipeline metrics
# ---------------------------------------------------------------------------

AUDIT_EXPORT_TOTAL = Counter(
    "frostgate_audit_export_total",
    "Total audit export generations by tenant and outcome",
    ["tenant_id", "status"],
)

AUDIT_EXPORT_LATENCY = Histogram(
    "frostgate_audit_export_latency_seconds",
    "Audit export generation latency in seconds",
    ["tenant_id"],
    buckets=_LATENCY_BUCKETS,
)

AUDIT_PIPELINE_FAILURES = Counter(
    "frostgate_audit_pipeline_failures_total",
    "Audit pipeline failures by failure type",
    ["failure_type"],
)

# ---------------------------------------------------------------------------
# Provenance validation metrics
# ---------------------------------------------------------------------------

PROVENANCE_VALIDATION_TOTAL = Counter(
    "frostgate_provenance_validation_total",
    "Total provenance validations by result",
    ["result"],  # pass | fail | error
)

PROVENANCE_FAILURE_SPIKE = Gauge(
    "frostgate_provenance_failure_rate_1m",
    "Rolling 1-minute provenance failure rate (0.0–1.0); updated by the validation path",
)

# ---------------------------------------------------------------------------
# HTTP / infrastructure metrics
# ---------------------------------------------------------------------------

HTTP_5XX_TOTAL = Counter(
    "frostgate_http_5xx_total",
    "Total HTTP 5xx responses",
    ["method"],
    # NOTE: path is intentionally excluded — paths containing UUIDs/IDs would
    # produce unbounded label cardinality and a denial-of-wallet billing event.
)

HTTP_REQUEST_DURATION = Histogram(
    "frostgate_http_request_duration_seconds",
    "HTTP request duration including middleware overhead",
    ["method", "status_class"],  # status_class: 2xx | 3xx | 4xx | 5xx
    buckets=_LATENCY_BUCKETS,
)

# ---------------------------------------------------------------------------
# Database / connectivity metrics
# ---------------------------------------------------------------------------

DB_ERRORS_TOTAL = Counter(
    "frostgate_db_errors_total",
    "Database operation errors by operation type",
    ["operation"],
)

DB_QUERY_LATENCY = Histogram(
    "frostgate_db_query_latency_seconds",
    "Database query latency in seconds",
    ["operation"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1.0, 5.0),
)

DB_CONNECTIVITY_FAILURES = Counter(
    "frostgate_db_connectivity_failures_total",
    "Database connectivity failures (connection refused, timeout, etc.)",
)

# ---------------------------------------------------------------------------
# Alerting support: current state gauges
# ---------------------------------------------------------------------------

ACTIVE_CONNECTIONS = Gauge(
    "frostgate_active_connections",
    "Current number of active HTTP connections being processed",
)

INGESTION_QUEUE_DEPTH = Gauge(
    "frostgate_ingestion_queue_depth",
    "Current ingestion queue depth (pending documents)",
)

# ---------------------------------------------------------------------------
# P1.3: Capability enforcement metrics
# No tenant_id label — high cardinality; no sensitive data in telemetry.
# ---------------------------------------------------------------------------

CAPABILITY_CHECKS_TOTAL = Counter(
    "frostgate_capability_checks_total",
    "Total capability enforcement checks by capability and result",
    ["capability", "result"],  # result: granted | denied | dep_failure | unknown
)

CAPABILITY_GRANTS_TOTAL = Counter(
    "frostgate_capability_grants_total",
    "Total capability checks that resolved to granted, by capability and grant source",
    ["capability", "source"],  # source: explicit | bundle | tier
)

CAPABILITY_DENIALS_TOTAL = Counter(
    "frostgate_capability_denials_total",
    "Total capability checks that resolved to denied, by capability and denial reason",
    ["capability", "reason"],  # reason: missing | dep_failure | unknown | no_tenant
)

CAPABILITY_DEPENDENCY_FAILURES_TOTAL = Counter(
    "frostgate_capability_dependency_failures_total",
    "Capability checks denied because a prerequisite capability was missing",
    ["capability", "missing_dep"],
)

CAPABILITY_CACHE_HITS_TOTAL = Counter(
    "frostgate_capability_cache_hits_total",
    "Capability resolver cache hits (tenant capability set served from TTL cache)",
)

CAPABILITY_CACHE_MISSES_TOTAL = Counter(
    "frostgate_capability_cache_misses_total",
    "Capability resolver cache misses (tenant capability set fetched from DB)",
)

# ---------------------------------------------------------------------------
# P1.4: Subscription Assignment Engine metrics
# No tenant_id labels — high cardinality.
# ---------------------------------------------------------------------------

SUBSCRIPTION_CONTRACTS_CREATED_TOTAL = Counter(
    "frostgate_subscription_contracts_created_total",
    "Total subscription contracts created, by SKU package",
    ["sku_package"],
)

SUBSCRIPTION_ITEMS_CREATED_TOTAL = Counter(
    "frostgate_subscription_items_created_total",
    "Total subscription items created, by SKU code",
    ["sku_code"],
)

SUBSCRIPTION_ITEMS_STATUS_CHANGES_TOTAL = Counter(
    "frostgate_subscription_items_status_changes_total",
    "Total subscription item status transitions, by from/to status",
    ["from_status", "to_status"],
)

SUBSCRIPTION_EVENT_LEDGER_ENTRIES_TOTAL = Counter(
    "frostgate_subscription_event_ledger_entries_total",
    "Total immutable ledger entries appended, by event type",
    ["event_type"],
)

SUBSCRIPTION_EXPLAIN_REQUESTS_TOTAL = Counter(
    "frostgate_subscription_explain_requests_total",
    "Total explain-capability requests, by decision result",
    ["result"],  # granted | denied
)

# ---------------------------------------------------------------------------
# P1.5: Billing Integration Layer metrics
# No tenant_id labels — high cardinality.
# ---------------------------------------------------------------------------

BILLING_ACCOUNTS_CREATED_TOTAL = Counter(
    "frostgate_billing_accounts_created_total",
    "Total billing accounts created",
    [],
)

BILLING_SUBSCRIPTION_LINKS_TOTAL = Counter(
    "frostgate_billing_subscription_links_total",
    "Total billing subscription links created",
    [],
)

BILLING_USAGE_EVENTS_TOTAL = Counter(
    "frostgate_billing_usage_events_total",
    "Total usage events recorded, by meter_code",
    ["meter_code"],
)

BILLING_USAGE_REPORT_FAILURES_TOTAL = Counter(
    "frostgate_billing_usage_report_failures_total",
    "Total usage events that failed to report to the provider",
    [],
)

BILLING_WEBHOOKS_TOTAL = Counter(
    "frostgate_billing_webhooks_total",
    "Total billing webhook events received, by event_type",
    ["event_type"],
)

BILLING_WEBHOOK_REPLAY_TOTAL = Counter(
    "frostgate_billing_webhook_replay_total",
    "Total billing webhook events that were replays (already processed)",
    [],
)

BILLING_RECONCILIATION_RUNS_TOTAL = Counter(
    "frostgate_billing_reconciliation_runs_total",
    "Total billing reconciliation runs",
    [],
)

BILLING_RECONCILIATION_FAILURES_TOTAL = Counter(
    "frostgate_billing_reconciliation_failures_total",
    "Total individual reconciliation item failures",
    [],
)

# ---------------------------------------------------------------------------
# PR 13.1: Remediation Management metrics
# No tenant_id labels — high cardinality.
# ---------------------------------------------------------------------------

REMEDIATION_TASKS_CREATED_TOTAL = Counter(
    "frostgate_remediation_tasks_created_total",
    "Total remediation tasks created",
    [],
)

REMEDIATION_TASKS_CLOSED_TOTAL = Counter(
    "frostgate_remediation_tasks_closed_total",
    "Total remediation tasks closed",
    [],
)

REMEDIATION_TASK_UPDATES_TOTAL = Counter(
    "frostgate_remediation_task_updates_total",
    "Total remediation task update operations",
    [],
)

REMEDIATION_TASK_DENIALS_TOTAL = Counter(
    "frostgate_remediation_task_denials_total",
    "Total remediation task operations denied (reference violations, tenant violations)",
    [],
)

# ---------------------------------------------------------------------------
# PR 13.2: Remediation Workflow Engine metrics
# from_status/to_status labels are safe — bounded cardinality (5 states × 5 = 25 max).
# No tenant_id labels.
# ---------------------------------------------------------------------------

REMEDIATION_STATUS_TRANSITIONS_TOTAL = Counter(
    "frostgate_remediation_status_transitions_total",
    "Total valid remediation task status transitions",
    ["from_status", "to_status"],
)

REMEDIATION_INVALID_TRANSITIONS_TOTAL = Counter(
    "frostgate_remediation_invalid_transitions_total",
    "Total rejected remediation task status transition attempts",
    [],
)

# ---------------------------------------------------------------------------
# PR 13.3: Remediation Ownership + SLA metrics
# No tenant_id labels.
# ---------------------------------------------------------------------------

REMEDIATION_ASSIGNMENTS_TOTAL = Counter(
    "frostgate_remediation_assignments_total",
    "Total remediation task owner assignments (first-time)",
    [],
)

REMEDIATION_REASSIGNMENTS_TOTAL = Counter(
    "frostgate_remediation_reassignments_total",
    "Total remediation task owner reassignments",
    [],
)

REMEDIATION_OVERDUE_TASKS_TOTAL = Counter(
    "frostgate_remediation_overdue_tasks_total",
    "Total remediation task overdue detections (incremented at SLA query time when overdue)",
    [],
)

# ---------------------------------------------------------------------------
# PR 13.4: Portal Remediation Integration metrics
# No tenant_id labels — high cardinality.
# ---------------------------------------------------------------------------

PORTAL_REMEDIATION_VIEWS_TOTAL = Counter(
    "frostgate_portal_remediation_views_total",
    "Total portal remediation dashboard and task detail views",
)
PORTAL_COMMENTS_TOTAL = Counter(
    "frostgate_portal_comments_total",
    "Total portal remediation comments added",
)
PORTAL_EVIDENCE_UPLOADS_TOTAL = Counter(
    "frostgate_portal_evidence_uploads_total",
    "Total portal evidence submissions",
)
PORTAL_OWNER_ACKNOWLEDGEMENTS_TOTAL = Counter(
    "frostgate_portal_owner_acknowledgements_total",
    "Total portal ownership acknowledgements",
)
PORTAL_OVERDUE_VIEWS_TOTAL = Counter(
    "frostgate_portal_overdue_views_total",
    "Total portal dashboard views with overdue tasks present",
)

# PR 13.5: Portal Input Hardening — validation failure counters.
# No tenant_id / user labels — bounded cardinality.
PORTAL_VALIDATION_FAILURES_TOTAL = Counter(
    "frostgate_portal_validation_failures_total",
    "Total portal input validation failures (all fields combined)",
)
PORTAL_SHA256_VALIDATION_FAILURES_TOTAL = Counter(
    "frostgate_portal_sha256_validation_failures_total",
    "Total portal evidence SHA256 format validation failures",
)
PORTAL_METADATA_REJECTIONS_TOTAL = Counter(
    "frostgate_portal_metadata_rejections_total",
    "Total portal evidence_metadata payloads rejected for exceeding 8 KB size limit",
)
PORTAL_COMMENT_VALIDATION_FAILURES_TOTAL = Counter(
    "frostgate_portal_comment_validation_failures_total",
    "Total portal comment body validation failures (blank/whitespace-only bodies)",
)

# PR 13.6: Portal Abuse Protection — rate-limit / throttle counters.
# No tenant_id / user labels — bounded cardinality.
PORTAL_RATE_LIMIT_HITS_TOTAL = Counter(
    "frostgate_portal_rate_limit_hits_total",
    "Total portal write requests rejected by rate limiting (all operations combined)",
)
PORTAL_COMMENT_THROTTLES_TOTAL = Counter(
    "frostgate_portal_comment_throttles_total",
    "Total portal comment write operations (create or edit) rejected by rate limiting",
)
PORTAL_EVIDENCE_THROTTLES_TOTAL = Counter(
    "frostgate_portal_evidence_throttles_total",
    "Total portal evidence upload operations rejected by rate limiting",
)
PORTAL_ACKNOWLEDGEMENT_THROTTLES_TOTAL = Counter(
    "frostgate_portal_acknowledgement_throttles_total",
    "Total portal ownership acknowledgement operations rejected by rate limiting",
)

REMEDIATION_SLA_BREACHES_TOTAL = Counter(
    "frostgate_remediation_sla_breaches_total",
    "Total SLA breaches observed",
    [],
)

REMEDIATION_UNASSIGNED_TASKS_TOTAL = Counter(
    "frostgate_remediation_unassigned_tasks_total",
    "Total remediation task unassignment operations",
    [],
)

# PR 13.7: Notification Authority + Unified Timeline
NOTIFICATIONS_SENT_TOTAL = Counter(
    "frostgate_notifications_sent_total",
    "Total notifications sent successfully",
    [],
)
NOTIFICATIONS_FAILED_TOTAL = Counter(
    "frostgate_notifications_failed_total",
    "Total notifications that failed delivery",
    [],
)
NOTIFICATIONS_ACKNOWLEDGED_TOTAL = Counter(
    "frostgate_notifications_acknowledged_total",
    "Total notifications acknowledged by recipients",
    [],
)
TIMELINE_EVENTS_TOTAL = Counter(
    "frostgate_timeline_events_total",
    "Total unified timeline API requests",
    [],
)
SLA_ESCALATIONS_TOTAL = Counter(
    "frostgate_sla_escalations_total",
    "Total SLA escalation notifications sent",
    [],
)

# ---------------------------------------------------------------------------
# PR 14.1: Risk Acceptance Governance metrics
# No tenant_id or user labels — bounded cardinality.
# from_status/to_status labels are safe: ≤7 states × 7 = ≤49 combinations.
# ---------------------------------------------------------------------------

RISK_ACCEPTANCE_TOTAL = Counter(
    "frostgate_risk_acceptance_total",
    "Total risk acceptance records created (all statuses)",
    [],
)

RISK_APPROVED_TOTAL = Counter(
    "frostgate_risk_approved_total",
    "Total risk acceptance records transitioned to approved",
    [],
)

RISK_REJECTED_TOTAL = Counter(
    "frostgate_risk_rejected_total",
    "Total risk acceptance records rejected",
    [],
)

RISK_EXPIRED_TOTAL = Counter(
    "frostgate_risk_expired_total",
    "Total risk acceptance records expired (automatic + manual)",
    [],
)

RISK_REVOKED_TOTAL = Counter(
    "frostgate_risk_revoked_total",
    "Total risk acceptance records revoked",
    [],
)

RISK_REVIEW_DUE_TOTAL = Counter(
    "frostgate_risk_review_due_total",
    "Total risk acceptance review-due detections",
    [],
)

RISK_STATUS_TRANSITIONS_TOTAL = Counter(
    "frostgate_risk_status_transitions_total",
    "Total valid risk acceptance status transitions",
    ["from_status", "to_status"],
)

RISK_INVALID_TRANSITIONS_TOTAL = Counter(
    "frostgate_risk_invalid_transitions_total",
    "Total rejected risk acceptance status transition attempts",
    [],
)

# ---------------------------------------------------------------------------
# PR 14.2 — Risk Governance Engine metrics
# No tenant or user labels; bounded cardinality only.
# ---------------------------------------------------------------------------

RISK_REVIEWS_TOTAL = Counter(
    "frostgate_risk_reviews_total",
    "Total risk acceptance governance reviews created",
    [],
)

RISK_REVIEWS_COMPLETED_TOTAL = Counter(
    "frostgate_risk_reviews_completed_total",
    "Total risk acceptance governance reviews completed or waived",
    [],
)

RISK_REVIEWS_OVERDUE_TOTAL = Counter(
    "frostgate_risk_reviews_overdue_total",
    "Total risk acceptance governance reviews marked overdue",
    [],
)

RISK_APPROVALS_TOTAL = Counter(
    "frostgate_risk_approvals_total",
    "Total risk acceptance approvals created",
    [],
)

RISK_APPROVALS_GRANTED_TOTAL = Counter(
    "frostgate_risk_approvals_granted_total",
    "Total risk acceptance approvals granted",
    [],
)

RISK_APPROVALS_REJECTED_TOTAL = Counter(
    "frostgate_risk_approvals_rejected_total",
    "Total risk acceptance approvals rejected",
    [],
)

RISK_GOVERNANCE_ESCALATIONS_TOTAL = Counter(
    "frostgate_risk_governance_escalations_total",
    "Total risk governance escalations raised",
    [],
)

# ---------------------------------------------------------------------------
# PR 14.3 — Compensating Control Registry metrics
# No tenant or user labels; bounded cardinality only.
# ---------------------------------------------------------------------------

CONTROLS_TOTAL = Counter(
    "frostgate_controls_total",
    "Total compensating controls created",
    [],
)

CONTROLS_VERIFIED_TOTAL = Counter(
    "frostgate_controls_verified_total",
    "Total compensating controls verified",
    [],
)

CONTROLS_EXPIRED_TOTAL = Counter(
    "frostgate_controls_expired_total",
    "Total compensating controls expired (stale verification)",
    [],
)

CONTROLS_REVIEWS_TOTAL = Counter(
    "frostgate_control_reviews_total",
    "Total control reviews created",
    [],
)

CONTROLS_REVIEWS_OVERDUE_TOTAL = Counter(
    "frostgate_control_reviews_overdue_total",
    "Total control reviews marked overdue",
    [],
)

CONTROLS_EVIDENCE_LINKS_TOTAL = Counter(
    "frostgate_control_evidence_links_total",
    "Total evidence records linked to controls",
    [],
)

# ---------------------------------------------------------------------------
# PR 14.4 — Governance Portal metrics
# No tenant or user labels; bounded cardinality only.
# ---------------------------------------------------------------------------

GOVERNANCE_PORTAL_VIEWS_TOTAL = Counter(
    "frostgate_governance_portal_views_total",
    "Total governance portal dashboard views",
    [],
)

GOVERNANCE_PORTAL_RISKS_TOTAL = Counter(
    "frostgate_governance_portal_risks_total",
    "Total governance portal risk read operations",
    [],
)

GOVERNANCE_PORTAL_CONTROLS_TOTAL = Counter(
    "frostgate_governance_portal_controls_total",
    "Total governance portal control read operations",
    [],
)

GOVERNANCE_PORTAL_EVIDENCE_TOTAL = Counter(
    "frostgate_governance_portal_evidence_total",
    "Total governance portal evidence read operations",
    [],
)

GOVERNANCE_PORTAL_ACKNOWLEDGEMENTS_TOTAL = Counter(
    "frostgate_governance_portal_acknowledgements_total",
    "Total governance portal acknowledgements created",
    [],
)

GOVERNANCE_PORTAL_EXPORTS_TOTAL = Counter(
    "frostgate_governance_portal_exports_total",
    "Total governance portal export operations",
    [],
)
