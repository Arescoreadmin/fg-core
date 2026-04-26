# Triage Workflow — FrostGate Core

**Task:** 14.2  
**Status:** Active  
**Owner:** Platform Engineering  
**Source of truth:** `api/triage.py`, `api/behavior_logging.py`

---

## Purpose

Convert high-value behavior signals into deterministic operator decisions.

```
signal → classify → decision → action
```

Without this workflow, behavior logs are noise. With it, they are leverage.

---

## Severity Rubric

| Severity | Definition | Operator Action |
|----------|-----------|-----------------|
| **HIGH** | Security risk, billing impact, data integrity risk, or systemic failure | Immediate investigation required. Always creates a backlog entry. |
| **MEDIUM** | Degraded experience or repeated signal pattern | Investigation required. Creates backlog entry only when repeated (≥ 3 occurrences, same tenant + event type). |
| **LOW** | Informational; non-blocking; expected noise | No action required. No backlog entry created. |

Severity is **deterministic**: it depends only on `event_type` and stored event count. It is never time-dependent, random, or operator-dependent.

---

## Event → Severity Mapping

| Event Type | Severity | Rationale |
|-----------|----------|-----------|
| `rag.no_answer` | LOW | Expected for low-context queries. Single instances are noise. |
| `rag.low_confidence` | MEDIUM | Indicates retrieval quality degradation. Repeated = systemic issue. |
| `rag.injection_detected` | HIGH | Security signal. Always escalate. |
| `rag.guardrail_triggered` | MEDIUM | Budget or safety limit hit. Repeated = systemic misconfiguration. |
| `billing.invoice_generated` | LOW | Normal success event. No action needed. |
| `auth.credential_rejected` | MEDIUM | May be user error. Repeated = potential abuse. |
| `auth.repeated_failure` | HIGH | Security pattern. Always escalate. |
| *(unknown type)* | LOW | Safe fallback. Unknown types never silently escalate. |

---

## Backlog Rule

**A backlog entry MUST be created when:**

```
severity == HIGH
OR
severity == MEDIUM AND count(tenant_id, event_type) >= 3
```

**A backlog entry MUST NOT be created when:**

```
severity == LOW
OR
severity == MEDIUM AND count(tenant_id, event_type) < 3
```

"Count" means the number of stored events with the same `tenant_id` and `event_type` in `api/behavior_logging._store`. No time window — all stored events count.

---

## Operator Workflow

### Step 1 — Event Ingestion

A high-value event is emitted by a system component:

```python
from api.behavior_logging import log_event, EVENT_RAG_INJECTION_DETECTED, SEVERITY_HIGH

log_event(
    trusted_tenant_id=tenant_id,
    event_type=EVENT_RAG_INJECTION_DETECTED,
    source="api.rag",
    severity=SEVERITY_HIGH,
    idempotency_key=f"inject-{request_id}",
    metadata={"chunk_count": 3, "score": 0},
)
```

### Step 2 — Classification

The event is classified by `api/triage.classify_event()`:

```python
from api.triage import classify_event, should_create_backlog
from api.behavior_logging import query_events

events = query_events(tenant_id, event_type=EVENT_RAG_INJECTION_DETECTED)
decision = classify_event(events[-1])
```

### Step 3 — Decision Routing

```python
if decision.action_required:
    # Alert on-call or platform team
    alert_operator(decision)

if should_create_backlog(decision):
    # Create a tracked issue
    create_backlog_entry(decision)
```

### Step 4 — Resolution

- Investigate root cause using `query_events(tenant_id)` for full event history.
- Resolve the issue in the codebase.
- Close the backlog entry.
- No event records are deleted — they are immutable audit evidence.

---

## Decision Rules (Quick Reference)

| Condition | action_required | backlog_required |
|-----------|----------------|-----------------|
| HIGH severity | ✅ Yes | ✅ Yes |
| MEDIUM severity, first occurrence | ✅ Yes | ❌ No |
| MEDIUM severity, ≥ 3 occurrences | ✅ Yes | ✅ Yes |
| LOW severity | ❌ No | ❌ No |
| Unknown event type | ❌ No | ❌ No |

---

## Example Scenarios

### Scenario A — Prompt Injection Detected

**Signal:** `rag.injection_detected` for `tenant-acme`

**Classification:** HIGH

**Decision:** `action_required=True`, `backlog_required=True`, `reason_code="high_severity_event"`

**Operator action:**
1. Immediately review the RAG retrieval pipeline for `tenant-acme`.
2. Inspect the source documents for injected content.
3. Revoke or quarantine affected ingestion sources.
4. Create and track a security backlog item.

---

### Scenario B — Billing Anomaly (Invoice Generation Failure)

> Note: `billing.invoice_generated` is a success signal (LOW). Failures surface
> via `auth.repeated_failure` or application-level errors, not a dedicated billing
> failure event type (add one if billing failure detection is required).

**Signal:** `auth.repeated_failure` for a billing service tenant

**Classification:** HIGH

**Decision:** `action_required=True`, `backlog_required=True`

**Operator action:**
1. Investigate the authentication pathway for the affected tenant.
2. Check for credential rotation issues or misconfigured integrations.
3. Escalate to billing team if invoice generation is blocked.

---

### Scenario C — Repeated Auth Failure

**Signal:** `auth.credential_rejected` for `tenant-xyz` — 3 occurrences

**Classification:** MEDIUM (1st and 2nd), then MEDIUM with backlog (3rd+)

**Decision at occurrence 3:** `action_required=True`, `backlog_required=True`, `reason_code="medium_severity_repeated_pattern"`

**Operator action:**
1. Check if the tenant has a misconfigured client.
2. Inspect the credential lifecycle (rotation due? expired?).
3. If pattern continues, investigate for credential stuffing or abuse.
4. Create a low-priority backlog entry to follow up with the tenant.

---

### Scenario D — Benign No-Answer

**Signal:** `rag.no_answer` for `tenant-demo`

**Classification:** LOW

**Decision:** `action_required=False`, `backlog_required=False`, `reason_code="low_severity_informational"`

**Operator action:** None. Single no-answer events are expected when queries
lack supporting context in the knowledge base. Monitor for repeated patterns
by querying `api/behavior_logging.query_events(tenant_id, event_type="rag.no_answer")`
if product quality review is needed.

---

## What NOT to Log

Do not create behavior events for:

- Every incoming request
- Successful RAG answers (normal operation)
- Health checks or ping endpoints
- Internal background jobs (unless they fail)
- Raw user queries or document contents

Logging noise defeats the signal-to-noise ratio this workflow depends on.

---

## Implementation Reference

| Component | File |
|-----------|------|
| Event types and logging | `api/behavior_logging.py` |
| Severity mapping and triage decisions | `api/triage.py` |
| Triage tests | `tests/test_triage_workflow.py` |
| Behavior logging tests | `tests/test_behavior_logging.py` |
