# FrostGate 30-Day Repo Blitz

## Phase 1 — Lock Core Invariants

### 1.0 Tenant Isolation
- 1.1 Remove Optional tenant_id
- 1.2 Enforce tenant_id at entry points
- 1.3 Audit read paths
- 1.4 Audit export paths
- 1.5 Background job isolation

### 2.0 Auth Boundary
- 2.1 Remove human auth from core
- 2.2 Enforce gateway-only access

### 3.0 CI Stability
- 3.1 Fix import paths
- 3.2 Remove flaky tests
- 3.3 Lock fg-fast

### 4.0 Production Validation
- 4.1 Enforce required env vars
- 4.2 Remove silent defaults

---

## Phase 2 — Deployability

### 5.0 Infrastructure
- 5.1 Docker compose cleanup
- 5.2 Service networking

### 6.0 Auth Flow
- 6.1 Keycloak integration
- 6.2 End-to-end auth

### 7.0 Observability
- 7.1 Structured logging
- 7.2 Request tracing
- 7.3 Distributed request tracing across async boundaries

### 8.0 Health
- 8.1 Health endpoints

---

## Phase 3 — Testability

### 9.0 Core Flows
- 9.1 Create tenant through supported product path
- 9.2 Run primary audit/control flow
- 9.3 Retrieve and export resulting artifacts

### 10.0 Tester Kit
- 10.1 Repeatable seed/bootstrap script
- 10.2 Tester collection and quickstart

### 11.0 Error Quality
- 11.1 Explicit actionable errors in primary flows

---

## Phase 4 — Monetization

### 12.0 Access Control
- 12.1 Customer access control via API key or equivalent tenant-scoped credential
- 12.2 Per-tenant usage attribution

### 13.0 Billing
- 13.1 Minimal billing integration

### 14.0 Feedback
- 14.1 High-value user behavior logging
- 14.2 Issue triage workflow

---

## Phase 5 — First AI Client / RAG Readiness

### 15.0 Plan Integrity
- 15.1 Plan/state integrity gate
- 15.2 Non-bypass tester journey enforcement
- 15.3 Runtime verification classification
- 15.4 Readiness fail-closed for enabled dependencies

### 16.0 RAG Readiness
- 16.1 Corpus ingestion integrity
- 16.2 Chunking and metadata fidelity
- 16.3 Retrieval tenant isolation
- 16.4 Answer grounding and citation contract
- 16.5 Retrieval evaluation dataset and thresholds
- 16.6 No-answer and insufficient-context behavior
- 16.7 Corpus update, delete, and reindex lifecycle
- 16.8 Prompt injection and poisoned-document resistance
- 16.9 Retrieval latency and cost guardrails
- 16.10 Operator and debug answer provenance