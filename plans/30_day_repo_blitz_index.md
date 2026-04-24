# FrostGate 30-Day Repo Blitz

## Target Outcome (Controlled Beta)

SSO login → plane/gateway enforced access → one real local-agent telemetry signal → searchable evidence/reporting → tenant-safe grounded RAG on ingested docs → per-tenant usage attribution.

This is viable for controlled beta. It is **not** HIPAA-ready or bank-ready.

---

## Phase 1 — Lock Core Invariants

### 1.0 Tenant Isolation
- 1.1 Remove Optional tenant_id ✅ completed
- 1.2 Enforce tenant_id at entry points ✅ completed
- 1.3 Audit read paths ✅ completed
- 1.4 Audit export paths ✅ completed
- 1.5 Background job isolation ✅ completed

### 2.0 Auth Boundary
- 2.1 Remove human auth from core ✅ completed
- 2.2 Enforce gateway-only access ✅ completed

### 3.0 CI Stability
- 3.1 Fix import paths ✅ completed
- 3.2 Remove flaky tests ✅ completed
- 3.3 Lock fg-fast ✅ completed

### 4.0 Production Validation
- 4.1 Enforce required env vars ✅ completed
- 4.2 Remove silent defaults ✅ completed

---

## Phase 2 — Critical Hardening Gaps

### 5.0 Infrastructure
- 5.1 Docker compose cleanup ✅ completed
- 5.2 Service networking and boundary hardening (active blocker)
- 5.3 Plane boundary enforcement

### 6.0 Auth Flow
- 6.1 Keycloak integration ✅ completed
- 6.2 End-to-end auth flow ✅ completed
- 6.3 OIDC hardening and key rotation

### 7.0 Observability
- 7.1 Structured logging ✅ completed
- 7.2 End-to-end request tracing ✅ completed
- 7.3 Distributed request tracing across async boundaries ✅ completed

### 8.0 Health
- 8.1 Health endpoints ✅ completed

### 15.0 Plan Integrity (moved forward)
- 15.1 Plan/state integrity gate
- 15.2 Non-bypass tester journey enforcement
- 15.3 Runtime verification classification
- 15.4 Readiness fail-closed for enabled dependencies

---

## Phase 3 — Testability

### 9.0 Core Flows
- 9.1 Create tenant through supported product path ✅ completed
- 9.2 Run primary audit/control flow ✅ completed
- 9.3 Retrieve and export resulting artifacts ✅ completed

### 10.0 Tester Kit
- 10.1 Repeatable seed/bootstrap script ✅ completed
- 10.2 Tester collection and quickstart ✅ completed

---

## Phase 4 — Monetization That Supports Product

### 12.0 Access Control
- 12.1 Customer credential issuance/revoke/rotate with tenant-scoped enforcement
- 12.2 Per-tenant usage attribution with query/export support

### 13.0 Billing
- 13.1 Minimal billing integration (single pricing model)

### 14.0 Feedback
- 14.1 High-value user behavior logging
- 14.2 Triage workflow (doc + severity rubric + operator workflow + backlog rule)

---

## Phase 5 — First Product Surface and RAG

### 17.0 Local Agent MVP
- 17.1 Agent collector framework
- 17.2 First real collector (single telemetry class)
- 17.3 Agent evidence ingestion path
- 17.4 Agent lifecycle controls
- 17.5 Agent observability

### 18.0 Server-side Agent / Control Execution
- 18.1 Server-side job/worker identity
- 18.2 Server-side control execution path
- 18.3 Operator-triggered run path
- 18.4 Audit trail for server-side agent actions

### 19.0 Evidence and Operator Reporting
- 19.1 Operator activity timeline
- 19.2 Evidence export bundle
- 19.3 Usage evidence summary
- 19.4 Admin/operator evidence quickstart

### 16.0 RAG (usable-first, hardening-later)
- 16.0 Real retrieval substrate
- 16.1 Corpus ingestion integrity
- 16.2 Chunking and metadata fidelity
- 16.3 Retrieval tenant isolation
- 16.4 Answer grounding and citation contract
- 16.5 Retrieval evaluation dataset and thresholds
- 16.6 No-answer and insufficient-context behavior
- 16.7 Corpus update/delete/reindex lifecycle
- 16.8 Prompt injection and poisoned-document resistance
- 16.9 Retrieval latency and cost guardrails
- 16.10 Operator/debug answer provenance

### 11.0 Error Quality
- 11.1 Explicit actionable errors in primary flows

---

## Phase 6 — Regulated Readiness Controls

### 20.0 Regulated Readiness Controls
- 20.1 Control mapping
- 20.2 Sensitive data handling
- 20.3 Retention and audit evidence policy surfaces
- 20.4 Encryption and key management gaps
- 20.5 Deployment/compliance prerequisites