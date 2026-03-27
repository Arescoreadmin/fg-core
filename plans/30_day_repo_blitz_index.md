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

### 8.0 Health
- 8.1 Health endpoints

---

## Phase 3 — Testability

### 9.0 Core Flows
- 9.1 Create tenant
- 9.2 Run audit
- 9.3 Export result

### 10.0 Tester Kit
- 10.1 Seed script
- 10.2 Postman collection

### 11.0 Error Quality
- 11.1 Explicit errors

---

## Phase 4 — Monetization

### 12.0 Access Control
- 12.1 API keys
- 12.2 Usage tracking

### 13.0 Billing
- 13.1 Stripe integration

### 14.0 Feedback
- 14.1 User behavior logging
- 14.2 Issue triage