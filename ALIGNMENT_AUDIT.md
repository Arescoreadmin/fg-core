# FrostGate-Core Blueprint v2 Alignment Audit (Staged)

## Executive Verdict
This repository is **~25% aligned** with Blueprint v2. It is **not safe to call a control plane** yet. The codebase has a functional core API with tenant-bound decisions, audit logging, and a basic evidence chain, but it lacks contract enforcement for core APIs/events/artifacts, missing required governance interfaces, no drift engine, and no container-per-feature separation for the core control-plane services.

## Staged Blueprint (MVP 1/2/3 + Complete)

### Stage 0 — Foundation (Non‑negotiable)
**Requires:**
- Container-per-feature (no shared deps)
- AuthN/AuthZ w/ tenant binding
- Deterministic startup/health
- Single deployment topology
- No module → core DB access

**Gate:** Core + 1 module deploys reliably; no cross-tenant leakage.

### MVP 1 — Authoritative Control Plane
**Requires:**
- Single decision pipeline
- Policy evaluation (OPA at minimum)
- Policy versioning (hash)
- Governance API for policy load/pin
- `/defend` + `/feed` or equivalent
- OpenAPI/gRPC spec for core APIs
- Evidence artifact per decision

**Gate:** You can prove why a decision happened via artifacts.

### MVP 2 — Governance + Drift Control
**Requires:**
- Policy + config registry (versioned, immutable)
- Rollout primitives (pin/stage/rollback)
- Event schemas for NATS subjects
- Artifact schemas (findings/decisions)
- CI gate for schema drift
- Drift detection (blueprint + contract)
- Deterministic simulation validator

**Gate:** Drift is detected automatically; CI blocks violations.

### MVP 3 — Audit‑Grade Evidence & Continuous Compliance
**Requires:**
- Append‑only evidence ledger
- Hash chaining + Merkle roots
- Verification API
- Control mappings (800‑53/171)
- Signed artifacts, module identity, replay protection
- DLQ treated as compliance failure

**Gate:** Auditor can verify evidence independently.

### Complete — Enterprise/DoD Grade
**Requires:**
- Exceptions + break‑glass workflows
- Change impact simulation
- Air‑gapped mode + offline verification
- Tenant sharding + performance SLOs
- Full governance UI (read‑only by default)

**Gate:** Continuous compliance; evidence history creates switching cost.

---

## Blueprint Requirement Table

| Requirement | Status | Evidence / Absence | Consequence |
|---|---|---|---|
| **Container‑per‑feature core control plane** (core api/policy/evidence/orchestrator/ui) | **RED** | Single `frostgate-core` service in compose; no separate core policy/evidence/orchestrator containers. | Monolith drift, no isolation of policy/evidence/orchestration duties. |
| **Backbone services (NATS/Redis/Postgres)** | **YELLOW** | NATS/Redis/Postgres are present in compose; no object store configured. | Partial backbone, missing artifact blob store. |
| **Modules (`fg-mod-*`)** | **RED** | No `modules/` directory in repo tree. | No data plane isolation or contract boundary enforcement. |
| **No shared utils container** | **UNKNOWN** | Not assessable without container manifests per service. | Risk of implicit shared deps remains. |
| **No module → core DB access** | **UNKNOWN** | No module containers present to evaluate. | Cannot prove isolation. |
| **Core never shells out into modules** | **UNKNOWN** | No modules present. | Cannot prove this invariant. |
| **Cross‑service comms only gRPC/REST + NATS** | **YELLOW** | NATS bus exists in code; no enforced contract for subjects. | Event contract drift likely. |
| **Governance objects (policy/config/contract/rollout/exception)** | **RED** | Only policy change requests exist; no config, contracts registry, rollout plans, or exceptions. | Governance is incomplete and non‑auditable. |
| **Change control pipeline (simulation + compatibility + evidence)** | **RED** | Governance APIs do not run simulation or compatibility checks; no evidence artifacts. | Changes can be applied without required controls. |
| **API contract enforced** | **YELLOW** | Admin OpenAPI contract exists; core API contract is missing. | Core API can drift silently. |
| **Event contract enforced (NATS)** | **RED** | NATS message schema is only defined in code, no schema files or CI gate. | Schema drift and incompatibility in async paths. |
| **Artifact contract enforced** | **RED** | Evidence chain exists in DB, no artifact schemas or signature verification. | Evidence is non‑verifiable, audit risk. |
| **Auth fail‑closed + constant‑time compare** | **GREEN** | Constant‑time compare in auth; key validation implemented. | Solid for key validation. |
| **Tenant binding mandatory on every request/event** | **YELLOW** | Tenant binding enforced on `/defend` and `/ingest`, but defaulting occurs in non‑prod. | Risk of implicit tenant in testing and drift into prod. |
| **RBAC enforced server‑side** | **YELLOW** | Scopes enforced in core/admin routes, but governance only checks one scope. | Partial, not comprehensive. |
| **Policy: single evaluation path** | **RED** | `engine/pipeline.py` declares single path but `/defend` and `/ingest` call `engine.evaluate` directly. | Decision drift and inconsistent outputs. |
| **Evidence: append‑only + immutable** | **YELLOW** | Hash chain exists in decisions table; no immutable storage or signatures. | Tamper resistance weak. |
| **Backpressure + DLQ** | **RED** | NATS ingestion has no DLQ or backpressure enforcement. | Silent drops and audit gaps under load. |
| **Drift detection (blueprint/contract/policy/config/evidence/infra)** | **RED** | No blueprint drift gate; release gate checks contracts/scorecard only. | Drift can accumulate undetected. |
| **CI contract checks** | **YELLOW** | `release_gate.py` runs contracts-gen/diff/fg-contract. | Only admin contracts are covered. |
| **Integration smoke (compose + /health + /defend + /feed + NATS loop)** | **YELLOW** | Compose exists; no evidence of NATS loop or `/feed` verification. | Integration gaps. |
| **Evidence verification** | **YELLOW** | Evidence chain verifier exists per tenant; no signature or Merkle verification API. | Evidence not audit‑grade. |
| **OPA compile + policy tests** | **RED** | PSS file is placeholder; no OPA bundles/tests. | No enforceable policy guardrail. |
| **Repo layout boundaries** | **RED** | Layout does not match `core/`, `modules/`, `contracts/` split required by blueprint. | Hard to enforce boundaries. |
| **Governance Interfaces** (`/policy/rollout`, `/policy/pin`, `/exceptions`, `/evidence/verify`, `/drift`, `/contracts/status`) | **RED** | Only `/governance/changes` and `/governance/changes/{id}/approve` exist. | Governance is incomplete; compliance claims invalid. |
| **Strictness defaults (signed/versioned/attributable)** | **RED** | No artifact signing; limited versioning of policy changes. | Not enterprise‑grade. |

---

## Repo Reality Scan (What Actually Exists)

### Control Plane Services & Containers
- **Core API:** `api/` service with `/defend`, `/ingest`, governance routes.
- **Admin Gateway + Console:** Separate containers exist in compose.
- **NATS/Redis/Postgres:** Wired in compose.
- **No core policy/evidence/orchestrator containers.**

### Contracts
- **Admin API contract**: `contracts/admin/openapi.json` + schemas.
- **No core API contract, no NATS event schemas, no artifact schemas.**

### Evidence
- **Hash‑chained decision records** via `DecisionRecord` and `evidence_chain`.
- **No signatures, no Merkle batches, no evidence verification API.**

### Governance
- **Policy change request workflow** with approvals.
- **No rollouts, pins, exceptions, or compatibility/simulation checks.**

### CI/CD Gates
- **Release gate** runs contracts-gen/diff and a scorecard drift check.
- **No drift engine for blueprint requirements or module import boundaries.**

---

## Control Plane Sanity Check

- **Single policy decision path?** **NO.** `/defend` and `/ingest` call `engine.evaluate` directly while `engine/pipeline.py` claims to be the single path.
- **One source of truth for tenant/policy/config/rollout?** **NO.** Tenant binding exists, but policies/configs are not versioned/pinned by tenant.
- **Modules subordinate to core?** **UNKNOWN.** No modules exist.
- **Evidence append‑only and tamper‑evident?** **PARTIAL.** Hash chaining exists, but no immutable store or signatures.
- **Auditor can reconstruct “why”?** **PARTIAL.** Decision records have request/response JSON, but no required artifact schema or versioning.

---

## Drift & Lie Detection (Explicit)

**LIES / OVER‑PROMISES**
- Docs claim OPA/Conftest policies; repo only has a placeholder PSS YAML.
- Pipeline claims a single decision path, but endpoints bypass it.

**SILENTLY LOAD‑BEARING TODOs**
- NATS message schema exists only in code; no external schema or CI enforcement.

---

## Alignment Plan (Executable, Not Aspirational)

### 1) Immediate Correctness Fixes (P0)
1. **Enforce single decision pipeline.**
   - Route `/defend` and `/ingest` to `engine/pipeline.evaluate`.
2. **Create core API contract.**
   - Add `contracts/core/openapi.json` and generate from core schemas.
3. **Add event & artifact schemas.**
   - Create `contracts/events/` and `contracts/artifacts/` with JSON Schema/Protobuf definitions.
4. **Add drift_check tool.**
   - Fail CI if: missing core specs, missing event schemas, missing artifact schemas, or module import violations.

### 2) Control‑Plane Unification
5. **Split core services into containers.**
   - `fg-core-api`, `fg-core-policy`, `fg-core-evidence`, `fg-core-orchestrator`, `fg-core-ui`.
6. **Add governance interfaces.**
   - `/policy/rollout`, `/policy/pin`, `/exceptions`, `/evidence/verify`, `/drift`, `/contracts/status`.
7. **Add policy registry + config registry.**
   - Versioned, immutable with hash pinning.

### 3) Audit/Compliance Hardening
8. **Signed artifacts + module identity.**
   - Add signing keys, verify signatures in CI and runtime.
9. **Evidence ledger hardening.**
   - Merkle batches + verification API.
10. **DLQ + backpressure enforcement.**
   - NATS consumer must route failures and track in compliance.

### 4) Scalability & Rollout Safety
11. **Deterministic simulation + replay in CI.**
12. **Tenant cohort rollouts with rollback tested.**

---

## ROI & Risk Scoring (Top 10)

1. **Single decision pipeline enforcement** — Risk: High, ROI: Fast, Complexity: Low.
2. **Core API contract + CI gate** — Risk: High, ROI: Fast, Complexity: Medium.
3. **Event + artifact schema registry** — Risk: High, ROI: Fast, Complexity: Medium.
4. **Drift_check CI gate** — Risk: High, ROI: Fast, Complexity: Medium.
5. **Governance rollout/pin/exception APIs** — Risk: High, ROI: Medium, Complexity: Medium.
6. **Evidence signing + verification** — Risk: High, ROI: Medium, Complexity: High.
7. **Split core services into containers** — Risk: Medium, ROI: Medium, Complexity: High.
8. **DLQ + backpressure enforcement** — Risk: Medium, ROI: Medium, Complexity: Medium.
9. **Policy/config registry** — Risk: Medium, ROI: Medium, Complexity: High.
10. **Merklized evidence bundles** — Risk: Medium, ROI: Moat, Complexity: High.

---

## What You Should Stop Doing Immediately

- **Stop claiming OPA/Conftest policy enforcement.** It does not exist in the repo.
- **Stop calling the system a control plane.** It lacks required governance and contracts.
- **Stop trusting in‑code message schemas.** Without external schemas and CI gates, drift is guaranteed.
- **Stop relying on implicit tenant defaults in any environment.** Explicit tenant binding must be required everywhere.

