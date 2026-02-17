0. Header

Title: FrostGate-Core Blueprint v2 (Staged, Strict)

Blueprint Version: 2.x.x

Contract Authority: contracts/core/openapi.json (prod)
Contract-Authority-SHA256: 872ac45f0a6afe1b7ab7c2a10d31ec32c76ca4c18c11003865ff0110e01474d0
Single Source of Truth: The prod OpenAPI spec above is authoritative. Any conflicting requirements elsewhere are invalid.

Enforced By: tools/align_score.py, tools/drift_check.py, CI job blueprint_gate

1. System Purpose and Planes
1.1 Purpose

Governance + policy + evidence control plane coordinating data-plane modules.

1.2 Planes

Control Plane (Core)

Data Plane Kernel (Core Runtime)

Modules (Executors)

Tooling/Ops

Presentation (UI)

1.3 Non-Goals

(Short list. No essays.)

2. Global Invariants (Apply to all stages)

These are always required once introduced:

Container-per-feature boundaries

Tenant binding mandatory

Single decision pipeline

Contracts required for APIs/events/artifacts

Evidence must be produced for decisions (once MVP1+)

Drift detection gates (once MVP2+)

3. Reference Architecture (Target End-State)

This is where your strict spec belongs, but concise:

3.1 Containers

fg-core-api

fg-core-policy

fg-core-evidence

fg-core-orchestrator

fg-core-ui (optional)

Backbone: nats, redis, db, object-store

Modules: fg-mod-*

3.2 Hard Rules

No shared utils container

No module → core DB

No core → shell-out to modules

Comms: REST/gRPC + NATS only

(Stop here. Don’t stuff governance and drift here. Those go in staged gates.)

4. Staged Requirements (This is the meat)

This must be written as requirements with IDs so tools can enforce them.

Stage 0 — Foundation

Gate: Core deploys reliably; tenant isolation holds.

BP-S0-001 Deterministic startup + probes

BP-S0-002 AuthN/AuthZ fail-closed

BP-S0-003 Tenant binding enforced on all requests

BP-S0-004 Compose/helm topology exists

BP-S0-005 Centralized auditable logs

MVP 1 — Authoritative Decisions + Minimal Evidence

Gate: Every decision is provable via artifacts.

BP-M1-001 Single decision pipeline enforced

BP-M1-002 Policy evaluation exists (OPA minimum)

BP-M1-003 Policy version referenced by hash

BP-M1-004 Core API contract exists + enforced in CI

BP-M1-005 Decision artifact schema exists + enforced

BP-M1-006 Evidence stored immutably (at least append-only semantics)

MVP 2 — Governance + Drift Control

Gate: Drift detected automatically; CI blocks violations.

BP-M2-001 Policy registry (versioned, immutable)

BP-M2-002 Config registry (tenant-scoped, versioned)

BP-M2-003 Rollout primitives: pin/stage/rollback

BP-M2-004 Event schemas registry + CI enforcement

BP-M2-005 Artifact schemas registry + CI enforcement

BP-M2-006 Drift engine exists + CI gate

BP-M2-007 Deterministic simulation validator in CI

MVP 3 — Audit-Grade Evidence + Continuous Compliance

Gate: Auditor can verify independently.

BP-M3-001 Evidence ledger append-only + verifiable

BP-M3-002 Merkle batching + roots

BP-M3-003 Evidence verification API

BP-M3-004 Signed artifacts + module identity verification

BP-M3-005 Replay protection + idempotency enforcement

BP-M3-006 DLQ treated as compliance failure

BP-M3-007 Control mappings 800-53/171 minimum

Complete — DoD / Enterprise Grade

Gate: Continuous compliance; offline verification supported.

BP-C-001 Exceptions workflow (time-boxed, approved)

BP-C-002 Break-glass with auto-expiry + audit artifacts

BP-C-003 Change impact simulation before rollout

BP-C-004 Air-gapped mode + offline verification bundles

BP-C-005 Tenant sharding + performance SLOs

BP-C-006 Governance UI (read-only default; writes audited)

5. Required Governance Interfaces (by stage)

List APIs, but gate them by stage:

MVP2+: /policy/pin, /policy/rollout, /policy/rollback, /drift, /contracts/status

MVP3+: /evidence/verify, /evidence/bundles/{id}

Complete+: /exceptions, /breakglass/*

6. Scoring & Enforcement Rules

This is what makes it “single source of truth”:

align_score.py must map each requirement ID → check

drift_check.py must fail CI for RED items above threshold

“No stage regression” rule
