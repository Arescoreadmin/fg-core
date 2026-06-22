# AI Field Assessment: Scoped Enterprise Plan

Date: 2026-06-02

## Review Scope

This plan is based on a repository-wide authored-source inventory and targeted
dependency tracing across:

- `api/` (197 files)
- `services/` (289 files)
- `agent/` (72 files)
- `apps/console/` (208 files)
- `apps/portal/` (42 files)
- `migrations/postgres/` (77 files)
- `tests/` (450 files)
- `docs/` (83 files)

Generated artifacts, dependency trees, caches, and build output were excluded.
The authored Python and TypeScript surface contains approximately 201,879 lines.

This document separates the AI Field Assessment product from the Autonomous AI
Governance Platform. The detailed vulnerability evidence remains in
`docs/ai/FIELD_ASSESSMENT_ENTERPRISE_AUDIT.md`.

## Product Boundary

### AI Field Assessment

Field Assessment is an enterprise assessment execution product. It should own:

- Engagement lifecycle, assessor assignment, playbooks, and QA gates.
- Evidence collection: scans, documents, interviews, observations, and
  questionnaires.
- Evidence normalization, control mapping, findings, confidence, and remediation
  recommendations.
- Signed, versioned, QA-approved assessment reports.
- Customer evidence collaboration and report delivery portal.
- Engagement and reassessment drift, evidence freshness, and assessment history.

Primary modules:

- `api/field_assessment.py`
- `services/field_assessment/`
- `services/connectors/`
- `api/db_models_field_assessment.py`
- `api/db_models_questionnaire.py`
- `api/db_models_drift.py`
- `apps/console/app/field-assessment/`
- `apps/console/components/field-assessment/`
- `apps/portal/`

### Autonomous AI Governance Platform

Autonomous Governance is the continuous post-assessment product. It should own:

- Governance asset registry and topology graph.
- Continuous tenant readiness posture and simulations.
- Governance workflows that persist beyond an engagement.
- Governed RAG corpus, AI assistant, provider routing, and AI plane policy.
- Agent enrollment, telemetry, command execution, rings, missions, and control
  plane.
- Autonomous recommendations, control degradation monitoring, and human approval
  loops.

Primary modules:

- `agent/`
- `api/agent_*`, `api/control_plane*`, `api/ring_router.py`,
  `api/mission_envelope.py`, `api/roe_engine.py`
- `api/governance_assets.py`, `api/governance_graph.py`,
  `api/governance_workflows.py`
- `api/readiness_*`, `services/readiness/`
- `api/rag*`, `services/ai/`, `services/ai_plane_extension/`
- `services/governance_asset_registry/`, `services/governance_graph/`,
  `services/governance_workflows/`

### Mandatory Shared Substrate

Field Assessment does need shared enterprise infrastructure. These are platform
primitives, not Autonomous Governance features:

- Tenant identity, RLS enforcement, and database role safety.
- Human identity boundary, fine-grained RBAC, and actor attribution.
- Immutable audit ledger and request correlation.
- Artifact registry, encrypted object storage, and retention policy.
- Durable job queue, worker leases, retry, cancellation, and dead-letter handling.
- Report signing, versioning, verification, and export.
- Customer account identity and portal session management.
- Outbound request and scanner security policy.

## Current Cross-Tier Coupling

The intended architecture says promotion is the only bridge, but the current
implementation crosses the product boundary early:

1. `api/field_assessment.py` performs inline governance promotion when an
   engagement becomes `delivered`.
2. `services/field_assessment/promotion.py` directly creates governance
   workflows, governance assets, RAG corpus entries, and governance timeline
   events.
3. `services/field_assessment/connectors/msgraph_bridge.py` writes governance
   report rows, asset candidates, auto-promoted assets, and graph rebuilds before
   delivery.
4. `services/field_assessment/timeline.py` directly writes governance timeline
   records.
5. `apps/portal/` exposes governance assets and AI chat beside assessment
   delivery surfaces.

Recommended boundary:

```text
Field Assessment core
    -> immutable assessment.delivered outbox event
    -> optional Governance activation consumer
    -> assets, workflows, graph, RAG, continuous readiness, agents
```

Assessment delivery must succeed without Autonomous Governance being installed or
enabled. Report signing and evidence custody should move into shared platform
packages rather than remain governance-named dependencies.

## Enterprise Blockers

### P0: Containment Before External Use

1. Replace the audio URL proxy with a tenant-bound artifact registry. The current
   proxy can forward `BLOB_READ_WRITE_TOKEN` to an attacker-controlled HTTPS host.
2. Disable arbitrary scanner targets until scans run through an isolated scanner
   control plane with approved targets, DNS validation, private-range blocking,
   redirect checks, quotas, and immutable authorization records.
3. Stop issuing plaintext reusable `client_access_code` values. Replace them with
   hashed, expiring, revocable portal grants and server-side sessions.
4. Stop pre-delivery governance writes. Convert them into assessment-owned
   records or optional post-delivery events.
5. Fix report creation so the report row and audit event commit atomically.

### P1: Trusted Pilot Foundation

1. Add RLS and startup assertions for `fa_drift_baselines`, `fa_drift_alerts`, and
   `fa_connector_schedules`, with Postgres cross-tenant tests.
2. Add composite tenant-aware foreign keys, state constraints, score constraints,
   and unique active-baseline enforcement.
3. Replace shared-key actor attribution with signed gateway actor context.
4. Split `governance:write` into Field Assessment permissions such as
   `assessment:create`, `assessment:transition`, `evidence:write`,
   `evidence:amend`, `scan:authorize`, `baseline:pin`, `report:generate`,
   `report:qa_approve`, and `portal:admin`.
5. Add a mutation-to-audit matrix. Every mutation must capture actor, request ID,
   reason, before, after, and outcome in the same transaction.
6. Anchor Field Assessment audit events into the shared tamper-evident ledger.
7. Enforce delivered-evidence and finalized-report immutability at the database
   layer. Post-delivery changes must be amendments or supersessions.
8. Replace `_MSGRAPH_RUNS` and FastAPI background jobs with durable tenant-bound
   jobs and workers. Authorize run status by `(tenant_id, engagement_id, run_id)`.

### P2: Enterprise Production

1. Build a governed document pipeline: upload, malware scan, classification,
   extraction, review, approval, evidence linking, retention, and provenance.
2. Add legal hold, retention schedules, purge proof, destruction records, and
   WORM-style storage options.
3. Finish the portal identity model: stable customer accounts, portal accounts,
   MFA readiness, lockout, revocation, session inventory, and audit trail.
4. Add executing scheduler workers. The current connector scheduler stores
   schedules but does not execute them.
5. Generate console and portal clients from OpenAPI and add BFF integration tests.
6. Add operational dashboards for job failures, evidence freshness, assessment
   backlog, QA aging, connector health, and SLA compliance.
7. Add evidence requests, assessor assignment, review queues, approval workflows,
   and amendment UX.

## What To Defer

These Autonomous Governance capabilities are not launch requirements for an
enterprise Field Assessment product:

- Endpoint agent fleet, mobile/desktop attestation, command bus, rings, missions,
  and rules of engagement.
- Continuous readiness simulations and autonomous control degradation alerts.
- Full governance asset topology UI.
- Autonomous remediation agents.
- Governed AI assistant and RAG retrieval product.
- Provider routing, AI plane policy, model evaluation lab, and runtime guardrails.
- Organization-wide workforce AI behavior analytics.

Keep only the optional post-delivery activation contract now. Assess these
capabilities separately later.

## Field Assessment Moat

The strongest defensibility available before Autonomous Governance is:

1. Longitudinal evidence graph across assessments: evidence, controls, findings,
   amendments, signed reports, owners, and remediation outcomes.
2. Regulator- and insurer-ready verification bundles with hashes, signatures,
   custody history, retention proof, and replayable scoring.
3. Reassessment intelligence: evidence aging, control regression, recurring root
   causes, remediation velocity, and confidence decay.
4. Consent-based industry benchmarks: evidence quality, maturity percentiles,
   control adoption, and remediation speed by sector.
5. Deterministic next-best evidence requests and remediation recommendations with
   human approval.

This moat compounds with every completed assessment and does not require an
autonomous agent platform to be valuable.

## Delivery Order

| Gate | Required work | Estimate |
|---|---|---|
| Internal demo | Existing product, restricted targets only | Ready |
| Controlled pilot | P0 containment, drift RLS, atomic audit, tenant-bound jobs | 2-4 weeks |
| Enterprise production | P1 foundation plus portal identity, artifact vault, retention, document pipeline, observability | 8-14 weeks |
| Regulated enterprise | Legal hold, WORM options, verification bundles, formal controls evidence, penetration testing, operational runbooks | 3-5 months |

The fastest credible path is to make Field Assessment independently deployable,
then connect Autonomous Governance through a durable post-delivery event.
