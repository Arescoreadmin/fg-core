# Governance Execution Constitution

**Established:** PR 18.8.3 — Closed-Loop Governance Execution Engine
**Status:** Permanent — inherited by all future execution PRs

---

## Foundational Rules

These rules are permanent and may not be violated by any future PR that builds on the execution substrate.

### 1. The Governance Digital Twin Is Immutable

The `GovernanceDigitalTwinSnapshot` is the canonical governance state record.
Execution consumes simulation results derived from immutable snapshots.
Execution never edits, replaces, or mutates canonical state.
All governance mutations are recorded as governed execution decisions — never as direct state writes.

### 2. The Simulation Is Immutable

The `SimulationResult` that seeds an `ExecutionPlan` is read-only and must not be altered during execution.
Execution plans are derived from simulations. Simulations are not re-derived from execution.
The `simulation_fingerprint` in every plan and run is the integrity anchor to the original simulation.

### 3. Execution Evidence First

No execution step may be recorded as Completed without an evidence declaration.
Evidence is the authoritative basis for every governance decision.
Absence of evidence produces `ExecutionOutcomeConfidence.UNKNOWN` — it does not produce success.

### 4. Approval Required

Every `ExecutionPlan` must have at least one `ExecutionApprovalRequirement` satisfied before
an `ExecutionRun` may be created. `create_run()` raises `ExecutionValidationError` if
approval requirements are not met.
No approval bypass mechanism is permitted.

### 5. Authority Required

Every `ExecutionStep` must declare a non-empty `authority_required`.
The `validate_execution_plan()` function enforces this at ERROR severity (fail-closed).
Empty authority is a configuration defect, not a runtime condition.

### 6. Replay Required

Every execution lifecycle produces an `ExecutionReplayPackage`.
Replay packages must be self-contained: they carry the plan, run, verifications, measurements,
decision ledger, and validation report needed to audit and reconstruct the execution record.
Identical inputs must produce identical `execution_fingerprint` values.

### 7. Rollback Required

Every `ExecutionPlan` must be produced with an `ExecutionRollbackPlan` with `rollback_ready=True`.
The planner enforces this unconditionally.
No plan without a rollback plan may proceed to execution.

### 8. Verification Required

All `ExecutionStep` objects produced by the planner have `verification_required=True`.
Every completed step should have a corresponding `ExecutionVerification` record.
Missing verifications trigger a WARNING-severity finding in the validator.

### 9. Measurement Required

Every `ExecutionRun` must produce at least one `ExecutionMeasurement` before archiving.
Measurements close the governance feedback loop from execution back to evidence.

### 10. Fail Closed

If `ExecutionValidationReport.highest_severity` is `ERROR` or `FATAL`, the engine must raise
`ExecutionValidationError` before returning any result. Partial or corrupted execution plans
must never be returned. Unknown states are always preferable to fabricated states.

### 11. UNKNOWN Over Fabrication

If outcome confidence cannot be proven from authoritative evidence, the confidence must be
`ExecutionOutcomeConfidence.UNKNOWN`.
Fabricating confidence values (`PROVEN` or `INFERRED` without backing) is prohibited.
Execution measurement must degrade gracefully — UNKNOWN is a valid, required outcome.

### 12. Tenant Isolation

An execution plan may only operate on entities belonging to its declared `tenant_id`.
Cross-tenant step operations are `FATAL` and cause fail-closed behavior.
Execution results must never leak governance state across tenant boundaries.
Tenant isolation is checked at FATAL severity by `validate_execution_plan()`.

### 13. Version Everything

All execution objects carry version constants: `GOVERNANCE_EXECUTION_VERSION`,
`GOVERNANCE_EXECUTION_PLANNER_VERSION`, `GOVERNANCE_EXECUTION_VALIDATOR_VERSION`,
`GOVERNANCE_EXECUTION_SCHEMA_VERSION`, `GOVERNANCE_EXECUTION_REPLAY_VERSION`, and
`GOVERNANCE_EXECUTION_MANIFEST_VERSION`. Version strings must never be empty at runtime.

### 14. Deterministic Ordering

All collections (steps, rollback steps, gates, approval requirements) must be sorted
by a stable, deterministic key before hashing or export.
No set iteration. No dict insertion ordering. Canonical ordering is mandatory for
fingerprint reproducibility.

### 15. No Autonomous Execution

The execution engine records governed execution decisions — it does not execute
infrastructure changes, run scripts, or provision resources.
`GovernanceExecutionService.replay()` raises `NotImplementedError` because replay
requires the original snapshot context, which must be supplied explicitly.
Autonomous execution is permanently reserved for future explicit governance action.

### 16. No Hidden Decisions

Every state transition produces an `ExecutionAuditRecord` with `before_state`, `after_state`,
`actor`, `authority`, `reason`, and a SHA-256 `fingerprint`.
No state change may occur without a corresponding audit trail.
Hidden governance decisions violate this constitution.

### 17. No AI-Generated Governance

The execution engine must not produce AI-generated approval decisions, AI-inferred authority
assignments, AI-synthesized evidence, or AI-generated rollback plans.
Every governance decision must trace back to an explicit human or system authority with a
declared `authority` field. No AI agent may act as an approver or authority without explicit
system configuration outside this engine.

---

## Extension Points

The following capabilities are reserved but not implemented in PR 18.8.3:

| Capability | Reserved For |
|---|---|
| Adaptive Execution (dynamic step reordering) | Future PR |
| Policy Optimization (evidence-driven policy updates) | Future PR |
| Agent Execution (approved agent as approver) | Future PR |
| Autonomous Remediation | Requires explicit AGI governance PR |
| Predictive Scheduling (risk-aware scheduling) | Future PR |
| Continuous Optimization (feedback loop learning) | Future PR |
| Multi-Agent Governance (agent swarm approval) | Requires AGI governance PR |
| Human Override (emergency break-glass execution) | Future PR |
| AGI Supervisory Controls | Requires dedicated AGI governance substrate |
| Recursive Governance (execution governing execution) | Future PR |

Extension points are stubs only. Implementing them in this package without a dedicated PR violates this constitution.

---

## Governing Data Flow

```
Authority Declaration
    ↓
Evidence Anchoring
    ↓
Governance Digital Twin Snapshot  (immutable)
    ↓
Simulation + Scenario Overlay     (PR 18.8.2, immutable after creation)
    ↓
SimulationResult                  (read-only input to execution engine)
    ↓
ExecutionPlan                     (planner.py — deterministic from SimulationResult)
    ↓
Approval Workflow                 (approvals.py — multi-party, authority-gated)
    ↓
ExecutionRun                      (execution.py — state machine, fail-closed)
    ↓
ExecutionVerification             (verification.py — evidence-first)
    ↓
ExecutionMeasurement              (measurement.py — UNKNOWN if unproven)
    ↓
ExecutionDecisionLedger           (append-only decision record)
    ↓
ExecutionReplayPackage            (replay.py — deterministic, self-contained)
```

---

## State Machine

```
Draft → Validated → AwaitingApproval → Approved → Scheduled
    → Executing → Verifying → Completed → Measured → Archived

Executing → Failed → Rollback → Verification → Closed
Rollback → Closed
```

Terminal states: `Archived`, `Closed`.
All transitions validated by `registry.EXECUTION_STATE_TRANSITIONS`.
Invalid transitions raise `ExecutionValidationError`.

---

## SHA-256 Fingerprinting

All fingerprints use `canonical_json_bytes` (sort_keys=True) and the domain prefix
`FG_GOVERNANCE_EXECUTION_V1` for domain separation.

Fingerprint hierarchy:
- `compute_step_hash` — per step
- `compute_plan_fingerprint` — over sorted step hashes
- `compute_run_fingerprint` — over stable run fields + sorted approval hashes
- `compute_execution_fingerprint` — master fingerprint (plan + run + verifications + measurements)
- `compute_replay_fingerprint` — replay package integrity

No cryptographic signing — SHA-256 is used for content-addressing only (no key material).

---

## MCIM Authority

MCIM remains the metadata authority for all execution objects.
Execution must not create parallel metadata registries.
New execution object types must be registered in `mcim_registration.py` under the established
`MCIM-18.8.3-EXEC-*` scheme.

Current MCIM registrations (PR 18.8.3):
- `MCIM-18.8.3-EXEC-PLAN`
- `MCIM-18.8.3-EXEC-RUN`
- `MCIM-18.8.3-EXEC-DECISION`
- `MCIM-18.8.3-EXEC-VERIFICATION`
- `MCIM-18.8.3-EXEC-MEASUREMENT`
- `MCIM-18.8.3-EXEC-REPLAY`
- `MCIM-18.8.3-EXEC-MANIFEST`
- `MCIM-18.8.3-EXEC-APPROVAL`
- `MCIM-18.8.3-EXEC-GATE`
- `MCIM-18.8.3-EXEC-POLICY`
- `MCIM-18.8.3-EXEC-AUTHORITY`
- `MCIM-18.8.3-EXEC-ROLLBACK`
- `MCIM-18.8.3-EXEC-AUDIT`
