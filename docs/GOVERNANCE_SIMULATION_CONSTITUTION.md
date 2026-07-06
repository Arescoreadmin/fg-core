# Governance Simulation Constitution

**Established:** PR 18.8.2 — Deterministic Scenario Simulation & Impact Analysis Engine
**Status:** Permanent — inherited by all future simulation PRs

---

## Foundational Rules

These rules are permanent and may not be violated by any future PR that builds on the simulation substrate.

### 1. The Governance Digital Twin Is Immutable

The `GovernanceDigitalTwinSnapshot` is the canonical governance state record.
Simulation consumes snapshots. Simulation never edits, replaces, or mutates canonical state.
All governance mutations exist exclusively as `ScenarioOverlay` objects — derived, not canonical.

### 2. Overlay Only

No simulation operation may produce side effects on the source snapshot.
Overlays are the only permissible mechanism for expressing hypothetical governance state changes.
Composed overlays inherit this rule.

### 3. UNKNOWN Over Fabrication

If impact cannot be proven from authoritative governance state, the impact confidence must be `UNKNOWN`.
Fabricating confidence values (`PROVEN` or `INFERRED` without authoritative backing) is prohibited.
Impact analysis must degrade gracefully — UNKNOWN is a valid and required outcome.

### 4. Replay Is Required

Every simulation run must produce a `ReplayPackage`.
A replay package must be self-contained enough to regenerate identical output from identical inputs.
Identical `(snapshot, scenario)` inputs must always produce identical `simulation_fingerprint` values.

### 5. Deterministic Ordering

All collections of simulation objects (diff entries, impact entries, comparison rows, chains) must be
sorted by a stable, deterministic key before hashing or export.
No set iteration. No dict insertion ordering. Canonical ordering is mandatory.

### 6. Authority Driven

Every overlay operation must declare an `authority`. Empty authority is an `ERROR` and causes fail-closed.
No inferred relationships. No AI-generated governance links. No fabricated governance state.

### 7. Tenant Isolation

A simulation scenario may only reference entities that belong to its declared `tenant_id`.
Cross-tenant overlay operations are `FATAL` and cause fail-closed.
Simulation results must never leak governance state across tenant boundaries.

### 8. Fail Closed

If `SimulationValidationReport.highest_severity` is `ERROR` or `FATAL`, the engine must raise
`SimulationValidationError` before returning any result. Partial or corrupted simulation results
must never be returned.

### 9. No Execution

The simulation engine must not trigger, enqueue, or otherwise initiate any real governance action.
Simulation results are read-only projections. Closed-loop execution is reserved for PR 18.8.3.

### 10. No Prediction

The simulation engine is not an AI reasoning system and must not produce AI-generated impact
narratives, risk scores, confidence values, or recommendations.
Every impact determination must trace back to authoritative governance entities in the source snapshot.

---

## Extension Points

The following capabilities are reserved but not implemented:

| Capability | Reserved For |
|---|---|
| Predictive Governance (horizon-aware impact scoring) | PR 18.9 |
| Closed-Loop Execution | PR 18.8.3 |
| Cost/Effort Estimation | Future |
| Rollback Execution | PR 18.8.3 |
| Scenario Template Execution Engine | Future |
| Multi-tenant Federation Simulation | Future |
| AGI/Autonomous Systems Governance Simulation | Future |

Extension points are stubs only. Implementing them in this package without a dedicated PR violates this constitution.

---

## Governing Data Flow

```
Authorities
    ↓
Evidence
    ↓
Governance Digital Twin Snapshot  (immutable)
    ↓
Scenario + Overlay                (derived, not canonical)
    ↓
Deterministic Diff
    ↓
Impact Analysis + Chain-of-Effect
    ↓
Executive Comparison
    ↓
SimulationRun + ReplayPackage
```

---

## MCIM Authority

MCIM remains the metadata authority for all simulation objects.
Simulation must not create parallel metadata registries.
New simulation object types must be registered in `mcim_registration.py` under the established scheme.
