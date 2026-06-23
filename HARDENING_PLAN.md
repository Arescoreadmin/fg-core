# FrostGate-Core — Hardening Plan

> Planning aid only. Authoritative requirements are defined in
> `BLUEPRINT_STAGED.md`.

**Derived From:** BLUEPRINT_STAGED.md  
**Current Stage:** Stage 0  
**Target Stage:** MVP 1  
**Time Horizon:** 1–3 sprints

---

## Hardening Objectives
- Enforce authoritative decisioning
- Eliminate undocumented interfaces
- Make evidence minimally provable

---

## Phase 1 — Correctness (P0)
### Goals
- Stop decision drift
- Stop silent API drift

### Tasks
- [ ] Enforce single decision pipeline (BP-M1-001)
- [ ] Remove direct calls to engine.evaluate (BP-M1-001)
- [ ] Add `contracts/core/openapi.json` (BP-M1-004)
- [ ] Add CI check for undocumented endpoints (BP-M1-004)

**Exit Criteria**
- CI fails if pipeline bypass exists
- CI fails if core API spec drifts

---

## Phase 2 — Evidence Discipline
### Tasks
- [ ] Add decision artifact schema (BP-M1-005)
- [ ] Enforce artifact emission per decision (BP-M1-006)
- [ ] Reject schema-invalid artifacts at runtime

---

## Phase 3 — Prep for Governance (MVP2)
### Tasks
- [ ] Stub policy registry (BP-M2-001)
- [ ] Introduce tenant policy pinning (BP-M2-002)
- [ ] Create `drift_check` tool scaffold (BP-M2-006)

---

## Deferred (Explicitly Not In Scope)
- Merkle anchoring
- Rollouts
- UI enhancements

---

**Rule:** Every task must reference a Blueprint requirement ID.  
If it doesn’t, it doesn’t ship.
