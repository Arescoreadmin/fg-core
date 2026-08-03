# FrostGate Governance Deviations

Known deviations from governance gates. Record when identified. Close in place when resolved. Do not delete entries.

---

## GD-2026-001

**Status:** OPEN (Controlled)

**Date Identified:** 2026-08-03

**Description:** IA-2 implementation was merged into main before IA-1 operational acceptance was completed.

**Reason:** Engineering implementation completed and passed code review prior to completion of operational evidence gates. PR #603 (IA-2) merged before G1-prod and G2-prod gates were run and before IA-1 Final Acceptance was recorded in `IA1_OPERATIONAL_EVIDENCE.md`.

**Risk:** Potential activation of IA-2 functionality before IA-1 operational controls are fully validated.

**Mitigation:**
- IA-2 features remain operationally disabled until all of the following are true:
  - G1-prod = PASS
  - G2-prod = PASS
  - IA-1 Operational Evidence receives Final Acceptance (recorded in `IA1_OPERATIONAL_EVIDENCE.md`)
- No production rollout of IA-2 until all IA-1 gates close.

**Owner:** Identity Authority

**Closure Criteria:**
1. IA-1 operational evidence completed and Final Acceptance block filled.
2. G2-prod = PASS (disposable tenant `fg-ia1-prod-validation-20260801` validated).
3. EXECUTION_STATE.md updated to reflect IA-1 closure.

---

<!-- When G2-prod passes, update Status to CLOSED, add Closed date, and add Evidence block. Do not delete this entry. -->

<!--
CLOSED TEMPLATE (fill when criteria met):

**Status:** CLOSED

**Closed:** 2026-08-XX

**Evidence:**
- `docs/governance/status/IA1_OPERATIONAL_EVIDENCE.md` — Final Acceptance block completed
- G2-prod PASS recorded in EXECUTION_STATE.md
- EXECUTION_STATE.md updated 2026-08-XX
-->
