# Blueprint Purge Report

## Phase 0 — Canonical sources check

- ✅ `BLUEPRINT_STAGED.md` present in repo root.
- ✅ Supporting root docs present: `ALIGNMENT_AUDIT.md`, `HARDENING_PLAN.md`, `MOAT_STRATEGY.md`, `STATUS.md`.
- ✅ `docs/` directory present, with `docs/GOVERNANCE_RULES.md`.

## Phase 1 — Inventory of candidate artifacts

| File | Summary | Classification |
| --- | --- | --- |
| `BLUEPRINT_STAGED.md` | Canonical Blueprint v2 staged requirements. | KEEP |
| `ALIGNMENT_AUDIT.md` | Alignment audit snapshot referencing blueprint stages. | KEEP (non-authoritative) |
| `HARDENING_PLAN.md` | Hardening plan with task list tied to blueprint IDs. | KEEP (non-authoritative) |
| `MOAT_STRATEGY.md` | Narrative explanation (already references blueprint as canonical). | KEEP |
| `STATUS.md` | Generated alignment/status snapshot. | KEEP (non-authoritative) |
| `CONTRACT.md` | MVP invariant contract enforced by CI via `contract_lint.py`. | KEEP (tooling-required) |
| `docs/GAP_MATRIX.md` | CI-enforced gap tracking matrix. | KEEP (tracking, non-authoritative) |
| `docs/GAP_SCORECARD.md` | Generated scorecard derived from GAP_MATRIX. | KEEP (generated) |
| `docs/HARDENING_PLAN_7DAY.md` | Legacy hardening plan. | DEPRECATE-REDIRECT |
| `docs/FrostGateCore_Buildout_vNext.md` | Legacy buildout blueprint/spec. | DELETE |
| `BLUEPRINT_CONTROL_PLANE_VNEXT.md` | Legacy blueprint/spec (control plane vNext). | DELETE |
| `BLUEPRINT_AUDIT.md` | Legacy blueprint audit checklist. | DELETE |
| `README_MVP.md` | Legacy MVP requirements doc. | DELETE |

## Phase 2 — Conflict/duplicate classification notes

- **CONFLICT/DUPLICATE:** `BLUEPRINT_CONTROL_PLANE_VNEXT.md`, `BLUEPRINT_AUDIT.md`, `README_MVP.md`, `docs/FrostGateCore_Buildout_vNext.md`
  - These define or restate requirements outside the canonical Blueprint v2.
- **DEPRECATE-REDIRECT:** `docs/HARDENING_PLAN_7DAY.md`
  - Legacy plan with normative language; replaced with stub pointing to `BLUEPRINT_STAGED.md`.
- **KEEP (non-authoritative / tooling-required):** `CONTRACT.md`, `docs/GAP_MATRIX.md`, `docs/GAP_SCORECARD.md`, `ALIGNMENT_AUDIT.md`, `HARDENING_PLAN.md`, `STATUS.md`
  - Required by CI/tests or retained as non-authoritative status/planning artifacts.

## Phase 3 — Usage analysis (rg evidence)

- `CONTRACT.md`
  - Referenced by `scripts/contract_lint.py` and `scripts/fg_snapshot_bundle.sh` → required by `make fg-contract`/release gate.
- `docs/GAP_MATRIX.md`
  - Referenced by `scripts/gap_audit.py`, `scripts/generate_scorecard.py`, `scripts/release_gate.py`, and tests.
- `docs/HARDENING_PLAN_7DAY.md`
  - Linked in `api/ui_dashboards.py` (docs list) and mentioned in tests docstrings.
- `docs/FrostGateCore_Buildout_vNext.md`
  - Only referenced by `docs/GAP_MATRIX.md` and `docs/GAP_SCORECARD.md` (updated).
- `BLUEPRINT_CONTROL_PLANE_VNEXT.md`, `BLUEPRINT_AUDIT.md`, `README_MVP.md`
  - No references found via ripgrep; safe to delete.

## Phase 4 — Actions applied

### DELETE
- `BLUEPRINT_CONTROL_PLANE_VNEXT.md` (legacy blueprint/spec, conflicts with Blueprint v2).
- `BLUEPRINT_AUDIT.md` (legacy audit that duplicates blueprint requirements).
- `README_MVP.md` (legacy MVP requirements doc).
- `docs/FrostGateCore_Buildout_vNext.md` (legacy buildout blueprint/spec).

### DEPRECATE-REDIRECT
- `docs/HARDENING_PLAN_7DAY.md`
  - Replaced with a short deprecation notice pointing to `BLUEPRINT_STAGED.md`.

### KEEP (with non-authoritative framing)
- `CONTRACT.md` (tooling-required; now labeled non-authoritative).
- `docs/GAP_MATRIX.md` (tracking doc; updated to remove “source of truth” language).
- `docs/GAP_SCORECARD.md` (generated from GAP_MATRIX; updated to reflect removed gaps).
- `ALIGNMENT_AUDIT.md`, `HARDENING_PLAN.md`, `STATUS.md` (retained with explicit non-authoritative notes).

## Phase 5 — Contracts reconciliation

**Inventory**
- `contracts/admin/` (OpenAPI + JSON schemas)
- `contracts/README.md`, `contracts/__init__.py`

**Usage**
- Contracts are referenced by `scripts/contracts_gen.py`, `scripts/release_gate.py`,
  `Makefile` targets (`contracts-gen`, `fg-contract`), and tests.

**Decision**
- KEEP `contracts/admin/` as the canonical **admin API contract** (tooling-required).
- No unused contract artifacts found to delete.
- No contract files moved; no CI references changed.

## Phase 6 — Entry point normalization

- `README.md` now explicitly points to `BLUEPRINT_STAGED.md` as canonical.
- Removed legacy doc references from gap tracking artifacts.

## Phase 7 — References updated

- Removed references to `docs/FrostGateCore_Buildout_vNext.md` from:
  - `docs/GAP_MATRIX.md`
  - `docs/GAP_SCORECARD.md`
- Added canonical pointer to `BLUEPRINT_STAGED.md` in:
  - `README.md`
  - `CONTRACT.md`
  - `ALIGNMENT_AUDIT.md`
  - `HARDENING_PLAN.md`
  - `STATUS.md`
  - `docs/GAP_MATRIX.md`
  - `docs/HARDENING_PLAN_7DAY.md`
  - `docs/SPINE_FLOW.md`

## Verification commands (suggested)

```
rg -n "BLUEPRINT_CONTROL_PLANE_VNEXT|BLUEPRINT_AUDIT|README_MVP|FrostGateCore_Buildout_vNext"
make fg-contract
make gap-audit
make release-gate
```
