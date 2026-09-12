# Customer-One Verified Governance Roadmap

**AUTHORITY NOTICE:** This document is the Level-2 sequencing authority for all FrostGate
engineering after 2026-09-09. It supersedes
`artifacts/audits/canonical_roadmap/FROSTGATE_CANONICAL_ROADMAP.md` for sequencing decisions.
`ROADMAP.md` is the Level-3 status ledger (merged PR tracker only).

- **Date:** 2026-09-09
- **Machine-readable mirror:** `customer_one/roadmap_authority.yaml`
- **Checker:** `tools/ci/check_customer_one_roadmap.py`

---

## 1. Customer-One Goal

**Definition:** Customer-One is the first paying client engagement, evidenced by all four of
the following conditions being simultaneously true:

1. Invoice issued to a named client.
2. Invoice paid (funds received or payment committed in writing).
3. Client portal accessed by a named user at the client organization.
4. Remediation roadmap opened and reviewed with the client.

No commercial milestone short of this complete set satisfies Customer-One. Design partner
scheduled does not equal L14 complete. All four conditions must be met before declaring
Customer-One closed.

---

## 2. Freeze Law

New capability enters the critical path only if it meets at least one of the following
criteria, supported by evidence:

1. **Closes a Customer-One blocker** — the capability is on the direct critical path to
   issuing, collecting, and delivering value to the first paying client.
2. **Required by a contracted customer requirement** — a signed or countersigned document
   from the client specifies the capability as a delivery condition.
3. **Measurably reduces delivery risk or cost** — a quantified argument with evidence shows
   that adding the capability reduces the probability or cost of a Customer-One failure mode.

**Insufficient justifications:** preference, curiosity, speculative future scale,
pre-emptive compliance preparation without a named client requirement, and internal tooling
improvements that do not map to a Customer-One blocker.

The Freeze Law applies to new capabilities only. Defect repair (work class `REPAIR`) is
always authorized and requires no Freeze Law justification.

---

## 3. Precedence Model

The following five levels form a strict hierarchy for sequencing and priority decisions.
Higher-level authorities override lower-level authorities when they conflict.

| Level | Name | Sources |
|-------|------|---------|
| 1 | Safety invariants | `SPINE_INVARIANTS.md`; security regression tests; RLS enforcement gates |
| 2 | Customer-One execution authority | `docs/plans/customer_one_verified_governance_roadmap_20260910.md`; `customer_one/roadmap_authority.yaml` |
| 3 | ROADMAP.md status ledger | `ROADMAP.md` — merged PR tracker only, not a sequencing authority |
| 4 | Scoped plans | `docs/plans/`; `docs/architecture/` |
| 5 | Historical evidence | `ENTERPRISE_PLAN.md`; `AUTHZ_COMPLIANCE_PLAN.md`; `artifacts/audits/canonical_roadmap/FROSTGATE_CANONICAL_ROADMAP.md` |

**Level 5 note:** `ENTERPRISE_PLAN.md` (Phase 3+ product strategy),
`AUTHZ_COMPLIANCE_PLAN.md` (RBAC tracking), and
`artifacts/audits/canonical_roadmap/FROSTGATE_CANONICAL_ROADMAP.md` (dated 2026-07-14) are
**SUBORDINATE** to this document for sequencing decisions. They remain valid historical
records but do not authorize new work or reprioritize the sequence below.

---

## 4. Current State

**As of 2026-09-11:**

| Metric | Value |
|--------|-------|
| Revenue Gate 1 | 12 / 12 items cleared |
| MRR | $0 |
| First invoice issued | Not yet |
| Identity platform | P-113.10 + P1-01-PR1 + P1-01-PR2 complete (#690 merged df1fc85f) |
| Open engineering work | FGA-028 (NEXT) |
| Open commercial work | L14 — design partner, price, packet, Stripe, founder review |

Revenue Gate 1 is fully cleared. P1-01-PR2 merged and post-merge validated (2026-09-10).
The path to Customer-One is now gated by:
- Completing FGA-028 (Grounded Determination & Executive Reporting Authority) — the
  deterministic result path must be release-gated by expert-approved golden and
  metamorphic outcomes with resolvable material-claim lineage.
- Executing the commercial track (L14) in parallel.

---

## 5. Authorized NEXT Sequence

The following items are the only authorized engineering and commercial work on the critical
path to Customer-One. Work not on this list requires a Freeze Law justification before it
can be added.

| ID | Title | Status | Blocker Closed |
|----|-------|--------|----------------|
| FGA-028 | Grounded Determination & Executive Reporting Authority | NEXT | The forensic audit still requires an expert-approved result-truth gate before a defensible Verified AI Governance Baseline can be issued; current semantic tests are not yet a release-blocking authority |
| L14 | Customer-One Commercial Execution | NEXT (non-engineering) | No paying client; L14 cannot close until FGA-028 result truth and all mandatory production gates pass |

### FGA-027 — Complete Evidence State Authority

- **Status:** COMPLETED — PR #693, merged SHA `c8c49d14aecf2838876d3d4a8f68a25e689ee9f3`.
- **Completion evidence:** Governance-report regressions and focused tests passed; mypy passed;
  `make fg-fast` passed; strict `codex_gates.sh` passed with `22562 passed, 92 skipped`,
  `==> All gates passed.`, and `codex_gates rc=0`.
- **Result:** Report evidence population is exhaustive, deterministic, replay-safe, and
  tenant/engagement scoped; partial retrieval, duplicate identities, and scope violations
  fail closed.

### FGA-028 — Grounded Determination & Executive Reporting Authority

- **Status:** NEXT — authorized; implementation not started.
- **Key files:** `api/field_assessment.py`, `services/governance/report/engine.py`,
  `tests/test_result_semantic_authority.py`.
- **Blocker:** The forensic Customer-One audit states that FrostGate must not issue a paid
  client report until an expert-approved golden and metamorphic result-truth gate proves
  malformed/incomplete evidence fails closed, adverse evidence cannot improve posture, and
  deterministic findings remain independent of LLM executive-summary behavior. Existing
  FGA-025 semantic corrections, FGA-026 epistemic states, and FGA-027 complete evidence
  population are necessary foundations but are not yet composed into a release-blocking
  authority with material-claim lineage and executive-report safety.
- **Mandatory acceptance gates:** FG_RESULT_TRUTH_GATE, production dependency security, production schema authority/closed-world RLS, canonical assessment proof, durable execution, and recovery/retention. All must pass before customer data access, report issuance, or L14 closure.
- **Required invariants:**
  - deterministic findings and posture are grounded in complete evidence and replay identically;
  - expert-approved golden and metamorphic outcomes are required for release;
  - incomplete, malformed, stale, contradictory, or unsupported evidence cannot improve truth;
  - every material executive claim resolves to canonical finding/evidence lineage;
  - LLM failure or disagreement cannot alter deterministic posture.

### Next-item determination

| Candidate | Repository evidence | Disposition |
|---|---|---|
| FGA-028 — Grounded Determination & Executive Reporting Authority | Forensic audit requires result-truth correction plus expert-approved golden/metamorphic outcomes before paid reports; current tests are regression coverage, not a release authority. | **NEXT** — immediate Customer-One truth blocker. |
| `FG_RESULT_TRUTH_GATE` promotion | The invariant set is the eventual gate, but no composed implementation or authority exists yet; promote through FGA-028 only after core truth/lineage checks are assembled. | Later within FGA-028; do not implement in this documentation PR. |
| Artifact ownership & evidence storage | Existing report/export manifests and storage-key validation provide foundations; no current evidence shows this is the immediate blocker ahead of result truth. | Deferred until result truth is release-gated. |
| Production dependency security closure | Forensic audit records critical/high dependency advisories as mandatory before external access. | **MANDATORY FGA-028 ACCEPTANCE GATE** — must pass before customer data access, report issuance, or L14 closure; no independent feature authorization. |
| Production schema authority / closed-world RLS | Audit identifies `create_all()` and migration/RLS census gaps as mandatory production prerequisites. | **MANDATORY FGA-028 ACCEPTANCE GATE** — migrations-only schema authority and tenant RLS proof required before L14 closure. |
| Canonical assessment proof, durable execution, recovery/retention | Audit requires a current-SHA end-to-end proof plus recoverable execution and restore/retention evidence before accepting customer data. | **MANDATORY FGA-028 ACCEPTANCE GATES** — required for Customer-One closure; implementation remains separately scoped and is not performed in this documentation PR. |

### L14 — Customer-One Commercial Execution

- **Status:** NEXT — parallel to engineering work; non-engineering tasks only.
- **Required tasks (all must be complete before L14 closes):**
  1. Design partner scheduled (confirmed calendar date with named contact).
  2. Price locked at $5,000.
  3. Commercial packet complete (deck, one-pager, terms).
  4. Stripe payment flow proven (test transaction or live).
  5. Founder review complete.
  6. Invoice issued and paid (final evidence gate).

---

## 6. DEFERRED (Freeze Law — blocked until named gate)

The following items are explicitly deferred. They are not authorized for work until the
named gate condition is met. Any proposal to undefer an item requires a Freeze Law
justification filed as a PR against `customer_one/roadmap_authority.yaml`.

| ID | Title | Deferred Until |
|----|-------|----------------|
| RAG-RETRY | RAG ingestion retry endpoint (currently returns 503) | Live client requires it |
| SAML | SAML support | Client 5 or first client with SAML requirement |
| FEDRAMP | FedRAMP preparation | Signed govcon LOI |
| PCI-PLAYBOOK | PCI DSS playbook | PCI client identified |
| GOV-SERVICES | Governance orchestration / simulation / digital twin services (`services/governance_orchestration/`, `governance_simulation/`, `governance_digital_twin/`) | Live client use case with signed requirement |
| NEW-CI-LANES | New CI lanes | Engineering team exceeds 3 engineers |
| CROSS-FINDING | Cross-finding correlation | After Customer-One — portal enhancement, not a blocker |
| PORTAL-AI-GATE | Remove `portal_ai_enabled` manual gate | Cleared by P-2 (QA auto-enable); no remaining Customer-One blocker |

---

## 7. Completed (Historical Record)

All items below are fully merged and production-proven unless otherwise noted.

| ID | Title | PRs |
|----|-------|-----|
| P1-01-PR2 | Canonical Delegation — FIAP path integration + auth_scopes enforcement | #690 (df1fc85f) — focused 154/1, fg-fast 496/2/22149, strict 22555/92, rc=0 |
| P-113.1–P-113.5 | Identity administration phases 1–5 | #639, #650, #651, #652, #653, #654, #655, #656, #657 |
| P-113.6 | Platform Admin Credential Authority | #677, #678, #679 |
| P-113.7 | Console canonical platform-admin cutover (production proven) | #680 |
| P-113.8 | Canonical Invitation Acceptance (production proven) | #680 |
| P-113.9 | Seamless Identity Verification | #681 |
| P-113.10 | Invitation-Authorized Identity Enrollment | #682 |
| P1-01-PR1 | Canonical Identity Authority PR-1 (tenant lifecycle OIDC gate) | #683 |
| TENANT-LIFECYCLE-OIDC-002 | Tenant lifecycle enforcement for all OIDC providers | #684 |
| FGA-025 | Domain health scale inversion + worst-case aggregation | #686 |
| FGA-026 | Evidence Sufficiency & Epistemic Authority | #687 |
| P0-ID-CUTOVER | Runtime Identity Authority Cutover | HARD-001 #657, migration 0183 — production proven (artifacts/identity/hard-002-production-proof.json) |
| REVENUE-GATE-1 | Revenue Gate 1 — all 12 items cleared | #539, #540, #544, P-1, FA-1, FA-2, R-1, R-2, P-2 |

---

## 8. How to Propose a New Item

If you believe a new capability must enter the critical path, follow this process:

1. **Draft a Freeze Law justification.** State which of the three criteria applies:
   - Customer-One blocker (what specific gate does this close, and how?)
   - Contracted customer requirement (attach or cite the signed document)
   - Risk/cost reduction (quantify: what failure mode, what probability change, what
     cost change?)

2. **File a PR against `customer_one/roadmap_authority.yaml`.** The PR must:
   - Add the new item to `next_sequence` (if authorized) or explain why it is not deferred.
   - Include the Freeze Law trigger in the item's `blocker_closed` field.
   - Include evidence (link to customer communication, defect report, or quantified
     risk argument) in the PR description.
   - State the Customer-One impact: what happens if this item is not done before
     Customer-One closes?

3. **Do not begin work until the PR merges.** The authority file is the gate. Starting
   work before the PR merges bypasses the Freeze Law and is not authorized.

4. **Verify your work class.** Before beginning any work, run:
   ```
   python tools/ci/check_customer_one_roadmap.py --work-class <CLASS>
   ```
   Exit 0 means authorized. Exit 1 means blocked. Work classes are `NEXT`, `REPAIR`,
   `DEFERRED`, and `UNKNOWN`. Undeclared classes are fail-closed (exit 1).
