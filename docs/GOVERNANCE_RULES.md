# FrostGate-Core — Governance Rules

This document explains governance behavior.  
Requirements live in `BLUEPRINT_STAGED.md`.

---

## Change Control
All policy, config, and contract changes must:
- Be versioned
- Be attributable
- Produce evidence artifacts

---

## Rollouts
- Tenant-scoped
- Cohort-based
- Rollback tested

---

## Exceptions
- Time-boxed
- Approved
- Auto-expire

---

## Break-Glass
- Two-person approval
- Fully audited
- Auto-revoked

---

See blueprint requirements:
- BP-M2-001 through BP-C-002

---

## Enterprise Additive Extensions
- Compliance Control Plane extension routes are isolated under `/compliance-cp/*`.
- Enterprise control catalog and framework crosswalk are tenant-governed under `/enterprise-controls/*`.
- Exception and break-glass workflows are additive under `/exceptions/*` and `/breakglass/*` with expiry and approval requirements.
- Governance risk extension can enforce quorum + SoD checks when `FG_GOVERNANCE_RISK_EXTENSION_ENABLED=1`.
- Evidence anchoring endpoints (`/evidence/anchors`) support immutable retention hooks and external anchor placeholders.
- Evidence anchors and evidence-run registrations accept only artifacts the caller's bound tenant owns per the producer's canonical record (today `decision_evidence_artifacts`, fingerprint-checked), or platform artifacts registered by an internal producer holding a code-defined grant (`services/artifact_paths.py`). Being inside `FG_ARTIFACTS_DIR` is not ownership (EVIDENCE-ARTIFACT-TENANT-AUTH-001).
- Federation endpoints (`/auth/federation/*`) are additive and optional; API key auth remains supported.
- AI Plane endpoints (`/ai-plane/*`) are additive, tenant-scoped, and governance-reviewed with policy + review surfaces.

- Plane registry (`/planes`) is authoritative for plane metadata and must align with route/flag/evidence/target invariants.
- Evidence index (`/evidence/runs*`) is tenant-scoped and records cross-plane evidence runs with retention and anchor metadata.
- Resilience guard enforces degraded read-only behavior and overload shedding with deterministic error codes.

- Evidence artifact commit/generation rules are governed by `docs/EVIDENCE_ARTIFACT_POLICY.md`.
- `make platform-inventory` is required pre-merge evidence for platform readiness survey.
