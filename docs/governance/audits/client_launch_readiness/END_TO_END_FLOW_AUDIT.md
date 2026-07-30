# End-to-End Flow Audit — The Real Service Journey

Trace of the full commercial journey on the current codebase. For each stage: actor, system of record (SoR), auth/tenant boundary, audit event, failure mode, recovery, and whether manual work is hidden inside it.

Legend: ✅ implemented+verified in code · 🟡 implemented, unverified on current prod stack · 📄 documented only · ❌ missing.

---

## Stage table

| # | Stage | Actor | System of record | Status | Notes (evidence) |
|---|-------|-------|------------------|--------|------------------|
| 1 | Lead → client approval | Founder | Off-system (email/letters #1–#3) | 📄 by design | Proposal, authorization letter, data-handling notice templates exist (`docs/operators/letters/`). Acceptable manual stage. |
| 2 | Tenant creation | Operator (console) | Postgres `tenants` (migration 0156, canonical since R7) | 🟡 | Zero-touch provisioning w/ Edge Config + Redis fallback; fail-closed with key revocation on dual persistence failure (R0 #549). Incident-hardened in July — needs one clean prod run (FG-LR-001). |
| 3 | Engagement creation | Operator | `fa_engagements` | ✅ | Preflight MSAL tenant validation (FA-2 #546); auto portal-grant on complete_workflow (P-1 #542); append-only `FaEngagementAuditEvent`. |
| 4 | Client invitation | Operator → client | `portal_users` + invitations (migration 0164) | 🟡 | Resend email; 72h expiry; **never exercised with a real external identity in prod** (FG-LR-002). |
| 5 | Portal access | Client | Core `portal_user_sessions` (HMAC-fingerprint stored) | 🟡 | Fail-closed middleware; server-side validation; logout revocation route present. Same verification gap. |
| 6 | Assessment / evidence collection | Operator + client | `fa_scan_results`, `fa_field_observations`, `fa_evidence` (canonical per Evidence Authority) | ✅ | 13 scan types; durable scan jobs w/ lease + orphan recovery (0084); SSRF-safe target validation; idempotency; evidence hash chain; operator acknowledgment receipt (HMAC, per-engagement). |
| 7 | Analysis / findings | System + operator | `fa_findings` | ✅ | Bridges map scan results → findings with NIST mappings; confidence w/ freshness decay applied at read (`services/field_assessment/confidence.py`). |
| 8 | Questionnaire fusion | Operator | `fa_questionnaires` / responses (69 NIST controls) | ✅ | Evidence fusion per control (PR 28); auto-link to findings. |
| 9 | Reviewer approval | QA reviewer | Governance decision ledger (`fa_governance_decisions`, append-only, actor-attributed) | ✅ | SoD: `governance:qa_approve` separate capability; H14 ledger with approval chain; H13-atomic audit events; auto-advance to `delivered` + client access code. |
| 10 | Report generation | Operator | `governance_reports` + Ed25519 signature (PR-SIGN; `FG_REPORT_SIGNING_KEY`) | 🟡 | AI exec summary (advisory-labeled), quality scores wired to live evidence (TC-7); split-commit audit fixed (H13). Current-stack render untested (FG-LR-011). |
| 11 | Export / delivery | Operator → client | PDF bytes (reportlab) + portal report viewer + verification bundle (0086) | 🟡 | Data-collected appendix populated from scan results at export; manifest hash footer. Untested on current stack. |
| 12 | Remediation | Client + operator | `fa_findings` status + remediation-authority (canonical per R-1 #543) | ✅ | Closed loop: resolve w/ evidence note → observation + evidence link → NIST bump → roadmap re-phase (PR 32). |
| 13 | Reassessment | Operator | Same engagement, new scan run | 🟡 manual | Supported by re-running scans; **no scheduled trigger, no baseline-delta surface for the client** (G6/G8 open; `/changes` stub). Manual is acceptable ≤ client 3. |
| 14 | Continuous governance | — | `monitoring` engagement status; governance_orchestration context | ❌ as a motion | Machinery exists (13 trigger types) but no scheduler execution and no client-facing offer (FG-LR-020). |
| 15 | Offboarding / deletion | Operator | ❌ none | ❌ | The DPA makes **three** deletion commitments (verified in `contracts/dpa_template.md`): 90-day retention expiry, **early deletion within 5 business days of request (§5)**, and **deletion within 10 business days of termination (§10)**. No purge path exists for any of them (FG-LR-006); the two event-driven deadlines can fire mid-engagement, so the manual runbook required before client 1 must cover all three triggers, not just day-90. *(Scope corrected per PR #593 review — Codex P1.)* |

## Broken handoffs and hidden manual work

1. **Invitation → first login** is the least-proven handoff in the whole chain and the only one with zero fallback (FG-LR-002).
2. **Report delivery → portal access handoff** *(corrected per PR #593 review — Codex P1)*: the audit originally described delivering the QA-generated client access code per `credential_delivery.md`. Verification shows both halves of that are stale: `credential_delivery.md` delivers/rotates only `PORTAL_PASSWORD` — a credential the production login route rejects (`PORTAL_DEMO_AUTH_DISABLED`) — and `client_access_code` (on `FaEngagement`, displayed in console) is **consumed by no portal or core auth path** in the named-user flow. The real handoff is the named-user invitation itself, which happens at onboarding, not delivery. Required: rewrite `credential_delivery.md` for the named-user flow (plan task T14), rehearse the real handoff in the dry run (T6), and decide the access code's fate — wire it to something or remove it from console display so operators don't hand clients a dead credential.
3. **Day-90 retention**: nothing fires. Hidden manual work that today doesn't even have a documented owner (FG-LR-006).
4. **Failed scan jobs**: dead-letter/orphan states exist in the API but have no console surface — recovery is API-level manual work (`GET /scan-jobs`) (Console audit §3.5).
5. **Duplicate remediation state**: legacy `/remediation/*` routes remain mounted though deprecated (R-1). Portal uses canonical routes; risk is latent, not active (FG-LR-025).
6. **Docs-only workflows**: lead intake, engagement letters, pricing — deliberately off-system at this stage; not a gap.

## Authorization & tenant boundaries along the chain

Every in-system stage above sits behind: API-key/OIDC actor resolution (`api/auth_dispatch.py` → ActorContext), permission checks (`require_permission`, 98 sites in FA alone, CI-enforced coverage), Postgres RLS with FORCE + parameterized session tenant binding, and append-only audit tables with UPDATE/DELETE triggers. Cross-tenant denial is regression-tested (15 `test_fa_forensic_*` modules). This chain is the strongest part of the platform — see `SECURITY_AND_TENANT_SAFETY.md`.

## Single-run bottleneck

Stages 2→11 all execute through one Railway API instance including AI calls and PDF rendering (FG-LR-004). The pre-meeting/no-auth scan split in `onboarding_runbook.md` is the correct operational mitigation; keep it mandatory in the runbook.
