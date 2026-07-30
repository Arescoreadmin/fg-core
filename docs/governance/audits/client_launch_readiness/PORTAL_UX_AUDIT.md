# Portal UX Audit — The Client Experience

**Surface audited:** `apps/portal` (20 pages), nav registry `packages/navigation/src/registrations/portal.ts`, BFF (`apps/portal/app/api/*`), session model (`apps/portal/lib/session.ts`).
**Frame:** a client contact (practice administrator, compliance officer, managing partner) who knows nothing about FrostGate internals and shouldn't need to.

**Portal usability score: 6/10.** The spine of the journey is real and often better than the market standard; the risks are concentrated at the front door (invite/login — FG-LR-002) and at the edges (stub pages, nav breadth — FG-LR-008).

---

## 1. Client journey trace

| Stage | State | Evidence / assessment |
|-------|-------|----------------------|
| 1. Invitation | ⚠️ built, unproven in prod | Console invite → Resend email (`apps/console/app/api/email/route.ts` — professional HTML, 72h expiry) → `/accept-invite`. **This exact chain has never carried a real external user in production** (EVIDENCE U1). |
| 2. First login | ⚠️ built, unproven | OIDC (`/api/auth/oidc`, PKCE) → `pnu1.` opaque session, server-side validated, fail-closed middleware (`apps/portal/middleware.ts`). Password fallback correctly disabled in prod. Recovery from a failed OIDC handshake = contact operator; acceptable at stage 1 given white-glove delivery. |
| 3. Tenant/engagement identification | ✅ good | Engagement selector hub with localStorage persistence, auto-select when single (`PR 30`; `engagementStore.ts`). Client never sees tenant machinery. |
| 4. Orientation | ✅ good | Home (`app/page.tsx`, 793 lines) is a real risk dashboard: severity strip, NIST function coverage, immediate actions, remediation center — value visible on first screen. |
| 5–6. Assessment start / questionnaire | ✅ (operator-led) | The NIST questionnaire is operator-driven in-console at this stage; portal shows coverage read-only (`/coverage`). Right call for the assessor-led model — the client is never asked to self-serve a 69-control questionnaire. |
| 7. Evidence upload | ✅ built | Engagement workspace Documents tab (PR 35); blob paths tenant-scoped SHA-256 opaque (Sprint 1). |
| 8. Attestation | ✅ built | `/attestation` submit + health (PR 11); asset_name binding bug fixed (FA-1 #541). |
| 9. Connector authorization | ✅ (operator-led) | Device-code flows run in-console with the client present; the portal never asks for credentials. Good trust posture. |
| 10. Progress tracking | ✅ | Home coverage bars + readiness; live refresh on remediation. |
| 11. Incomplete work recovery | ✅ | localStorage engagement persistence; attestation drafts (`lib/attestationDrafts.ts`). |
| 12. Clarification requests | ⚠️ minimal | `/support` is a static self-serve FAQ (real content, verified) — no in-app message channel. Acceptable stage 1–2: the operator relationship *is* the channel. |
| 13. Finding review | ✅ strong | `/findings` with severity filter, plain-language explainer + remediation steps (PRs 22/33). |
| 14. Report delivery | ✅ built / ⚠️ UT | `/reports` version list + viewer + verify; PDF export (PR 38). Current-stack rendering quality untested (FG-LR-011). |
| 15. Remediation response | ✅ strong | Mark-resolved with evidence notes; NIST auto-update; roadmap re-phases live (PR 32); RemediationCenter 4-tab on home (R-2). This loop is a genuine differentiator — Big-4 PDFs and Vanta checklists have no equivalent closed loop with evidence capture. |
| 16. Follow-up | ❌ manual | No email nudges/digests (G7 open). Operator letters #4/#5 cover it manually. P2 (FG-LR-014). |
| 17. Continuous governance transition | ❌ not a motion | `monitoring` status exists; no client-facing offer surface (FG-LR-020). Post-launch. |

## 2. Trust, wording, and state quality

- **Trust signals present:** report manifest hashes + verify page, verification-bundle status card on Overview, data-collected disclosure appendix in the PDF, DPA + data-handling letter templates. This is above-market for the segment.
- **Empty/error states:** generally handled (fail-closed BFF errors, PortalApiError surfaces). The exceptions are the two stubs below.
- **Terminology:** mostly plain ("findings," "remediation," "coverage"). Watch NIST jargon on `/coverage` (GOVERN/MAP/MEASURE/MANAGE unexplained) — one tooltip line each would do; fold into FG-LR-008 day.
- **Accessibility/responsive:** not systematically assessed (no automated a11y checks found in CI). Not a launch gate for the white-glove segment; note for stage 3.

## 3. Concrete defects (verified)

1. **`/changes` can never show data** — `apps/portal/app/changes/page.tsx:15` declares `const [groups] = useState<ChangeGroup[]>([])` with no setter; the page permanently renders its empty state. A paying client clicking "Changes" hits a dead end. **Hide it.**
2. **`/export` defaults every option to `available: false`** (`app/export/page.tsx`) — reads as "nothing available to export" unless upstream flips flags. Show only live formats.
3. **Nav breadth:** 12+ registered destinations for a client with ~6 jobs. Every extra item raises abandonment and support load.

## 4. Recommended launch information architecture

**Default portal nav (6 items):** Dashboard · Assessment (engagement detail) · Findings · Remediation · Reports · Support.
**Conditional:** Assistant (appears when QA-approval flips `portal_ai_enabled` — mechanism exists, P-2 merged) · Attestation & Coverage (link from Dashboard cards rather than top-level nav).
**Hidden for launch:** Changes (stub), Export (until options are live), Timeline, Trust, Continuity, Notifications (fold its content into Dashboard activity), Actions.

Optimizes exactly what the brief demands: minimal cognitive load, obvious next action (Immediate Actions callout already on home), visible progress (coverage bars), low abandonment, low support burden. **Effort: 1 day** (registry gating + friendly fallback for direct URLs).

## 5. Abandonment & support-burden risks ranked

1. Invite email lands in spam / OIDC misconfig → client never gets in (FG-LR-002 — the dry run must include a cold external mailbox).
2. Dead-end stub pages → "is this product finished?" (FG-LR-008).
3. NIST jargon on coverage → confusion → support call (cheap fix above).
4. No reminder emails → remediation stalls silently between meetings (accepted at stage 1; operator letters cover; automate by stage 3).
