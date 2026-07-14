# FrostGate Canonical Implementation Roadmap

**Document Authority:** This document supersedes all prior phase descriptions, chat-history roadmaps, and ad hoc feature lists. ROADMAP.md remains the per-PR merge tracker. This document defines phase objectives, criteria, PR sequence, and competitive positioning.

**Date:** 2026-07-14
**Commit:** f70cccc29c6d28c3c012f8dcdc96dbe0bf8bd25e
**Branch:** main
**Audit Sources Reconciled:** master_inventory_claude · master_inventory_codex · revenue_execution_master_plan

---

## FrostGate Mission

> Every assessment becomes institutional memory.
> Every remediation becomes organizational improvement.
> Every interaction increases customer switching cost.
> Every client increases the intelligence of the platform.

No PR should reduce any of those four properties. This is the philosophical anchor for every product decision. When a PR is proposed and its effect on all four properties cannot be named, it does not ship.

---

## Section 1: Executive Summary

FrostGate is the only platform that combines assessor-led field evidence collection with a cryptographic evidence chain, a governed AI workspace grounded in the client's own verified documents, and a governance graph that compounds with every finding, control, and remediation closure. Competitors (Vanta, OneTrust, Credo AI, Big 4 consultancies) offer one layer of this stack. None offer all four simultaneously. The compounding moat is not theoretical — every assessment adds institutional memory that cannot be migrated away.

**Current state by phase:** The trust chain logic layer is 70% complete (1.6A-1.8A merged, #533-537 merged; foundation PRs 1.1-1.6 still open). Field assessment core is production-ready (10,903-line engine, 13 scan types, 13 connectors, ReportLab PDF, QA approval workflow, verification bundles). The customer portal is structurally live but the AI assistant requires a manual operator flag per client. Remediation tracking has a split-brain between a canonical authority and a legacy router. AI Workspace exists as governed chat but lacks conversation history, citations, and saved sessions. RAG ingestion has a planned-only retry endpoint (503). Continuous monitoring connector runtime returns stubs for polling and subscription. CGIN infrastructure (Ed25519 trust, Merkle transparency, key management) is built but invisible to customers.

**If this roadmap is executed in order:** Within 6-8 weeks, FrostGate can deliver and invoice its first paying client with a legally defensible, cryptographically signed assessment report and a live portal. Within 16 weeks, it can convert that client to a recurring portal + remediation subscription. Within 6 months, with one real connector monitoring path live and the AI workspace with conversation history and citations, it can command enterprise subscription pricing that no boutique assessment firm or compliance automation tool can match. Within 12 months, with CGIN benchmarks surfaced and governance graph visible to clients, the switching cost becomes economically irrational.

**The single most important next action:** Ship the evidence provenance persistence foundation (PR 1.1 / PR 417) — this is the first open PR in the trust chain series and all downstream provenance, signing, and link authority work depends on it.

---

## Section 2: Audit Reconciliation

| Topic | Codex Finding | Claude Finding | Revenue Plan Finding | Reconciled Truth | Evidence |
|---|---|---|---|---|---|
| Portal remediation page | "pilot_ready engagement portal" | "placeholder-backed — census shows no backend" | "WIRED — 635 lines confirmed" | **WIRED** — 635-line component, `getRemediationRoadmap()` confirmed at `api/field_assessment.py:9629` | Direct repo read |
| Portal findings page | Not separately assessed | "no backend per census" | "WIRED confirmed" | **WIRED** — `portalApi.ts:446` → `/field-assessment/engagements/${id}/findings` | Direct repo read |
| Report quality | "P0 blocker — `_PLACEHOLDER_COVERAGE = 0.5`" | Not identified as distinct blocker | "P0-B — CRITICAL" | **CONFIRMED** — `services/report_authority/engine.py:96`: all five quality inputs (evidence, verification, freshness, confidence, completeness) are 0.5 | Direct repo read |
| Connector monitoring | "polling: stub, subscription: stub" | Not specifically cited | "CONFIRMED STUB" | **CONFIRMED** — `services/connectors/runner.py:170-173` | Direct repo read |
| RAG retry ingestion | "returns 503, planned capability" | "incomplete RAG lifecycle" | "CONFIRMED 503" | **CONFIRMED** — `api/rag_corpus_ingestion.py:1073` with `"planned": True` | Direct repo read |
| AI assistant gate | "hardening incomplete" | "manual portal_ai_enabled flag at page.tsx:72" | "CONFIRMED — no self-serve path" | **CONFIRMED** — `apps/portal/app/assistant/page.tsx:72` | Direct repo read |
| Actor attribution status | ROADMAP shows "🔄 open" | "dead symbol census — ambiguous" | "recently shipped" | **MERGED** — git log confirms #536 `feat(actor-attribution)` merged | git log |
| Identity assurance status | ROADMAP shows "🔄 open" | Not specifically assessed | "recently shipped" | **MERGED** — git log confirms #537 `feat(identity)` merged | git log |
| Entra ID status | "stub" per June audit | "resolved — full implementation per PR #537" | "VERIFIED resolved" | **RESOLVED** — `api/identity_authority/providers/entra_provider.py` full RS256/ES256 | Direct repo read |
| PDF export | "pseudoformat — major risk" | "resolved — real ReportLab per PR #534" | "VERIFIED real" | **RESOLVED** — ReportLab in `api/report_exports.py` | Direct repo read |
| Trust chain 1.1-1.6 foundation | Not assessed | Not assessed | "evidence provenance series open" | **OPEN** — PRs 417, 418, 1.2A, 1.3, 1.4, 1.5, 1.5A, 1.6 all 🔄 open in ROADMAP.md | ROADMAP.md |
| Trust chain 1.6A-1.8A logic | Not assessed | Not assessed | Not assessed | **MERGED** — PRs #425, #426, 1.7, 1.7A, 1.8, 1.8A all ✅ merged | ROADMAP.md |
| Subscription engine (P1.4) | "wired_not_validated" | "shipped" | "engine open PR" | **OPEN PR** — `feat/p1-4-subscription-assignment-engine` not yet merged | ROADMAP.md |
| Remediation split-brain | "canonical vs legacy — declare canonical" | Not specifically addressed | "PR-2 required" | **SPLIT-BRAIN EXISTS** — `api/remediation_authority.py` (24 routes, canonical) and `api/remediation.py` (legacy) both active | ROADMAP.md, Codex system_inventory |
| Branch contamination | "dirty tree — actor attribution uncommitted" | N/A | "resolved by PRs #536, #537" | **RESOLVED** — both merged, branch clean | git log |

---

## Section 3: Current Platform State

### 3A: Complete Capabilities

| Capability | Evidence | Commercial Value |
|---|---|---|
| Field Assessment core engine | `api/field_assessment.py` (10,903 lines), 87+ routes | PRIMARY REVENUE PRODUCT |
| 13 scan connectors | `services/connectors/` (MS Graph, Entra ID, OAuth Risk, SharePoint, Endpoint, DNS/Email, Web Headers, Network, AI Tool Discovery, AI Data Access Mapping, External AI Risk Register, AI Vendor Governance, OAuth Inventory) | Differentiator: no competing tool does this with evidence chain |
| NIST AI RMF 1.0 questionnaire (69 controls) | `migrations/postgres/0059_question_bank_v2_nist_mapped.sql` | First paid assessment product |
| 5 compliance playbooks (NIST AI RMF, HIPAA, SOC 2, CMMC, ISO 27001) | `services/field_assessment/playbooks.py` | Multi-framework assessment pricing |
| ReportLab PDF export | `api/report_exports.py` (invariant mode, byte-stable replay) | Client deliverable |
| Report approval workflow, QA gates | `api/field_assessment.py` QA routes | Audit defensibility |
| Verification bundle (SHA-256, 9-component snapshot) | `services/verification_bundle/bundle_service.py`, migration 0086 | Regulatory audit package |
| Ed25519 report signing | `services/governance/report/signing.py`, `FG_REPORT_SIGNING_KEY` | Immutability proof |
| Governance decision ledger (append-only, DB triggers) | `api/governance_decision_ledger.py`, migration 0085 | Irreversible audit trail |
| AI Vendor Governance workflow (8-state, AGI target types) | `api/field_assessment.py`, `FaAiVendorGovernanceRecord` | Unique differentiator vs. all GRC competitors |
| Portal auth (HMAC-SHA256 sessions) | `apps/portal/app/api/auth/login/route.ts` | Client access security |
| Portal: findings, remediation roadmap, coverage, engagement workspace | `portalApi.ts`, `apps/portal/app/findings`, `apps/portal/app/remediation` | Client interface |
| 5-layer RBAC with 6 enterprise roles | `api/tenant_rbac_router.py`, `api/auth_scopes/` | Enterprise auth requirement |
| Auth0 OIDC + Entra ID (RS256/ES256) | `api/identity_authority/providers/entra_provider.py` | Enterprise identity |
| CGIN Trust (Ed25519), Merkle Transparency, Key Management, Privacy | `services/cgin/trust.py`, `services/cgin/transparency/`, `services/cgin/key_management/` | Future moat infrastructure |
| Trust Graph Authority + Snapshot (1.6A, 1.6B) | `services/field_assessment/trust_graph_authority.py`, PRs #425 #426 | Evidence relationship map |
| Trust Confidence + Authority (1.7, 1.7A) | `services/field_assessment/trust_confidence.py`, `confidence_authority.py` | Deterministic report confidence |
| Trust Intelligence + Authority (1.8, 1.8A) | `services/field_assessment/trust_intelligence.py`, `trust_intelligence_authority.py` | Cross-evidence corroboration |
| Actor Attribution (3-layer fingerprint chain) | PR #536, `api/actor_attribution.py` | Non-repudiation for regulators |
| Identity Assurance (8-level ladder, 0-100 score) | PR #537, migration 0153 | Enterprise trust levels |
| Server-side evidence file integrity | PR #533 | Immutable evidence claim |
| Enterprise report delivery (approval, immutability, manifest, delivery audit) | PR #534 | Legal defensibility |
| Billing ledger (HMAC-attested, hash-chained invoices) | `api/billing.py` (1,971 lines) | Commercial authority |
| Identity Governance (14-dimension score, forecast, benchmark, SLA, ledger) | PRs identity 1-9, all merged | Enterprise governance depth |
| AI executive summary (Anthropic API) | `api/explain_brief.py` | Report differentiation |

### 3B: Partially Implemented

| Capability | Status | What's Missing | Evidence |
|---|---|---|---|
| Trust chain persistence foundation (1.1-1.6) | Logic done; DB layer open | PRs 417, 418, 1.2A, 1.3, 1.4, 1.5, 1.5A, 1.6 not merged | ROADMAP.md |
| Report quality scoring | Placeholder 0.5 for all 5 inputs | Wire to real evidence/verification/freshness/confidence/completeness reads | `services/report_authority/engine.py:96` |
| Portal AI assistant | Live but manual gate | Remove `portal_ai_enabled` flag; auto-enable on QA approval | `apps/portal/app/assistant/page.tsx:72` |
| AI Workspace (console) | Chat UI live, policy enforcement active | No conversation history, no citations, no saved sessions | `api/ui_ai_console.py`, Codex system_inventory |
| RAG ingestion | Ingest, chunking, retrieval all exist | Retry returns 503; no freshness UI; no deletion lifecycle | `api/rag_corpus_ingestion.py:1073` |
| Subscriptions (P1.4) | Engine designed and specced | Open PR not yet merged | ROADMAP.md `feat/p1-4-subscription-assignment-engine` |
| Billing integration (P1.5) | Provider design complete | Open PR not yet merged | ROADMAP.md `feat/p1-5-billing-integration-layer` |
| Capability framework (P1.2, P1.3) | Architecture designed | Open PRs not yet merged | ROADMAP.md |
| Identity consolidation (PR 10, PR-01a) | Admin gateway works; portal named-user OIDC | PR #446 open; portal password-only for now | ROADMAP.md |
| Membership versioning (P1.1) | Specced | Open PR not yet merged | ROADMAP.md |
| Remediation tracking | Authority canonical + portal wired | Split-brain: legacy `api/remediation.py` still active; notifications are stubs | ROADMAP.md |
| Trust monitoring (TIM) | Architecture exists | Fail-open on error (returns `{}`); `services/trust_monitoring/monitoring_engine.py` | Codex audit |
| Notification engine | `services/notifications/` exists | No confirmed template library; dispatch not confirmed in portal | Revenue plan |
| Portal reports page | Routes exist | Live-data validation unconfirmed with real engagement | Revenue plan verification_backlog |
| Portal attestation page | Component exists | Backend contract unconfirmed with live engagement | Revenue plan |
| Persistent report signature (PR-SIGN-5b) | Specced | Open PR not merged | ROADMAP.md |

### 3C: Missing Capabilities

| Capability | Why It Matters |
|---|---|
| Self-serve subscription checkout UI | Every MRR conversion requires Jason manually via API |
| Connector monitoring runtime (polling, subscription) | Continuous monitoring value proposition is a stub |
| RAG retry-ingestion | Document ingestion cannot recover from failures |
| Conversation history (AI Workspace) | No habit formation; no saved investigations |
| Citation display in AI workspace | Governed AI requires attributable answers |
| Portal subscription offer modal | No client-facing path to upgrade |
| CGIN customer surface (benchmarks, maturity) | CGIN moat is invisible; no client sees it |
| Continuous monitoring portal dashboard | No client-visible proof of ongoing governance |
| Portal notifications (overdue tasks, drift alerts) | No pull to return to portal without Jason |
| Evidence freshness alerts | Evidence decay is tracked but not surfaced |
| SOC 2 Type II certification (for FrostGate itself) | Enterprise procurement requires vendor certification |

---

## Section 4: Revenue Readiness Assessment

| Strategic Step | Revenue Phase | Readiness | Primary Blocker | Revenue Unlock |
|---|---|---|---|---|
| 1: Trust Chain | Phase 0 | 70% (logic done; persistence open) | PRs 1.1-1.6 + report quality fix | Enables legally defensible report |
| 2: Field Assessment | Phase 1 | 90% | Report quality placeholder; portal validation | First paid invoice ($5k-$40k) |
| 3: Customer Portal | Phase 2 | 60% | AI auto-enable; reports/attestation validation; notifications | Portal subscription ($300-$800/mo) |
| 4: Remediation Tracking | Phase 3 | 70% | Remediation canonical declaration; split-brain | Remediation revenue ($300-$800/mo add-on) |
| 5: AI Workspace | Phase 4 | 40% | Conversation history; citations; subscription checkout | AI Workspace subscription ($500-$2k/mo) |
| 6: Enterprise RAG | Phase 5 | 50% | Retry operational; embedding verified; FA-to-RAG binding | RAG tier premium ($1k-$3k/mo) |
| 7: Continuous Monitoring | Phase 6 | 15% | Connector runtime (polling, subscription) real path | Monitoring subscription ($500-$2k/mo) |
| 8: CGIN | Phase 7 | 25% (infra only) | Customer surface; privacy contribution pipeline | Data product + benchmarks premium |
| 9: Autonomous Governance | Phase 8 | 15% | Steps 1-7 must precede | Enterprise managed governance |
| 10: AGI Scale | Phase 9 | 5% | All prior phases + product-market evidence | Category leadership |

**First Client Readiness: READY WITH CONDITIONS**
Conditions: (1) Report quality fix shipped — `services/report_authority/engine.py:96`; (2) startup key assertions added for HMAC and minisign; (3) Anthropic API credit balance verified; (4) dry run H1-H18 completed; (5) portal pages validated with live engagement data.

**Portal Readiness: READY WITH CONDITIONS**
The portal is live and structurally wired. Conditions: (1) AI assistant auto-enabled on QA approval; (2) reports and attestation pages confirmed with live engagement data; (3) basic notification for overdue tasks.

**Remediation Revenue Readiness: READY WITH CONDITIONS**
`api/remediation_authority.py` has 24 routes and a 5-state lifecycle. Conditions: (1) Canonical declaration — mark `api/remediation.py` non-canonical; (2) portal remediation validated with live data; (3) minimal notification for overdue tasks.

**MRR Readiness: NOT READY — 3 Blockers**
(1) No portal subscription checkout surface; (2) AI assistant activation requires manual operator action per client; (3) P1.4 Subscription Engine open PR not yet merged.

### Commercial Analysis by Phase

| Phase | Enterprise Readiness | Customer Readiness | Sales Readiness | Pricing Capability | MRR Potential | Competitive Differentiation | Moat Score |
|---|---|---|---|---|---|---|---|
| Phase 0-1 (Trust Chain + FA) | 6/10 | 7/10 | 7/10 | $5k-$40k per engagement | Assessment fees only | Unique: assessor-led + evidence chain + PDF + portal in one workflow | 5/10 |
| Phase 2-3 (Portal + Remediation) | 7/10 | 8/10 | 8/10 | $300-$800/mo per client | Early MRR | Unique: closed-loop remediation with immutable audit trail | 6/10 |
| Phase 4-5 (AI Workspace + RAG) | 8/10 | 9/10 | 9/10 | $1k-$3k/mo per client | Scale MRR | Unique: AI grounded in client's own verified evidence + cited answers | 8/10 |
| Phase 6-7 (Monitoring + CGIN) | 9/10 | 9/10 | 9/10 | $2k-$8k/mo per client | Platform MRR | Unique: continuous trust with cross-tenant benchmark intelligence | 9/10 |
| Phase 8-10 (Autonomous + AGI) | 10/10 | 9/10 | 10/10 | Enterprise contracts + managed services | Platform + services | Category-defining: the only AI constitutional governance platform | 10/10 |

---

## Section 5: Capability Inventory

| Capability | Status | Maturity | Customer Visible | Revenue Driver | Moat Asset | Blocker | Evidence |
|---|---|---|---|---|---|---|---|
| Field Assessment engine | COMPLETE | 5/5 | Indirect (via portal) | PRIMARY | HIGH | None | `api/field_assessment.py` |
| 13 scan connectors (assessment mode) | COMPLETE | 5/5 | Via findings | HIGH | HIGH | None | `services/connectors/` |
| NIST AI RMF questionnaire | COMPLETE | 5/5 | Via portal coverage | HIGH | MEDIUM | None | migration 0059 |
| HIPAA / SOC2 / CMMC / ISO27001 playbooks | COMPLETE | 5/5 | Via report | HIGH | MEDIUM | None | `playbooks.py` |
| ReportLab PDF | COMPLETE | 5/5 | Direct download | HIGH | LOW | None | `api/report_exports.py` |
| QA approval workflow | COMPLETE | 5/5 | Indirect | HIGH | LOW | None | FA routes |
| Verification bundle | COMPLETE | 5/5 | Portal (read-only) | HIGH | HIGH | None | `bundle_service.py` |
| Ed25519 report signing | COMPLETE | 5/5 | Report manifest | HIGH | HIGH | None | `signing.py` |
| AI Vendor Governance (8-state) | COMPLETE | 5/5 | Console + Portal | HIGH | HIGHEST | None | `FaAiVendorGovernanceRecord` |
| Governance decision ledger | COMPLETE | 5/5 | Console | HIGH | HIGH | None | migration 0085 |
| Actor Attribution (#536) | COMPLETE | 5/5 | Audit endpoints | MEDIUM | HIGH | None | `api/actor_attribution.py` |
| Identity Assurance (#537) | COMPLETE | 5/5 | Audit endpoints | MEDIUM | HIGH | None | migration 0153 |
| CGIN Trust (Ed25519) | COMPLETE | 4/5 | NOT VISIBLE | LOW today | HIGHEST | No customer surface | `services/cgin/trust.py` |
| CGIN Transparency (Merkle) | COMPLETE | 4/5 | NOT VISIBLE | LOW today | HIGHEST | No customer surface | `services/cgin/transparency/` |
| CGIN Key Management | COMPLETE | 4/5 | NOT VISIBLE | LOW today | HIGH | No customer surface | `services/cgin/key_management/` |
| CGIN Privacy Hardening | COMPLETE | 4/5 | NOT VISIBLE | LOW today | HIGH | No customer surface | `services/cgin/privacy.py` |
| Trust Graph Authority (1.6A, 1.6B) | COMPLETE | 4/5 | Console (topology) | MEDIUM | HIGH | Foundation 1.6 open | `trust_graph_authority.py` |
| Trust Confidence Authority (1.7, 1.7A) | COMPLETE | 4/5 | Via report | HIGH | HIGH | Foundation 1.1-1.5 open | `trust_confidence.py` |
| Trust Intelligence Authority (1.8, 1.8A) | COMPLETE | 4/5 | Via report | HIGH | HIGH | Foundation open | `trust_intelligence.py` |
| Evidence provenance persistence (1.1-1.6) | PARTIAL | 2/5 | None | HIGH | HIGHEST | PRs 417, 418, 1.2A-1.6 open | ROADMAP.md |
| Report quality scoring | PARTIAL | 2/5 | Via report quality grade | CRITICAL | HIGH | `_PLACEHOLDER_COVERAGE = 0.5` | `engine.py:96` |
| Portal auth + session | COMPLETE | 5/5 | Login gate | HIGH | LOW | None | `apps/portal/app/api/auth/` |
| Portal: findings page | COMPLETE | 4/5 | Direct | HIGH | MEDIUM | Validate with live data | `portalApi.ts:446` |
| Portal: remediation page | COMPLETE | 4/5 | Direct | HIGH | HIGH | Validate with live data; split-brain | `page.tsx` (635 lines) |
| Portal: reports page | PARTIAL | 3/5 | Direct | HIGH | MEDIUM | Live-data validation unconfirmed | Revenue plan |
| Portal: coverage page | PARTIAL | 3/5 | Direct | MEDIUM | LOW | Live-data validation unconfirmed | Revenue plan |
| Portal: attestation page | PARTIAL | 3/5 | Direct | MEDIUM | MEDIUM | Live-data validation unconfirmed | Revenue plan |
| Portal: AI assistant | PARTIAL | 3/5 | Direct (when enabled) | HIGHEST | HIGHEST | Manual `portal_ai_enabled` gate | `page.tsx:72` |
| AI Workspace (console) | PARTIAL | 3/5 | Console | HIGH | HIGH | No history; no citations; no saved sessions | `api/ui_ai_console.py` |
| RAG ingestion | PARTIAL | 3/5 | Indirect | HIGH | HIGHEST | Retry 503; no deletion lifecycle | `api/rag_corpus_ingestion.py` |
| RAG retrieval + policy | PARTIAL | 3/5 | Via AI assistant | HIGH | HIGH | No citation display; unverified embeddings | `api/rag_retrieval.py` |
| Remediation Authority (canonical) | PARTIAL | 4/5 | Via portal | HIGH | HIGH | Split-brain; notifications stub | `api/remediation_authority.py` |
| Remediation (legacy) | OBSOLETE | 2/5 | Via portal (wrong path) | NEGATIVE | NEGATIVE | Must be declared non-canonical | `api/remediation.py` |
| Connector runtime (monitoring mode) | MISSING | 1/5 | NOT VISIBLE | BLOCKS MRR | HIGHEST | `polling: stub` | `runner.py:170-173` |
| Trust Monitoring (TIM) | PARTIAL | 2/5 | NOT VISIBLE | BLOCKS MRR | HIGH | Fail-open on error | `monitoring_engine.py` |
| Subscription Engine (P1.4) | PARTIAL | 2/5 | NOT VISIBLE | CRITICAL for MRR | HIGH | Open PR not merged | ROADMAP.md |
| Billing Integration (P1.5) | PARTIAL | 2/5 | NOT VISIBLE | CRITICAL for MRR | LOW | Open PR not merged | ROADMAP.md |
| Capability Framework (P1.2, P1.3) | PARTIAL | 2/5 | NOT VISIBLE | HIGH for MRR | LOW | Open PRs not merged | ROADMAP.md |
| Identity Consolidation (PR 10, PR-01a) | PARTIAL | 3/5 | Console | MEDIUM | MEDIUM | Open PRs not merged | ROADMAP.md #446 |
| Membership versioning (P1.1) | PARTIAL | 2/5 | NOT VISIBLE | LOW today | LOW | Open PR not merged | ROADMAP.md |
| Notifications | PARTIAL | 2/5 | Email | HIGH for retention | MEDIUM | No template library confirmed | `services/notifications/` |
| Self-serve subscription checkout | MISSING | 0/5 | NOT BUILT | CRITICAL | LOW | Nothing exists | Verified |
| Conversation history (AI) | MISSING | 0/5 | NOT BUILT | HIGH | HIGH | Nothing exists | Verified |
| Citation display (AI) | MISSING | 0/5 | NOT BUILT | HIGH | HIGHEST | Nothing exists | Verified |
| CGIN customer surface | MISSING | 0/5 | NOT BUILT | HIGH future | HIGHEST | Infrastructure only | Verified |
| Monitoring dashboard (portal) | MISSING | 0/5 | NOT BUILT | HIGH for MRR | HIGH | Nothing exists | Verified |
| Evidence freshness alerts | MISSING | 1/5 | NOT BUILT | HIGH for retention | MEDIUM | Service exists; no surface | `services/evidence_freshness_authority/` |
| Duplicate console subtree | OBSOLETE | 0/5 | NOT VISIBLE | NEGATIVE | NEGATIVE | Cleanup required | `apps/console/console/` 114 overlapping paths |
| Legacy backend app | OBSOLETE | 1/5 | NOT VISIBLE | NEGATIVE | NEGATIVE | Ambiguity risk | `backend/app/main.py` |

---

## Section 6: Gap Analysis

| Capability | Why It Matters | Customer Impact | Revenue Impact | Dependencies | Est PR Count | Est Effort | Risk if Postponed |
|---|---|---|---|---|---|---|---|
| Evidence provenance persistence (TC-1 through TC-6) | Trust chain logic exists but DB layer absent — evidence provenance cannot be queried, replayed, or verified without persistence | Invisible to client | Enables legally defensible report quality claim | None | 6 PRs (as specced) | 2-3 weeks | Report quality cannot be real without this foundation |
| Report quality fix | All 5 quality inputs hardcoded 0.5 — report is legally indefensible | Client sees fabricated quality scores | CRITICAL — blocks first invoice | TC-1 through TC-4 | 1 PR | 3-5 days | Legal exposure on every report delivered |
| Remediation canonical declaration | Two remediation systems — portal may route to wrong backend | Client remediation state may be in legacy system | Blocks remediation revenue | None | 1 PR (declaration + routing fix) | 1 day | Remediation data split, irreversible at scale |
| Portal AI auto-enable | Every new client requires Jason to manually patch engagement metadata | Client cannot access primary habit-forming feature | Blocks AI Workspace MRR | None | 1 PR | 4 hours | Jason bottleneck at every client activation |
| Subscription + Capability Engine (P1.2-P1.4) | Without merged subscription engine, no automated subscription activation | Client cannot self-activate | Every MRR conversion requires Jason | TC work | 3 open PRs | 2-4 weeks total | MRR cannot scale without this |
| Subscription checkout UI | Engine built; client has no button to click | Client cannot upgrade without Jason | Every MRR conversion requires Jason | P1.4 | 1 PR | 1 week | Manual MRR ceiling at ~5 clients |
| RAG retry-ingestion | Document re-ingestion after failure not possible | Client's document corpus has permanent failures | Blocks RAG reliability | TC work | 1 PR | 3-5 days | RAG corpus silently degraded |
| Production embedding verification | Unknown if real semantic embeddings used in production | AI answers may be keyword-matched, not semantic | Governs AI Workspace quality claim | None | 1 PR (startup check) | 1 day | Quality unknown; enterprise trust at risk |
| Connector monitoring real path | Continuous monitoring is a stub — no actual recurring governance data | Client has no ongoing drift visibility | Blocks MRR renewal narrative | CM infrastructure | 1 large PR | 4-6 weeks | Cannot pitch continuous monitoring without this |
| Trust Monitoring fail-safe | TIM swallows errors, returns `{}` — degraded monitoring looks like clean posture | Silent false confidence | Undermines continuous trust claim | None | 1 PR | 2-3 days | Trust claim is invalidated when monitoring is silent during failure |
| Conversation history + citations | AI Workspace has no memory; answers have no sources | Client cannot reference prior investigations; cannot trust answers | Blocks daily-use habit | RAG operational | 2 PRs | 2-3 weeks | AI Workspace is a demo, not a product |
| CGIN customer surface | The most powerful moat asset is invisible to every paying client | Client cannot see peer benchmarks or maturity scores | Blocks moat monetization | 5+ clients' data | 2-3 PRs | 4-6 weeks | Moat compounds silently; competitors could replicate before it's visible |
| Notifications | Clients have no reason to return to portal without Jason prompting | Churn risk after assessment novelty fades | Blocks MRR retention | None | 2 PRs | 1-2 weeks | Portal habit never forms |
| Startup key assertions | HMAC and minisign keys may not be set in production without detection | Evidence bundles signed with fallback/dev keys | Integrity claim silently broken | None | 1 PR | 2 hours | Regulatory audit would expose this |

---

## Section 7: Deterministic PR Roadmap

### Two-Lane Architecture

Every PR belongs to exactly one lane. The cost of lane confusion is months spent building a castle while the business waits for somewhere to sleep.

**Lane 1 — Revenue Critical Path.** These PRs must ship before first invoice or first MRR. When anything else appears while Lane 1 is open — a governance feature, a new connector, a dashboard enhancement — it goes to Platform Expansion. Never to Lane 1.

**Lane 2 — Platform Expansion.** Every other PR. Genuinely valuable. Never allowed to interrupt Lane 1.

**Before First Invoice (Lane 1):**
TC-0 · R-1 · TC-1 · TC-7 · TC-2 · TC-3 · TC-4 · FA-1 · FA-2 · P-1 · P-2 · R-2 · Dry Run H1-H18

**Before First MRR (Lane 1 continued):**
TC-IDENTITY · P-3 · P-4 · AI-1

**Platform Expansion (Lane 2 — after Revenue Gate 1):**
TC-5 · TC-6 · TC-8 · FA-3 · P-5 · P-6 · R-3 through R-6 · AI-2 through AI-8 · RAG-1 through RAG-6 · CM-1 through CM-6 · CGIN-1 through CGIN-4 · AG-1 through AGI-3

### Primary Business KPI Map

Every PR is assigned exactly one KPI. A PR that cannot be assigned a KPI is a Platform Expansion PR, not Revenue Critical Path.

| KPI | Definition | Revenue Checkpoint |
|---|---|---|
| **Report Defensibility** | Legal and commercial quality of the delivered assessment report | Real scores before first invoice |
| **Customer Trust** | Client confidence in evidence chain integrity and signing claims | Zero silent failures in production |
| **Portal Adoption** | Client-initiated portal sessions per week post-delivery | 3+ sessions/week within 30 days |
| **Subscription Conversion** | % of delivered assessments converting to recurring subscription | 50% within 90 days of delivery |
| **Monthly Retention** | Month-over-month subscription renewal rate | 90%+ by Month 3 |
| **Annual Contract Value** | Per-client revenue expansion through upgrades and add-ons | $500–$2k/mo per client by Phase 4 |
| **Billing Integrity** | Correctness and auditability of the billing evidence chain | Zero unsigned invoices |
| **Moat Depth** | Compounding switching cost from evidence corpus and CGIN data | Grows with every assessment |

---

### STEP 1 — TRUST CHAIN COMPLETION

Complete the evidence provenance persistence foundation and the report quality fix. The trust chain is commercially complete when evidence provenance has DB durability, the report quality scores derive from real data, and all signing keys are production-asserted.

---

**TC-0: Assert Production Keys at Startup**

Step: 1 | Priority: P0-A | Size: XS
Objective: Add startup validator that raises RuntimeError if `FG_BILLING_EVIDENCE_HMAC_KEY` or `MINISIGN_SECRET_KEY` are absent in production.
Root Problem: No startup check exists; keys can be unset silently in Railway — `api/config/startup_validation.py` does not assert these.
Customer Outcome: Evidence bundles and report signatures are guaranteed valid; no silent fallback to dev keys.
Revenue Impact: CRITICAL — billing evidence signed with wrong key invalidates the commercial audit trail.
Moat Impact: HIGH — integrity claim is the trust moat; a compromised signing key destroys it instantly.
Competitive Differentiation: Assessment firms have no cryptographic chain to break; FrostGate's integrity is only a moat when it's actually enforced.
Dependencies: None.
Files: `api/config/startup_validation.py`
Scope: Add two assertions; raise RuntimeError with specific key names if absent in FG_ENV=prod.
Exclusions: Do not change key generation or rotation logic.
DB Impact: NO. API Impact: NO. UI Impact: NO.
Security: Fail-closed on missing keys.
Testing: Unit test asserting startup fails with clear error when keys absent.
Acceptance Criteria:
  - `FG_BILLING_EVIDENCE_HMAC_KEY` absent → startup fails with RuntimeError naming the key
  - `MINISIGN_SECRET_KEY` absent → startup fails with RuntimeError naming the key
  - Existing startup validator tests pass
Rollback: Revert assertion. No DB changes.
Size: XS | Risk: LOW
Manual Workaround if Deferred: Jason manually checks Railway environment before each engagement — documented in CLIENT_READINESS.
Reason for Sequence: First — 2 hours, zero risk, eliminates integrity silent-failure before first client.

---

**TC-1: Evidence Provenance Foundation** *(PR 417)*

Step: 1 | Priority: P0-B | Size: M
Objective: Ship `fa_evidence_provenance` table, append-only RLS + triggers, and provenance service wired into `create_evidence_link_route`.
Root Problem: Trust chain logic (1.7, 1.8) exists but has no durable storage for provenance events — everything is in-memory or unlinked.
Customer Outcome: Every evidence link created during an assessment creates a durable, tamper-evident provenance record.
Revenue Impact: HIGH — enables legally defensible evidence chain claim.
Moat Impact: COMPOUNDING — each evidence link logged creates an immutable history that grows with every engagement and cannot be migrated away.
Competitive Differentiation: OneTrust and Vanta track checklist items; FrostGate tracks cryptographic evidence provenance. No compliance automation tool has this.
Dependencies: TC-0 (keys asserted).
Files: `services/field_assessment/evidence_provenance.py` (new), `migrations/postgres/0105_evidence_provenance.sql` (new), `api/field_assessment.py` (wire on evidence link creation)
Scope: Exactly as specced in ROADMAP.md PR 417 — 30-column table, append-only RLS, provenance service with sanitize/hash/create/list/review/verify, wired into create_evidence_link_route. 22 tests minimum.
DB Impact: YES — migration 0105, append-only RLS + triggers.
API Impact: YES — provenance data available via evidence link routes.
Security: RLS by tenant; append-only enforced at DB level.
Testing: 22 tests per ROADMAP spec.
Acceptance Criteria:
  - Creating an evidence link creates a corresponding provenance record
  - Provenance records are append-only (UPDATE/DELETE fail at DB level)
  - Provenance records are tenant-isolated
  - Chain verification returns valid on a fresh engagement
Rollback: Drop migration 0105; remove provenance service calls.
Size: M | Risk: MEDIUM
Reason for Sequence: Foundation for all downstream provenance chain PRs.

---

**TC-2: Full Chain Replay Verification** *(PRs 418 + 1.2A)*

Step: 1 | Priority: P0-B | Size: M
Objective: Ship `verify_full_provenance_chain()` in `trust_replay.py` with hash_mismatch/broken_link/cycle/duplicate detection and a deterministic replay manifest.
Root Problem: Evidence integrity cannot be replayed end-to-end — no chain walk exists from latest → genesis.
Customer Outcome: A compliance auditor or regulator can replay the entire evidence chain for an engagement and receive a signed manifest proving chain integrity.
Revenue Impact: HIGH — chain replay proof is required for regulated-industry clients.
Moat Impact: HIGH — irreversible history that regulators can verify independently.
Dependencies: TC-1.
Files: `services/field_assessment/trust_replay.py` (new), hardening from PR 1.2A
Acceptance Criteria:
  - `verify_full_provenance_chain()` walks chain from latest → genesis without loading all records into memory
  - Detects: hash_mismatch, broken_link, cycle, tenant contamination, corrupt_genesis
  - Returns `chain_replay_score` (100/75/50/0) deterministically
  - 53 tests per ROADMAP spec
Size: M | Risk: MEDIUM | Reason: Depends on TC-1 persistence.

---

**TC-3: Evidence Authority Foundation** *(PR 1.3)*

Step: 1 | Priority: P0-B | Size: M
Objective: Ship `evidence_authority.py` with Ed25519 signing over canonical provenance events.
Root Problem: Provenance records exist but are not Ed25519-signed — cannot be verified externally without trusting FrostGate's database.
Customer Outcome: Every evidence provenance event has a cryptographic signature verifiable by the client or their auditor.
Moat Impact: HIGH — externally verifiable evidence claims are rare in compliance tooling; no GRC competitor has this.
Dependencies: TC-1, TC-2.
Acceptance Criteria:
  - Ed25519 signing applied to canonical provenance event (immutable identity fields only)
  - External verifier can verify signature without accessing FrostGate database
  - 40+ tests per ROADMAP spec
Size: M | Risk: MEDIUM

---

**TC-4: Evidence-to-Report Link Authority** *(PR 1.4)*

Step: 1 | Priority: P0-B | Size: M
Objective: Ship `fa_evidence_report_links` join table connecting evidence provenance to reports with Ed25519-signed link events.
Root Problem: Evidence and reports are not cryptographically linked — cannot prove which evidence supported which report assertion.
Customer Outcome: Client (or their auditor) can trace every report assertion to the specific evidence item that supports it, with a signed link event.
Moat Impact: COMPOUNDING — as reports accumulate, the evidence-to-report link graph becomes a unique institutional memory.
Dependencies: TC-3.
DB Impact: YES — new join table, append-only.
Acceptance Criteria:
  - Report generation creates evidence-report link events
  - Link events are Ed25519-signed and append-only
  - Chain walk includes link traversal
Size: M | Risk: MEDIUM

---

**TC-5: Trust Enforcement Authority** *(PRs 1.5 + 1.5A)*

Step: 1 | Priority: P0-C | Size: M
Objective: Ship `FG_PROVENANCE_MODE` (off/warn/strict) enforcement with `TrustInputs` + `TrustDecision` dataclasses and 6 adapter functions wired into evidence creation, review, and report generation.
Root Problem: Trust decisions are computed (1.7, 1.8) but not enforced — the system produces trust scores but does not act on them.
Customer Outcome: Evidence with low trust scores is flagged at creation time (warn mode) or blocked (strict mode). Report generation fails or warns when evidence trust is below threshold.
Revenue Impact: HIGH — trust enforcement is what distinguishes FrostGate from a checklist tool.
Dependencies: TC-4.
Acceptance Criteria:
  - `FG_PROVENANCE_MODE=warn` emits warnings on low-trust evidence; does not block
  - `FG_PROVENANCE_MODE=strict` blocks evidence creation below trust threshold
  - Default is `warn` for backward compatibility
Size: M | Risk: MEDIUM

---

**TC-6: Trust Graph Persistence Foundation** *(PR 1.6)*

Step: 1 | Priority: P0-C | Size: M
Objective: Ship the durable trust graph substrate backing `trust_graph_authority.py` (already merged in 1.6A).
Root Problem: Trust graph authority (1.6A) operates on an in-memory substrate — graph state is lost on restart.
Customer Outcome: Governance topology persists across restarts; longitudinal trust graph enables historical comparison.
Moat Impact: COMPOUNDING — persistent governance graph grows with every assessment and cannot be rebuilt by a competitor from scratch.
Dependencies: TC-5.
DB Impact: YES — trust graph persistence tables.
Acceptance Criteria:
  - Trust graph state persists across API restarts
  - Existing 1.6A + 1.6B tests pass against persistent backend
  - Graph query performance acceptable for 1000+ node graphs
Size: M | Risk: MEDIUM

---

**TC-7: Wire Report Quality to Real Evidence Sources**

Step: 1 | Priority: P0-B | Size: M
Objective: Replace `_PLACEHOLDER_COVERAGE = 0.5` with live reads from field assessment evidence chain, verification bundle, and remediation status.
Root Problem: `services/report_authority/engine.py:96` — all five quality inputs (evidence_coverage, verification_coverage, freshness, confidence, completeness) hardcoded to 0.5. Report quality grade is fabricated.
Customer Outcome: Report quality scores reflect actual evidence coverage — a client with 5 evidence links on 50 controls sees ~10% coverage, not 50%.
Revenue Impact: CRITICAL — without this fix, the report is legally indefensible. Every report delivered before this PR carries legal exposure.
Moat Impact: HIGH — real quality scores make the evidence chain visible and meaningful to clients.
Competitive Differentiation: Compliance automation tools (Vanta, Drata) generate quality scores from questionnaire completion; FrostGate's quality score reflects cryptographically verified evidence coverage — provably different.
Dependencies: TC-4 (evidence-to-report links provide evidence_coverage input). TC-0 (keys asserted). Can ship in parallel with TC-3/5/6.
Files: `services/report_authority/engine.py` (primary), `services/report_authority/statistics.py`, adapter to FA evidence/verification/freshness services.
Scope: Wire five float inputs. Do NOT change quality formula. Do NOT change PDF renderer. Do NOT change hashing/manifest logic.
DB Impact: NO — reads only.
API Impact: YES — quality grades returned by `/reports/{id}` will change from 0.5 to real values.
Testing: Unit tests covering evidence_coverage = 0.0 when zero evidence, 1.0 when all controls covered, freshness decay, verification_coverage from bundle status.
Acceptance Criteria:
  - `_PLACEHOLDER_COVERAGE` constant removed
  - Report with 0 evidence links → evidence_coverage_score = 0.0 (not 0.5)
  - Report with signed verification bundle → verification_coverage_score > 0.0
  - CI passes; existing report hash/signing tests unchanged
Rollback: Restore `_PLACEHOLDER_COVERAGE = 0.5`.
Size: M | Risk: MEDIUM | Note: Can be shipped alongside TC-3/5/6 (no dependency conflict); should ship before TC-6 to unlock first client.

---

**TC-8: Persistent Ingest Report Signature Metadata** *(PR-SIGN-5b)*

Step: 1 | Priority: P0-C | Size: S
Objective: Persist Ed25519 signature metadata on `ReportRecord` (6 nullable columns); prefer persisted signature on export.
Root Problem: Report signatures are recomputed at export time — signature is not persisted alongside the report record.
Dependencies: TC-3 (Ed25519 signing pattern).
DB Impact: YES — migration 0104, 6 nullable columns on ReportRecord.
Acceptance Criteria: 18 tests per ROADMAP spec; export prefers persisted signature metadata.
Size: S | Risk: LOW

---

**TC-IDENTITY: Merge Open Identity + Capability + Subscription + Billing PRs**

Step: 1 (commercial auth layer) | Priority: P1 | Size: L aggregate
Objective: Merge all open commercial authorization PRs in dependency order.

Sequence (from ROADMAP dependencies):
1. **PR-01a** (FIAP + Identity Governance Foundation) — 144 tests, identity lifecycle FSM, session evaluator
2. **PR-01a.1** (Identity Runtime Integration) — wire governance checks into live request path
3. **PR 10** (Enterprise Identity Consolidation — Auth0 OIDC + Portal named-user) — portal OIDC, membership enforcement
4. **P1.1** (Membership Versioning + Immediate Session Revocation) — version-based revocation
5. **P1.2** (Tenant Policy Bundles + Capability Framework) — 7 canonical bundles
6. **P1.3** (Capability Enforcement Engine) — fail-closed `require_capability()` dependency
7. **P1.4** (Subscription Assignment Engine) — contract/item/ledger pipeline, auto-sync to capability bundles
8. **P1.5** (Billing Integration Layer) — Stripe provider bridge, usage metering, webhook handler

Each is already specced in ROADMAP.md with acceptance criteria. Ship in order listed. These enable the commercial authorization layer required for subscription-based pricing.

---

## ⛔ REVENUE GATE 1 — STOP BEFORE PHASE 1+

**This gate must be cleared before any Phase 2 through Phase 7 work begins. It is not optional.**

| # | Gate Requirement | PR | Cleared |
|---|---|---|---|
| G1.1 | Startup key assertions active in production | TC-0 | ☐ |
| G1.2 | Evidence provenance foundation durable in DB | TC-1 | ☐ |
| G1.3 | Report quality scores real — `_PLACEHOLDER_COVERAGE` removed | TC-7 | ☐ |
| G1.4 | Remediation authority canonical — legacy declared non-canonical | R-1 | ☐ |
| G1.5 | All portal pages render live data for real engagement | FA-1 | ☐ |
| G1.6 | Connector credential pre-flight operational | FA-2 | ☐ |
| G1.7 | AI assistant auto-enables on QA approval (no Jason action) | P-2 | ☐ |
| G1.8 | Provisioning → portal activation is deterministic | P-1 | ☐ |
| G1.9 | Remediation portal routing confirmed with live engagement data | R-2 | ☐ |
| G1.10 | Dry run H1–H18 completed end-to-end | — | ☐ |
| G1.11 | Anthropic API credit balance verified | — | ☐ |
| G1.12 | Railway Hobby plan headroom verified | — | ☐ |

**Gate 1 Exit Condition:**
One paying client. Invoice issued. Invoice paid. Report delivered. Portal accessed. Remediation roadmap opened.

**Gate 1 Rule:**
No new infrastructure work, governance capability, or Platform Expansion PR begins until Gate 1 is cleared. The only permitted new work while Gate 1 is open is fixing something that directly blocks a gate item above.

*If you are working on TC-5, TC-6, TC-8, P-5, P-6, AI-2, CM-1, RAG-1, CGIN-1, or any non-gate PR while Gate 1 is unchecked: stop and return to the checklist.*

---

### STEP 2 — FIELD ASSESSMENT: FIRST PAYING CLIENT

**FA-1: Validate All Portal Pages with Live Engagement Data**

Step: 2 | Priority: P0-C | Size: S
Objective: Confirm reports page, coverage page, and attestation page return live data for a real engagement. Identify and fix any broken API bindings.
Root Problem: Revenue plan verification_backlog identifies reports, coverage, and attestation pages as unconfirmed with live data.
Customer Outcome: Client can download their report, view framework coverage, and submit attestations without encountering empty or broken content.
Dependencies: TC-7 (report quality real).
Files: `apps/portal/app/reports/`, `apps/portal/app/coverage/`, `apps/portal/app/attestation/`, `apps/portal/lib/portalApi.ts`
Acceptance Criteria: Each page renders real data for a completed engagement; empty state is explicit and informative; no 5xx errors on standard client flows.
Size: S | Risk: LOW | Manual Workaround: Jason emails PDF directly and covers coverage in person during assessment review.

---

**FA-2: Add Connector Credential Pre-Flight Validation**

Step: 2 | Priority: P0-C | Size: S
Objective: Validate MS Graph credentials before launching a scan; fail with clear error at engagement creation if credentials are invalid.
Root Problem: A scan launched with invalid credentials runs for hours and silently fails.
Customer Outcome: Jason receives a clear error at scan launch time, not 3 hours into a live engagement.
Files: `api/field_assessment.py` (engagement creation flow), `services/connectors/msgraph/credential.py`
Acceptance Criteria: Invalid credentials at scan launch → 422 with descriptive error. Valid credentials → scan proceeds normally.
Size: S | Risk: LOW

---

**FA-3: Verify Production Embedding Provider + Startup Check**

Step: 2 | Priority: P1 | Size: S
Objective: Confirm production AI calls use real semantic embeddings (not stub_provider); add startup assertion.
Root Problem: Production embedding provider unconfirmed per verification_backlog. If stub_provider active, RAG answers are keyword-matched.
Customer Outcome: AI assistant answers are semantically grounded, not lexical matches.
Files: `api/embeddings/state.py`, `api/config/startup_validation.py`
Acceptance Criteria: Startup fails if stub_provider detected in FG_ENV=prod; production chat returns answer referencing embedded document; embedding provider name logged.
Size: S | Risk: MEDIUM

---

### STEP 3 — CUSTOMER PORTAL

**P-1: Bind Provisioning to Portal Activation Deterministically**

Step: 3 | Priority: P0-C | Size: S
Objective: Ensure tenant provisioning → portal grant issuance → client session is a deterministic sequence with no manual gaps.
Root Problem: Provisioning completion does not automatically seed portal prerequisites (Codex: "activation handoff to provisioning is still manual-ish").
Files: `api/provisioning_manager.py`, `services/provisioning/`, portal grant tables (migration 0080).
Acceptance Criteria: After provisioning completes, client can log into portal without additional operator action. Integration test covers full flow.
Size: S | Risk: LOW

---

**P-2: Auto-Enable AI Assistant on QA Approval**

Step: 3 | Priority: P0-C | Size: S
Objective: Remove `portal_ai_enabled` manual gate; auto-enable AI assistant when assessment is QA-approved.
Root Problem: `apps/portal/app/assistant/page.tsx:72` — `portal_ai_enabled` flag in engagement metadata with no automation and no operator UI.
Customer Outcome: Client opens AI Assistant immediately after receiving portal access. No Jason action required.
Revenue Impact: CRITICAL for MRR — the AI workspace is the highest-habit-forming, highest-switching-cost feature. Dark by default means no habit.
Moat Impact: COMPOUNDING — each AI conversation compounds the RAG corpus value; auto-enable on delivery starts compounding immediately.
Competitive Differentiation: Assessment firms have no AI; Vanta/Drata have generic AI copilots with no evidence grounding. FrostGate's AI knows this client's specific findings, evidence, and controls.
Files: `apps/portal/app/assistant/page.tsx` (remove flag check), `api/field_assessment.py` (QA approval → set portal_ai_enabled).
Acceptance Criteria: AI assistant enabled for client after QA approval; first response returned within 5s; policy enforcement active.
Size: S | Risk: LOW

---

**P-3: Subscription Intent Surface in Portal**

Step: 3 | Priority: P1 | Size: S
Objective: Add a subscription offer modal on the portal report delivery page — even "notify Jason" model sufficient for clients 1-3.
Root Problem: No client-facing path to upgrade to recurring subscription after assessment delivery.
Customer Outcome: Client sees a clear CTA to continue with remediation tracking / AI workspace / monitoring after reviewing their report.
Dependencies: TC-IDENTITY (P1.4 merged).
Files: `apps/portal/app/reports/`, new modal component, `POST /portal/subscription/request` route.
Acceptance Criteria: Client clicks "Continue with FrostGate" → request logged in system → Jason notified. No payment required yet (Phase 3 adds checkout).
Size: S | Risk: LOW

---

**P-4: Portal Notifications — Overdue Tasks + Report Ready**

Step: 3 | Priority: P1 | Size: M
Objective: Implement basic email notifications for overdue remediation tasks and report delivery events.
Root Problem: Clients have no pull to return to portal without Jason prompting manually. Portal habit requires notifications.
Files: `services/notifications/`, `apps/portal/app/notifications/`
Acceptance Criteria: Overdue remediation task → client email within 24 hours. Report delivered → client notified with portal link. Notification preferences stored per-user.
Size: M | Risk: MEDIUM

---

**P-5: Executive Summary Dashboard (Board-Ready)**

Step: 3 | Priority: P1 | Size: M
Objective: Add a board-facing executive dashboard to the portal — risk posture summary, compliance coverage, open findings count, remediation progress.
Root Problem: Portal currently requires navigating tabs; executives need a single-screen view they can show their board.
Customer Outcome: CISO can open one URL and screenshot governance posture for board reporting.
Moat Impact: HIGH — a CISO who presents FrostGate data at their board meeting creates organizational lock-in.
Files: `apps/portal/app/dashboard/`, new executive summary component.
Size: M | Risk: LOW

---

**P-6: Governance Timeline View**

Step: 3 | Priority: P2 | Size: M
Objective: Render a chronological governance timeline in the portal — assessments, finding closures, attestations, policy changes, risk acceptances.
Customer Outcome: Client has a permanent, immutable record of their governance history that they can show regulators.
Moat Impact: COMPOUNDING — governance timeline grows with every action; cannot be replicated by starting over with a competitor.
Size: M | Risk: LOW

---

### STEP 4 — REMEDIATION TRACKING

**R-1: Declare Remediation Authority Canonical**

Step: 4 | Priority: P0-D | Size: XS
Objective: Mark `api/remediation.py` non-canonical; ensure portal routes through `api/remediation_authority.py` exclusively.
Root Problem: Two active remediation systems. Split-brain means client remediation state could be split between systems.
Files: `api/remediation.py` (add non-canonical header/comment), `api/portal_remediation.py` (redirect to authority routes), ROADMAP.md.
Acceptance Criteria: All portal remediation traffic hits `remediation_authority.py`; legacy module not called from any portal path.
Size: XS | Risk: LOW | Manual Workaround: None — this is a declaration, not a rewrite.

---

**R-2: Validate Portal Remediation with Live Engagement Data**

Step: 4 | Priority: P0-D | Size: S
Objective: Confirm `RemediationCenter.tsx` renders real data from `remediation-roadmap` endpoint for a completed engagement.
Root Problem: Revenue plan verification_backlog item — remediation endpoint exists and is wired, but live-data behavior unconfirmed.
Acceptance Criteria: All 4 status tabs (open/overdue/completed/blocked) render; status patch updates UI; evidence upload works; empty state explicit.
Size: S | Risk: LOW

---

**R-3: Remediation Notifications — Email for Overdue Tasks**

Step: 4 | Priority: P1 | Size: S
Objective: Send client email when remediation tasks become overdue. Jason can verify and close.
Root Problem: Clients forget about overdue tasks without notifications; Jason must follow up manually.
Dependencies: P-4 (notification infrastructure).
Size: S | Risk: LOW

---

**R-4: Retest + Closure Verification**

Step: 4 | Priority: P1 | Size: M
Objective: Implement formal retest workflow — Jason verifies remediation evidence, marks finding as closed, generates closure record in governance decision ledger.
Customer Outcome: Client can demonstrate to their board and auditors that findings were formally verified and closed.
Moat Impact: HIGH — closure records in append-only ledger are the regulatory audit package.
Dependencies: R-1, R-2.
Acceptance Criteria: Finding closure creates a GovernanceDecision record. Client sees verified closure state in portal. Closure is irreversible.
Size: M | Risk: MEDIUM

---

**R-5: Exception Management**

Step: 4 | Priority: P2 | Size: M
Objective: Allow clients to formally accept risk for a finding with a reason, approval chain, and expiry date.
Dependencies: R-4.
Acceptance Criteria: Exception request → approval flow → accepted/rejected state in ledger. Expired exceptions surface in dashboard.
Size: M | Risk: MEDIUM

---

**R-6: Remediation SLA Enforcement**

Step: 4 | Priority: P2 | Size: S
Objective: Surface SLA breaches in portal and notifications. Critical findings overdue 30+ days → escalation.
Size: S | Risk: LOW

---

### STEP 5 — AI WORKSPACE

**AI-1: Self-Serve Stripe Subscription Checkout**

Step: 5 | Priority: P1 | Size: M
Objective: Add portal Stripe Checkout flow — client clicks "Subscribe" → Stripe Checkout → webhook → capability auto-activated.
Root Problem: P1.4 subscription engine exists (when merged); no client-facing checkout page.
Dependencies: TC-IDENTITY (P1.4 + P1.5 merged).
Files: `apps/portal/` new checkout route, Stripe Checkout integration, `services/billing/stripe_provider.py`, webhook flow.
Acceptance Criteria: Client completes checkout → `SubscriptionContract` created → capabilities auto-assigned → AI assistant auto-enabled → first portal session after checkout shows AI enabled.
Size: M | Risk: MEDIUM

---

**AI-2: Conversation History and Saved Sessions**

Step: 5 | Priority: P1 | Size: M
Objective: Persist AI workspace conversations per tenant+user. Client can return to prior investigations.
Root Problem: No conversation history exists. Every session starts blank. No habit formation possible without memory.
Moat Impact: COMPOUNDING — as conversation history grows, the AI workspace becomes a richer working environment. Historical investigations compound in value.
Files: `api/ui_ai_console.py`, `apps/portal/app/assistant/`, new conversation persistence tables.
DB Impact: YES — conversation/message tables, append-only, tenant-isolated.
Acceptance Criteria: Session persists across browser closes; client can reference prior answer; conversation list shows previous sessions; tenant isolation enforced.
Size: M | Risk: MEDIUM

---

**AI-3: Citation Display in AI Workspace**

Step: 5 | Priority: P1 | Size: M
Objective: Display source citations in AI responses — document name, section, chunk, evidence link.
Root Problem: AI answers have no source attribution. Client cannot verify or trust AI assertions. "Governed AI" claim requires provenance.
Moat Impact: HIGHEST — cited answers grounded in client's own verified evidence are the primary differentiator vs. every AI copilot competitor. Credo AI, Fairly AI, generic AI assistants produce uncited answers. FrostGate produces answers with cryptographic provenance.
Dependencies: RAG-1 (retry operational), AI-2 (conversation history).
Acceptance Criteria: AI response includes citation block with document name, section, engagement context, confidence score. Clicking citation opens source document.
Size: M | Risk: MEDIUM

---

**AI-4: Evidence Interrogation Mode**

Step: 5 | Priority: P1 | Size: M
Objective: Allow client to ask questions directly about their uploaded evidence files — "What does our incident response plan say about AI systems?"
Dependencies: RAG-3 (FA evidence bound to RAG corpus).
Acceptance Criteria: Client can query evidence by natural language; answers cite specific evidence documents; tenant isolation verified.
Size: M | Risk: MEDIUM

---

**AI-5: Report Q&A Mode**

Step: 5 | Priority: P2 | Size: M
Objective: Client can ask questions about their assessment report — "What were our 3 most critical AI governance findings?"
Dependencies: RAG-3.
Acceptance Criteria: AI answers reference specific report sections; citations include report version hash.
Size: M | Risk: LOW

---

**AI-6: Remediation Drafting Mode**

Step: 5 | Priority: P2 | Size: M
Objective: AI Workspace can draft remediation actions based on findings — generates step-by-step remediation plan for a specific finding.
Dependencies: AI-3, AI-4.
Acceptance Criteria: Drafted remediation is saved as a draft task in remediation tracking; not auto-confirmed without human review.
Size: M | Risk: MEDIUM

---

**AI-7: Policy Drafting Mode**

Step: 5 | Priority: P2 | Size: L
Objective: AI Workspace can draft governance policies — AI Use Policy, Data Governance Policy, Vendor Risk Policy — based on client's assessment findings.
Dependencies: AI-3, RAG-5 (corpus management).
Moat Impact: HIGH — policy drafts grounded in client's evidence are unique; generic policy generators exist everywhere but none are assessment-evidence-grounded.
Acceptance Criteria: Drafted policy is saved as a draft document; goes through approval workflow before being committed to governance record.
Size: L | Risk: MEDIUM

---

**AI-8: Executive Summary Generation (on-demand)**

Step: 5 | Priority: P2 | Size: S
Objective: Client can generate a board-ready executive summary from the AI workspace at any time — not just at report delivery.
Dependencies: AI-3.
Acceptance Criteria: Summary generated on demand; includes current risk posture, remediation progress, and governance timeline highlights; exportable as PDF.
Size: S | Risk: LOW

---

### STEP 6 — ENTERPRISE RAG

**RAG-1: Wire Retry-Ingestion (Remove 503)**

Step: 6 | Priority: P1 | Size: M
Objective: Implement the retry-ingestion route that currently returns 503 with `"planned": True`.
Root Problem: `api/rag_corpus_ingestion.py:1073` — explicit 503 stub. Document re-ingestion after failure is impossible.
Customer Outcome: Failed document ingestion can be retried without data loss.
Files: `api/rag_corpus_ingestion.py` (implement retry logic), `services/embeddings/` (retry embedding call).
Acceptance Criteria: `POST /rag/documents/{id}/retry-ingestion` succeeds for a previously failed document; retry route no longer returns 503; retry state tracked.
Size: M | Risk: MEDIUM

---

**RAG-2: Bind Field Assessment Evidence to Client RAG Corpus**

Step: 6 | Priority: P1 | Size: M
Objective: Create deterministic path from uploaded client evidence files into tenant-bound RAG corpus collections.
Root Problem: RAG exists in isolation from field assessment evidence — uploaded client documents are not automatically available for AI interrogation.
Moat Impact: COMPOUNDING — as clients upload more evidence, the AI workspace becomes smarter about their environment. This corpus grows permanently and cannot be recreated by a competitor.
Dependencies: RAG-1.
Files: `api/field_assessment.py` (evidence upload hook), `api/rag_corpus_ingestion.py` (corpus binding), tenant corpus management.
Acceptance Criteria: Evidence uploaded during assessment appears in tenant corpus; AI assistant can query evidence with citation; ACL binding prevents cross-tenant access.
Size: M | Risk: MEDIUM

---

**RAG-3: RAG Freshness Tracking**

Step: 6 | Priority: P2 | Size: S
Objective: Track when each corpus document was last updated; surface stale documents in console; block retrieval of documents past freshness window.
Dependencies: RAG-2.
Acceptance Criteria: Documents past freshness threshold flagged in corpus management; AI response notes freshness of cited source.
Size: S | Risk: LOW

---

**RAG-4: Corpus Management UI**

Step: 6 | Priority: P2 | Size: M
Objective: Operator UI for viewing, managing, and organizing client corpus — documents, chunks, embedding status, freshness.
Dependencies: RAG-2.
Size: M | Risk: LOW

---

**RAG-5: Deletion and Retention Lifecycle**

Step: 6 | Priority: P2 | Size: M
Objective: Implement document deletion from corpus with provenance record — client-requested deletion removes chunks and embedding vectors.
Root Problem: No deletion lifecycle confirmed. Regulatory compliance (GDPR, HIPAA retention) requires data deletion capability.
Dependencies: RAG-2.
DB Impact: YES — deletion event log, append-only, with tombstone records.
Acceptance Criteria: Deleted document no longer retrieved; deletion event logged; chunk vectors removed; prior citations remain but note deletion.
Size: M | Risk: HIGH (data integrity implications)

---

**RAG-6: Prompt Injection and Poisoning Defenses**

Step: 6 | Priority: P2 | Size: M
Objective: Implement defenses against corpus poisoning (malicious documents that redirect AI behavior) and prompt injection through document content.
Root Problem: Enterprise RAG without poisoning defenses is not enterprise-safe. `api/rag/guardrails.py` exists; confirm it covers corpus poisoning.
Files: `api/rag/guardrails.py`, `api/rag/safety.py`
Acceptance Criteria: Corpus document containing prompt injection instructions does not override system behavior; adversarial retrieval test suite passes.
Size: M | Risk: HIGH

---

### STEP 7 — CONTINUOUS MONITORING

**CM-1: Make Trust Monitoring Fail-Visible**

Step: 7 | Priority: P1 | Size: S
Objective: Stop TIM from swallowing errors and returning `{}`. Make monitoring failure explicit in API response and operator dashboard.
Root Problem: `services/trust_monitoring/monitoring_engine.py` logs errors and returns `{}` — degraded monitoring looks like clean posture.
Customer Outcome: Operator sees "monitoring degraded" rather than false clean status. Client portal would not show stale monitoring results as current.
Competitive Differentiation: Continuous trust requires visible failure states; a platform that fails silently cannot claim "continuous trust."
Files: `services/trust_monitoring/monitoring_engine.py`
Acceptance Criteria: Monitoring error → explicit error state in API response with timestamp; no `{}` success return on failure path; operator dashboard shows degraded state.
Size: S | Risk: LOW

---

**CM-2: One Real Connector Monitoring Path (MS Graph Recurring Scan)**

Step: 7 | Priority: P1 | Size: L
Objective: Implement real recurring monitoring for one connector (MS Graph) — replace stub polling with a scheduled real scan and delta detection.
Root Problem: `services/connectors/runner.py:170-173` returns `polling: stub`. No continuous monitoring is real today.
Customer Outcome: Client receives drift alerts when their MS 365 environment changes — new risky OAuth grants, new admin accounts, new AI tool access.
Revenue Impact: CRITICAL for MRR renewal — recurring monitoring is the primary justification for an ongoing subscription.
Moat Impact: HIGH — longitudinal drift data creates a governance history that compounds with every scan.
Competitive Differentiation: Assessment firms deliver static PDFs; continuous monitoring with evidence chain creates a perpetual advantage. Vanta/Drata monitor technical controls; FrostGate monitors AI governance posture — unique.
Files: `services/connectors/runner.py` (replace stub), `services/connectors/drift/scheduler.py` (real scheduler), `api/connectors_control_plane.py`.
Acceptance Criteria: MS Graph scan runs on schedule (daily or configurable); delta detected between scans; finding created when new risky OAuth grant appears; portal drift alert generated.
Size: L | Risk: HIGH

---

**CM-3: Continuous Monitoring Dashboard in Portal**

Step: 7 | Priority: P1 | Size: M
Objective: Surface monitoring status, last scan time, drift alerts, and posture trend in the client portal.
Root Problem: No client-visible monitoring surface — clients cannot see ongoing governance health without logging into the console.
Customer Outcome: Client logs into portal dashboard and sees "Last scan: 6 hours ago. 2 new drift alerts since your assessment. Trust score: 84/100."
Dependencies: CM-2.
Files: `apps/portal/app/trust/`, `apps/portal/components/portal/TrustDrift.tsx`, `apps/portal/components/portal/TrustHeatmap.tsx`.
Size: M | Risk: LOW

---

**CM-4: Evidence Freshness Alerts**

Step: 7 | Priority: P2 | Size: S
Objective: Alert clients when evidence is approaching or past freshness threshold — drives active engagement with the portal.
Dependencies: CM-3, `services/evidence_freshness_authority/`.
Acceptance Criteria: Client notified 30 days before evidence expires; portal surfaces expired evidence in findings view.
Size: S | Risk: LOW

---

**CM-5: Control Drift Detection**

Step: 7 | Priority: P2 | Size: M
Objective: Detect when a previously-controlled AI governance control has regressed — new AI tool deployed without governance, MFA disabled for admin user, etc.
Dependencies: CM-2.
Moat Impact: HIGH — control drift tracking over time creates a governance memory that is unique to FrostGate's evidence chain.
Size: M | Risk: MEDIUM

---

**CM-6: Scheduled Reassessment Engine**

Step: 7 | Priority: P2 | Size: L
Objective: Trigger a partial reassessment when drift exceeds threshold — automatically schedules a focused scan and generates updated findings.
Dependencies: CM-5.
Customer Outcome: Client receives a "Reassessment Required" alert with specific drifted controls when their environment changes materially.
Size: L | Risk: HIGH

---

### STEP 8 — CGIN

**CGIN-1: Surface CGIN Benchmark in Client Portal**

Step: 8 | Priority: P2 | Size: M
Objective: Display client's governance maturity percentile against anonymized peer data in the portal dashboard.
Root Problem: CGIN infrastructure (Ed25519, Merkle, privacy hardening) is built but invisible to clients.
Customer Outcome: CISO sees "Your AI governance maturity is in the 73rd percentile for your industry sector." Drives renewal and competitive positioning.
Moat Impact: COMPOUNDING + NETWORK EFFECT — each new client improves the benchmark; clients with more clients in their sector get better benchmarks; switching means losing benchmark positioning.
Competitive Differentiation: No GRC platform, AI governance tool, or assessment firm has cross-tenant anonymized benchmarking with cryptographic privacy guarantees.
Dependencies: 5+ clients with data in the system.
Files: `apps/portal/app/trust/`, `services/cgin/`, `api/cgin_trust.py`.
Acceptance Criteria: Client sees percentile rank (no peer names exposed); benchmark is cryptographically anonymized per privacy.py; trust verified via Merkle root.
Size: M | Risk: MEDIUM

---

**CGIN-2: Industry Maturity Scoring**

Step: 8 | Priority: P2 | Size: M
Objective: Generate industry-specific maturity scores (healthcare AI governance, fintech AI governance, etc.) from aggregated CGIN data.
Dependencies: CGIN-1, 10+ clients.
Size: M | Risk: MEDIUM

---

**CGIN-3: Privacy-Preserving Contribution Pipeline**

Step: 8 | Priority: P2 | Size: L
Objective: Build the client consent and data contribution pipeline — clients opt in to contributing anonymized governance data to CGIN.
Dependencies: CGIN-1.
Size: L | Risk: HIGH (privacy compliance requirements)

---

**CGIN-4: Trend Analytics**

Step: 8 | Priority: P3 | Size: M
Objective: Surface governance trend analytics — industry-wide AI governance adoption curves, control adoption rates, most common findings.
Dependencies: CGIN-3, 20+ clients.
Size: M | Risk: LOW

---

### STEP 9 — AUTONOMOUS GOVERNANCE

*Defer until Steps 1-7 complete and product-market fit is demonstrated.*

**AG-1: Policy Enforcement Engine Surface**
Objective: Expose governance_orchestration policy enforcement as a client-facing capability — automated policy checks on governance decisions.
Dependencies: Steps 1-7 complete.
Size: L | Priority: P3

**AG-2: Approval Routing Automation**
Objective: Route governance decisions through configurable approval chains — no human bottleneck for routine governance.
Size: L | Priority: P3

**AG-3: Agent Governance Framework**
Objective: Govern AI agents acting on behalf of the organization — approvals, restrictions, monitoring, exception handling.
Size: XL | Priority: Strategic Later

---

### STEP 10 — AGI-SCALE GOVERNANCE

*Defer until Steps 1-9 complete. Target types (AGI, agent_swarm, decision_engine) already exist in the field assessment schema — no schema migration required when this step is activated.*

**AGI-1: Machine Identity Governance**
**AGI-2: Cross-Agent Trust Negotiation**
**AGI-3: AI Constitutional Governance**
All: Size: XL | Priority: Strategic Later

---

## Section 8: Expansion Backlog

| Item | Triggering Condition | Why Deferred |
|---|---|---|
| SAML 2.0 enterprise SSO | First enterprise deal that explicitly requires SAML | Not needed for clients 1-5; defers 6-8 weeks of work |
| FedRAMP ATO preparation | Signed govcon client letter of intent | 12-18 month and $100k+ investment; no govcon client identified |
| PCI DSS playbook | Signed PCI client | No PCI client; scope increases liability |
| Multi-region deployment | Client contractually requires EU or specific region data residency | Railway scales first; region-specific deployment after client 10 |
| HITRUST certification | Healthcare client requiring HITRUST | Pursue after SOC 2 Type II complete |
| SOC 2 Type II for FrostGate itself | Pre-sales requirement from enterprise client | Start observation period at Phase 5 (5 clients) |
| External penetration test | Pre-regulated-enterprise contract | Commission after Phase 5; required before Phase 6 |
| governance_simulation | Client requests scenario planning | Not buildable until clients have established governance baselines |
| governance_digital_twin | Client requests digital twin | Requires scale that doesn't exist yet |
| governance_learning / optimization / adaptive_intelligence | Data scale requirements | Year 3 capability; requires aggregated governance data at scale |
| ai_plane_extension extensions | Live production call path confirmed | 1,143-line service flagged as potentially dead; audit before building more |
| Duplicate console subtree cleanup (apps/console/console) | Available engineering bandwidth | Negative impact only; cleanup when not on critical path |
| Legacy backend app removal (backend/app) | Available bandwidth | Topology ambiguity only; safe to defer |

---

## Section 9: Timeline to First Paying Customer

**Critical Path:** TC-0 → TC-1 → TC-7 → TC-2 → TC-3 → TC-4 → FA-1 → FA-2 → R-1 → R-2

| Step | PRs | Duration | Parallelizable With |
|---|---|---|---|
| TC-0: Startup key assertions | 1 PR (XS) | 0.5 days | Nothing — ship today |
| TC-1: Evidence provenance foundation | 1 PR (M) | 3-4 days | TC-0 complete |
| TC-7: Report quality fix | 1 PR (M) | 3-5 days | Parallel with TC-2, TC-3 after TC-1 |
| TC-2: Chain replay verification | 1 PR (M) | 3-4 days | Parallel with TC-7 |
| TC-3: Evidence authority | 1 PR (M) | 3-4 days | After TC-2 |
| TC-4: Evidence-to-report link | 1 PR (M) | 2-3 days | After TC-3 |
| FA-1: Portal page validation | 1 PR (S) | 1-2 days | Parallel with TC-3 |
| FA-2: Credential pre-flight | 1 PR (S) | 1 day | Parallel with TC-4 |
| R-1: Remediation canonical | 1 PR (XS) | 0.5 days | Parallel with TC-0 |
| R-2: Remediation live validation | 1 PR (S) | 1-2 days | After R-1 |
| Dry run H1-H18 | Not a PR | 1 day | After all above |

**Estimated total: 3-4 weeks to first deliverable client engagement.**

Revenue range: $5,000-$40,000 for first assessment depending on framework scope.

---

## Section 10: Timeline to Sustainable MRR

**Definition:** 3+ clients paying recurring subscriptions (portal + remediation + AI workspace).

| Phase | PRs | Duration | Revenue Milestone |
|---|---|---|---|
| Phase 2-3: Portal + Remediation | P-1, P-2, P-3, P-4, R-3, R-4 | Weeks 5-10 | First portal subscription ($300-$800/mo) |
| TC-IDENTITY merges (P1.2-P1.5) | 4 open PRs | Parallel, weeks 3-8 | Subscription infrastructure live |
| Phase 4: AI Workspace foundation | AI-1, AI-2, AI-3 | Weeks 10-16 | AI Workspace subscription ($500-$2k/mo) |
| Phase 5: First 3 recurring clients | Operate clients 2-3 | Weeks 12-20 | Sustainable MRR: $2k-$6k/mo |

**Estimated: 4-6 months to sustainable MRR of $5k-$10k/month from 3+ clients.**

---

## Section 11: Timeline to Platform Leadership

**Definition:** FrostGate is the recognized category leader for enterprise AI governance + continuous trust. CGIN benchmark data makes switching economically irrational.

| Phase | Milestone | Timeline |
|---|---|---|
| Phase 6: Continuous Monitoring | One real connector monitoring path live; client portal shows drift alerts | Month 6-8 |
| Phase 7-8: AI Workspace + RAG mature | Citations, saved sessions, corpus management live | Month 8-12 |
| Phase 8: CGIN Surface | Benchmarks visible to clients; industry maturity scores | Month 12-18 |
| 10+ clients | Network effect begins; CGIN data meaningful; governance graph rich | Month 18-24 |
| Category leadership | No competitor can offer: assessor evidence + chain + governed AI + cross-tenant benchmarks | Month 24-36 |

**Estimated: 24-36 months to unassailable category position if execution follows this roadmap.**

---

## Section 12: Risks to Revenue

| Risk | Category | Probability | Impact | Current Mitigation | Gap | Action |
|---|---|---|---|---|---|---|
| Report quality placeholder discovered during client review | Legal | HIGH | CRITICAL | None | PR TC-7 not shipped | Ship TC-7 before first invoice |
| Anthropic credit depleted during engagement | Operational | MEDIUM | HIGH | $3.50 confirmed 2026-05-31 | Balance may be depleted | Verify balance before each engagement; set credit alert |
| Connector credential failure during live engagement | Operational | MEDIUM | HIGH | `docs/operators/azure_ad_app_setup.md` | No pre-flight check | Ship FA-2 |
| Railway Hobby plan capacity exceeded under load | Infrastructure | MEDIUM | HIGH | None confirmed | A10 unchecked in CLIENT_READINESS | Check Railway metrics before first client engagement |
| Single operator dependency (Jason) | Operational | HIGH | CRITICAL | 13 operator runbooks | Zero delegation; zero automation | Ship P-2 (AI auto-enable), TC-IDENTITY (P1.4); train second operator |
| Subscription conversion requires Jason for every client | Revenue | HIGH | HIGH | Manual workaround documented | No checkout UI | Ship AI-1 (Stripe checkout) before client 4 |
| Continuous monitoring pitched before it works | Sales | MEDIUM | HIGH | Internal — do not pitch | No external disclosure plan | Do not sell monitoring until CM-2 shipped |
| TIM silent failure creating false clean posture | Trust | MEDIUM | HIGH | None | `monitoring_engine.py` fail-open | Ship CM-1 immediately after CM infrastructure stable |
| AI workspace quality disappoints if embeddings are stub | Trust | MEDIUM | HIGH | None confirmed | FA-3 unshipped | Ship FA-3 before enabling AI for enterprise clients |

---

## Section 13: Risks to Architecture

| Risk | Impact | Evidence | Recommendation |
|---|---|---|---|
| Remediation split-brain | Client remediation state split across two systems; data integrity risk at scale | `api/remediation.py` and `api/remediation_authority.py` both active | Ship R-1 immediately (XS — 0.5 days) |
| Duplicate console subtree | Stale code increases review surface; supply-chain risk | `apps/console/console/` — 114 overlapping paths | Schedule cleanup PR when not on critical path |
| Legacy backend app ambiguity | Inventory and topology confusion; unclear which app is authoritative | `backend/app/main.py` | Document as non-authoritative; remove in cleanup pass |
| Runtime-contract drift (1178 vs 1012 routes) | Unmanaged API surface; weakens contract governance | `artifacts/route_inventory_summary.json` | Add drift check to CI; reconcile top 50 uncontracted routes |
| Dead symbol accumulation (403 flagged) | Ambiguity about what's live in production; maintenance burden | `artifacts/full_repo_census/13_DEAD_DUPLICATE_ORPHAN_PLACEHOLDER_MAP.md` | Audit top 20 flagged services; quarantine confirmed dead; add live integration tests for confirmed live |
| Trust chain foundation (1.1-1.6) built after logic (1.6A-1.8A) | Top-down build creates risk of impedance mismatch between logic and persistence layers | ROADMAP.md — 1.6A merged before 1.6 | Prioritize TC-1 through TC-6; validate logic layer against persistence layer systematically |
| `services/ai/` call path ambiguous | 403 dead-symbol flags include AI dispatch — may mean AI Workspace is not routing through this module | `artifacts/full_repo_census/13_DEAD_DUPLICATE_ORPHAN_PLACEHOLDER_MAP.md` | Trace one production AI chat request end-to-end; confirm actual call path before shipping AI-2 |

---

## Section 14: Risks to Long-Term Vision

| Risk | Vision Threatened | Probability | Mitigation |
|---|---|---|---|
| CGIN privacy compromise | Cross-tenant benchmark intelligence is the 24-month network-effect moat | LOW (Ed25519 + privacy hardening done) | Continue privacy-first approach; third-party privacy audit before CGIN-1 ships |
| RAG corpus poisoning | Client's AI workspace gives adversarial answers | MEDIUM | Ship RAG-6 (poisoning defenses) before client corpus grows materially; `guardrails.py` already started |
| Governance graph accuracy degradation | If evidence quality is low, the governance graph becomes misleading | MEDIUM | TC-7 (quality fix) + TC-5 (trust enforcement) ensure only trusted evidence enters the graph |
| Competitor replication of evidence chain | Evidence chain is replicable in theory | MEDIUM (12-18 month lead) | Deepen moat by making the compounding data irreplaceable — more engagements, more clients, more graph depth |
| Autonomous governance prematurely deployed | Autonomous actions without sufficient trust foundation cause governance failures | LOW today | Enforce Step 1-7 completion before AG-1 ships; autonomous governance requires the full trust chain |
| Regulatory requirement for FrostGate's own compliance | Enterprise clients may require FrostGate's own SOC 2, FedRAMP, HITRUST | MEDIUM | Start SOC 2 Type II observation period at Phase 5 (5 clients); plan for 12-month certification timeline |
| Single-founder knowledge concentration | All platform knowledge in Jason's head | HIGH today | Document all operator procedures; train second operator; automate top 10 manual workflows before client 5 |

---

## Section 15: Final Recommended Execution Order

### Complete Stop-Doing List

| Item | Reason |
|---|---|
| New work in governance_orchestration, governance_simulation, governance_digital_twin, governance_learning, governance_optimization, governance_adaptive_intelligence | Phase 9-10 work; no client has asked for it; each new file delays first revenue |
| Extending ai_plane_extension until call path confirmed | 1,143-line service may be entirely dead; audit first |
| New CI lanes | 15 lanes exceeds 1-person team needs; slow PR cycle |
| FedRAMP planning | No signed govcon client; premature |
| PCI DSS playbook | No signed PCI client |
| SAML before client 5 | Not needed; portal OIDC (PR 10) sufficient for clients 1-5 |
| Trust-chain depth beyond TC-0 through TC-8 | The trust chain is commercially sufficient after TC-8; do not add more provenance layers before first client |
| Duplicate console subtree (non-urgent) | Wait for engineering bandwidth; do not let it interrupt the revenue path |

### Stays Manual Through Clients 1-3

| Step | Manual Process | Owner |
|---|---|---|
| Tenant creation | JSON API or console | Jason |
| Engagement creation | Console | Jason |
| MS Graph credential entry | Console scan panel | Jason + Client IT |
| Scan triggering | Console scan panel | Jason |
| QA approval | Console QA button | Jason |
| AI assistant enable | Auto after P-2 ships | — |
| Invoice issuance | Stripe Dashboard | Jason |
| Subscription activation | Portal intent form (P-3) → Jason creates in Stripe | Jason |
| Second operator onboarding | Email + documentation | Jason |

### Must Automate Before Client 5

| Capability | PR | Why |
|---|---|---|
| AI assistant activation | P-2 (auto-enable on QA) | Cannot enable per-client at scale |
| Subscription activation | AI-1 (Stripe checkout) | Cannot bill manually at scale |
| Portal activation | P-1 (provisioning bind) | Cannot set up per-client at scale |
| Overdue task notifications | P-4 | Cannot follow up per-client manually |
| Capability enforcement | TC-IDENTITY (P1.3) | Manual enforcement breaks at scale |
| Usage metering | TC-IDENTITY (P1.5) | Cannot bill usage manually at scale |
| Second-operator delegation | Documentation + console | Single-operator risk |
| Production health monitoring | Already deployed (UptimeRobot, Sentry) | Maintain |
| Evidence bundle signing | TC-0 (startup key assertion) | Silent failure at any scale is unacceptable |
| Remediation routing (canonical) | R-1 | Split-brain gets worse at scale |

---

### Complete PR Execution Sequence

**LANE 1 — REVENUE CRITICAL PATH (Before First Invoice)**

| # | PR | Title | Priority | Size | Deps | Primary KPI |
|---|---|---|---|---|---|---|
| 1 | TC-0 | Assert production keys at startup | P0-A | XS | — | Billing Integrity |
| 2 | R-1 | Declare remediation authority canonical | P0-D | XS | — | Monthly Retention |
| 3 | TC-1 | Evidence provenance foundation (PR 417) | P0-B | M | TC-0 | Report Defensibility |
| 4 | TC-7 | Wire report quality to real evidence sources | P0-B | M | TC-1 | Report Defensibility |
| 5 | TC-2 | Full chain replay verification (PR 418+1.2A) | P0-B | M | TC-1 | Customer Trust |
| 6 | TC-3 | Evidence authority foundation (PR 1.3) | P0-B | M | TC-2 | Customer Trust |
| 7 | TC-4 | Evidence-to-report link authority (PR 1.4) | P0-B | M | TC-3 | Customer Trust |
| 8 | FA-1 | Validate portal pages with live engagement data | P0-C | S | TC-7 | Portal Adoption |
| 9 | FA-2 | Connector credential pre-flight validation | P0-C | S | — | Portal Adoption |
| 10 | P-1 | Bind provisioning to portal activation | P0-C | S | PR-01a | Portal Adoption |
| 11 | P-2 | Auto-enable AI assistant on QA approval | P0-C | S | — | Subscription Conversion |
| 12 | R-2 | Validate portal remediation with live data | P0-D | S | R-1 | Monthly Retention |
| — | DRY RUN H1-H18 | Full engagement from tenant creation to invoice | — | — | — | — |

> ⛔ **REVENUE GATE 1** — Clear G1.1–G1.12 before continuing. First paying client required: invoice issued, paid, portal accessed, remediation viewed.

**LANE 1 — REVENUE CRITICAL PATH (Before First MRR — parallel commercial auth track)**

| # | PR | Title | Priority | Size | Deps | Primary KPI |
|---|---|---|---|---|---|---|
| 13 | PR-01a | FIAP + Identity Governance Foundation | P1 | L | #537 merged | Subscription Conversion |
| 14 | PR-01a.1 | Identity Runtime Integration | P1 | M | PR-01a | Subscription Conversion |
| 15 | PR 10 | Enterprise Identity Consolidation | P1 | L | PR-01a.1 | Subscription Conversion |
| 16 | P1.1 | Membership Versioning | P1 | M | PR 10 | Subscription Conversion |
| 17 | P1.2 | Tenant Policy Bundles + Capability Framework | P1 | M | P1.1 | Subscription Conversion |
| 18 | P1.3 | Capability Enforcement Engine | P1 | M | P1.2 | Subscription Conversion |
| 19 | P1.4 | Subscription Assignment Engine | P1 | M | P1.3 | Subscription Conversion |
| 20 | P1.5 | Billing Integration Layer | P1 | M | P1.4 | Billing Integrity |
| 21 | P-3 | Subscription intent surface in portal | P1 | S | P1.4 | Subscription Conversion |
| 22 | P-4 | Portal notifications (overdue + report ready) | P1 | M | — | Monthly Retention |
| 23 | AI-1 | Self-serve Stripe subscription checkout | P1 | M | P1.5 | Subscription Conversion |

> ⛔ **REVENUE GATE 2** — First MRR contract signed. Stripe subscription active. Before proceeding to Platform Expansion.

---

**LANE 2 — PLATFORM EXPANSION (Phase 2: Portal Depth)**

| # | PR | Title | Priority | Size | Deps | Primary KPI |
|---|---|---|---|---|---|---|
| 24 | TC-5 | Trust enforcement authority (PRs 1.5+1.5A) | P0-C | M | TC-4 | Customer Trust |
| 25 | TC-6 | Trust graph persistence foundation (PR 1.6) | P0-C | M | TC-5 | Moat Depth |
| 26 | TC-8 | Persistent ingest report signature (PR-SIGN-5b) | P0-C | S | TC-3 | Customer Trust |
| 27 | FA-3 | Verify production embedding + startup check | P1 | S | — | Customer Trust |
| 28 | P-5 | Executive summary dashboard (board-ready) | P1 | M | — | Annual Contract Value |
| 29 | P-6 | Governance timeline view | P2 | M | P-5 | Monthly Retention |

**LANE 2 — PLATFORM EXPANSION (Phase 3: Remediation Revenue)**

| # | PR | Title | Priority | Size | Deps | Primary KPI |
|---|---|---|---|---|---|---|
| 30 | R-3 | Remediation notifications — email for overdue tasks | P1 | S | P-4 | Monthly Retention |
| 31 | R-4 | Retest + closure verification | P1 | M | R-2 | Annual Contract Value |
| 32 | R-5 | Exception management | P2 | M | R-4 | Annual Contract Value |
| 33 | R-6 | Remediation SLA enforcement | P2 | S | R-4 | Monthly Retention |

**LANE 2 — PLATFORM EXPANSION (Phase 4: AI Workspace)**

| # | PR | Title | Priority | Size | Deps | Primary KPI |
|---|---|---|---|---|---|---|
| 34 | AI-2 | Conversation history + saved sessions | P1 | M | AI-1 | Monthly Retention |
| 35 | AI-3 | Citation display in AI workspace | P1 | M | AI-2, RAG-1 | Subscription Conversion |
| 36 | AI-4 | Evidence interrogation mode | P1 | M | RAG-2 | Annual Contract Value |
| 37 | AI-5 | Report Q&A mode | P2 | M | RAG-2 | Monthly Retention |
| 38 | AI-6 | Remediation drafting mode | P2 | M | AI-3 | Annual Contract Value |
| 39 | AI-7 | Policy drafting mode | P2 | L | AI-3, RAG-4 | Annual Contract Value |
| 40 | AI-8 | Executive summary on demand | P2 | S | AI-3 | Portal Adoption |

**LANE 2 — PLATFORM EXPANSION (Phase 5: Enterprise RAG — after 3+ clients)**

| # | PR | Title | Priority | Size | Deps | Primary KPI |
|---|---|---|---|---|---|---|
| 41 | RAG-1 | Wire retry-ingestion (remove 503) | P1 | M | — | Customer Trust |
| 42 | RAG-2 | Bind FA evidence to client RAG corpus | P1 | M | RAG-1 | Moat Depth |
| 43 | RAG-3 | RAG freshness tracking | P2 | S | RAG-2 | Customer Trust |
| 44 | RAG-4 | Corpus management UI | P2 | M | RAG-2 | Annual Contract Value |
| 45 | RAG-5 | Deletion + retention lifecycle | P2 | M | RAG-2 | Customer Trust |
| 46 | RAG-6 | Poisoning + injection defenses | P2 | M | RAG-2 | Customer Trust |

**LANE 2 — PLATFORM EXPANSION (Phase 6: Continuous Monitoring)**

| # | PR | Title | Priority | Size | Deps | Primary KPI |
|---|---|---|---|---|---|---|
| 47 | CM-1 | Make trust monitoring fail-visible | P1 | S | — | Customer Trust |
| 48 | CM-2 | One real connector monitoring path (MS Graph) | P1 | L | CM-1 | Annual Contract Value |
| 49 | CM-3 | Continuous monitoring dashboard in portal | P1 | M | CM-2 | Monthly Retention |
| 50 | CM-4 | Evidence freshness alerts | P2 | S | CM-3 | Monthly Retention |
| 51 | CM-5 | Control drift detection | P2 | M | CM-2 | Annual Contract Value |
| 52 | CM-6 | Scheduled reassessment engine | P2 | L | CM-5 | Annual Contract Value |

**LANE 2 — PLATFORM EXPANSION (Phase 7: CGIN — after 5+ clients)**

| # | PR | Title | Priority | Size | Deps | Primary KPI |
|---|---|---|---|---|---|---|
| 53 | CGIN-1 | Surface CGIN benchmark in client portal | P2 | M | 5+ clients | Annual Contract Value |
| 54 | CGIN-2 | Industry maturity scoring | P2 | M | CGIN-1 | Annual Contract Value |
| 55 | CGIN-3 | Privacy-preserving contribution pipeline | P2 | L | CGIN-1 | Moat Depth |
| 56 | CGIN-4 | Trend analytics | P3 | M | CGIN-3, 20+ clients | Annual Contract Value |

**LANE 2 — PLATFORM EXPANSION (Phase 8+: Autonomous + AGI — after PMF signal)**

| # | PR | Title | Priority | Size | Deps | Primary KPI |
|---|---|---|---|---|---|---|
| 57 | AG-1 | Policy enforcement engine surface | P3 | L | Steps 1-7 | Annual Contract Value |
| 58 | AG-2 | Approval routing automation | P3 | L | AG-1 | Annual Contract Value |
| 59 | AG-3 | Agent governance framework | P3 | XL | AG-2 | Moat Depth |
| 60 | AGI-1 | Machine identity governance | Strategic | XL | AG-3 | Moat Depth |
| 61 | AGI-2 | Cross-agent trust negotiation | Strategic | XL | AGI-1 | Moat Depth |
| 62 | AGI-3 | AI constitutional governance | Strategic | XL | AGI-2 | Moat Depth |

---

*This document is the canonical implementation roadmap for FrostGate Core. Every future PR must appear in this sequence or in the ROADMAP.md PR tracker before implementation begins. Changes to this roadmap require explicit justification against: DTFR reduction, MRR improvement, trust increase, defensibility increase, or compounding moat. This document was produced from reconciliation of three independent audits against the repository state at commit f70cccc on 2026-07-14.*

---

## Section 16: Customer Journey Map

From cold lead to annual subscription. Every stage: what the customer sees, what Jason does, what the software does, what revenue event occurs.

---

### Stage 1: LEAD

| | |
|---|---|
| **Customer sees** | Nothing — outbound, referral, or web search |
| **Jason does** | Identifies prospect: CISO or CTO of an AI-intensive organization; initiates outreach |
| **Software does** | Nothing |
| **Revenue event** | None |

---

### Stage 2: DISCOVERY CALL

| | |
|---|---|
| **Customer sees** | FrostGate positioning: "the only platform that combines assessor-led AI governance with a live cryptographic evidence chain and an AI workspace grounded in your own verified documents" |
| **Jason does** | Identifies compliance framework, scope, and stakeholders; asks: NIST AI RMF? HIPAA? SOC 2? CMMC? ISO 27001? |
| **Software does** | Nothing |
| **Revenue event** | None |

---

### Stage 3: ASSESSMENT PROPOSAL

| | |
|---|---|
| **Customer sees** | Scope document; price quote ($5,000–$40,000 depending on framework and scope); timeline (2–4 weeks); deliverables: signed PDF, portal access, remediation roadmap, AI workspace |
| **Jason does** | Drafts proposal tailored to identified framework; prices per complexity |
| **Software does** | Nothing — prior reports may serve as credibility evidence |
| **Revenue event** | None (proposal sent) |

---

### Stage 4: CONTRACT SIGNED

| | |
|---|---|
| **Customer sees** | Service agreement; data handling terms; portal privacy notice |
| **Jason does** | Signs engagement authorization; collects MS Graph / Entra ID credentials; schedules kickoff |
| **Software does** | Nothing yet |
| **Revenue event** | Engagement authorized — deposit optional or Net-30 |

---

### Stage 5: TENANT + ENGAGEMENT PROVISIONED

| | |
|---|---|
| **Customer sees** | Nothing (operator-side setup) |
| **Jason does** | Creates tenant in console; creates engagement; configures connector credentials; issues portal invite |
| **Software does** | Tenant creation + RBAC; engagement creation; connector credential storage; provisioning → portal grant (P-1 makes this deterministic) |
| **Revenue event** | None |

---

### Stage 6: QUESTIONNAIRE + EVIDENCE COLLECTION

| | |
|---|---|
| **Customer sees** | Questionnaire (69 NIST AI RMF controls or framework equivalent); evidence upload requests; document submission portal |
| **Jason does** | Coordinates completion; explains evidence requirements; reviews responses for gaps; follows up on missing items |
| **Software does** | Questionnaire engine; question bank; evidence upload; evidence chain creation (TC-1 through TC-4); actor attribution (#536) |
| **Revenue event** | None |

---

### Stage 7: SCANNING

| | |
|---|---|
| **Customer sees** | Nothing — scanning is transparent to the client |
| **Jason does** | Triggers connector scans from console; monitors for credential errors (FA-2 prevents silent multi-hour failures) |
| **Software does** | 13 connectors execute: MS Graph, Entra ID, OAuth Risk, SharePoint, Endpoint Inventory, DNS/Email, Web Headers, Network, AI Tool Discovery, AI Data Access Mapping, External AI Risk Register, AI Vendor Governance, OAuth Inventory. Findings generated; controls mapped to compliance framework. |
| **Revenue event** | None |

---

### Stage 8: REPORT GENERATION + QA

| | |
|---|---|
| **Customer sees** | Nothing — Jason reviews before delivery |
| **Jason does** | Reviews draft report in console; requests AI executive summary; approves via QA workflow |
| **Software does** | Report Authority computes real quality scores (TC-7 prerequisite); ReportLab PDF; Ed25519 signing; SHA-256/SHA-512 dual hash; verification bundle; immutability manifest; AI executive summary (Anthropic API) |
| **Revenue event** | None |

---

### Stage 9: REPORT DELIVERY + PORTAL ACCESS

| | |
|---|---|
| **Customer sees** | Portal notification; PDF download; findings list; remediation roadmap; NIST coverage matrix; risk posture dashboard; AI workspace (auto-enabled after P-2 ships) |
| **Jason does** | Schedules delivery call; walks client through findings, risk posture, and top remediation priorities (1–2 hours) |
| **Software does** | Portal reports page; findings page (portalApi.ts:446 → /field-assessment/engagements/{id}/findings); remediation roadmap (api/field_assessment.py:9629); NIST coverage matrix; AI assistant auto-enabled on QA approval |
| **Revenue event** | ⚡ **INVOICE #1 SENT — $5,000–$40,000** |

---

### Stage 10: AI WORKSPACE FIRST USE

| | |
|---|---|
| **Customer sees** | AI chat that knows their specific findings, controls, evidence, and compliance posture; asks "What are my three highest-priority AI governance gaps?" and gets an answer grounded in their own evidence |
| **Jason does** | Introduces AI workspace during delivery call; demonstrates one meaningful query |
| **Software does** | Tenant-isolated RAG retrieval; governed responses with policy enforcement; AI input policy blocking; citations from verified evidence (AI-3 when shipped) |
| **Revenue event** | None — but AI first use within 48 hours of delivery is the strongest predictor of subscription conversion |

---

### Stage 11: REMEDIATION BEGINS

| | |
|---|---|
| **Customer sees** | Remediation task list; due dates; SLA indicators; 5-state workflow (open → in-progress → evidence submitted → verified → closed); evidence upload |
| **Jason does** | Reviews initial remediation assignments; confirms priorities with client; answers questions |
| **Software does** | Remediation Authority canonical routes (24 routes); evidence submission; timeline view; overdue notifications (P-4); actor attribution on every state change |
| **Revenue event** | Potential add-on invoice for remediation tracking — $300–$800/month |

---

### Stage 12: SUBSCRIPTION INTENT + FIRST MRR

| | |
|---|---|
| **Customer sees** | "Continue with FrostGate" offer surface in portal (P-3); clear value proposition: portal access, AI workspace, remediation tracking, ongoing monitoring |
| **Jason does** | Follows up on subscription intent within 14 days of delivery; proposes pricing package |
| **Software does** | Intent form logged; Jason notified (notify-Jason model for clients 1–3); Stripe self-serve checkout (AI-1 for clients 4+); SubscriptionContract + capability auto-assignment |
| **Revenue event** | ⚡ **FIRST MRR — $500–$2,000/month** |

---

### Stage 13: CONTINUOUS MONITORING (Phase 6 forward)

| | |
|---|---|
| **Customer sees** | Monitoring dashboard: "Last scan: 6 hours ago. 2 new drift alerts since your assessment. Trust score: 84/100." Drift alerts in email. |
| **Jason does** | Reviews drift alerts with client in monthly check-in call |
| **Software does** | MS Graph recurring scans (CM-2); delta detection between scans; portal monitoring dashboard (CM-3); evidence freshness alerts (CM-4); control drift detection (CM-5) |
| **Revenue event** | Monitoring tier upgrade — $500–$2,000/month |

---

### Stage 14: SUBSCRIPTION RENEWAL

| | |
|---|---|
| **Customer sees** | Renewal notice; governance timeline showing a year of finding closures, attestations, and drift resolutions; year-over-year risk posture improvement graph |
| **Jason does** | Renewal call; presents governance timeline as proof of value; proposes retest or expanded scope |
| **Software does** | Usage metering (P1.5); capability enforcement (P1.3); Stripe renewal; governance timeline view (P-6); engagement snapshot for comparison |
| **Revenue event** | ⚡ **RENEWAL — annual contract value anchored by proven governance history** |

---

### Stage 15: CGIN PARTICIPATION (10+ clients)

| | |
|---|---|
| **Customer sees** | "Your AI governance maturity is in the 73rd percentile for your industry sector" — first time they can benchmark their posture against anonymized peers |
| **Jason does** | Nothing — automatic and opt-in |
| **Software does** | CGIN benchmark computation (Ed25519-attested, privacy-preserving per services/cgin/privacy.py); portal benchmark surface (CGIN-1); Merkle transparency root |
| **Revenue event** | Moat deepens — switching means losing benchmark positioning and peer context |

---

### Stage 16: EXPANSION

| | |
|---|---|
| **Customer sees** | Proposal for expanded scope: second assessment framework (HIPAA after NIST AI RMF), formal retest after major remediation milestone, new AI system added to scope |
| **Jason does** | Proposes expanded engagement; prices at $5,000–$15,000 per additional framework |
| **Software does** | New engagement created with prior evidence corpus available for AI context; prior governance history makes new assessment significantly faster; existing client trust graph extended |
| **Revenue event** | ⚡ **EXPANSION — additional assessment fee + subscription tier upgrade** |

---

### Journey Summary

| Stage | Customer Action | Jason Action | Software Action | Revenue Event |
|---|---|---|---|---|
| Lead | — | Outreach | — | — |
| Discovery | Call | Scope | — | — |
| Proposal | Review | Draft | — | — |
| Contract | Sign | Setup | Tenant + engagement | — |
| Questionnaire | Answer | Coordinate | Questionnaire engine | — |
| Scanning | Cooperate | Trigger | 13 connectors | — |
| Report QA | — | Approve | Report Authority + PDF + sign | — |
| Delivery | Open portal | Walk through | Portal pages live | **Invoice #1** |
| AI First Use | Query | Introduce | Tenant-isolated RAG | — |
| Remediation | Work tasks | Review | 5-state lifecycle | **Add-on MRR** |
| Subscription | Intent | Follow-up | Stripe checkout | **First MRR** |
| Monitoring | View drift | Check-in | Recurring scans | **Tier upgrade** |
| Renewal | Renew | Renewal call | Metering + billing | **Annual contract** |
| CGIN | Benchmark | — | Privacy computation | **Moat anchors** |
| Expansion | New scope | Propose | New engagement | **Expansion invoice** |

---

## Section 17: Anti-Drift Constitution

One page. No exceptions.

---

### The Problem It Solves

FrostGate has 21 governance orchestration files, 14 governance simulation files, a 1,143-line potentially-dead AI plane extension service, and a dozen partially-implemented capabilities — all built before the first paying client existed. This document is the rule that prevents the next version of that pattern.

---

### Permitted Work

Every PR merged to FrostGate Core must advance exactly one of these:

| # | Product | What "Better" Means |
|---|---|---|
| 1 | **Field Assessment** | More defensible, more accurate, faster to deliver, or covers a new compliance scope requested by a signed client |
| 2 | **Client Portal** | More reliable, more likely to be used daily, or surfaces a capability a paying client has requested |
| 3 | **Remediation Tracking** | More accurate, reduces Jason's manual workload, or increases the likelihood of renewal |
| 4 | **AI Workspace** | More trusted (cited, evidence-grounded), more integrated with client evidence, or requested by a paying subscriber |
| 5 | **Enterprise RAG** | More reliable, more complete, or more resistant to poisoning — only after 3+ clients have live corpora |
| 6 | **Continuous Monitoring** | More real, more visible, or more actionable — only after CM-2 (real connector path) ships |
| 7 | **CGIN** | More accurate, more private, or more visible to clients — only after 10+ clients have data in the system |
| 8 | **Autonomous Governance** | More trustworthy, more governed, or more auditable — only after Steps 1–7 complete and PMF is demonstrated |
| 9 | **Security** | Fixes a confirmed vulnerability or closes a confirmed production incident risk |
| 10 | **Revenue Gate** | Directly unblocks a Gate 1 or Gate 2 item — the only category that may interrupt Platform Expansion |

---

### Deferred — No Exceptions

The following work is deferred regardless of how interesting, valuable, or nearly-complete it appears:

- Any new file in `services/governance_orchestration/`, `services/governance_simulation/`, `services/governance_digital_twin/`, `services/governance_learning/`, `services/governance_optimization/`, or `services/governance_adaptive_intelligence/` before Phase 8 (10+ clients, PMF signal)
- Any extension of `services/ai_plane_extension/` before the live production AI call path is confirmed end-to-end
- New CI test lanes before team exceeds 3 engineers
- FedRAMP planning before a signed govcon letter of intent
- PCI DSS playbook before a PCI client is identified
- SAML before Client 5
- Any new compliance framework without an identified client requesting it
- Any PR whose primary beneficiary is "the platform" rather than a named client outcome
- Any PR that cannot be explained to a client in one sentence
- Any PR that cannot be assigned to one of the 8 KPIs defined in Section 7

---

### Adjudication Protocol

When a PR is proposed that does not clearly fit the permitted list:

1. **Name the product it makes better.** Field Assessment? Portal? Remediation? AI Workspace? RAG? Monitoring? CGIN? Autonomous? If you cannot name one: defer.
2. **Name the KPI it moves.** Report Defensibility? Customer Trust? Portal Adoption? Subscription Conversion? Monthly Retention? Annual Contract Value? Billing Integrity? Moat Depth? If you cannot name one: defer.
3. **Name the paying client who will notice.** Client 1? Client 3? First enterprise client? If the answer is "no client exists yet": defer until that client exists.

---

### The Override Case

There is exactly one override: a confirmed production incident affecting a paying client.

Emergency fixes ship immediately, outside the sequence. A post-incident review updates ROADMAP.md. No other exception exists.

---

*Anti-Drift Constitution v1.0. Adopted 2026-07-14. Every roadmap update must preserve this section or explicitly justify its amendment.*

---

## Section 18: Product Operating Metrics

Not engineering metrics. Business metrics. Every PR must name the metric it moves. If it cannot, it belongs in Platform Expansion or does not ship.

---

### North Star Metric

**Monthly Recurring Revenue (MRR)**

Every other metric is a leading or lagging indicator of MRR. Track it weekly. Every merge should accelerate or protect it.

---

### Leading Indicators

These metrics predict future MRR. They move before revenue does. Watch them to know if execution is on track before revenue confirms it.

| Metric | Definition | Phase 0–1 Baseline | Phase 4+ Target | KPI Link |
|---|---|---|---|---|
| **Assessments completed** | Full engagements delivered | 1 | 10+ | Report Defensibility |
| **Proposal conversion %** | Proposals sent → engagements signed | Establish baseline | >60% | Report Defensibility |
| **Assessment duration** | Days from engagement creation to report delivery | <21 days | <14 days | Portal Adoption |
| **Portal activation %** | Clients who log into portal within 7 days of delivery | Establish baseline | >90% | Portal Adoption |
| **Portal weekly active users** | Distinct clients opening portal per week | Establish baseline | 3+ sessions/week per client | Portal Adoption |
| **AI conversations per tenant** | AI workspace queries per active client per week | Establish baseline | >5/week | Subscription Conversion |
| **Evidence uploaded per engagement** | Files + links submitted per completed assessment | Establish baseline | >20 | Customer Trust |
| **Remediation tasks created** | Tasks generated per delivered engagement | Establish baseline | >10 | Monthly Retention |
| **Remediation completion %** | Tasks closed / tasks created within 90 days | Establish baseline | >40% | Monthly Retention |
| **Subscription conversion %** | Delivered assessments converting to MRR within 90 days | 0% → first client | >50% | Subscription Conversion |
| **Average revenue per client** | Total revenue ÷ active clients | $5k–$40k (assessment only) | $1k–$3k/month (subscription) | Annual Contract Value |
| **Client retention** | Subscriptions active at Month 12 / subscriptions at Month 1 | Establish baseline | >85% | Monthly Retention |
| **NPS** | Net Promoter Score from post-delivery survey | Establish baseline | >50 | Customer Trust |
| **Time to first value** | Days from contract signed to client portal access | <21 days | <14 days | Portal Adoption |
| **Time from proposal to invoice** | Days from proposal sent to invoice issued | Establish baseline | <30 days | Subscription Conversion |
| **Time from report delivery to subscription** | Days from first invoice paid to first recurring charge | Establish baseline | <45 days | Subscription Conversion |

---

### Metric → PR Mapping

Before any PR is scoped, name which metric it improves and by how much. This is the build filter.

| PR | Primary Metric Improved | Mechanism |
|---|---|---|
| TC-7 | Proposal conversion %; Assessment duration | Real quality scores make the report defensible; removes legal exposure before first invoice |
| R-1 | Remediation tasks created; Remediation completion % | Canonical routing ensures tasks reach the right system; no split-brain at scale |
| FA-1 | Portal activation % | Portal pages with live data means clients can engage the day of delivery |
| P-2 | AI conversations per tenant | AI auto-enable means 100% of clients can use the workspace on delivery day, not after Jason acts |
| P-4 | Portal weekly active users | Overdue notifications pull clients back without Jason; habit forms |
| AI-1 | Subscription conversion %; Time from delivery to subscription | Self-serve Stripe checkout eliminates the Jason-assisted delay for every client |
| AI-2 | AI conversations per tenant | Saved sessions let clients continue investigations; compounds habit |
| AI-3 | Subscription conversion %; NPS | Citations are what enterprise clients need to trust and justify AI use to their board |
| CM-2 | Client retention; Average revenue per client | Real monitoring gives clients a reason to renew beyond the initial assessment |
| CGIN-1 | Client retention; NPS | Benchmark positioning creates value that grows with network size; switching means losing peer context |

---

### Instrumentation Minimum

Before Gate 1 is cleared, the following five events must be tracked — even in a spreadsheet:

1. Assessment delivery date per engagement
2. Portal first login date per client
3. AI first conversation date per client
4. Subscription start date per client
5. Invoice date and amount per engagement

If these five events are not tracked, no PR can be attributed to a metric improvement. The data matters more than the instrumentation tool.

---

*Product Operating Metrics v1.0. Adopted 2026-07-14.*
