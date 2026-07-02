# MCIM 18.6 Master Command Information Model

Status: Canonical planning artifact for PR 18.6 Phase 0  
Scope: Console, Portal, Command Center, Trust Center, Governance Intelligence, Field Assessment, customer portal information architecture  
Change policy: Documentation only. No route, navigation, API, UI component, backend, or business-logic changes.

## Section 1 - Executive Summary

The Master Command Information Model (MCIM) is FrostGate's canonical inventory of capabilities, authorities, routes, screens, widgets, actions, state, workflows, personas, navigation tiers, lifecycle states, and technical debt. It exists so future 18.6.x PRs stop inferring intent from partial UI coverage, placeholder pages, or backend breadth and instead reorganize the product against one source-backed map.

FrostGate needs the MCIM because the repository already contains a large governance platform with a narrower visible UI. The Phase 1 architecture audit, PR 18.6 audit blueprint, and generated census artifacts all show the same pattern: the Field Assessment -> Reports -> Portal spine is strong, while trust, intelligence, identity governance, billing, provider governance, and orchestration authorities are materially broader than their current Console and Portal affordances.

The MCIM governs:

- capability naming and classification
- route reachability and screen ownership
- authority-to-surface mapping
- source-of-truth boundaries
- navigation tiering
- lifecycle and retirement decisions
- validation rules for future UI-only refactors

The MCIM does not change:

- Console layout in this PR
- Portal layout in this PR
- existing route names
- existing navigation structure
- backend APIs
- business logic
- legacy pages

Future PRs 18.6.1 through 18.6.7 must use the MCIM as the contract for safe reorganization. They may regroup, reprioritize, relabel, and contextualize surfaces, but they must preserve capability coverage, authority visibility, mutation safety, auditability, and route reachability.

Explicit rule: Future Console/Portal PRs must preserve existing route reachability unless a route is explicitly classified as retired in the MCIM.

Implementation rule for future work:

1. classify every touched route against the MCIM before changing labels or placement
2. preserve every authority family with a discoverable home, even if the home is contextual or specialist
3. move only after source-of-truth, state ownership, and audit expectations remain intact

Primary evidence base:

- `audits/2026-07-02_frostgate_console_portal_architecture_audit_phase1.md`
- `audits/2026-07-02_pr18-6_unified_governance_command_center_portal_ia_blueprint.md`
- `artifacts/full_repo_census/*`
- `artifacts/platform_inventory.det.json`
- `artifacts/route_inventory_summary.json`
- `apps/console/app/**`
- `apps/portal/app/**`
- `api/*`
- `services/*`
- `authority_manifest.yaml`
- `docs/operators/*`
- `docs/architecture/*`
- `docs/ai/FIELD_ASSESSMENT_ENTERPRISE_AUDIT.md`

## Section 2 - Canonical Capability Registry

| Capability | Family | Authority owner | Backend services / API routes | Console surfaces | Portal surfaces | Reports / exports / runbooks | Personas | Maturity | Business value | Nav tier | Lifecycle | Source of truth | Known gaps |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Assessment | Commercial intake | `api/assessments.py`, legacy assessment workflow | `/ingest/assessment`, `/assessment` | `/assessment`, `/onboarding`, dashboard quick actions | none | assessment scoring, report kickoff | Executive, Consultant | partial | lead-in funnel | legacy primary | legacy | `apps/console/app/assessment/page.tsx`, `apps/console/app/onboarding/page.tsx` | sessionStorage score coupling, overlaps Field Assessment |
| Field Assessment | Operator execution | `services/field_assessment`, `api/field_assessment.py` | `/field-assessment/engagements*`, connector runs, questionnaires, reports | `/field-assessment`, `/field-assessment/{engagementId}` | `/engagement`, `/engagement/{engagementId}` | onboarding runbook, report generation, verification bundle | Assessment Engineer, Field Assessor | strong | core service delivery spine | primary | core | `docs/architecture/PLATFORM_ARCHITECTURE.md`, `docs/ai/FIELD_ASSESSMENT_ENTERPRISE_AUDIT.md` | portal grant model, audit gaps, scan durability gaps |
| Evidence | Trust + audit | `services/evidence_authority`, `api/evidence_authority.py` | `/evidence*`, evidence links, evidence freshness | Field Assessment evidence tab, `/dashboard/provenance`, `/dashboard/forensics` | `/engagement/{engagementId}`, `/reports` | verification bundle, audit packet | Auditor, Assessor | strong | legal defensibility | contextual | core | `authority_manifest.yaml`, `services/field_assessment/evidence_authority.py` | fragmented UX, not a single evidence workspace |
| Verification | Trust | `services/verification_authority`, `services/verification_bundle`, `api/verification_authority.py` | `/verification*`, `/verification-bundle*` | Verification Bundle panel, report verify buttons | report verify, verification bundle card | signed report verify, bundle manifest | Auditor, Customer | functional | proof of integrity | contextual | stable | `apps/console/components/field-assessment/VerificationBundlePanel.tsx`, `apps/portal/app/reports/page.tsx` | contextual, underexposed as product pillar |
| Reports | Delivery | `services/report_authority`, `api/report_authority.py`, `api/reports_engine.py` | `/reports*`, `/report-exports*` | Report generation/history/viewer/export | `/reports` | JSON/PDF export, QA approval | Executive, Customer, QA Reviewer | strong | core deliverable | primary | core | `services/report_authority/*`, `apps/portal/app/reports/page.tsx` | split between report version ids and engagement context |
| Portal | Customer delivery | `services/governance_portal`, `api/governance_portal.py`, portal BFF | `/portal*`, portal BFF allowlist | admin portal grant management in tenant pages | `/`, `/engagement`, `/findings`, `/reports`, `/coverage`, `/attestation`, `/remediation`, `/continuity`, `/assistant` | portal grant tests, portal structure/security tests | Customer, Board Member, MSP | strong | customer retention + proof delivery | primary | core | `apps/portal/app/**`, `apps/portal/app/api/core/[...path]/route.ts` | localStorage engagement context, misleading read-only label |
| Remediation | Closed loop | `services/remediation_authority`, `services/remediation`, `api/remediation_authority.py` | `/remediation*`, remediation roadmap, finding patch | Field Assessment findings/remediation hinting | `/remediation`, `/findings` | remediation sections in reports | Customer, Compliance Officer | functional | converts findings into work | primary portal / contextual console | growing | `services/remediation_authority/*`, `apps/portal/app/remediation/page.tsx` | portal mutation exists but wording implies read-only |
| Governance | Continuous posture | `api/governance.py`, `services/governance_*` | governance graph/workflows/reporting/routes | `/dashboard/policies`, `/dashboard/providers`, `/dashboard/readiness`, `/governance/topology` | coverage, continuity | governance reports and trends | CISO, Compliance Officer | functional | expansion from assessment to platform | secondary | growing | `docs/architecture/PLATFORM_ARCHITECTURE.md` | authority breadth exceeds current IA |
| Governance Learning | Intelligence | `services/governance_learning`, `api/governance_learning.py` | `/governance-learning*` | none | none | none | Platform Administrator | latent | future recommendation quality | hidden | future | `services/governance_learning/*` | backend-only authority |
| Governance Optimization | Intelligence | `services/governance_optimization`, `api/governance_optimization.py` | `/governance-optimization*` | none | none | none | CISO, Platform Administrator | latent | prioritization and ROI | hidden | future | `services/governance_optimization/*` | no UI surface |
| Governance Orchestration | Intelligence / automation | `services/governance_orchestration`, `api/governance_orchestration.py` | `/governance-orchestration*` | none | none | workflow automation | Platform Administrator | partial backend | high future leverage | hidden | growing | `services/governance_orchestration/*` | no operator home |
| Governance Intelligence | Intelligence | `services/governance_intelligence`, `api/governance_intelligence.py` | `/intelligence/*` | none directly; hidden via specialist routes | none | export packages, quality score | CISO, Auditor | partial backend | high strategic value | specialist hidden | growing | `artifacts/platform_inventory.det.json`, `services/governance_intelligence/*` | hidden runtime-only family |
| Decision Provenance | Trust + explainability | `services/governance_chain`, `api/governance_chain.py`, decision APIs | `/decisions`, `/governance-chain`, `/intelligence/provenance*` | `/dashboard/decisions`, `/dashboard/provenance` | report verify context, engagement history | provenance chain, audit exports | Auditor, Executive | functional | explainability and defensibility | specialist | stable | `services/governance_chain/*`, `apps/console/app/dashboard/decisions/page.tsx` | not packaged as single trust center |
| Benchmarking | Intelligence | `services/governance_intelligence/benchmarking.py` | `/intelligence/benchmark-confidence`, admin identity governance benchmark | none | none | none | Executive, CISO | latent | comparative posture | hidden | future | `artifacts/platform_inventory.det.json` | backend-only |
| Simulation | Intelligence | `services/governance_intelligence/simulation.py`, `services/readiness/simulation` | `/intelligence/simulation-compare`, readiness simulation | none | none | simulation exports | CISO | latent | what-if planning | hidden | future | `services/governance_intelligence/simulation.py` | no UI entry point |
| Replay | Trust + forensics | `services/field_assessment/trust_replay.py`, intelligence replay | `/intelligence/replay*`, `/forensics/chain/verify` | Control Tower replay verify, forensics | report verify, bundle verify | replay proof | Auditor, Support Engineer | partial | tamper investigation | specialist | growing | `apps/console/lib/coreApi.ts`, `services/field_assessment/trust_replay.py` | valuable but hidden |
| Counterfactual | Intelligence | `services/governance_intelligence/counterfactual.py` | `/intelligence/counterfactual*` | none | none | none | Executive, CISO | latent | scenario planning | hidden | future | `services/governance_intelligence/counterfactual.py` | backend-only |
| Trust | Trust center | `services/trust_arc`, `services/executive_trust`, verification bundle | `/cgin-trust*`, `/verification*`, `/forensics/chain/verify` | `/dashboard/control-tower`, `/dashboard/provenance`, `/dashboard/forensics` | `/reports`, `/engagement/{engagementId}` | signature verify, trust exports | Auditor, Customer, Board | functional | provable governance moat | contextual today / future primary | stable | `artifacts/full_repo_census/10_SECURITY_TRUST_EVIDENCE_MAP.md` | fragmented across control tower, provenance, reports |
| Transparency | Trust center | `api/cgin_transparency.py`, report transparency appendices | transparency routes, report transparency | `/dashboard/provenance`, `/dashboard/decisions` | `/reports`, `/continuity` | transparency appendices | Board Member, Auditor | functional | customer confidence | contextual | stable | `services/report_authority/transparency_appendix.py` | no dedicated surface |
| Privacy | Trust + policy | `api/cgin_privacy.py`, evidence sensitivity and policy layers | privacy routes, evidence metadata | implicit in evidence/provenance | none explicit | privacy controls in evidence/report | Compliance Officer | partial | regulated delivery | hidden | growing | `api/cgin_privacy.py`, `services/readiness/evidence/*` | backend-heavy, no IA home |
| Key Management | Platform admin | `api/keys.py`, `api/key_rotation.py`, admin key routes | `/admin/keys*`, `/keys*` | `/dashboard/control-tower`, `/keys` | none | key lifecycle audit | Tenant Admin, Platform Administrator | functional | platform security | administrative | stable | `apps/console/lib/coreApi.ts`, `api/keys.py` | `/keys` hidden and duplicate with Control Tower |
| Notifications | Cross-platform | `services/notifications`, `api/feed.py`, event stream | `/feed`, notifications routes | top bar badge, recent events, feed | none dedicated | incident/audit feed | Operator, Support Engineer | partial | operational awareness | contextual | growing | `services/notifications/*`, `apps/console/app/dashboard/page.tsx` | no unified notification center |
| Administration | Platform ops | admin gateway + control plane APIs | `/admin/*`, `/control-plane/*` | `/dashboard/control-tower`, `/admin/tenants`, `/dashboard/settings` | none | operator guide, tenant admin docs | Platform Administrator | strong | tenant operations | administrative | core | `docs/operators/console_user_guide.md`, `api/admin*.py` | fragmented across multiple surfaces |
| Providers | AI governance | `api/ui_provider_governance.py`, `services/provider_baa`, provider routing | `/ui/provider/*`, provider governance | `/dashboard/providers` | none | provider routing/failover | Platform Administrator, CISO | partial | AI supplier control | specialist | growing | `apps/console/components/governance/ProviderGovernanceConsole.tsx` | nav page exists, capability still immature |
| Identity | Identity + grants | `api/admin_identity.py`, auth scope modules, portal grants | `/admin/identity/*`, auth routes | `/admin/tenants`, login | `/login`, `/accept-invite` | Auth0 roles guide, invitation flow | Tenant Admin, Support Engineer | functional | tenancy and authorization | administrative | stable | `docs/operators/auth0_roles.md`, `apps/portal/app/api/auth/*` | rich backend, thin UX |
| Billing | Commercial ops | `services/subscriptions`, `api/billing.py`, `api/billing_v2.py` | `/billing*`, `/admin/billing*`, `/admin/subscriptions*` | billing readiness banner on dashboard | none | billing ledger, stripe hooks | Platform Administrator, Executive | partial backend | monetization | hidden / future admin | growing | `artifacts/full_repo_census/12_BILLING_MONETIZATION_MAP.md` | UI maturity low |
| Workforce | Monitoring | `api/workforce.py` | `/workforce*` | `/dashboard/workforce` | none | workforce alerts | Operator | partial | employee/governance awareness | specialist | growing | `apps/console/app/dashboard/workforce/page.tsx` | page exists, workflow story weak |
| Evaluation Lab | AI quality | `api/ui_evaluation.py`, `services/governance/report/confidence.py` | `/ui/evaluation/*` | `/dashboard/evaluation` | none | eval exports | Developer, Platform Administrator | functional specialist | model quality governance | specialist | stable | `artifacts/full_repo_census/11_RAG_EVALUATION_AGENT_MAP.md` | specialist-only, not tied to executive story |
| Control Tower | Platform ops | `api/control_tower.py`, `api/control_plane*.py` | `/control-plane/*`, `/admin/agent/*`, `/admin/connectors/*` | `/dashboard/control-tower` | none | audit evidence export, agent controls | Platform Administrator, Support Engineer | strong | control plane confidence | primary ops | core | `docs/operators/console_user_guide.md` | mixed with other admin concerns |
| AI Workspace | AI + retrieval | `api/ui_ai_console.py`, `api/ai_plane_extension.py` | `/ui/ai*`, `/ui/ai/chat` | `/dashboard/assistant` | `/assistant` | chat export, provenance trace | Operator, Customer | functional | guided answers | secondary | growing | `apps/console/app/dashboard/assistant/page.tsx`, `apps/portal/app/assistant/page.tsx` | portal assistant uses local device id storage |
| Corpus | Knowledge | `api/rag_corpus_console.py`, corpus services | `/rag/corpora*`, `/rag/documents*` | `/dashboard/corpus`, `/dashboard/ingestion` | none | ingestion workflows | Operator, Developer | functional | knowledge substrate | specialist | stable | `artifacts/full_repo_census/11_RAG_EVALUATION_AGENT_MAP.md` | not tied back to business outcomes |
| Retrieval | Knowledge | `api/rag_retrieval_policy.py`, retrieval services | `/rag/retrieval-policy*`, `/rag/retrieval*` | `/dashboard/retrieval` | indirect via assistant | retrieval policy export | Operator, Developer | functional | answer quality and safety | specialist | stable | `apps/console/components/governance/RetrievalPolicyCenter.tsx` | specialist experience hidden from executives |
| Audit & Forensics | Trust + support | `api/forensics.py`, audit pipeline | `/ui/forensics/*`, `/audit*`, `/admin/audit/*` | `/dashboard/forensics`, `/audit` | engagement history, reports verify context | audit exports, chain verify | Auditor, Support Engineer | functional | incident response and proof | specialist | stable | `apps/console/components/governance/AuditForensicsConsole.tsx` | duplicate `/audit` vs `/dashboard/forensics` |
| Readiness | Posture | `services/readiness`, `api/readiness_manager.py` | `/control-plane/readiness/*`, readiness history | `/dashboard/readiness` | `/coverage`, `/continuity`, overview KPIs | score history, coverage | Executive, Compliance Officer | strong | core posture signal | primary | core | `services/readiness/*`, `apps/portal/app/coverage/page.tsx` | duplicate computations across console and portal |
| Policies | Governance control | policy engine, control registry | `/control-registry*`, policy routes, connectors policy | `/dashboard/policies` | none | policy docs | Compliance Officer | partial | governance rule management | specialist | growing | `api/control_registry.py`, `apps/console/app/dashboard/policies/page.tsx` | page largely placeholder |
| Clients | Tenancy | admin tenant + portal grants | `/admin/tenants*`, `/admin/identity/tenants*` | `/admin/tenants`, `/admin/tenants/{tenantId}` | none | tenant and grant management | Tenant Admin, MSP | functional | customer ops | administrative | stable | `apps/console/app/admin/tenants/*.tsx` | placeholder-backed details, strong backend hidden |

## Section 3 - Authority-to-Surface Matrix

| Authority / capability | Backend service | API route family | Console page(s) | Portal page(s) | Current navigation location | Proposed future navigation home | Role visibility | Workflow usage | Test coverage evidence | Gap status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Field Assessment | `services/field_assessment` | `/field-assessment/engagements*` | `/field-assessment`, `/field-assessment/{engagementId}` | `/engagement`, `/engagement/{engagementId}` | Governance sidebar | Operations Workspace | assessor, qa_reviewer, auditor | assessment lifecycle | `apps/console/tests/field-assessment-workspace.test.js`, `tests/test_field_assessment.py` | core, retain |
| Evidence Authority | `services/evidence_authority` | `/evidence*` | `/dashboard/provenance`, `/dashboard/forensics`, workspace evidence panels | engagement evidence/history | hidden specialist | Trust Center | assessor, auditor | evidence chain, verification | `tests/test_evidence_authority.py` | underexposed |
| Verification Bundle | `services/verification_bundle` | `/verification-bundle*` | workspace verification panel | engagement bundle, report verify | contextual | Trust Center | qa_reviewer, auditor, customer | report proof | `tests/test_pr52_verification_bundle.py` | retain and elevate |
| Report Authority | `services/report_authority` | `/reports*` | workspace reports, `/reports/{reportId}` | `/reports` | contextual, no sidebar route for detail | Executive Command Center + Portal Experience | assessor, qa_reviewer, executive | report generation/export | `tests/test_governance_report.py`, `tests/test_governance_report_exports.py` | detail route hidden |
| Remediation Authority | `services/remediation_authority` | remediation roadmap + finding patch | workspace findings panels | `/remediation`, `/findings` | portal primary, console contextual | Operations Workspace + Portal Experience | compliance_reviewer, customer | close-loop remediation | portal structure tests | wording mismatch |
| Readiness | `services/readiness` | `/control-plane/readiness/*` | `/dashboard/readiness` | `/coverage`, `/continuity`, `/` | Governance sidebar + portal nav | Executive Command Center | executive, compliance | posture review | `apps/console/tests/readiness-dashboard.test.js` | duplicate score derivation |
| Governance Intelligence | `services/governance_intelligence` | `/intelligence/*` | none | none | no nav | Governance & Intelligence Workspace | platform_admin, ciso | replay, simulation, counterfactual | `tools/ci/check_governance_intelligence.py` | backend-only authority |
| Governance Orchestration | `services/governance_orchestration` | `/governance-orchestration*` | none | none | no nav | Governance & Intelligence Workspace | platform_admin | automation and reassessment | `tools/ci/check_governance_orchestration.py` | backend-only authority |
| Governance Learning | `services/governance_learning` | `/governance-learning*` | none | none | no nav | Governance & Intelligence Workspace | platform_admin | recommendation learning | service tests only | backend-only authority |
| Governance Optimization | `services/governance_optimization` | `/governance-optimization*` | none | none | no nav | Governance & Intelligence Workspace | ciso | ranking/optimization | service tests only | backend-only authority |
| Decision Provenance | `services/governance_chain` | `/governance-chain`, `/decisions`, `/intelligence/provenance*` | `/dashboard/decisions`, `/dashboard/provenance` | reports/engagement history | Compliance + AI Knowledge | Trust Center | auditor, executive | explainability, provenance | `tests/test_governance_chain.py` | split across pages |
| Trust Arc | `services/trust_arc`, `services/executive_trust` | `/forensics/chain/verify`, trust routes | `/dashboard/control-tower`, `/dashboard/forensics` | `/reports`, `/engagement/{engagementId}` | contextual | Trust Center | auditor, board, support | verify trust | `tests/test_trust_enforcement.py` | underrepresented |
| Provider Governance | `services/provider_baa`, provider routes | `/ui/provider/*` | `/dashboard/providers` | none | Governance sidebar | Governance & Intelligence Workspace | platform_admin | provider routing/failover | provider console tests | placeholder-adjacent |
| Corpus | `api/rag_corpus_console.py` | `/rag/corpora*`, `/rag/documents*` | `/dashboard/corpus`, `/dashboard/ingestion` | none | AI & Knowledge | Operations Workspace specialist | operator, developer | ingestion, search prep | `apps/console/tests/document-ingestion-console.test.js` | specialist hidden value |
| Retrieval Policy | retrieval services | `/rag/retrieval-policy*` | `/dashboard/retrieval` | portal assistant indirect | AI & Knowledge | Governance & Intelligence Workspace specialist | operator, developer | grounded answers | `apps/console/tests/retrieval-policy-center.test.js` | specialist only |
| Evaluation Lab | `api/ui_evaluation.py` | `/ui/evaluation/*` | `/dashboard/evaluation` | none | Compliance | Governance & Intelligence Workspace specialist | developer, platform_admin | eval quality | evaluation tests | no executive framing |
| Control Tower | `api/control_tower.py`, `api/control_plane.py` | `/control-plane/*`, `/admin/agent/*`, `/admin/connectors/*` | `/dashboard/control-tower` | none | Operations | Admin & Platform Ops | platform_admin, support | key/device/connector control | `tests/tools/test_control_tower_trust_proof_tool.py` | keep primary |
| Identity / Tenant Admin | `api/admin_identity.py` | `/admin/identity/*`, `/admin/tenants*` | `/admin/tenants`, `/admin/tenants/{tenantId}` | `/login`, `/accept-invite` | Admin + hidden auth | Admin & Platform Ops | tenant_admin, platform_admin | invites, portal grants | `tests/test_admin_identity_routes.py`, `tests/test_c7_portal_grants.py` | UI thinner than backend |
| Billing | `api/billing.py`, `api/billing_v2.py` | `/billing*`, `/admin/billing*`, `/admin/subscriptions*` | dashboard banner only | none | hidden | Admin & Platform Ops future | platform_admin, executive | commercial readiness | `tests/test_billing_module.py` | no real UI home |
| Keys | `api/keys.py`, `api/key_rotation.py` | `/admin/keys*`, `/keys` | `/dashboard/control-tower`, `/keys` | none | hidden + control tower | Admin & Platform Ops | tenant_admin, platform_admin | rotate/revoke | key route checks | duplicate surface |
| Audit / Forensics | audit pipeline | `/ui/forensics/*`, `/admin/audit/*` | `/dashboard/forensics`, `/audit` | engagement history | Compliance + hidden | Trust Center specialist | auditor, support | chain verify, export | forensics tests | duplicate surfaces |

Matrix findings:

- backend-only authorities: governance intelligence, governance orchestration, governance learning, governance optimization, benchmarking, counterfactual, much of billing
- UI-only or placeholder surfaces: `/dashboard/policies`, `/dashboard/providers`, `/dashboard/workforce`, `/assessment`, `/onboarding`, `/products*`
- duplicated surfaces: `apps/console/app/**` vs `apps/console/console/**`, `/audit` vs `/dashboard/forensics`, `/keys` vs Control Tower key cards
- orphaned surfaces: `/governance/topology`, `/reports/{reportId}`, `/products*`, `/keys`
- hidden but valuable surfaces: report detail, topology explorer, verification bundle, provider governance, intelligence runtime routes

## Section 4 - Screen Registry

Classification vocabulary: `mission_critical`, `high_value`, `contextual`, `specialist`, `administrative`, `hidden`, `legacy`, `duplicate`, `placeholder`, `future`, `retire_candidate`.

| Route | Display name | Owning capability | Current nav group | Future recommended group | Primary / secondary persona | Source authority | APIs consumed | Writes allowed | Business value | Frequency | Confidence | Lifecycle | Recommendation | Classification | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `/` (console) | Console root | Console shell | hidden | Hidden/Auth | Operator / Support | layout shell | redirect/shell only | no | low | daily entry | high | stable | keep hidden | hidden | `apps/console/app/page.tsx` |
| `/login` (console) | Console login | Identity | hidden | Hidden/Auth | All users / none | auth | Auth0 session | yes | required access | daily | high | stable | keep | hidden | `apps/console/app/login/page.tsx` |
| `/dashboard` | Command Center | Control Tower / executive ops | Operations | Executive Command Center | Executive / Operator | control tower + health | `/api/core/health/ready`, `/api/core/stats/summary`, feed, control tower snapshot | no | very high | daily | high | core | keep primary | mission_critical | `apps/console/app/dashboard/page.tsx` |
| `/dashboard/control-tower` | Control Tower | Administration | Operations | Admin & Platform Ops | Platform Administrator / Support | control plane | control tower APIs, key/device/connector routes | yes | very high | daily | high | core | keep primary | mission_critical | `apps/console/app/dashboard/control-tower/page.tsx` |
| `/dashboard/assistant` | AI Workspace | AI Workspace | AI & Knowledge | Operations Workspace | Operator / Customer Support | AI plane | `/api/core/ui/ai/chat` | yes | medium | daily | high | growing | keep | high_value | `apps/console/app/dashboard/assistant/page.tsx` |
| `/dashboard/corpus` | Corpus | Corpus | AI & Knowledge | Operations Workspace specialist | Operator / Developer | corpus console | rag corpora/documents | yes | medium | weekly | high | stable | keep contextual | specialist | `apps/console/app/dashboard/corpus/page.tsx` |
| `/dashboard/retrieval` | Retrieval | Retrieval | AI & Knowledge | Governance & Intelligence Workspace | Developer / Operator | retrieval policy | retrieval policy APIs | yes | medium | weekly | high | stable | keep contextual | specialist | `apps/console/app/dashboard/retrieval/page.tsx` |
| `/dashboard/provenance` | Provenance | Decision Provenance | AI & Knowledge | Trust Center | Auditor / Operator | evidence + governance chain | evidence explorer, audit chain | no | high | weekly | high | stable | elevate | specialist | `apps/console/app/dashboard/provenance/page.tsx` |
| `/dashboard/policies` | Policies | Policies | Governance | Governance & Intelligence Workspace | Compliance Officer / Platform Admin | control registry/policy | placeholder/no proven live contract | unclear | medium | weekly | medium | growing | keep but contextualize | placeholder | `apps/console/app/dashboard/policies/page.tsx` |
| `/dashboard/providers` | Providers | Provider Governance | Governance | Governance & Intelligence Workspace | Platform Administrator / CISO | provider governance | provider governance APIs | likely yes | medium | weekly | medium | growing | keep contextual | placeholder | `apps/console/app/dashboard/providers/page.tsx` |
| `/dashboard/readiness` | Readiness | Readiness | Governance | Executive Command Center | Executive / Compliance Officer | readiness | readiness assessment APIs | no | very high | daily | high | core | keep primary | mission_critical | `apps/console/app/dashboard/readiness/page.tsx` |
| `/field-assessment` | Field Assessments | Field Assessment | Governance | Operations Workspace | Assessment Engineer / Consultant | field assessment | engagements list/create | yes | very high | daily | high | core | keep primary | mission_critical | `apps/console/app/field-assessment/page.tsx` |
| `/field-assessment/{engagementId}` | Engagement Workspace | Field Assessment | contextual from list | Operations Workspace | Field Assessor / QA Reviewer | field assessment | engagement, scans, docs, observations, findings, reports, questionnaire, verification | yes | very high | daily | high | core | keep primary-contextual | mission_critical | `apps/console/app/field-assessment/[engagementId]/page.tsx` |
| `/dashboard/forensics` | Audit & Forensics | Audit & Forensics | Compliance | Trust Center | Auditor / Support Engineer | audit pipeline | `/ui/forensics/*`, chain verify | mostly read | high | weekly | high | stable | keep | specialist | `apps/console/app/dashboard/forensics/page.tsx` |
| `/dashboard/decisions` | Decisions | Decision Provenance | Compliance | Trust Center | Auditor / Executive | decisions | `/decisions`, decision detail | no | medium | weekly | medium | stable | keep contextual | specialist | `apps/console/app/dashboard/decisions/page.tsx` |
| `/dashboard/evaluation` | Evaluation Lab | Evaluation Lab | Compliance | Governance & Intelligence Workspace | Developer / Platform Admin | evaluation | `/ui/evaluation/*` | mixed | medium | weekly | high | stable | keep contextual | specialist | `apps/console/app/dashboard/evaluation/page.tsx` |
| `/dashboard/workforce` | Workforce Intel | Workforce | Workforce | Operations Workspace specialist | Operator / HR security | workforce | workforce alert routes | unclear | medium | weekly | medium | growing | keep contextual | placeholder | `apps/console/app/dashboard/workforce/page.tsx` |
| `/dashboard/settings` | Settings | Administration | System | Admin & Platform Ops | Tenant Admin / Platform Admin | config | config routes | yes | medium | weekly | medium | stable | keep | administrative | `apps/console/app/dashboard/settings/page.tsx` |
| `/assessment` | Assessment | Assessment | System | Legacy / Commercial | Executive / Consultant | legacy assessment flow | ingest assessment routes | yes | medium | monthly | medium | legacy | demote | legacy | `apps/console/app/assessment/page.tsx` |
| `/audit` | Audit Log | Audit & Forensics | hidden | Trust Center specialist | Auditor / Support | audit pipeline | audit export/search | read/export | medium | monthly | medium | stable | demote behind forensics | duplicate | `apps/console/app/audit/page.tsx` |
| `/dashboard/alignment` | Alignment | Compliance posture | hidden | Governance & Intelligence Workspace | Compliance Officer / Developer | alignment artifact | alignment artifact read | no | low-medium | rare | medium | stable | contextualize | hidden | `apps/console/app/dashboard/alignment/page.tsx` |
| `/dashboard/ingestion` | Ingestion | Corpus | hidden | Operations Workspace specialist | Operator / Developer | ingestion | document ingestion routes | yes | medium | weekly | medium | stable | contextualize | specialist | `apps/console/app/dashboard/ingestion/page.tsx` |
| `/governance/topology` | Governance Topology | Governance | hidden | Governance & Intelligence Workspace | CISO / Auditor | governance graph | graph, anomalies, lineage | likely read | high | rare | high | growing | elevate as specialist | specialist | `apps/console/app/governance/topology/page.tsx` |
| `/keys` | API Keys | Key Management | hidden | Admin & Platform Ops | Tenant Admin / Platform Admin | keys | key routes | yes | medium | rare | medium | stable | demote into Control Tower | duplicate | `apps/console/app/keys/page.tsx` |
| `/onboarding` | Onboarding | Assessment | hidden | Legacy / Commercial | Consultant / Sales Engineer | legacy onboarding | legacy assessment routes | yes | medium | rare | medium | legacy | demote | legacy | `apps/console/app/onboarding/page.tsx` |
| `/products` | Products list | Commercial catalog | hidden | Legacy / Commercial | Sales / Consultant | none proven | none proven | unclear | low | rare | low | legacy | retire candidate | placeholder | `apps/console/app/products/page.tsx` |
| `/products/new` | New product | Commercial catalog | hidden | Legacy / Commercial | Sales / Consultant | none proven | none proven | yes | low | rare | low | legacy | retire candidate | placeholder | `apps/console/app/products/new/page.tsx` |
| `/products/{id}` | Product detail | Commercial catalog | hidden | Legacy / Commercial | Sales / Consultant | none proven | none proven | unclear | low | rare | low | legacy | retire candidate | legacy | `apps/console/app/products/[id]/page.tsx` |
| `/reports/{reportId}` | Report detail | Reports | hidden/contextual | Executive Command Center | Executive / QA Reviewer | report authority | report detail/export | no | high | weekly | medium | stable | keep contextual | contextual | `apps/console/app/reports/[reportId]/page.tsx` |
| `/admin/tenants` | Clients | Clients / Identity | Admin | Admin & Platform Ops | Tenant Admin / MSP | admin identity + tenants | tenant provisioning, grants | yes | high | weekly | medium | stable | keep | administrative | `apps/console/app/admin/tenants/page.tsx` |
| `/admin/tenants/{tenantId}` | Client detail | Clients / Identity | contextual from clients | Admin & Platform Ops | Tenant Admin / MSP | admin identity + portal grants | tenant detail, invites, grants | yes | high | weekly | medium | stable | keep | administrative | `apps/console/app/admin/tenants/[tenantId]/page.tsx` |
| `/` (portal) | Portal overview | Portal | Overview | Portal Experience | Customer / Board Member | portal aggregate | findings, roadmap, questionnaires, attestation health | no | very high | daily | high | core | keep primary | mission_critical | `apps/portal/app/page.tsx` |
| `/login` (portal) | Portal login | Identity | hidden | Hidden/Auth | Customer / none | portal auth | `/api/auth/login` | yes | required access | daily | high | stable | keep | hidden | `apps/portal/app/login/page.tsx` |
| `/accept-invite` | Accept invite | Identity | hidden | Hidden/Auth | Customer / Support | invitation flow | `/api/auth/accept-invite` | yes | required onboarding | rare | high | stable | keep | hidden | `apps/portal/app/accept-invite/page.tsx` |
| `/engagement` | Assessment summary | Field Assessment | Assessment | Portal Experience | Customer / Auditor | field assessment | engagement list/selection | no | high | weekly | medium | stable | keep | high_value | `apps/portal/app/engagement/page.tsx` |
| `/engagement/{engagementId}` | Engagement detail | Field Assessment | contextual | Portal Experience | Customer / Auditor | field assessment | engagement detail, scans, documents, observations, evidence, verification bundle | no | high | weekly | high | core | keep | high_value | `apps/portal/app/engagement/[engagementId]/page.tsx` |
| `/findings` | Findings | Remediation | Findings | Portal Experience | Customer / Compliance Officer | field assessment | findings list, explain finding | no | very high | weekly | high | core | keep | mission_critical | `apps/portal/app/findings/page.tsx` |
| `/reports` | Reports | Reports | Reports | Portal Experience | Executive / Board Member | report authority | reports list, export, verify | yes verify/export | very high | weekly | high | core | keep | mission_critical | `apps/portal/app/reports/page.tsx` |
| `/coverage` | Coverage | Readiness | Coverage | Portal Experience | Compliance Officer / Executive | questionnaires + readiness | questionnaires, roadmap | no | high | weekly | high | core | keep | high_value | `apps/portal/app/coverage/page.tsx` |
| `/attestation` | Attestation | Attestation / Governance assets | Attestation | Portal Experience | Asset Owner / Customer | governance assets | assets, attestations | yes | high | monthly | high | growing | keep | high_value | `apps/portal/app/attestation/page.tsx` |
| `/remediation` | Remediation | Remediation | Remediation | Portal Experience | Customer / Compliance Officer | remediation roadmap | roadmap, finding patch | yes | very high | weekly | high | core | keep | mission_critical | `apps/portal/app/remediation/page.tsx` |
| `/continuity` | Continuity | Readiness / Attestation | Continuity | Portal Experience | Customer / Board Member | governance assets continuity | attestation health, continuity gaps | no | high | monthly | high | growing | keep | high_value | `apps/portal/app/continuity/page.tsx` |
| `/assistant` | Portal AI Assistant | AI Workspace | AI Assistant | Portal Experience contextual | Customer / Board Member | AI plane | `/api/core/ui/ai/chat` | yes | medium | weekly | medium | growing | contextualize | contextual | `apps/portal/app/assistant/page.tsx` |

Screen registry summary:

- `mission_critical`: `/dashboard`, `/dashboard/control-tower`, `/dashboard/readiness`, `/field-assessment`, `/field-assessment/{engagementId}`, `/`, `/findings`, `/reports`, `/remediation`
- `legacy`: `/assessment`, `/onboarding`, `/products*`
- `duplicate`: `/audit`, `/keys`
- `hidden specialist`: `/governance/topology`, `/reports/{reportId}`, `/dashboard/alignment`, `/dashboard/ingestion`

## Section 5 - Widget Registry

| Widget / card | Screen | Capability owner | Data source | API route | Source of truth | Persona | Action destination | Maturity | Business value | Recommendation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| System Health | `/dashboard` | Control Tower | health snapshot | `/api/core/health/ready` | core readiness response | Operator | forensics / control tower | strong | high | keep |
| Retrieval Health | `/dashboard` | Retrieval | control tower snapshot | control tower snapshot through BFF | control tower snapshot | Operator | retrieval | functional | medium | keep |
| Audit Status | `/dashboard` | Trust | chain integrity snapshot | `/api/core/forensics/chain/verify` | trust/forensics response | Auditor | forensics | functional | high | keep |
| Tenant Context | `/dashboard` | Administration | control tower snapshot | control tower APIs | control tower snapshot | Operator | clients | functional | medium | keep |
| Provider Health | `/dashboard` | Providers | control tower snapshot | control tower APIs | connector status | Operator | providers | partial | medium | modify when provider UI matures |
| Active Alerts | `/dashboard` | Notifications | recent feed events | `/api/core/feed/live` | feed event stream | Operator | forensics | functional | high | keep |
| Billing Status | `/dashboard` | Billing | billing readiness | `/api/core/health/ready` | billing readiness field | Executive | admin future | partial | medium | keep, later relocate |
| Stats row | `/dashboard` | Executive ops | stats summary | `/api/core/stats/summary` | stats summary | Executive | dashboard drill-down | functional | high | keep |
| Requests Chart | `/dashboard` | Executive ops | live feed rollup | `/api/core/feed/live` | feed events | Executive | forensics | functional | high | keep |
| Risk Domain Scores | `/dashboard` | Assessment | browser session state | sessionStorage `fg_last_assessment_scores` | legacy assessment result | Executive | `/assessment` / `/onboarding` | partial | medium | modify; replace with server-backed source |
| Quick Actions | `/dashboard` | Operations | static nav actions | page links | route model | Operator | assessment, reports, audit | partial | medium | modify per MCIM |
| Engagement Summary Panel | `/field-assessment/{engagementId}` | Field Assessment | engagement summary | summary route | field assessment summary | Assessor | tab deep links | strong | very high | keep |
| Guided Execution Panel | `/field-assessment/{engagementId}` | Field Assessment | execution state | `/execution-state`, `/next-actions` | playbook + execution state | Field Assessor | scans, docs, interviews | strong | very high | keep |
| Control Gap Matrix | `/field-assessment/{engagementId}` | Readiness | questionnaire coverage | questionnaire coverage routes | questionnaire state | Compliance Officer | questionnaire tab | functional | high | keep |
| Report Generation Panel | `/field-assessment/{engagementId}` | Reports | report generation state | reports routes | report authority | QA Reviewer | reports tab | strong | high | keep |
| Verification Bundle Panel | `/field-assessment/{engagementId}` | Verification | verification bundle | `/verification-bundle*` | verification bundle | Auditor | download / verify | strong | high | keep |
| Coverage Panel | `/` portal | Readiness | roadmap coverage | remediation roadmap | remediation roadmap + questionnaires | Executive | `/coverage` | strong | high | keep |
| Severity Strip | `/` portal | Findings | findings list | findings list | finding status list | Customer | `/findings` | strong | high | keep |
| NIST Function Heatmap | `/` portal | Readiness | questionnaires | questionnaires route | questionnaire responses | Compliance Officer | `/coverage` | strong | high | keep |
| Immediate Actions | `/` portal | Remediation | remediation roadmap | remediation roadmap | roadmap immediate phase | Customer | `/remediation` | strong | high | keep |
| Verification Bundle Card | `/engagement/{engagementId}` | Verification | verification bundle | `/verification-bundle` | verification bundle | Auditor | reports / history | strong | high | keep |
| Report Row action strip | `/reports` portal | Reports | report version list | reports routes | report authority | Executive | export / verify / summary | strong | very high | keep |
| Attestation Health meter | `/continuity` | Attestation | attestation health | governance assets attestation health | governance assets authority | Board Member | attestation | strong | high | keep |
| Continuity Gap cards | `/continuity` | Continuity | continuity gaps | governance assets continuity gaps | governance assets authority | Customer | attestation/remediation | strong | high | keep |

## Section 6 - Action Registry

| Action | Screen | User intent | Authority owner | API route | HTTP method | Required role / scope | Mutates state | Audit event expected | Current label | Recommended future label | Risk | Confidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Create assessment / engagement | `/field-assessment` | open new operator engagement | Field Assessment | `/field-assessment/engagements` | `POST` | `assessor` | yes | yes | `Create Engagement` | `Create Assessment Engagement` | medium | high |
| Start assessment | `/field-assessment/{engagementId}` | advance engagement lifecycle | Field Assessment | `/field-assessment/engagements/{id}/status` | `PATCH` | `assessor` | yes | yes | status transition | `Advance Status` | high | high |
| Upload evidence document | workspace documents tab | register policy/report/doc evidence | Field Assessment / Evidence | `/field-assessment/engagements/{id}/document-analyses` | `POST` | `assessor` | yes | yes | document registration | `Register Evidence Document` | medium | high |
| Run scan | workspace scan panels | execute connector-based data collection | Field Assessment connectors | `/connector-runs/*/initiate` or `/run` | `POST` | `assessor` | yes | yes | panel-specific labels | keep explicit connector labels | high | high |
| Import connector results | workspace scan import | ingest existing connector output | Field Assessment | `/connector-runs/msgraph/import` | `POST` | `assessor` | yes | yes | import | `Import Scan Results` | high | high |
| Capture observation | workspace observations | record forensic or interview observation | Field Assessment | `/observations` | `POST` | `assessor` | yes | yes | save observation | `Capture Observation` | medium | high |
| Update observation | workspace observations | refine evidence narrative | Field Assessment | `/observations/{observationId}` | `PATCH` | `assessor` | yes | yes | save changes | `Update Observation` | medium | high |
| Create evidence link | workspace evidence | link finding to evidence | Evidence | `/evidence-links` | `POST` | `assessor` | yes | yes | link evidence | `Link Evidence` | medium | high |
| Generate report | workspace reports | compile signed deliverable | Reports | `/reports` | `POST` | `assessor` | yes | yes | generate report | `Generate Report` | high | high |
| Export report | workspace reports, portal reports | download signed artifact | Reports | `/reports/{version}/export?format=*` | `GET` | `viewer` or portal grant | no | optional download event | `Export JSON`, `Export PDF` | keep | medium | high |
| Verify report | workspace reports, portal reports | validate signature/manifests | Verification | `/reports/{version}/verify` | `POST` | `viewer`, portal grant | no material mutation | yes verification event | `Verify Signature` | `Verify Report Signature` | low | high |
| QA approve report | workspace history | finalize report and issue portal access | Reports / Portal | `/reports/{reportId}/qa-approve` | `POST` | `qa_reviewer` | yes | yes | `QA Approve` | `Approve and Issue Portal Access` | high | high |
| Publish to portal | workspace after QA | expose client-facing package | Portal grants | portal access issuance through QA approval + tenant grant routes | `POST` | `qa_reviewer`, `tenant_admin` | yes | yes | portal enabled toggle / grant create | `Publish to Client Portal` | high | medium |
| Submit attestation | `/attestation` | customer asserts asset state | Governance assets | `/governance/assets/{assetId}/attestations` | `POST` | portal grant | yes | yes | `Submit Attestation` | keep | medium | high |
| Update remediation | `/remediation` | close or accept a finding | Remediation | `/field-assessment/engagements/{id}/findings/{findingId}` | `PATCH` | portal grant / compliance reviewer | yes | yes | `Mark as resolved` | `Submit Remediation Outcome` | high | high |
| Approve governance action | hidden admin identity | approve invitation or governance action | Identity / Governance | `/admin/identity/invitations/{id}/approve` | `POST` | `tenant_admin` | yes | yes | approve | `Approve` | medium | medium |
| Reject governance action | hidden admin identity | reject invitation or governance action | Identity / Governance | `/admin/identity/invitations/{id}/reject-approval` | `POST` | `tenant_admin` | yes | yes | reject | `Reject` | medium | medium |
| Replay verify | `/dashboard/control-tower` | re-run chain verification | Trust | `/forensics/chain/verify` | `GET` | `platform_admin` | no | optional | `Replay verify` | `Replay Chain Verification` | low | medium |
| Simulate | future intelligence workspace | run scenario compare | Governance Intelligence | `/intelligence/simulation-compare` | `POST` | `platform_admin`, `ciso` | yes derived job | yes | not surfaced | `Run Simulation` | medium | medium |
| Export package | future trust/intelligence | export evidence or intelligence package | Reports / Intelligence | `/intelligence/export` or audit packet routes | `POST` / `GET` | `auditor`, `platform_admin` | maybe | yes | export | `Export Evidence Package` | medium | medium |
| Verify trust | `/dashboard/control-tower`, `/reports` | inspect trust posture | Trust | `/forensics/chain/verify`, report verify | `GET` / `POST` | `auditor`, portal grant | no | yes | `Verify Signature` | `Verify Trust Proof` | low | high |
| View transparency | `/dashboard/provenance`, reports | inspect provenance links | Transparency | provenance routes | `GET` | `viewer` | no | no | view | `View Provenance` | low | medium |
| Create client | `/admin/tenants` | provision tenant | Administration | `/admin/tenants` or BFF provision route | `POST` | `tenant_admin` | yes | yes | create tenant | `Create Client` | high | medium |
| Invite user | `/admin/tenants/{tenantId}` | invite tenant or portal user | Identity | `/admin/identity/tenants/{tenantId}/invitations` | `POST` | `tenant_admin` | yes | yes | invite | `Invite User` | medium | high |
| Rotate key | `/dashboard/control-tower`, `/keys` | rotate API credential | Key Management | `/admin/keys/{key_prefix}/rotate` | `POST` | `tenant_admin` | yes | yes | `Rotate key` | `Rotate API Key` | high | high |
| Revoke key | `/dashboard/control-tower`, `/keys` | revoke API credential | Key Management | `/admin/keys/{key_prefix}/revoke` | `POST` | `tenant_admin` | yes | yes | `Revoke key` | `Revoke API Key` | high | high |
| Run evaluation | `/dashboard/evaluation` | assess answer quality | Evaluation Lab | `/ui/evaluation/*` | `GET` / specialist workflow | `platform_admin` | maybe | yes | run eval | `Run Evaluation` | medium | medium |

## Section 7 - State Ownership Map

| State item | Screen(s) | Storage location | Source of truth | Derived | Cached | Mutable | Sensitivity | Current risk | Recommended ownership |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Active engagement route param | engagement workspaces, portal detail | URL path | router path | no | no | yes by navigation | medium | low | keep in URL |
| Portal engagement context | portal overview, findings, remediation, reports | `localStorage` key `fg_portal_eid` | client-side persistence only | no | yes | yes | medium | high, breaks continuity and shareability | move to URL + session-backed fallback |
| Portal auth session | portal BFF | cookie `COOKIE_NAME`, grant session lookup | server session + portal grant session | no | yes | yes | high | medium | keep server-owned |
| Console auth session | console BFF / Auth0 | NextAuth/Auth0 session cookies | auth provider and admin gateway | no | yes | yes | high | medium | keep server-owned |
| Legacy assessment domain scores | console dashboard, legacy assessment | `sessionStorage` key `fg_last_assessment_scores` | legacy assessment result in browser only | yes | yes | yes | low-medium | high, non-shareable KPI source | replace with server-backed metric or retire with legacy flow |
| Report selection | engagement workspace reports tab | React state `selectedReportVersion`, `reportDoc` | report authority API | yes | transient | yes | medium | low | keep page-local state |
| Selected tenant/client | clients/admin flows, control tower | route context + server responses | admin tenant APIs | no | transient | yes | medium | medium | keep route/response-driven, no browser storage |
| Selected engagement | field assessment list/detail, portal list/detail | route param plus local state | field assessment API | no | transient | yes | medium | low | keep in URL |
| Notification badge count | top bar / sidebar shell | hard-coded UI state today | none proven | yes | no | yes | low | medium because it implies live notifications without authority | replace with notifications authority feed |
| Attestation drafts | portal attestation | IndexedDB `fg_portal_drafts` | local-only draft queue | no | yes | yes | medium | low-medium | acceptable, document as local draft cache only |
| Theme preference | console/portal layouts | `localStorage` `fg-theme` | client preference | no | yes | yes | low | low | keep local |
| Workspace evidence collections | engagement workspace | React state arrays | field assessment API | no | transient | yes | medium | low | keep API-backed |
| Verification bundle | workspace + portal engagement | API + React state | verification bundle authority | no | transient | no on read surfaces | high | low | keep authority-backed |
| Generated inventory artifacts | docs and audits | repo `artifacts/*` files | generated artifact pipeline | yes | yes | yes by regeneration | low | low | keep file-backed and regenerate explicitly |
| Portal report export result | portal reports | in-memory blob URL | report export endpoint | yes | transient | yes | medium | low | keep transient |

Special focus conclusions:

- critical context should not depend only on `localStorage`
- report and verification states are mostly API-backed and healthy
- the only explicit `sessionStorage` business state is the legacy assessment domain score bridge
- portal and console auth are server-session based, which is the correct ownership boundary

## Section 8 - Source-of-Truth Map

| Metric / displayed value | Displayed where | Computed where | Stored where | API route | Authority owner | Duplicate computations | Risk if duplicated |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Governance score | admin identity runtime-only, future command center | governance intelligence / admin identity | governance score tables/snapshots | `/admin/identity/tenants/{tenant_id}/governance-score` | Identity + Governance | yes, hidden admin route vs future UX | medium |
| Readiness score | `/dashboard/readiness`, portal overview/coverage | readiness services + questionnaire coverage | readiness snapshots and derived questionnaire results | readiness routes, questionnaires | Readiness | yes, console and portal derive from different views | high |
| Risk score | findings severity, external AI risk register | field assessment normalization and risk engines | findings and external risk tables | findings routes, external AI risk records | Field Assessment / Risk | yes | high |
| Trust score / trust posture | control tower, verification bundle, future trust center | trust arc + verification bundle | trust and verification records | chain verify, verification bundle | Trust | partial | medium |
| Evidence freshness | readiness evidence panels, future portal freshness | evidence freshness authority | freshness tables | `/freshness*` | Evidence Freshness | yes, some pages infer from timestamps | medium |
| Verification status | report row, verification bundle, portal engagement | verification bundle + report verify | verification tables, manifests | `/reports/{version}/verify`, `/verification-bundle` | Verification | low | medium |
| Report status | workspace history, portal reports | report authority | report records | `/reports*` | Reports | low | low |
| Remediation status | findings, remediation roadmap | remediation roadmap + finding status | findings/workflow tables | findings, roadmap routes | Remediation | yes | high |
| Attestation status | `/attestation`, `/continuity` | governance assets authority | attestation records | `/governance/assets/*/attestations` | Governance assets | low | medium |
| Continuity status | `/continuity`, portal overview snippets | continuity gap computation | governance asset continuity views | `/governance/assets/continuity-gaps` | Governance assets | low | low |
| Benchmark percentile | backend only | governance intelligence benchmarking | intelligence tables | `/intelligence/benchmark-confidence` | Governance Intelligence | unknown | medium |
| Simulation result | backend only | governance intelligence simulation | intelligence tables | `/intelligence/simulation-compare` | Governance Intelligence | low | medium |
| Replay result | control tower replay verify, backend | trust replay + intelligence replay | trust and intelligence stores | `/forensics/chain/verify`, `/intelligence/replay*` | Trust / Governance Intelligence | yes | medium |
| Confidence score | AI Workspace, finding explanations, reports | retrieval/evaluation/report confidence | report and evaluation stores | AI/eval routes | AI / Reports | yes | medium |
| Quality score | evaluation lab, intelligence quality score | evaluation lab and governance intelligence | evaluation/intelligence stores | `/ui/evaluation/quality`, `/intelligence/quality-score*` | Evaluation / Governance Intelligence | yes | medium |
| Portal summary metrics | portal overview cards | portal page derives from findings, roadmap, questionnaire, attestation health | distributed across respective authorities | multiple portal routes | Portal aggregate | yes | medium |
| Command Center KPIs | `/dashboard` | dashboard page composition | health/stats/feed responses plus legacy sessionStorage | health, stats, feed | Control Tower / Assessment | yes | high, especially sessionStorage coupling |

Canonical rule: future UI PRs must not introduce a new computation path for any business KPI unless the MCIM explicitly reassigns the source of truth.

## Section 9 - Workflow Map

### 1. Field assessment lifecycle

- Start point: `/field-assessment`
- End point: `/field-assessment/{engagementId}` delivered and promoted
- Screens: list, engagement workspace, report history
- APIs: engagements create/get/status, summary, execution-state, next-actions
- Authorities: Field Assessment, Reports
- State mutations: engagement rows, metadata, status, audit events
- Audit events: required for create, transition, QA approval
- Reports / exports: generated reports, verification bundle
- Current friction: lifecycle gates are strong but the surrounding IA mixes legacy and specialist pages
- Future IA recommendation: anchor all operator work under Operations Workspace

### 2. Evidence collection

- Start point: engagement workspace scans/documents/interviews/observations tabs
- End point: evidence linked to findings
- Screens: engagement workspace, provenance, portal engagement detail
- APIs: scan-result ingest/initiate, document-analyses, observations, evidence-links
- Authorities: Field Assessment, Evidence
- State mutations: scan rows, document analyses, observations, evidence links
- Audit events: required for all writes
- Reports / exports: evidence appendices, verification bundle
- Current friction: many data capture modes, no single evidence home
- Future IA recommendation: expose Evidence as a first-class trust context inside the workspace and portal

### 3. Verification

- Start point: report row or verification bundle panel
- End point: verified signature / verified bundle
- Screens: workspace reports, portal reports, portal engagement detail
- APIs: report verify, verification bundle routes
- Authorities: Verification, Trust
- State mutations: verification event append only
- Audit events: verification event expected
- Reports / exports: signed report, bundle manifest
- Current friction: verification is contextual instead of discoverable
- Future IA recommendation: consolidate into Trust Center patterns without moving routes yet

### 4. Report generation

- Start point: engagement workspace reports tab
- End point: report version published and optionally QA-approved
- Screens: engagement workspace, report history, portal reports
- APIs: reports create/list/get/export, QA approve
- Authorities: Reports
- State mutations: report records, signatures, QA approval, access code issuance
- Audit events: generation + QA approval required
- Reports / exports: JSON, PDF, verification bundle
- Current friction: report detail route is hidden; QA approval couples portal issuance
- Future IA recommendation: separate authoring, approval, and delivery states in the IA

### 5. Portal publication

- Start point: QA approval or tenant grant creation
- End point: customer-accessible portal session
- Screens: tenant detail, portal login, portal overview
- APIs: report QA approve, portal grant/session routes
- Authorities: Reports, Identity, Portal
- State mutations: portal grant/session state
- Audit events: grant issuance and login expected
- Reports / exports: portal availability of reports and findings
- Current friction: label says read-only, but portal allows some mutations
- Future IA recommendation: represent portal as guided collaboration, not read-only brochureware

### 6. Customer review

- Start point: portal overview
- End point: customer reaches findings/reports/continuity/attestation surfaces
- Screens: `/`, `/findings`, `/reports`, `/coverage`, `/continuity`
- APIs: findings, reports, questionnaires, roadmap, continuity
- Authorities: Portal aggregate
- State mutations: none on pure review flows
- Audit events: view telemetry optional
- Reports / exports: report export and verify
- Current friction: engagement selection and persistence rely on localStorage
- Future IA recommendation: URL-first engagement context with consistent cross-page handoff

### 7. Remediation

- Start point: portal remediation or findings page
- End point: finding marked remediated, accepted, or false positive
- Screens: `/remediation`, `/findings`
- APIs: remediation roadmap, finding patch
- Authorities: Remediation
- State mutations: finding status, notes, owner email
- Audit events: required
- Reports / exports: reflected in readiness and later reports
- Current friction: current label implies simple resolution, but writes have governance meaning
- Future IA recommendation: make outcome submission explicit and auditable

### 8. Attestation

- Start point: `/attestation`
- End point: attestation record submitted for operator review
- Screens: attestation page, continuity page
- APIs: governance assets list, submit attestation, list attestations, attestation health
- Authorities: Governance assets / Attestation
- State mutations: attestation records, IndexedDB draft cache
- Audit events: submit event required
- Reports / exports: attestation health affects continuity view
- Current friction: portal footer says read-only while this is a write path
- Future IA recommendation: keep portal write paths but surface review workflow honestly

### 9. Continuity / reassessment

- Start point: `/continuity` or readiness drift monitoring
- End point: overdue assets identified, reassessment triggered through operations
- Screens: continuity page, readiness page, field assessment list
- APIs: continuity gaps, attestation health, readiness history, future orchestration routes
- Authorities: Readiness, Governance Orchestration
- State mutations: mostly derived today; future orchestration will mutate schedules
- Audit events: expected for future trigger actions
- Reports / exports: continuity summaries
- Current friction: split between portal continuity and operator reassessment
- Future IA recommendation: connect continuity signals back to Operations Workspace

### 10. Trust verification

- Start point: Control Tower, report verify, verification bundle card
- End point: operator or customer confirms integrity
- Screens: `/dashboard/control-tower`, `/reports`, `/engagement/{engagementId}`
- APIs: chain verify, verification bundle, report verify
- Authorities: Trust, Verification
- State mutations: verification logs only
- Audit events: yes
- Reports / exports: report verify result, bundle manifest
- Current friction: multiple trust touchpoints without a common navigation home
- Future IA recommendation: Trust Center owns the narrative

### 11. Transparency verification

- Start point: provenance or report summary
- End point: user sees source links, evidence lineage, and history
- Screens: `/dashboard/provenance`, `/dashboard/decisions`, `/reports`, `/engagement/{engagementId}`
- APIs: evidence, provenance, decisions, history
- Authorities: Transparency, Decision Provenance
- State mutations: none
- Audit events: optional
- Reports / exports: transparency appendices
- Current friction: evidence and decision provenance live on separate specialist pages
- Future IA recommendation: unify under Trust Center information model

### 12. Governance intelligence / replay / simulation

- Start point: runtime-only intelligence endpoints today
- End point: exported simulation/replay/quality/benchmark outputs
- Screens: none primary today
- APIs: `/intelligence/*`
- Authorities: Governance Intelligence
- State mutations: simulation and export jobs
- Audit events: expected for mutations
- Reports / exports: export package, replay result, simulation compare
- Current friction: no first-class screen
- Future IA recommendation: Governance & Intelligence Workspace in 18.6.4

### 13. Admin client onboarding

- Start point: `/admin/tenants`
- End point: tenant created, invitations/grants issued
- Screens: clients list and client detail
- APIs: tenant create/detail, identity invitations, portal grants
- Authorities: Administration, Identity
- State mutations: tenant rows, invitation rows, grant rows
- Audit events: required
- Reports / exports: tenant audit summary
- Current friction: placeholder-backed admin UI hides rich backend capabilities
- Future IA recommendation: Admin & Platform Ops grouping, preserve routes

### 14. Key management

- Start point: Control Tower or `/keys`
- End point: key created, rotated, or revoked
- Screens: `/dashboard/control-tower`, `/keys`
- APIs: admin keys routes
- Authorities: Key Management
- State mutations: key ledger
- Audit events: required
- Reports / exports: audit logs
- Current friction: duplicate surfaces
- Future IA recommendation: consolidate semantics under Control Tower while preserving `/keys`

### 15. Evaluation Lab

- Start point: `/dashboard/evaluation`
- End point: run quality/comparison/confidence investigations
- Screens: evaluation lab
- APIs: `/ui/evaluation/*`
- Authorities: Evaluation Lab
- State mutations: evaluation runs and comparison artifacts
- Audit events: expected
- Reports / exports: evaluation exports
- Current friction: specialist-only destination disconnected from business value
- Future IA recommendation: keep specialist but classify clearly

## Section 10 - Persona Model

| Persona | Goals | Primary screens | Secondary screens | Daily workflows | Rare workflows | Required KPIs | Required actions | Current gaps | Recommended navigation entry point |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Executive | see posture and progress | `/dashboard`, `/dashboard/readiness`, portal `/`, `/reports` | `/dashboard/decisions` | review KPIs and latest reports | verify trust proof | readiness, active alerts, report status | view/export reports | specialist clutter before value | Executive Command Center |
| Board Member | review trust and continuity | `/`, `/reports`, `/continuity` | `/findings` | review overview and reports | verify signature | continuity, open critical findings, trust proof | export/verify report | engagement context not board-centric | Portal overview |
| CISO | understand enterprise risk | `/dashboard`, `/field-assessment/{engagementId}`, `/dashboard/readiness` | `/governance/topology`, `/dashboard/forensics` | review readiness and active engagements | run simulations | readiness, critical findings, drift | review evidence, approve priorities | intelligence hidden | Executive Command Center then Governance & Intelligence |
| Compliance Officer | control coverage and remediation | `/dashboard/readiness`, `/field-assessment/{engagementId}`, `/coverage`, `/remediation` | `/reports` | track controls and close gaps | accept risk | coverage, remediation status | update remediation, review questionnaire | console/portal split | Readiness |
| Auditor | verify evidence and signatures | `/dashboard/provenance`, `/dashboard/forensics`, `/reports`, `/engagement/{engagementId}` | `/dashboard/decisions` | inspect chain and report signatures | export evidence packages | verification status, chain integrity | verify trust, export package | no single audit workspace | Trust Center |
| Operator | monitor platform health | `/dashboard`, `/dashboard/control-tower` | `/dashboard/forensics`, `/admin/tenants` | health checks and incident review | connector/key actions | system health, alerts, active tenants | quarantine/restart/rotate | primary nav mixes legacy flows | Command Center |
| Assessment Engineer | execute engagements | `/field-assessment`, `/field-assessment/{engagementId}` | `/dashboard/readiness`, `/reports` | run scans and compile reports | generate verification bundle | engagement progress, findings, evidence links | create engagement, run scan, generate report | strong core, but specialist context scattered | Operations Workspace |
| Field Assessor | deliver client assessment | `/field-assessment`, `/field-assessment/{engagementId}` | portal preview routes | collect evidence and interviews | publish to portal | gates, document/scans counts | capture observation, link evidence | best served persona | Operations Workspace |
| Customer | understand findings and respond | `/`, `/findings`, `/remediation`, `/reports`, `/attestation` | `/continuity` | review findings and submit actions | verify signature | open findings, roadmap, attestation health | submit remediation, submit attestation | read-only label mismatch | Portal overview |
| MSP | manage multiple client states | `/admin/tenants`, `/field-assessment`, portal | `/dashboard` | tenant/admin oversight | portal grant admin | tenant counts, engagement states | create client, invite user | multi-tenant UX thinner than API | Clients |
| Consultant | run repeatable assessment program | `/field-assessment`, `/reports`, `/onboarding` | `/dashboard/readiness` | create and guide engagements | legacy assessment demo | engagement throughput | create engagement, generate report | legacy/onboarding overlap | Operations Workspace |
| Platform Administrator | own control plane | `/dashboard/control-tower`, `/admin/tenants`, `/dashboard/settings` | `/keys`, `/dashboard/providers` | manage keys/devices/connectors | approve governance actions | health, key status, connector status | rotate/revoke/quarantine | admin capabilities fragmented | Control Tower |
| Support Engineer | diagnose incidents | `/dashboard/control-tower`, `/dashboard/forensics`, `/dashboard` | `/audit` | trace incidents and replay state | export audit packet | alerts, chain integrity | replay verify, review trace | `/audit` duplication | Control Tower |
| Developer | validate contracts and authority exposure | eval/retrieval/census docs | `/dashboard/evaluation`, `/dashboard/retrieval`, artifacts docs | inspect APIs and route inventories | run CI and export artifacts | contract parity, quality score | run evaluation | backend/UI mismatch | Governance & Intelligence Workspace |

## Section 11 - Navigation Classification Model

Canonical navigation tiers:

- `primary`: daily landing destinations for core personas
- `secondary`: important but not always first-hop destinations
- `contextual`: reachable from workflows, cards, or drill-downs
- `specialist`: advanced destinations for a small persona set
- `administrative`: tenant/platform operations
- `hidden`: auth, drill-down, or non-nav routes
- `legacy`: older flow preserved for compatibility
- `deprecated`: kept reachable but should not gain new product meaning
- `future`: authority exists but first-class destination does not yet

Current nav item classifications:

| Current label | Current route | Current group | Recommended tier | Recommended future group | Reason | Evidence | Confidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Command Center | `/dashboard` | Operations | primary | Executive Command Center | daily health and KPI hub | sidebar + operator guide | high |
| Control Tower | `/dashboard/control-tower` | Operations | primary | Admin & Platform Ops | core admin action surface | sidebar + operator guide | high |
| AI Workspace | `/dashboard/assistant` | AI & Knowledge | secondary | Operations Workspace | useful but not first-hop for every operator | sidebar + page wiring | high |
| Corpus | `/dashboard/corpus` | AI & Knowledge | specialist | Operations Workspace | specialist knowledge admin | sidebar + RAG map | high |
| Retrieval | `/dashboard/retrieval` | AI & Knowledge | specialist | Governance & Intelligence Workspace | specialist policy tuning | sidebar + RAG map | high |
| Provenance | `/dashboard/provenance` | AI & Knowledge | specialist | Trust Center | core trust value but advanced persona | sidebar + evidence map | high |
| Policies | `/dashboard/policies` | Governance | secondary | Governance & Intelligence Workspace | important domain, current UI immature | sidebar + census placeholder finding | medium |
| Providers | `/dashboard/providers` | Governance | specialist | Governance & Intelligence Workspace | valuable but not daily | sidebar + provider console | medium |
| Readiness | `/dashboard/readiness` | Governance | primary | Executive Command Center | core posture view | sidebar + readiness tests | high |
| Field Assessments | `/field-assessment` | Governance | primary | Operations Workspace | strongest operator workflow | sidebar + audits | high |
| Audit & Forensics | `/dashboard/forensics` | Compliance | specialist | Trust Center | investigation destination | sidebar + operator guide | high |
| Decisions | `/dashboard/decisions` | Compliance | specialist | Trust Center | provenance/explainability surface | sidebar + decisions page | medium |
| Evaluation Lab | `/dashboard/evaluation` | Compliance | specialist | Governance & Intelligence Workspace | developer/platform specialty | sidebar + eval map | high |
| Workforce Intel | `/dashboard/workforce` | Workforce | specialist | Operations Workspace | not daily for most personas | sidebar + placeholder finding | medium |
| Clients | `/admin/tenants` | Admin | administrative | Admin & Platform Ops | tenant operations | sidebar + admin routes | high |
| Settings | `/dashboard/settings` | System | administrative | Admin & Platform Ops | config management | sidebar | high |
| Assessments | `/assessment` | System | legacy | Legacy / Commercial | overlaps stronger field assessment flow | sidebar + legacy sessionStorage | high |
| Overview | `/` | Portal | primary | Portal Experience | core customer hub | portal layout + page | high |
| Assessment | `/engagement` | Portal | secondary | Portal Experience | customer engagement drill-down | portal layout | high |
| Findings | `/findings` | Portal | primary | Portal Experience | customer action hub | portal layout + page | high |
| Reports | `/reports` | Portal | primary | Portal Experience | signed deliverables | portal layout + page | high |
| Coverage | `/coverage` | Portal | secondary | Portal Experience | posture detail | portal layout + page | high |
| Attestation | `/attestation` | Portal | secondary | Portal Experience | customer write collaboration | portal layout + page | high |
| Remediation | `/remediation` | Portal | primary | Portal Experience | customer action loop | portal layout + page | high |
| Continuity | `/continuity` | Portal | secondary | Portal Experience | long-cycle trust posture | portal layout + page | high |
| AI Assistant | `/assistant` | Portal | contextual | Portal Experience | optional assistant, not core proof path | portal layout + page | medium |

Do not implement these tier changes in this PR.

## Section 12 - Module Lifecycle Map

| Module / capability | Classification | Justification | Risk | Migration note |
| --- | --- | --- | --- | --- |
| Field Assessment | core | strongest end-to-end workflow and revenue delivery spine | low | preserve routes and tabs |
| Reports | core | signed customer deliverable | low | preserve report reachability and exports |
| Portal overview/findings/remediation/reports | core | customer-facing core journey | low | preserve all routes and write paths |
| Readiness | core | primary executive and compliance KPI | medium | converge console and portal calculations |
| Control Tower | stable | mature operator/admin surface | low | preserve action semantics |
| Evidence / Verification | stable | trust moat already present | medium | elevate discoverability, not route churn |
| Provenance / Decisions / Forensics | growing | valuable specialist trust surfaces | medium | regroup into Trust Center |
| AI Workspace / Corpus / Retrieval | growing | meaningful platform differentiation | medium | contextualize by persona |
| Governance Topology | growing | high-value hidden specialist graph | medium | surface under Governance & Intelligence |
| Governance Intelligence family | growing | strong backend, no UX packaging | high | add future workspace before broad relabeling |
| Governance Orchestration | growing | strategic automation layer | high | keep backend-only until explicit UX home exists |
| Governance Learning | future | backend authority without UI | medium | do not invent UI in 18.6.0 |
| Governance Optimization | future | backend authority without UI | medium | same as above |
| Benchmarking | future | runtime-only | medium | expose only after source metrics clarified |
| Simulation | future | runtime-only | medium | pair with governance intelligence workspace |
| Counterfactual | future | runtime-only | medium | same |
| Providers | growing | exists but immature | medium | keep route, reduce primary prominence |
| Workforce | growing | real page, unclear day-two value | medium | specialist classification |
| Billing | growing | backend maturity > UI maturity | medium | defer to commercial readiness PR |
| `/assessment` | legacy | older commercial assessment path | medium | retain route, demote from primary nav later |
| `/onboarding` | legacy | overlaps with field assessment initiation | medium | retain, contextualize |
| `/products*` | retire_candidate | low evidence of active business value, placeholder tendency | medium | retain route until explicit retirement PR |
| `/audit` | duplicate | overlaps `/dashboard/forensics` | low | keep reachable; demote |
| `/keys` | duplicate | overlaps Control Tower key management | low | keep reachable; contextualize |
| `apps/console/console/**` shell tree | duplicate | duplicate legacy shell tree | high | quarantine in a later safe cleanup PR, not 18.6.0 |
| portal `read-only` footer language | deprecated | conflicts with actual write affordances | medium | fix language in later portal PR without removing routes |

## Section 13 - Technical Debt Ranking

| Rank | Finding | Evidence | Risk | Business impact | Security impact | UX impact | Fix complexity | Priority | Recommended PR target |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | duplicate console shell tree | `apps/console/console/**`, Phase 1 audit | route drift and maintenance confusion | high | medium | medium | medium | P0 | 18.6.1 |
| 2 | legacy `/assessment` sessionStorage score bridge | `apps/console/app/assessment/page.tsx`, dashboard sessionStorage read | KPI source drift | high | low | high | medium | P0 | 18.6.1 |
| 3 | legacy `/onboarding` overlaps field assessment initiation | audits + route inventory | conflicting entry point | medium | low | high | low | P1 | 18.6.1 |
| 4 | `/products*` lacks clear active authority | route census placeholder findings | orphaned commercial surface | medium | low | medium | low | P1 | 18.6.7 |
| 5 | portal localStorage engagement context | `apps/portal/lib/engagementStore.ts` | continuity break and deep-link fragility | high | medium | high | medium | P0 | 18.6.6 |
| 6 | portal read-only label vs write-capable actions | portal layout + BFF allowlist + attestation/remediation pages | trust/expectation mismatch | medium | medium | high | low | P0 | 18.6.6 |
| 7 | placeholder surfaces in primary or near-primary nav | frontend map, sidebar, workforce/providers/policies/pages | broken information scent | medium | low | high | medium | P1 | 18.6.1 |
| 8 | backend-only authorities without UI homes | platform inventory runtime-only routes | hidden product value | high | low | high | medium | P1 | 18.6.4 |
| 9 | trust/provenance underexposure | provenance/forensics/verification split | missed differentiation | medium | medium | high | medium | P1 | 18.6.5 |
| 10 | intelligence/replay/simulation hiddenness | `/intelligence/*` runtime-only routes | unmonetized capability | medium | low | medium | medium | P1 | 18.6.4 |
| 11 | billing/subscription UI maturity gap | billing map, dashboard banner only | commercial readiness limit | medium | low | medium | medium | P1 | 18.6.7 |
| 12 | `/audit` duplicates `/dashboard/forensics` | route inventory and operator guide | navigation redundancy | low | low | medium | low | P2 | 18.6.5 |
| 13 | `/keys` duplicates Control Tower | hidden route plus control tower actions | admin confusion | low | medium | medium | low | P2 | 18.6.1 |
| 14 | portal grants and access-code model still visible in workspace | Field Assessment enterprise audit | customer isolation model concerns | high | high | medium | high | P0 | out-of-scope architecture note, later security PR |

Top P0 findings for 18.6 planning:

- duplicate shell and route truth drift
- local browser storage as business context source
- read-only labeling that hides live customer mutations
- legacy assessment score source feeding dashboard KPIs

## Section 14 - Proposed 18.6 PR Breakdown

### 18.6.1 Unified Navigation Framework

- Scope: classify all existing routes, preserve reachability, regroup labels and entry points around MCIM tiers
- Screens affected: all current nav items plus hidden route inventory annotations
- Capabilities affected: navigation only across Command Center, Field Assessment, Trust, Governance, Portal
- Risks: accidental route loss, orphaning hidden surfaces
- Acceptance criteria: no route lost, every route classified, no primary nav item backed only by placeholder
- Test strategy: route inventory, screen inventory, navigation decision log review, smart gate
- Must not change: route names, backend APIs, business logic, page content semantics

### 18.6.2 Executive Command Center

- Scope: make `/dashboard` and `/dashboard/readiness` the executive/operator posture hub
- Screens affected: `/dashboard`, `/dashboard/readiness`, report detail contextual links
- Capabilities affected: readiness, reports, alerts, executive KPIs
- Risks: accidentally depending on sessionStorage legacy metrics
- Acceptance criteria: all primary KPIs are authority-backed or explicitly tagged legacy
- Test strategy: command center/readiness tests plus MCIM source-of-truth checks
- Must not change: assessment routes, backend metrics contracts

### 18.6.3 Operations Workspace

- Scope: reinforce Field Assessment, Corpus, AI Workspace, Workforce specialist placement
- Screens affected: `/field-assessment*`, `/dashboard/assistant`, `/dashboard/corpus`, `/dashboard/ingestion`, `/dashboard/workforce`
- Capabilities affected: assessment execution, evidence intake, operations specialist tools
- Risks: breaking current assessor flow
- Acceptance criteria: field assessment workflow unchanged, hidden specialist tools remain reachable
- Test strategy: field-assessment workspace tests, report UI tests
- Must not change: engagement APIs, scan flows, report generation behavior

### 18.6.4 Governance & Intelligence Workspace

- Scope: give governance intelligence, topology, evaluation, retrieval, policies, providers a coherent specialist home
- Screens affected: `/dashboard/evaluation`, `/dashboard/retrieval`, `/dashboard/policies`, `/dashboard/providers`, `/governance/topology`
- Capabilities affected: governance intelligence, provider governance, evaluation lab, topology
- Risks: surfacing immature or backend-only capabilities without clear labels
- Acceptance criteria: hidden backend-only authorities have documented future homes; placeholders are clearly tiered
- Test strategy: retrieval/evaluation/provider component tests plus route parity review
- Must not change: intelligence APIs or specialist business logic

### 18.6.5 Trust Center

- Scope: unify provenance, verification, forensics, decisions, transparency, and trust proof navigation
- Screens affected: `/dashboard/provenance`, `/dashboard/forensics`, `/dashboard/decisions`, contextual report verify surfaces
- Capabilities affected: trust, transparency, verification, audit & forensics
- Risks: breaking provenance links or verification affordances
- Acceptance criteria: provenance links preserved end-to-end; trust routes remain reachable
- Test strategy: trust/provenance CI checks, verification bundle tests, report signing tests
- Must not change: report verification semantics, audit chain behavior

### 18.6.6 Portal Experience

- Scope: cleanly package overview, findings, reports, remediation, attestation, continuity, assistant
- Screens affected: all portal screens
- Capabilities affected: portal, remediation, attestation, continuity, report verification
- Risks: localStorage context regressions, mutation labeling regressions
- Acceptance criteria: portal write paths are accurately labeled; engagement context no longer depends only on localStorage
- Test strategy: portal structure/security tests and MCIM checklist
- Must not change: portal routes, BFF allowlist semantics, report export/verify APIs

### 18.6.7 UX Polish & Commercial Readiness

- Scope: billing/admin maturity, legacy commercial route treatment, label clean-up, placeholder reduction
- Screens affected: `/assessment`, `/onboarding`, `/products*`, dashboard billing card, admin surfaces
- Capabilities affected: billing, commercial readiness, legacy assessment
- Risks: confusing sales/demo flows during cleanup
- Acceptance criteria: legacy routes preserved or explicitly retired by MCIM amendment
- Test strategy: route parity, billing guards, documentation review
- Must not change: billing backend contracts or monetization ledger behavior

## Section 15 - Validation Rules for Future UI PRs

Every 18.6.x PR must pass these checks:

1. No route lost unless retired in MCIM.
2. No authority orphaned.
3. No nav item without route.
4. No route without classification.
5. No primary nav item backed only by placeholder.
6. No duplicated source of truth introduced for business KPIs.
7. No customer portal write action mislabeled read-only.
8. No localStorage critical context without URL or server-session fallback.
9. All new labels must map to a business capability in the registry.
10. All mutations must have explicit audit expectations.
11. All trust and verification surfaces must preserve provenance links.
12. Hidden and specialist routes must remain reachable from at least one canonical entry point.
13. Legacy routes must be demoted or contextualized before retirement; never silently removed.
14. Duplicate surfaces must be documented until consolidated.
15. UI changes must not imply a new authority owner without source-of-truth updates in the MCIM.

## Section 16 - Machine-Readable Appendix

### capability_registry

```json
[
  {"capability":"Assessment","family":"commercial_intake","owner":"api/assessments.py","console":["/assessment","/onboarding"],"portal":[],"lifecycle":"legacy","nav_tier":"legacy","maturity":"partial"},
  {"capability":"Field Assessment","family":"operator_execution","owner":"services/field_assessment","console":["/field-assessment","/field-assessment/{engagementId}"],"portal":["/engagement","/engagement/{engagementId}"],"lifecycle":"core","nav_tier":"primary","maturity":"strong"},
  {"capability":"Evidence","family":"trust_audit","owner":"services/evidence_authority","console":["/dashboard/provenance","/dashboard/forensics"],"portal":["/engagement/{engagementId}"],"lifecycle":"core","nav_tier":"contextual","maturity":"strong"},
  {"capability":"Verification","family":"trust","owner":"services/verification_bundle","console":["/field-assessment/{engagementId}"],"portal":["/reports","/engagement/{engagementId}"],"lifecycle":"stable","nav_tier":"contextual","maturity":"functional"},
  {"capability":"Reports","family":"delivery","owner":"services/report_authority","console":["/field-assessment/{engagementId}","/reports/{reportId}"],"portal":["/reports"],"lifecycle":"core","nav_tier":"primary","maturity":"strong"},
  {"capability":"Portal","family":"customer_delivery","owner":"services/governance_portal","console":["/admin/tenants/{tenantId}"],"portal":["/","/findings","/reports","/coverage","/attestation","/remediation","/continuity"],"lifecycle":"core","nav_tier":"primary","maturity":"strong"},
  {"capability":"Remediation","family":"closed_loop","owner":"services/remediation_authority","console":["/field-assessment/{engagementId}"],"portal":["/findings","/remediation"],"lifecycle":"growing","nav_tier":"primary","maturity":"functional"},
  {"capability":"Governance","family":"continuous_posture","owner":"services/governance_*","console":["/dashboard/policies","/dashboard/providers","/dashboard/readiness","/governance/topology"],"portal":["/coverage","/continuity"],"lifecycle":"growing","nav_tier":"secondary","maturity":"functional"},
  {"capability":"Governance Learning","family":"intelligence","owner":"services/governance_learning","console":[],"portal":[],"lifecycle":"future","nav_tier":"future","maturity":"latent"},
  {"capability":"Governance Optimization","family":"intelligence","owner":"services/governance_optimization","console":[],"portal":[],"lifecycle":"future","nav_tier":"future","maturity":"latent"},
  {"capability":"Governance Orchestration","family":"automation","owner":"services/governance_orchestration","console":[],"portal":[],"lifecycle":"growing","nav_tier":"future","maturity":"partial_backend"},
  {"capability":"Governance Intelligence","family":"intelligence","owner":"services/governance_intelligence","console":[],"portal":[],"lifecycle":"growing","nav_tier":"specialist","maturity":"partial_backend"},
  {"capability":"Decision Provenance","family":"trust_explainability","owner":"services/governance_chain","console":["/dashboard/decisions","/dashboard/provenance"],"portal":["/reports"],"lifecycle":"stable","nav_tier":"specialist","maturity":"functional"},
  {"capability":"Benchmarking","family":"intelligence","owner":"services/governance_intelligence/benchmarking.py","console":[],"portal":[],"lifecycle":"future","nav_tier":"future","maturity":"latent"},
  {"capability":"Simulation","family":"intelligence","owner":"services/governance_intelligence/simulation.py","console":[],"portal":[],"lifecycle":"future","nav_tier":"future","maturity":"latent"},
  {"capability":"Replay","family":"trust_forensics","owner":"services/field_assessment/trust_replay.py","console":["/dashboard/control-tower"],"portal":["/reports"],"lifecycle":"growing","nav_tier":"specialist","maturity":"partial"},
  {"capability":"Counterfactual","family":"intelligence","owner":"services/governance_intelligence/counterfactual.py","console":[],"portal":[],"lifecycle":"future","nav_tier":"future","maturity":"latent"},
  {"capability":"Trust","family":"trust_center","owner":"services/trust_arc","console":["/dashboard/control-tower","/dashboard/provenance","/dashboard/forensics"],"portal":["/reports","/engagement/{engagementId}"],"lifecycle":"stable","nav_tier":"contextual","maturity":"functional"},
  {"capability":"Transparency","family":"trust_center","owner":"api/cgin_transparency.py","console":["/dashboard/provenance","/dashboard/decisions"],"portal":["/reports","/continuity"],"lifecycle":"stable","nav_tier":"contextual","maturity":"functional"},
  {"capability":"Privacy","family":"trust_policy","owner":"api/cgin_privacy.py","console":[],"portal":[],"lifecycle":"growing","nav_tier":"hidden","maturity":"partial"},
  {"capability":"Key Management","family":"admin_security","owner":"api/keys.py","console":["/dashboard/control-tower","/keys"],"portal":[],"lifecycle":"stable","nav_tier":"administrative","maturity":"functional"},
  {"capability":"Notifications","family":"cross_platform","owner":"services/notifications","console":["/dashboard"],"portal":[],"lifecycle":"growing","nav_tier":"contextual","maturity":"partial"},
  {"capability":"Administration","family":"platform_ops","owner":"api/admin.py","console":["/dashboard/control-tower","/admin/tenants","/dashboard/settings"],"portal":[],"lifecycle":"core","nav_tier":"administrative","maturity":"strong"},
  {"capability":"Providers","family":"ai_governance","owner":"api/ui_provider_governance.py","console":["/dashboard/providers"],"portal":[],"lifecycle":"growing","nav_tier":"specialist","maturity":"partial"},
  {"capability":"Identity","family":"tenant_access","owner":"api/admin_identity.py","console":["/admin/tenants","/login"],"portal":["/login","/accept-invite"],"lifecycle":"stable","nav_tier":"administrative","maturity":"functional"},
  {"capability":"Billing","family":"commercial_ops","owner":"api/billing.py","console":["/dashboard"],"portal":[],"lifecycle":"growing","nav_tier":"future","maturity":"partial_backend"},
  {"capability":"Workforce","family":"monitoring","owner":"api/workforce.py","console":["/dashboard/workforce"],"portal":[],"lifecycle":"growing","nav_tier":"specialist","maturity":"partial"},
  {"capability":"Evaluation Lab","family":"ai_quality","owner":"api/ui_evaluation.py","console":["/dashboard/evaluation"],"portal":[],"lifecycle":"stable","nav_tier":"specialist","maturity":"functional"},
  {"capability":"Control Tower","family":"platform_ops","owner":"api/control_tower.py","console":["/dashboard/control-tower"],"portal":[],"lifecycle":"core","nav_tier":"primary","maturity":"strong"},
  {"capability":"AI Workspace","family":"ai_assistance","owner":"api/ui_ai_console.py","console":["/dashboard/assistant"],"portal":["/assistant"],"lifecycle":"growing","nav_tier":"secondary","maturity":"functional"},
  {"capability":"Corpus","family":"knowledge","owner":"api/rag_corpus_console.py","console":["/dashboard/corpus","/dashboard/ingestion"],"portal":[],"lifecycle":"stable","nav_tier":"specialist","maturity":"functional"},
  {"capability":"Retrieval","family":"knowledge","owner":"api/rag_retrieval_policy.py","console":["/dashboard/retrieval"],"portal":["/assistant"],"lifecycle":"stable","nav_tier":"specialist","maturity":"functional"},
  {"capability":"Audit & Forensics","family":"trust_support","owner":"api/forensics.py","console":["/dashboard/forensics","/audit"],"portal":["/engagement/{engagementId}"],"lifecycle":"stable","nav_tier":"specialist","maturity":"functional"},
  {"capability":"Readiness","family":"posture","owner":"services/readiness","console":["/dashboard/readiness"],"portal":["/","/coverage","/continuity"],"lifecycle":"core","nav_tier":"primary","maturity":"strong"},
  {"capability":"Policies","family":"governance_control","owner":"api/control_registry.py","console":["/dashboard/policies"],"portal":[],"lifecycle":"growing","nav_tier":"specialist","maturity":"partial"},
  {"capability":"Clients","family":"tenancy","owner":"api/admin_identity.py","console":["/admin/tenants","/admin/tenants/{tenantId}"],"portal":[],"lifecycle":"stable","nav_tier":"administrative","maturity":"functional"}
]
```

### screen_registry

```json
[
  {"route":"/","app":"console","capability":"console_shell","classification":"hidden","lifecycle":"stable","recommendation":"keep"},
  {"route":"/login","app":"console","capability":"identity","classification":"hidden","lifecycle":"stable","recommendation":"keep"},
  {"route":"/dashboard","app":"console","capability":"control_tower","classification":"mission_critical","lifecycle":"core","recommendation":"keep"},
  {"route":"/dashboard/control-tower","app":"console","capability":"administration","classification":"mission_critical","lifecycle":"core","recommendation":"keep"},
  {"route":"/dashboard/assistant","app":"console","capability":"ai_workspace","classification":"high_value","lifecycle":"growing","recommendation":"keep"},
  {"route":"/dashboard/corpus","app":"console","capability":"corpus","classification":"specialist","lifecycle":"stable","recommendation":"contextual"},
  {"route":"/dashboard/retrieval","app":"console","capability":"retrieval","classification":"specialist","lifecycle":"stable","recommendation":"contextual"},
  {"route":"/dashboard/provenance","app":"console","capability":"decision_provenance","classification":"specialist","lifecycle":"stable","recommendation":"elevate"},
  {"route":"/dashboard/policies","app":"console","capability":"policies","classification":"placeholder","lifecycle":"growing","recommendation":"contextual"},
  {"route":"/dashboard/providers","app":"console","capability":"providers","classification":"placeholder","lifecycle":"growing","recommendation":"contextual"},
  {"route":"/dashboard/readiness","app":"console","capability":"readiness","classification":"mission_critical","lifecycle":"core","recommendation":"keep"},
  {"route":"/field-assessment","app":"console","capability":"field_assessment","classification":"mission_critical","lifecycle":"core","recommendation":"keep"},
  {"route":"/field-assessment/{engagementId}","app":"console","capability":"field_assessment","classification":"mission_critical","lifecycle":"core","recommendation":"keep"},
  {"route":"/dashboard/forensics","app":"console","capability":"audit_forensics","classification":"specialist","lifecycle":"stable","recommendation":"keep"},
  {"route":"/dashboard/decisions","app":"console","capability":"decision_provenance","classification":"specialist","lifecycle":"stable","recommendation":"contextual"},
  {"route":"/dashboard/evaluation","app":"console","capability":"evaluation_lab","classification":"specialist","lifecycle":"stable","recommendation":"contextual"},
  {"route":"/dashboard/workforce","app":"console","capability":"workforce","classification":"placeholder","lifecycle":"growing","recommendation":"contextual"},
  {"route":"/dashboard/settings","app":"console","capability":"administration","classification":"administrative","lifecycle":"stable","recommendation":"keep"},
  {"route":"/assessment","app":"console","capability":"assessment","classification":"legacy","lifecycle":"legacy","recommendation":"demote"},
  {"route":"/audit","app":"console","capability":"audit_forensics","classification":"duplicate","lifecycle":"stable","recommendation":"demote"},
  {"route":"/dashboard/alignment","app":"console","capability":"compliance_posture","classification":"hidden","lifecycle":"stable","recommendation":"contextual"},
  {"route":"/dashboard/ingestion","app":"console","capability":"corpus","classification":"specialist","lifecycle":"stable","recommendation":"contextual"},
  {"route":"/governance/topology","app":"console","capability":"governance","classification":"specialist","lifecycle":"growing","recommendation":"elevate"},
  {"route":"/keys","app":"console","capability":"key_management","classification":"duplicate","lifecycle":"stable","recommendation":"demote"},
  {"route":"/onboarding","app":"console","capability":"assessment","classification":"legacy","lifecycle":"legacy","recommendation":"demote"},
  {"route":"/products","app":"console","capability":"commercial_catalog","classification":"placeholder","lifecycle":"legacy","recommendation":"retire_candidate"},
  {"route":"/products/new","app":"console","capability":"commercial_catalog","classification":"placeholder","lifecycle":"legacy","recommendation":"retire_candidate"},
  {"route":"/products/{id}","app":"console","capability":"commercial_catalog","classification":"legacy","lifecycle":"legacy","recommendation":"retire_candidate"},
  {"route":"/reports/{reportId}","app":"console","capability":"reports","classification":"contextual","lifecycle":"stable","recommendation":"keep"},
  {"route":"/admin/tenants","app":"console","capability":"clients","classification":"administrative","lifecycle":"stable","recommendation":"keep"},
  {"route":"/admin/tenants/{tenantId}","app":"console","capability":"clients","classification":"administrative","lifecycle":"stable","recommendation":"keep"},
  {"route":"/","app":"portal","capability":"portal","classification":"mission_critical","lifecycle":"core","recommendation":"keep"},
  {"route":"/login","app":"portal","capability":"identity","classification":"hidden","lifecycle":"stable","recommendation":"keep"},
  {"route":"/accept-invite","app":"portal","capability":"identity","classification":"hidden","lifecycle":"stable","recommendation":"keep"},
  {"route":"/engagement","app":"portal","capability":"field_assessment","classification":"high_value","lifecycle":"stable","recommendation":"keep"},
  {"route":"/engagement/{engagementId}","app":"portal","capability":"field_assessment","classification":"high_value","lifecycle":"core","recommendation":"keep"},
  {"route":"/findings","app":"portal","capability":"remediation","classification":"mission_critical","lifecycle":"core","recommendation":"keep"},
  {"route":"/reports","app":"portal","capability":"reports","classification":"mission_critical","lifecycle":"core","recommendation":"keep"},
  {"route":"/coverage","app":"portal","capability":"readiness","classification":"high_value","lifecycle":"core","recommendation":"keep"},
  {"route":"/attestation","app":"portal","capability":"attestation","classification":"high_value","lifecycle":"growing","recommendation":"keep"},
  {"route":"/remediation","app":"portal","capability":"remediation","classification":"mission_critical","lifecycle":"core","recommendation":"keep"},
  {"route":"/continuity","app":"portal","capability":"readiness","classification":"high_value","lifecycle":"growing","recommendation":"keep"},
  {"route":"/assistant","app":"portal","capability":"ai_workspace","classification":"contextual","lifecycle":"growing","recommendation":"contextual"}
]
```

### action_registry

```json
[
  {"action":"create_engagement","screen":"/field-assessment","route":"/field-assessment/engagements","method":"POST","mutates":true,"audit_expected":true,"risk":"medium"},
  {"action":"transition_engagement","screen":"/field-assessment/{engagementId}","route":"/field-assessment/engagements/{id}/status","method":"PATCH","mutates":true,"audit_expected":true,"risk":"high"},
  {"action":"register_document","screen":"workspace_documents","route":"/field-assessment/engagements/{id}/document-analyses","method":"POST","mutates":true,"audit_expected":true,"risk":"medium"},
  {"action":"initiate_scan","screen":"workspace_scans","route":"/field-assessment/engagements/{id}/connector-runs/*","method":"POST","mutates":true,"audit_expected":true,"risk":"high"},
  {"action":"capture_observation","screen":"workspace_observations","route":"/field-assessment/engagements/{id}/observations","method":"POST","mutates":true,"audit_expected":true,"risk":"medium"},
  {"action":"update_observation","screen":"workspace_observations","route":"/field-assessment/engagements/{id}/observations/{observationId}","method":"PATCH","mutates":true,"audit_expected":true,"risk":"medium"},
  {"action":"create_evidence_link","screen":"workspace_evidence","route":"/field-assessment/engagements/{id}/evidence-links","method":"POST","mutates":true,"audit_expected":true,"risk":"medium"},
  {"action":"generate_report","screen":"workspace_reports","route":"/field-assessment/engagements/{id}/reports","method":"POST","mutates":true,"audit_expected":true,"risk":"high"},
  {"action":"export_report","screen":"workspace_reports_or_portal_reports","route":"/field-assessment/engagements/{id}/reports/{version}/export","method":"GET","mutates":false,"audit_expected":false,"risk":"medium"},
  {"action":"verify_report","screen":"workspace_reports_or_portal_reports","route":"/field-assessment/engagements/{id}/reports/{version}/verify","method":"POST","mutates":false,"audit_expected":true,"risk":"low"},
  {"action":"qa_approve_report","screen":"workspace_report_history","route":"/field-assessment/engagements/{id}/reports/{reportId}/qa-approve","method":"POST","mutates":true,"audit_expected":true,"risk":"high"},
  {"action":"submit_attestation","screen":"/attestation","route":"/governance/assets/{assetId}/attestations","method":"POST","mutates":true,"audit_expected":true,"risk":"medium"},
  {"action":"update_finding_status","screen":"/remediation","route":"/field-assessment/engagements/{id}/findings/{findingId}","method":"PATCH","mutates":true,"audit_expected":true,"risk":"high"},
  {"action":"create_client","screen":"/admin/tenants","route":"/admin/tenants","method":"POST","mutates":true,"audit_expected":true,"risk":"high"},
  {"action":"invite_user","screen":"/admin/tenants/{tenantId}","route":"/admin/identity/tenants/{tenantId}/invitations","method":"POST","mutates":true,"audit_expected":true,"risk":"medium"},
  {"action":"rotate_key","screen":"/dashboard/control-tower","route":"/admin/keys/{key_prefix}/rotate","method":"POST","mutates":true,"audit_expected":true,"risk":"high"},
  {"action":"revoke_key","screen":"/dashboard/control-tower","route":"/admin/keys/{key_prefix}/revoke","method":"POST","mutates":true,"audit_expected":true,"risk":"high"},
  {"action":"run_evaluation","screen":"/dashboard/evaluation","route":"/ui/evaluation/*","method":"GET","mutates":false,"audit_expected":false,"risk":"medium"}
]
```

### state_ownership

```json
[
  {"state":"active_engagement_route_param","owner":"router","storage":"url_path","risk":"low"},
  {"state":"portal_engagement_context","owner":"client_browser","storage":"localStorage:fg_portal_eid","risk":"high"},
  {"state":"portal_session","owner":"server_session","storage":"cookie+grant_session","risk":"medium"},
  {"state":"console_session","owner":"auth0_nextauth","storage":"session_cookie","risk":"medium"},
  {"state":"legacy_assessment_domain_scores","owner":"legacy_assessment_ui","storage":"sessionStorage:fg_last_assessment_scores","risk":"high"},
  {"state":"selected_report_version","owner":"workspace_page","storage":"react_state","risk":"low"},
  {"state":"selected_tenant","owner":"admin_routes","storage":"route_context+api_response","risk":"medium"},
  {"state":"notification_badge","owner":"ui_shell","storage":"hardcoded_state","risk":"medium"},
  {"state":"attestation_draft","owner":"portal_browser","storage":"IndexedDB:fg_portal_drafts","risk":"low_medium"},
  {"state":"theme_preference","owner":"client_browser","storage":"localStorage:fg-theme","risk":"low"},
  {"state":"verification_bundle","owner":"verification_authority","storage":"api+react_state","risk":"low"},
  {"state":"inventory_artifacts","owner":"artifact_pipeline","storage":"repo_artifacts_files","risk":"low"}
]
```

### navigation_classification

```json
[
  {"label":"Command Center","route":"/dashboard","tier":"primary","future_group":"Executive Command Center"},
  {"label":"Control Tower","route":"/dashboard/control-tower","tier":"primary","future_group":"Admin & Platform Ops"},
  {"label":"AI Workspace","route":"/dashboard/assistant","tier":"secondary","future_group":"Operations Workspace"},
  {"label":"Corpus","route":"/dashboard/corpus","tier":"specialist","future_group":"Operations Workspace"},
  {"label":"Retrieval","route":"/dashboard/retrieval","tier":"specialist","future_group":"Governance & Intelligence Workspace"},
  {"label":"Provenance","route":"/dashboard/provenance","tier":"specialist","future_group":"Trust Center"},
  {"label":"Policies","route":"/dashboard/policies","tier":"secondary","future_group":"Governance & Intelligence Workspace"},
  {"label":"Providers","route":"/dashboard/providers","tier":"specialist","future_group":"Governance & Intelligence Workspace"},
  {"label":"Readiness","route":"/dashboard/readiness","tier":"primary","future_group":"Executive Command Center"},
  {"label":"Field Assessments","route":"/field-assessment","tier":"primary","future_group":"Operations Workspace"},
  {"label":"Audit & Forensics","route":"/dashboard/forensics","tier":"specialist","future_group":"Trust Center"},
  {"label":"Decisions","route":"/dashboard/decisions","tier":"specialist","future_group":"Trust Center"},
  {"label":"Evaluation Lab","route":"/dashboard/evaluation","tier":"specialist","future_group":"Governance & Intelligence Workspace"},
  {"label":"Workforce Intel","route":"/dashboard/workforce","tier":"specialist","future_group":"Operations Workspace"},
  {"label":"Clients","route":"/admin/tenants","tier":"administrative","future_group":"Admin & Platform Ops"},
  {"label":"Settings","route":"/dashboard/settings","tier":"administrative","future_group":"Admin & Platform Ops"},
  {"label":"Assessments","route":"/assessment","tier":"legacy","future_group":"Legacy / Commercial"},
  {"label":"Overview","route":"/","tier":"primary","future_group":"Portal Experience"},
  {"label":"Assessment","route":"/engagement","tier":"secondary","future_group":"Portal Experience"},
  {"label":"Findings","route":"/findings","tier":"primary","future_group":"Portal Experience"},
  {"label":"Reports","route":"/reports","tier":"primary","future_group":"Portal Experience"},
  {"label":"Coverage","route":"/coverage","tier":"secondary","future_group":"Portal Experience"},
  {"label":"Attestation","route":"/attestation","tier":"secondary","future_group":"Portal Experience"},
  {"label":"Remediation","route":"/remediation","tier":"primary","future_group":"Portal Experience"},
  {"label":"Continuity","route":"/continuity","tier":"secondary","future_group":"Portal Experience"},
  {"label":"AI Assistant","route":"/assistant","tier":"contextual","future_group":"Portal Experience"}
]
```

### module_lifecycle

```json
[
  {"module":"Field Assessment","classification":"core","risk":"low","migration_note":"preserve workflow and routes"},
  {"module":"Reports","classification":"core","risk":"low","migration_note":"preserve export and verify flows"},
  {"module":"Portal core screens","classification":"core","risk":"low","migration_note":"preserve customer routes"},
  {"module":"Readiness","classification":"core","risk":"medium","migration_note":"converge source calculations carefully"},
  {"module":"Control Tower","classification":"stable","risk":"low","migration_note":"preserve admin actions"},
  {"module":"Evidence / Verification","classification":"stable","risk":"medium","migration_note":"elevate discoverability only"},
  {"module":"Provenance / Forensics / Decisions","classification":"growing","risk":"medium","migration_note":"group under Trust Center"},
  {"module":"AI Workspace / Corpus / Retrieval","classification":"growing","risk":"medium","migration_note":"contextualize by persona"},
  {"module":"Governance Topology","classification":"growing","risk":"medium","migration_note":"specialist home in 18.6.4"},
  {"module":"Governance Intelligence","classification":"growing","risk":"high","migration_note":"create future workspace before UI expansion"},
  {"module":"Governance Orchestration","classification":"growing","risk":"high","migration_note":"keep backend-only until explicit UX home"},
  {"module":"Governance Learning","classification":"future","risk":"medium","migration_note":"no UI invention in phase 0"},
  {"module":"Governance Optimization","classification":"future","risk":"medium","migration_note":"same as learning"},
  {"module":"Benchmarking","classification":"future","risk":"medium","migration_note":"expose only after KPI ownership clarified"},
  {"module":"Simulation","classification":"future","risk":"medium","migration_note":"ship with intelligence workspace"},
  {"module":"Counterfactual","classification":"future","risk":"medium","migration_note":"ship with intelligence workspace"},
  {"module":"Providers","classification":"growing","risk":"medium","migration_note":"reduce prominence, keep route"},
  {"module":"Workforce","classification":"growing","risk":"medium","migration_note":"specialist classification"},
  {"module":"Billing","classification":"growing","risk":"medium","migration_note":"defer UI maturation to 18.6.7"},
  {"module":"/assessment","classification":"legacy","risk":"medium","migration_note":"retain route, demote later"},
  {"module":"/onboarding","classification":"legacy","risk":"medium","migration_note":"retain route, contextualize"},
  {"module":"/products*","classification":"retire_candidate","risk":"medium","migration_note":"retain until explicit retirement"},
  {"module":"/audit","classification":"duplicate","risk":"low","migration_note":"keep reachable while forensics becomes canonical"},
  {"module":"/keys","classification":"duplicate","risk":"low","migration_note":"fold meaning into Control Tower"},
  {"module":"apps/console/console shell tree","classification":"duplicate","risk":"high","migration_note":"clean up in a separate safe PR"}
]
```

### technical_debt

```json
[
  {"rank":1,"finding":"duplicate console shell tree","priority":"P0","target_pr":"18.6.1"},
  {"rank":2,"finding":"legacy /assessment sessionStorage score bridge","priority":"P0","target_pr":"18.6.1"},
  {"rank":3,"finding":"legacy /onboarding overlaps field assessment","priority":"P1","target_pr":"18.6.1"},
  {"rank":4,"finding":"/products* orphaned commercial surface","priority":"P1","target_pr":"18.6.7"},
  {"rank":5,"finding":"portal localStorage engagement context","priority":"P0","target_pr":"18.6.6"},
  {"rank":6,"finding":"portal read-only label vs write-capable actions","priority":"P0","target_pr":"18.6.6"},
  {"rank":7,"finding":"placeholder surfaces in nav","priority":"P1","target_pr":"18.6.1"},
  {"rank":8,"finding":"backend-only authorities without UI homes","priority":"P1","target_pr":"18.6.4"},
  {"rank":9,"finding":"trust/provenance underexposure","priority":"P1","target_pr":"18.6.5"},
  {"rank":10,"finding":"intelligence/replay/simulation hiddenness","priority":"P1","target_pr":"18.6.4"},
  {"rank":11,"finding":"billing/subscription UI maturity gap","priority":"P1","target_pr":"18.6.7"},
  {"rank":12,"finding":"/audit duplicates /dashboard/forensics","priority":"P2","target_pr":"18.6.5"},
  {"rank":13,"finding":"/keys duplicates Control Tower","priority":"P2","target_pr":"18.6.1"},
  {"rank":14,"finding":"portal grant and access-code security model debt","priority":"P0","target_pr":"follow-on security PR"}
]
```
