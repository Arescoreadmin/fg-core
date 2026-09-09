# FrostGate AI Workspace Canonical Product and Engineering Specification

**Document status:** CANONICAL TARGET SPECIFICATION WITH VERIFIED CURRENT-STATE BASELINE  
**Audit basis date:** 2026-09-08  
**Repository:** `fg-core`  
**Baseline branch:** `main`  
**Baseline SHA:** `2f1301db461e11e41f013c2006686ba52b6399f8`  
**Company principle:** Trust, but Verify.  
**Primary owner:** FrostGate AI Workspace authority  
**Review owners:** Product, Security, Privacy, Compliance, Platform Engineering  

---

## Contents

1. [Purpose and Authority](#1-purpose-and-authority)
2. [Executive Product Definition](#2-executive-product-definition)
3. [Goals, Non-Goals, and Success Criteria](#3-goals-non-goals-and-success-criteria)
4. [Users and Authority](#4-users-and-authority)
5. [Verified Current Repository Reality](#5-verified-current-repository-reality)
6. [Hard Invariants](#6-hard-invariants)
7. [Target Architecture](#7-target-architecture)
8. [Canonical Operation Lifecycle](#8-canonical-operation-lifecycle)
9. [Processing Modes](#9-processing-modes)
10. [Confidential Spreadsheet Analysis](#10-confidential-spreadsheet-analysis)
11. [Data Classification and DLP](#11-data-classification-and-dlp)
12. [Industry Profiles](#12-industry-profiles)
13. [Hybrid AI and Provider Routing](#13-hybrid-ai-and-provider-routing)
14. [Secure Egress Enforcement](#14-secure-egress-enforcement)
15. [RAG, Knowledge, and Provenance](#15-rag-knowledge-and-provenance)
16. [Identity, Authorization, and Purpose](#16-identity-authorization-and-purpose)
17. [Canonical Data Model](#17-canonical-data-model)
18. [API and Contract Design](#18-api-and-contract-design)
19. [Compliance and AI Usage Dashboard](#19-compliance-and-ai-usage-dashboard)
20. [Workspace User Experience](#20-workspace-user-experience)
21. [Security and Privacy Threat Model](#21-security-and-privacy-threat-model)
22. [Privacy, Logging, Retention, and Deletion](#22-privacy-logging-retention-and-deletion)
23. [Deployment Models and Trust Zones](#23-deployment-models-and-trust-zones)
24. [Resilience and Operations](#24-resilience-and-operations)
25. [Observability and Evidence](#25-observability-and-evidence)
26. [Testing Strategy](#26-testing-strategy)
27. [Production-Proof Gates](#27-production-proof-gates)
28. [Dependency-Aware PR Sequence](#28-dependency-aware-pr-sequence)
29. [Commercial Packaging, ROI, and MRR](#29-commercial-packaging-roi-and-mrr)
30. [Market Position and Competitive Boundaries](#30-market-position-and-competitive-boundaries)
31. [Product, Governance, and Business Metrics](#31-product-governance-and-business-metrics)
32. [Governance and Change Control](#32-governance-and-change-control)
33. [Decisions and Open Questions](#33-decisions-and-open-questions)
34. [Repository Ownership and Maintenance Map](#34-repository-ownership-and-maintenance-map)
35. [External Control References](#35-external-control-references)
36. [Definitions of Done](#36-definitions-of-done)
37. [Final Build Direction](#37-final-build-direction)

---

## 1. Purpose and Authority

This document is the durable product, architecture, security, data, UX, testing,
deployment, and delivery specification for the FrostGate AI Workspace.

It exists so future work starts from one verified reference instead of repeatedly
reconstructing the Workspace from source files, historical PR notes, roadmap claims,
and partial documentation.

This document does four things:

1. Records what the repository actually implements at the baseline SHA.
2. Defines the intended customer product without requiring a platform rewrite.
3. Establishes hard invariants that implementation work must preserve.
4. Provides a dependency-ordered path from the current code to a supportable,
   recurring-revenue product.

Where this document conflicts with an older AI Workspace roadmap or descriptive
document, this document controls target design. Runtime code and tests still control
claims about current behavior.

This specification does not itself prove implementation. Every target capability
must be implemented, tested, and production-proven before its status changes.

### 1.1 Normative language

The terms `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are normative.

### 1.2 Truth labels

Every implementation statement in this document uses one of these labels:

| Label | Meaning |
| --- | --- |
| `CURRENT` | Proven to exist in the repository at the baseline SHA |
| `PARTIAL` | Substantial implementation exists, but the complete customer operation is not proven |
| `TARGET` | Required design that is not yet fully implemented |
| `DEFERRED` | Intentionally excluded from the first production release |
| `PROHIBITED` | Behavior that must not be implemented or enabled |
| `NEEDS PROOF` | Code exists, but production behavior has not been demonstrated |

Documentation, tests, route registration, and successful HTTP responses are evidence,
but none alone proves a complete business operation.

---

## 2. Executive Product Definition

FrostGate AI Workspace is a managed, governed AI environment that allows organizations
to use multiple AI models and organizational data without requiring the customer to
assemble an AI security and governance program from independent components.

The customer outcome is:

> Use AI without building an AI security program first. FrostGate provides the
> governed workspace, private processing, data controls, and proof.

FrostGate does not remove required controls. It productizes, operates, verifies, and
explains them.

The Workspace combines:

- canonical identity and tenant authority;
- data-source and resource authorization;
- content classification;
- industry and tenant policy;
- local deterministic analysis;
- retrieval-augmented generation;
- local/private and external model routing;
- complete-envelope DLP;
- provider eligibility and contractual governance;
- output inspection;
- immutable activity evidence;
- a compliance and usage dashboard; and
- signed release receipts.

### 2.1 Category

The preferred category is:

> Managed Governed AI Workspace

The broader strategic category is:

> Independent AI Governance Assurance

### 2.2 Product promise

The defensible target promise is:

> FrostGate applies fail-closed, tenant- and industry-specific release policies to
> every governed AI operation and produces auditable evidence of what was allowed,
> redacted, routed, reviewed, or blocked.

FrostGate MUST NOT promise that legal or regulatory violations are impossible. No
DLP system can eliminate endpoint misuse, authorized-user misuse, screenshots,
misclassification, compromised administrators, kernel compromise, or incorrect
customer policy decisions.

### 2.3 Primary customer

The initial target customer is a regulated or confidentiality-sensitive organization
with approximately 200 to 2,000 employees that:

- wants employees to use AI now;
- cannot justify a large internal AI governance engineering program;
- handles healthcare, financial, legal, government, or proprietary information;
- is concerned about unmanaged ChatGPT, Claude, Copilot, or other AI usage;
- needs evidence for executives, customers, auditors, insurers, or regulators; and
- prefers a managed outcome over another toolkit to configure.

### 2.4 Initial sellable wedge

The first exceptional workflow MUST be:

```text
Upload an authorized document or spreadsheet
-> classify it locally
-> analyze it in the permitted execution zone
-> disclose only policy-approved information
-> generate an evidence-backed answer or report
-> issue a signed release receipt
```

The initial product is not a general replacement for ChatGPT, Microsoft 365, document
management, spreadsheet software, SIEM, DLP, or GRC platforms.

---

## 3. Goals, Non-Goals, and Success Criteria

### 3.1 Product goals

The Workspace MUST:

1. Be useful to ordinary business users without requiring security expertise.
2. Preserve tenant, identity, matter, engagement, and resource boundaries.
3. Keep raw restricted information local when policy requires it.
4. Route work to approved external or private models based on verified policy.
5. Prevent silent fallback to a less-protected provider or processing mode.
6. Inspect the complete provider-bound envelope and returned output.
7. Provide grounded, provenance-aware answers when organizational evidence is used.
8. Show users where processing occurred and what protection mode was applied.
9. Show compliance officers who used AI, what was stopped, and why.
10. Create evidence that can be independently investigated and exported.
11. Integrate customer labels and controls instead of demanding replacement.
12. Support managed recurring governance after the initial assessment.

### 3.2 Engineering goals

The implementation SHOULD:

- extend existing Python domain services and TypeScript applications;
- introduce narrow new authorities only where current authority is absent;
- use a provider-neutral contract;
- make a future Go enforcement gateway possible without rewriting domain logic;
- use deterministic tools for deterministic operations;
- keep model implementations replaceable;
- preserve stable reason codes and audit contracts; and
- avoid duplicating identity, tenant, evidence, and governance authorities.

### 3.3 Non-goals for the first release

The first production release will not:

- train a FrostGate foundation model;
- replace Microsoft Purview or customer DLP products;
- provide classified-data processing;
- support autonomous unrestricted agents;
- permit arbitrary model-selected tools;
- execute spreadsheet macros or external workbook links;
- guarantee compliance by product use alone;
- support every industry profile simultaneously;
- replace the customer's identity provider;
- expose raw prompts to broad administrative audiences; or
- move FrostGate Core wholesale from Python to Go.

### 3.4 Product success criteria

The first production version is successful when a customer can, without engineering
intervention:

1. sign in through the configured identity authority;
2. upload an approved document or spreadsheet;
3. see its classification and permitted processing modes;
4. ask a useful business question;
5. receive a grounded result or an explicit safe denial;
6. see whether data remained local or was externally processed;
7. inspect the release receipt;
8. have a compliance officer find the event in the dashboard; and
9. reproduce the same enforcement decision from the recorded policy and hashes.

---

## 4. Users and Authority

| Persona | Primary need | Permitted authority |
| --- | --- | --- |
| Workforce user | Safely analyze approved work data | Use allowed Workspace capabilities and view own events |
| Customer administrator | Configure access and approved use cases | Manage tenant users and approved Workspace settings |
| Data owner | Control use of a corpus, document, workbook, or matter | Approve resource access and permitted processing purposes |
| Security officer | Investigate AI and DLP activity | View security events, alerts, redacted details, and exceptions |
| Privacy officer | Govern sensitive data and retention | View classifications, retention, legal holds, and privacy events |
| Compliance officer | Verify policies operated | View control evidence, exceptions, mappings, and exports |
| Legal officer | Control privilege and matter restrictions | Approve legal profile, matter boundaries, and exceptional release |
| AI administrator | Govern models and providers | Manage provider eligibility, models, tools, and quotas |
| Executive | Understand adoption and risk | View aggregated posture, trends, unresolved exceptions, and value |
| FrostGate operator | Operate service without customer-content access | View service health and safe operational metadata |
| Break-glass operator | Resolve exceptional incidents | Time-bound, dual-approved, fully audited access only |

Authentication does not imply authorization. Resource access does not imply authority
to disclose that resource to a model. Model access does not imply authority to use
every tool or data source.

---

## 5. Verified Current Repository Reality

### 5.1 Current component ledger

| Component | Status | Repository evidence | Current conclusion |
| --- | --- | --- | --- |
| Console AI Workspace page | `CURRENT/PARTIAL` | `apps/console/app/dashboard/assistant/page.tsx` | Functional governed chat UI; no upload or processing-mode selection |
| Portal assistant | `CURRENT/PARTIAL` | `apps/portal/app/assistant/page.tsx`, navigation registry | Customer-facing assistant exists and shares the UI AI route |
| UI AI route | `CURRENT/PARTIAL` | `api/ui_ai_console.py::ai_chat` | Tenant, capability, device, quota, provider, PHI, BAA, and output checks exist |
| AI inference route | `CURRENT/PARTIAL` | `api/ai_plane_extension.py::ai_infer` | Separate RAG-aware inference path exists |
| Provider dispatch | `CURRENT` | `services/ai/dispatch.py::call_provider` | Explicit provider call, no silent fallback |
| Anthropic provider | `CURRENT` | `services/ai/providers/anthropic_provider.py` | External call implementation exists |
| Azure OpenAI provider | `CURRENT` | `services/ai/providers/azure_openai_provider.py` | External call implementation exists |
| Direct OpenAI provider | `ABSENT` | `_KNOWN_PROVIDERS` in `services/ai/dispatch.py` | Not currently implemented; Azure OpenAI is distinct |
| Simulated provider | `DEV/TEST` | `services/ai/providers/simulated_provider.py` | Blocked by default in production-like environments |
| Provider allowlist/routing | `CURRENT/PARTIAL` | `services/ai/policy.py`, `services/ai/routing.py` | Tenant policy and PHI routing exist; data-class routing does not |
| Provider governance UI | `CURRENT/PARTIAL` | `api/ui_provider_governance.py`, Console providers page | Operational/governance and BAA states visible; provider posture schema is incomplete |
| PHI classifier | `CURRENT/PARTIAL` | `services/phi_classifier/classifier.py` | Deterministic SSN, MRN, email, phone, DOB, labeled-name rules; not complete PHI detection |
| PHI minimization | `CURRENT/PARTIAL` | `services/phi_classifier/minimizer.py` | Supported detected spans replaced with stable placeholders |
| BAA gate | `CURRENT` | `services/provider_baa/gate.py` | Fail-closed route gate for detected PHI |
| Generic input DLP | `PARTIAL` | `services/ai_plane_extension/policy_engine.py`, `_contains_pii` in UI route | Narrow regex and deny-term checks only |
| Complete-envelope DLP | `ABSENT` | UI and inference traces | User message is checked more completely than system prompt, context, tools, and attachments |
| Output DLP | `PARTIAL` | UI `_contains_pii`, extension `evaluate_output` | Narrow patterns; no industry-aware complete output inspection |
| Persisted lexical RAG | `CURRENT` | `services/ai/rag_context.py`, `api/rag_retrieval.py` | Tenant-aware lexical retrieval and context construction exist |
| Visible Workspace RAG | `ABSENT` | `api/ui_ai_console.py` states UI path does not execute retrieval | Console copy and operator guide overstate current runtime |
| Semantic/hybrid retrieval | `PARTIAL` | `api/rag_semantic_retrieval.py`, `api/rag_hybrid_retrieval.py` | Algorithms exist; production embedding provider does not |
| Production embeddings | `ABSENT` | `api/embeddings/providers.py`, `api/embeddings/stub_provider.py` | Stub vectors are explicitly not semantically meaningful |
| Document ingestion | `CURRENT/PARTIAL` | `api/rag_corpus_ingestion.py` | TXT, Markdown, PDF, DOCX supported with quarantine handling |
| Spreadsheet ingestion | `ABSENT` | Supported content types in ingestion route | CSV/XLSX analysis is not implemented |
| Prompt-injection safety | `CURRENT/PARTIAL` | `api/rag/safety.py`, `api/rag/answering.py` | Safety logic exists, but is not proven in the active external-provider RAG dispatch path |
| Provenance validation | `CURRENT/PARTIAL` | `services/ai/provenance.py`, `services/ai/response_validation.py` | Citation and grounding enforcement exists on the AI inference path |
| Usage metering/quotas | `CURRENT` | `ai_token_usage`, `ai_quota_daily`, UI route | Atomic quota enforcement and provider usage records exist |
| Raw query log | `CURRENT/RISK` | `migrations/postgres/0069_ai_query_log.sql`, `_log_query` | Stores raw query, response, and email; no RLS or retention migration found |
| AI activity ledger | `ABSENT` | No canonical complete event authority | Existing usage, audit, inference, and raw query records are fragmented |
| AI compliance dashboard | `ABSENT/PARTIAL DATA` | Usage endpoint and workforce queries only | No complete DLP, release, and AI-use dashboard |
| Local/private LLM lane | `ABSENT` | No local inference provider in dispatch | Required for semantic analysis of data prohibited from external processing |
| Local analytical sandbox | `ABSENT` | No Workspace spreadsheet execution path | Required for protected spreadsheet analysis |
| Secure egress gateway | `ABSENT` | Provider adapters call external APIs directly | Current Go sidecar only reports health/status |
| Go supervisor sidecar | `CURRENT/NON-AUTHORITY` | `supervisor-sidecar/main.go` | Not a DLP or provider-enforcement boundary |
| Industry policy profiles | `ABSENT` | Only default/example AI policies exist | `legal_grade` and `finance_grade` are review modes, not DLP profiles |
| Signed release receipt | `ABSENT` | Request/response hashes exist but no release artifact | Target capability |

### 5.2 Current externally relevant routes

| Route | Consumer | Status | Notes |
| --- | --- | --- | --- |
| `GET /ui/ai` | Direct/basic HTML | `CURRENT` | Minimal embedded UI, separate from primary Console page |
| `GET /ui/ai/experience` | Console/Portal setup | `CURRENT` | Resolves experience, policy, theme, providers, quotas, and device |
| `GET /ui/ai/usage` | Administrative UI | `CURRENT/PARTIAL` | Returns token usage, not complete AI governance activity |
| `POST /ui/ai/chat` | Console and Portal BFF | `CURRENT/PARTIAL` | Visible Workspace execution path; no RAG retrieval |
| `GET /admin/devices` | Operator | `CURRENT` | Lists tenant device state |
| `POST /admin/devices/{id}/enable` | Operator | `CURRENT` | Audited device enable |
| `POST /admin/devices/{id}/disable` | Operator | `CURRENT` | Audited device disable |
| `POST /ui/devices/{id}/enable` | UI-authorized caller | `CURRENT` | Device state operation |
| `POST /ui/devices/{id}/disable` | UI-authorized caller | `CURRENT` | Device state operation |
| `POST /ai/infer` | API clients/internal consumers | `CURRENT/PARTIAL` | RAG-aware evidence response path |
| `POST /ai/chat` | API clients/internal consumers | `CURRENT/PARTIAL` | Separate AI-plane chat contract |
| `GET /ai-plane/policies` | Operator/API | `CURRENT` | Tenant AI policy read |
| `POST /ai-plane/policies` | Administrator | `CURRENT` | Tenant AI policy update |
| `GET /ai-plane/inference` | Operator/API | `CURRENT` | Tenant inference history |
| `POST /rag/upload` | Corpus/ingestion UI | `CURRENT/PARTIAL` | TXT, Markdown, PDF, DOCX only |
| `GET /rag/uploads` | Ingestion UI | `CURRENT` | Tenant-scoped ingestion history |
| `GET/PUT /rag/retrieval-policy` | Retrieval UI | `CURRENT` | Tenant retrieval policy |
| `GET /rag/corpora` | Retrieval UI | `CURRENT` | Corpus policy options |
| `GET /rag/corpora/{id}` | Corpus UI | `CURRENT` | Corpus detail |
| `GET /rag/corpora/{id}/documents` | Corpus UI | `CURRENT` | Document list |
| `GET /rag/documents/{id}` | Corpus UI | `CURRENT` | Document detail |
| `GET /ui/provider/governance*` | Provider UI | `CURRENT/PARTIAL` | Provider governance, routing, and failover views |

### 5.3 Current persistence authorities

| Table/domain | Purpose | Isolation status | Target disposition |
| --- | --- | --- | --- |
| `tenant_ai_policy` | Tenant AI-plane policy | RLS added by later hardening migration | Extend or replace through versioned canonical Workspace policy |
| `ai_inference_records` | AI-plane inference history | RLS present | Preserve; link to canonical operation/receipt IDs |
| `ai_policy_violations` | AI-plane violations | RLS present | Preserve or project from canonical activity ledger |
| `ai_device_registry` | Tenant device enablement | RLS + FORCE RLS | Preserve until replaced by canonical device trust authority |
| `ai_token_usage` | Provider/model usage | RLS + FORCE RLS | Preserve as metering projection, not compliance evidence authority |
| `ai_quota_daily` | Atomic quota state | RLS + FORCE RLS | Preserve |
| `provider_baa_records` | Tenant/provider BAA state | RLS + FORCE RLS | Preserve and expand provider posture contract |
| `provider_governance_records` | Tenant provider governance | RLS + FORCE RLS | Preserve and expand |
| `rag_corpora`, `rag_documents`, `rag_chunks` | Tenant knowledge corpus | RLS hardening exists | Preserve; add classification and access metadata |
| `embedding_vectors` | Tenant embeddings | Tenant-scoped hardening exists | Preserve; require production-safe local/private provider |
| `tenant_retrieval_policies` | Retrieval behavior | RLS hardening exists | Preserve; merge into effective Workspace policy resolution |
| `ai_query_log` | Raw query/response workforce analytics | No RLS/retention migration found | Do not use as canonical authority; migrate, minimize, restrict, and retire raw default storage |

### 5.4 Proven contradictions

| ID | Contradiction | Evidence | Required resolution |
| --- | --- | --- | --- |
| `AW-C-001` | Operator guide says visible Workspace uses classification, OPA, RAG, routing, and provenance | `docs/operators/console_user_guide.md` AI Workspace section | Correct docs immediately when implementation PR begins; until then label no-context behavior honestly |
| `AW-C-002` | Visible route explicitly states it does not execute RAG | `api/ui_ai_console.py` near the retrieval-policy gate | Route Workspace through canonical RAG-aware orchestrator |
| `AW-C-003` | Console renders rich RAG/provenance UI while backend always reports no RAG on this path | Console assistant page and UI response provenance | Populate from real retrieval or present a truthful no-retrieval mode |
| `AW-C-004` | Engagement system prompt may contain client/finding context but classification checks the user message | `_build_engagement_system_prompt`, BAA/DLP checks, provider dispatch in `api/ui_ai_console.py` | Classify the complete provider envelope after all context assembly |
| `AW-C-005` | Generic DLP checks query before RAG assembly; post-assembly check is PHI-specific | `AIPlaneService.infer` | Apply all classifiers and policy to the final outbound envelope |
| `AW-C-006` | `legal_grade` and `finance_grade` sound like policy profiles but primarily alter uncertainty/review thresholds | `services/ai_plane_extension/service.py` | Rename or document as analysis modes; implement real industry profiles separately |
| `AW-C-007` | AI audit guidance forbids raw prompts, but `ai_query_log` stores raw prompts/responses | AI audit docs and migration `0069` | Separate privacy-safe compliance events from optional quarantined content |
| `AW-C-008` | Semantic/hybrid retrieval is documented as production-safe infrastructure but only a non-semantic stub provider is present | semantic retrieval docs and embedding provider modules | Add approved local/private embedding provider and production proof |

---

## 6. Hard Invariants

These invariants are release-blocking. No roadmap pressure, customer urgency, or
fallback behavior may weaken them.

### 6.1 Identity and tenant invariants

1. External identity providers authenticate; FrostGate authorizes.
2. The canonical principal and tenant come from trusted gateway context, not payload.
3. Every tenant-owned read, write, cache key, object key, vector, job, and event carries
   immutable `tenant_id`.
4. Matter, workspace, engagement, and resource boundaries narrow tenant authority;
   they never widen it.
5. Cross-tenant ambiguity fails closed and emits a safe audit event.
6. Portal authority is always a strict subset of tenant authority.
7. A model never receives more resource authority than the initiating actor.

### 6.2 Data-release invariants

1. Resource access does not imply external-disclosure authority.
2. Every provider-bound byte MUST traverse the canonical egress enforcement boundary.
3. The complete envelope MUST be classified after context assembly and before TLS.
4. The complete envelope includes user input, system instructions, history, RAG,
   attachments, metadata, tool arguments, tool results, and derived values.
5. Output MUST be reclassified before display, export, persistence, or tool use.
6. Unknown classification in a regulated profile defaults to block or human review.
7. Deny overrides allow at every policy layer.
8. Provider failure never causes silent fallback to another provider or execution zone.
9. Private/local mode failure never falls back to external processing.
10. External processing is impossible when policy requires local-only operation.

### 6.3 Evidence invariants

1. Every terminal operation creates an immutable activity event.
2. Every external release creates a release receipt.
3. Every block records the rule and safe classification metadata without raw content.
4. Request, policy, model, source, and output versions are reproducible or explicitly
   marked unavailable.
5. Operational telemetry is not compliance evidence.
6. Compliance events are not sampled.
7. Raw prompts are not retained by default.
8. Break-glass access is time-bound, dual-approved, justified, and itself immutable.

### 6.4 AI and retrieval invariants

1. Models advise; deterministic FrostGate policy decides.
2. An LLM is never the sole authority for DLP classification or authorization.
3. Retrieved content is data, not trusted instruction.
4. Retrieved content cannot override system, policy, tool, or authorization boundaries.
5. Citations must resolve to context retrieved and included for that operation.
6. No evidence is better than fabricated evidence; insufficient support returns a
   no-answer or review state.
7. Embeddings inherit the source tenant, classification, retention, and deletion rules.
8. Model and embedding changes require evaluation against a versioned golden corpus.

---

## 7. Target Architecture

### 7.1 Logical architecture

```text
Browser
  -> Console or Portal BFF
  -> Admin-Gateway human authentication boundary
  -> Core Workspace API
       -> canonical actor + tenant + resource authorization
       -> operation orchestrator
            -> local ingestion and analytical sandbox
            -> authorized RAG retrieval
            -> complete-envelope classifier
            -> effective policy resolver
            -> execution router
                 -> deterministic local tools
                 -> private/local model runtime
                 -> secure egress gateway
                      -> approved external provider
            -> output classifier and provenance validator
            -> immutable AI activity ledger
            -> signed release receipt
       -> safe response
  -> user

AI activity ledger
  -> compliance dashboard
  -> security alerts
  -> audit export
  -> managed governance and reassessment
```

### 7.2 Control planes

| Plane | Authority | Responsibilities |
| --- | --- | --- |
| Identity plane | Existing canonical identity authority | Authentication provenance, principal, membership, role, delegation, device context |
| Resource plane | Existing tenant/resource authorities | Corpus, document, workbook, engagement, matter, and connector authorization |
| Policy plane | Canonical Workspace policy service | Classification rules, industry profile, tenant overlay, purpose, provider/tool eligibility |
| Execution plane | Workspace orchestrator | Plans and coordinates deterministic, retrieval, private, and external work |
| Enforcement plane | Secure egress gateway and infrastructure | Prevents unauthorized external transmission and validates release manifests |
| Evidence plane | AI activity ledger and receipt signer | Durable facts, hashes, decisions, chain integrity, export |
| Presentation plane | Console and Portal | User operation, transparent protection status, dashboards, investigations |

### 7.3 Language boundaries

The initial canonical policy and orchestration implementation SHOULD remain in Python
to reuse the current domain implementation.

A future Go `frostgate-ai-egress` binary MAY own provider credentials, outbound TLS,
manifest verification, destination allowlisting, and release receipts.

Go does not become a second policy authority. Python and Go MUST share versioned,
language-neutral contracts and deterministic conformance fixtures.

The existing `supervisor-sidecar` MUST NOT silently become the egress authority. A
security-critical gateway requires a separate package, threat model, deployment unit,
credential boundary, and tests.

---

## 8. Canonical Operation Lifecycle

### 8.1 State machine

```text
RECEIVED
  -> AUTHENTICATED
  -> AUTHORIZED
  -> INGESTED_OR_REFERENCED
  -> CLASSIFIED
  -> POLICY_DECIDED
  -> PLANNED
  -> EXECUTING_LOCAL | EXECUTING_PRIVATE | EGRESS_PENDING | REVIEW_REQUIRED | BLOCKED
  -> EGRESS_VERIFIED (external only)
  -> OUTPUT_RECEIVED
  -> OUTPUT_CLASSIFIED
  -> GROUNDED_OR_MARKED_UNGROUNDED
  -> RELEASED | QUARANTINED | BLOCKED
  -> RECEIPT_FINALIZED
```

Every transition records actor, timestamp, policy version, reason code, and operation
ID. Failed transitions are terminal unless an explicit retry policy creates a new
attempt linked to the original operation.

### 8.2 Terminal outcomes

| Outcome | Meaning |
| --- | --- |
| `ALLOWED` | Operation completed without protected transformation |
| `ALLOWED_AFTER_REDACTION` | Protected values were removed or tokenized before processing/release |
| `LOCAL_ONLY` | All content and inference remained within the approved local boundary |
| `PROTECTED_AGGREGATE` | Raw data stayed local; only approved derived values left |
| `ROUTED_TO_PRIVATE_AI` | Semantic processing used an approved private model |
| `REVIEW_REQUIRED` | No release occurred pending authorized human decision |
| `BLOCKED` | Policy prevented the operation; no prohibited release occurred |
| `QUARANTINED` | Input or output is isolated for authorized investigation |
| `NO_ANSWER` | Evidence or confidence was insufficient; no unsupported answer released |
| `FAILED_SAFE` | Dependency failed and the operation terminated without unsafe fallback |

### 8.3 Idempotency

Every mutating or externally dispatching operation MUST include an idempotency key.
Retries MUST NOT duplicate provider calls, quota charges, ledger events, or release
receipts. A retry after an uncertain external result MUST enter reconciliation rather
than blindly sending again.

---

## 9. Processing Modes

| Mode | Raw data location | AI execution | External disclosure | Intended use |
| --- | --- | --- | --- | --- |
| `PUBLIC_EXTERNAL` | FrostGate and provider | Approved external model | Public/approved content | Public or low-risk work |
| `PROTECTED_EXTERNAL` | FrostGate | Approved external model | Redacted/minimized content | Confidential content with safe transformation |
| `PROTECTED_AGGREGATE` | Local/private data plane | External model may explain approved aggregates | Aggregates only | Regulated spreadsheet analytics |
| `PRIVATE_MODEL` | Customer VPC or approved FrostGate private boundary | Private model | None to public model vendors | Restricted semantic analysis |
| `LOCAL_ONLY` | Customer-controlled environment | Deterministic tools and/or local model | No external AI egress | Strict contractual or sovereignty requirements |
| `HUMAN_REVIEW` | Approved storage only | No release until decision | None pending approval | Ambiguous classification or exceptional purpose |
| `PROHIBITED` | Quarantine or rejected before persistence | None | None | Classified or unsupported data/use cases |

The user MAY request a stricter mode. A user MUST NOT request a less restrictive mode
than effective policy allows.

The UI MUST state the selected mode before execution when practical and MUST state the
actual mode after execution.

---

## 10. Confidential Spreadsheet Analysis

### 10.1 Product objective

A customer must be able to analyze a confidential spreadsheet without sending the raw
workbook or prohibited row-level values to OpenAI, Anthropic, or another external
provider.

The default regulated workflow is `PROTECTED_AGGREGATE`.

### 10.2 Supported formats

Initial target formats:

- CSV with explicit encoding and delimiter handling;
- XLSX without macros;
- optionally TSV as CSV-equivalent.

Initial exclusions:

- XLS legacy binary format;
- XLSM and other macro-enabled formats;
- password-protected workbooks unless a separately approved decryption workflow exists;
- workbooks requiring external link execution;
- workbooks requiring formula recalculation by an office application; and
- embedded executable objects.

### 10.3 Secure ingestion sequence

```text
1. Authorize upload against tenant, workspace, matter/engagement, and capability.
2. Stream to tenant-scoped quarantine storage with a size limit.
3. Verify content signature independently of filename and declared MIME type.
4. Detect archive bombs, malformed ZIP structure, macros, VBA, external links,
   DDE references, embedded objects, hidden sheets, hidden rows/columns, comments,
   formulas, stale cached formula results, and workbook metadata.
5. Reject or quarantine unsupported active content.
6. Hash the original bytes and normalized logical content.
7. Parse in a resource-bounded sandbox without network access.
8. Create a structural inventory before exposing data to analysis.
9. Classify workbook, sheet, column, and selected cell content locally.
10. Persist only approved representations under tenant RLS and retention policy.
11. Emit ingestion evidence without raw cell values.
```

Macros, formulas, external links, and embedded objects MUST NOT execute. Formula text
and cached values MAY be inspected as data. Stale or unavailable calculated values MUST
be identified to the user rather than silently treated as current truth.

### 10.4 Structural inventory

The local analyzer SHOULD produce:

- workbook and sheet identifiers that do not expose original names externally;
- row and column counts;
- inferred data types;
- missing-value counts;
- uniqueness and cardinality summaries;
- formula counts and formula-risk flags;
- hidden-data flags;
- direct identifier classifications;
- quasi-identifier classifications;
- free-text columns requiring semantic processing;
- financial, health, legal, government, credential, and proprietary tags;
- data-quality findings; and
- a content hash and parser version.

Original filenames, sheet names, comments, and column labels are potentially sensitive
and must be classified like cell values.

### 10.5 Query planning and local execution

The external model acts as an optional planner and explainer, not as the database.

```text
User question
-> policy-approved schema abstraction
-> constrained analysis plan
-> deterministic plan validation
-> local execution
-> privacy transformation
-> DLP decision
-> optional external explanation
```

The local execution engine MUST accept an allowlisted analytical DSL or typed operation
contract. It MUST NOT execute arbitrary model-generated Python, shell, SQL against
unapproved databases, URLs, macros, or filesystem paths.

Example operation:

```json
{
  "operation": "group_and_compare",
  "dataset_id": "ds_01",
  "group_by": ["approved_category"],
  "metric": {"field": "approved_cost", "aggregate": "sum"},
  "period": "quarter",
  "minimum_group_size": 10
}
```

The validator MUST bind logical field IDs to an authorized dataset and reject unknown
operations, fields, functions, joins, filters, output sizes, and resource budgets.

### 10.6 Privacy transformation

Before any result leaves the local boundary, FrostGate MUST evaluate:

- direct identifiers;
- small groups and rare categories;
- unique combinations and quasi-identifiers;
- differencing against prior queries;
- raw free text;
- minimum-necessary purpose;
- tenant-defined prohibited fields;
- industry-specific disclosure rules;
- output size and precision; and
- re-identification risk.

Available transformations include:

- redaction;
- stable tenant-scoped tokenization;
- generalization;
- bucketing;
- aggregation;
- small-cell suppression;
- minimum group-size enforcement;
- precision reduction; and
- approved differential privacy for explicitly designed workloads.

Differential privacy MUST NOT be added as decorative security language. If used, its
privacy budget, composition, accuracy impact, and reset policy must be explicit.

### 10.7 Example healthcare flow

```text
Question: Which diagnoses are driving increased treatment cost?

Local input:
- patient identifiers
- claim identifiers
- diagnosis codes
- dates
- provider information
- treatment costs

Local operation:
- authorize purpose
- classify PHI
- group approved diagnosis category
- calculate quarterly cost deltas
- suppress groups below tenant threshold
- remove direct and quasi-identifiers
- inspect safe aggregate

Provider-visible input:
- approved question abstraction
- approved aggregate category labels
- cost deltas
- limitations and suppression notice

Provider never receives:
- workbook bytes
- patient names
- MRNs
- claim IDs
- raw rows
- original filename
- hidden sheets
- comments
```

### 10.8 Semantic free-text limitation

Deterministic analytics can answer many structured spreadsheet questions without a
local LLM. A local/private model becomes necessary when prohibited free-text content
must be semantically interpreted.

If a task cannot be completed without exposing prohibited content and no approved
private model is available, FrostGate MUST deny the task with an actionable reason.

---

## 11. Data Classification and DLP

### 11.1 Classification model

Classification has two dimensions:

1. **Sensitivity level** determines handling severity.
2. **Data categories** determine applicable rules.

Sensitivity levels:

| Level | Meaning | Default external behavior |
| --- | --- | --- |
| `PUBLIC` | Approved for public release | Allow to approved provider |
| `INTERNAL` | Ordinary nonpublic business information | Allow only under tenant policy |
| `CONFIDENTIAL` | Material customer or business information | Transform, private route, review, or block |
| `RESTRICTED` | Regulated, privileged, security-sensitive, or contract-restricted | Private/local by default |
| `PROHIBITED` | Unsupported or forbidden for this environment | Block |
| `UNKNOWN` | Classification cannot be established confidently | Block or review in regulated profiles |

Data categories include, at minimum:

- credentials and authentication secrets;
- cryptographic material;
- personal information;
- protected health information;
- financial nonpublic personal information;
- payment card information;
- legal privilege and work product;
- employment and human-resources information;
- customer confidential information;
- trade secrets and source code;
- CUI categories and dissemination controls;
- CJIS-related information;
- export-controlled/ITAR information;
- security findings and vulnerability information;
- biometric and genetic information;
- precise location;
- children/minor information;
- contractual restrictions; and
- tenant-defined categories.

### 11.2 Classification pipeline

```text
Existing labels and metadata
-> deterministic structured detectors
-> exact data identifiers and tenant dictionaries
-> document/column context
-> optional local statistical or ML classifier
-> conflict and confidence resolver
-> effective classification
```

Existing customer labels from Microsoft Purview or other systems SHOULD be retained and
treated as authoritative constraints unless a stricter FrostGate classification applies.

An LLM MAY suggest classifications but MUST NOT independently authorize release.

### 11.3 Complete-envelope contract

The classification input MUST represent:

```json
{
  "actor_context": {},
  "purpose": "approved-purpose-id",
  "user_message": "...",
  "system_messages": ["..."],
  "conversation_history": [],
  "retrieved_chunks": [],
  "attachments": [],
  "tool_arguments": [],
  "tool_results": [],
  "derived_data": [],
  "provider_options": {},
  "destination": {}
}
```

Every field is inspected after final assembly. A separately generated system prompt,
engagement summary, filename, source title, citation excerpt, or tool result cannot
bypass classification.

### 11.4 Policy precedence

Effective policy is resolved in this order:

```text
Platform hard prohibition
-> deployment/environment restriction
-> law/contract/industry profile
-> provider contract and posture
-> tenant policy
-> workspace/matter/engagement policy
-> resource policy and data-owner restrictions
-> actor capability and purpose
-> requested operation and destination
```

Rules may narrow authority but cannot widen an upstream denial. `DENY` wins. Policy
conflict or missing required state fails closed.

### 11.5 Decision actions

The policy engine returns exactly one terminal or routing action:

- `ALLOW`
- `ALLOW_AFTER_REDACTION`
- `ALLOW_AGGREGATE_ONLY`
- `ROUTE_PRIVATE`
- `ROUTE_LOCAL`
- `REQUIRE_APPROVAL`
- `BLOCK`

The result MUST include stable reason codes, matched rules, policy versions, required
transformations, approved destination, retention class, and receipt requirements.

### 11.6 Output DLP

Output inspection applies before:

- browser display;
- API response;
- export/download;
- clipboard convenience actions where enforceable;
- email or notification;
- connector write-back;
- report persistence;
- tool invocation; and
- inclusion in a later prompt.

Output DLP MUST detect both copied source data and newly inferred sensitive content.
Blocked output may be replaced by a safe explanation, but the blocked content MUST NOT
be embedded in an error response, operational log, trace, or dashboard.

---

## 12. Industry Profiles

Industry profiles are versioned policy packages, not marketing labels. They provide
reviewed defaults and must be overlaid by the customer's actual obligations, contracts,
jurisdictions, and risk decisions.

### 12.1 Healthcare profile

Required capabilities:

- PHI classification beyond current narrow patterns;
- BAA status and scope validation for every relevant processor/subprocessor;
- minimum-necessary enforcement;
- approved endpoint/tool matrix;
- local/private route for prohibited uses;
- healthcare-specific retention and deletion;
- purpose-of-use recording;
- audit and breach-investigation evidence; and
- tests for direct and indirect identifiers.

Current reusable foundations: PHI classifier interface, deterministic minimizer,
provider BAA records, BAA gate, tenant provider routing, and safe AI audit metadata.

### 12.2 Financial-services profile

Required capabilities:

- GLBA nonpublic personal information categories;
- bank account and routing identifiers;
- payment-card data with explicit PCI scope handling;
- tax, income, credit, transaction, and customer-authentication information;
- service-provider contractual controls;
- encryption and retention rules;
- high-risk transaction and fraud-analysis restrictions;
- approved region/provider matrix; and
- financial record and regulatory retention overlays.

`finance_grade` is not this profile and MUST NOT be represented as equivalent.

### 12.3 Legal profile

Required capabilities:

- tenant plus matter-level isolation;
- client, matter, privilege, work-product, protective-order, and ethical-wall labels;
- conflict-aware resource authorization;
- external provider and retention restrictions by client/matter;
- prevention of cross-matter retrieval and memory;
- client-consent and outside-counsel-guideline evidence;
- restricted exports and sharing; and
- private/local inference for privileged content when required.

`legal_grade` is not this profile and MUST NOT be represented as equivalent.

### 12.4 Government/CUI profile

Required capabilities depend on contract and data category and may include:

- CUI category and dissemination markings;
- NIST SP 800-171 contractual control mapping;
- approved system boundary and deployment evidence;
- provider authorization and region restrictions;
- FIPS-validated cryptographic requirements where applicable;
- personnel, nationality, support, and subprocessor restrictions;
- CJIS and export-control overlays where applicable;
- disconnected operation and controlled updates; and
- government-specific incident, audit, and retention handling.

No generic `government` switch is sufficient. Each contract must be represented by an
approved policy overlay.

### 12.5 Classified information

Classified processing is `PROHIBITED` in ordinary FrostGate environments. It may only be
considered inside a separately authorized system specifically designed and accredited
for that classification level. Marketing MUST NOT imply otherwise.

### 12.6 Recommended profile order

1. Healthcare, because reusable PHI and BAA primitives already exist.
2. Legal, with a paid design partner and matter-isolation requirements.
3. Financial services, with a paid design partner and specific GLBA/PCI scope.
4. Government/CUI, only against a concrete contractual system boundary.

Do not build all profiles simultaneously.

---

## 13. Hybrid AI and Provider Routing

### 13.1 Hybrid definition

Hybrid AI means policy-directed execution across three replaceable classes:

```text
Deterministic local tools
Private/local model runtimes
Approved external model providers
```

It does not mean FrostGate trains a foundation model.

### 13.2 Routing inputs

Routing MUST consider:

- tenant and deployment environment;
- actor, role, purpose, and resource authority;
- sensitivity and categories;
- industry and contract profile;
- provider posture and current evidence;
- required tools and modalities;
- data residency and processing region;
- retention and training behavior;
- BAA or other contractual requirements;
- model capability and evaluation status;
- availability, latency, cost, and quota; and
- required grounding and review level.

Security and contractual eligibility precede quality, latency, and cost optimization.

### 13.3 Provider posture registry

Each provider/deployment record SHOULD include:

| Field | Purpose |
| --- | --- |
| `provider_id` and `deployment_id` | Stable routing identity |
| `service_type` | External API, customer cloud, private VPC, on-prem, disconnected |
| `approved_models` | Model-level allowlist |
| `approved_tools` | Tool and modality allowlist |
| `training_use` | Whether customer content may be used for training |
| `abuse_monitoring_retention` | Provider retention behavior |
| `application_state_retention` | Endpoint-specific persistence |
| `zdr_status` | Verified zero-retention eligibility/configuration |
| `baa_status` and scope | Healthcare eligibility |
| `processing_regions` | Permitted processing locations |
| `storage_regions` | Permitted persistence locations |
| `private_connectivity` | Private Link/VPC/other verified path |
| `subprocessors` | Evidence/reference and review date |
| `approved_data_classes` | Maximum permitted classifications/categories |
| `contract_reference` | Non-secret contract/evidence identifier |
| `evidence_hash` | Integrity of reviewed provider documentation |
| `effective_at`, `expires_at` | Time validity |
| `reviewed_by` | Governance authority |
| `operational_state` | Healthy, degraded, restricted, suspended |

Expired, missing, contradictory, or suspended posture fails closed for affected data.

### 13.4 Local/private model requirements

A private model runtime MUST:

- expose the same provider-neutral request/response contract;
- run inside the approved boundary;
- have no unauthorized telemetry or network egress;
- use signed, hash-verified model artifacts;
- declare model, tokenizer, quantization, prompt-template, and runtime versions;
- enforce resource limits;
- support safe cancellation and timeout;
- avoid cross-tenant memory;
- pass the same output DLP and provenance controls; and
- pass task-specific quality and security evaluations.

Local embeddings, OCR, parsing, and retrieval are required when source content cannot
be externally processed. A local LLM with externally generated embeddings is not a
local-only architecture.

### 13.5 No silent fallback

If the selected route fails:

- `LOCAL_ONLY` remains local and fails safe;
- `PRIVATE_MODEL` does not fall back externally;
- an external provider does not switch to another provider without a new policy
  decision and visible reason;
- a PHI-approved provider does not fall back to a non-BAA provider; and
- a grounded request does not become an ungrounded answer unless policy explicitly
  allows it and the response visibly states that fact.

### 13.6 Current configuration contract

This inventory records names and behavior only. Secret values were not read.

| Variable | Current owner/use | Required when | Default/current behavior | Target requirement |
| --- | --- | --- | --- | --- |
| `FG_ENV` | UI route, policy, routing, simulated provider | All production-like deployments | Empty/non-production behavior differs | One validated environment enum at startup |
| `FG_AI_ALLOWED_PROVIDERS` | UI experience and tenant policy defaults | When policy is sourced from environment | Optional compatibility input | Move authority to versioned tenant/deployment policy |
| `FG_AI_DEFAULT_PROVIDER` | Default route | When an environment default is intended | May be derived through compatibility behavior | Must reference an approved deployment record |
| `FG_AI_PHI_PROVIDER` | PHI route | When PHI external processing is enabled | No safe arbitrary fallback | Must reference current BAA-scoped posture |
| `FG_AI_ENABLE_SIMULATED` | Simulated provider gate | Development/test only | Disabled by default in production-like environments | Prohibit in production through startup and release gate |
| `FG_ANTHROPIC_API_KEY` | Anthropic adapter | Anthropic deployment enabled | Missing provider is unavailable | Secret manager/workload identity; presence-only readiness |
| `FG_ANTHROPIC_MODEL` | Anthropic adapter model | Anthropic deployment enabled | Adapter default exists | Pin approved model/deployment and eval version |
| `FG_ANTHROPIC_TIMEOUT_SECONDS` | Anthropic adapter timeout | Optional | Adapter default exists | Validated bounded duration |
| `FG_AZURE_AI_KEY` | Azure OpenAI adapter | Azure OpenAI deployment enabled | Missing provider is unavailable | Secret manager/workload identity where supported |
| `FG_AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint | Azure OpenAI deployment enabled | No usable provider without it | Allow-listed deployment URI and private-route evidence |
| `FG_AZURE_OPENAI_DEPLOYMENT` | Azure model deployment | Azure OpenAI enabled | No usable provider without it | Approved deployment registry identity |
| `FG_AZURE_OPENAI_API_VERSION` | Azure API contract | Optional/current default | Adapter default exists | Pin, validate, and include in posture/receipt |
| `FG_AZURE_OPENAI_MODEL` | Reported Azure model | Optional | Falls back to deployment/default | Verify against actual response/deployment metadata |
| `FG_AZURE_OPENAI_TIMEOUT_SECONDS` | Azure adapter timeout | Optional | Adapter default exists | Validated bounded duration |
| `FG_AI_DEVICE_SIGNATURE_ENABLED` | UI device-request signature | Deployment policy enables it | Disabled by default | Explicit production policy; no undocumented downgrade |
| `FG_AI_DEVICE_SIG_SECRET` | Device-signature verification | Signature enabled | Missing secret raises configuration error | Managed key, rotation, version, and startup validation |
| `FG_AI_MAX_TOKENS_PER_REQUEST` | UI request token cap | Optional | `4096` | Validated bound governed by tenant/deployment policy |
| `FG_AI_TENANT_POLICY_DIR` | Tenant policy-file lookup | File-backed policy mode | Optional | Retire or make signed/read-only compatibility source |
| `FG_AI_POLICY_PATH` | Global policy-file lookup | File-backed policy mode | Optional | Retire or make signed/read-only compatibility source |

The target system SHOULD reduce environment variables to bootstrap connectivity and secret
references. Tenant policy, provider posture, model approval, retention class, region, industry
profile, and exceptions belong in versioned governed records. Startup validation MUST report
name, presence, source, and validity without printing values. Missing security-critical
configuration MUST disable the affected route or mode; it must not select a weaker provider.

---

## 14. Secure Egress Enforcement

### 14.1 Purpose

Application policy determines what should leave. Infrastructure enforcement makes it
difficult for an application defect to send information around that decision.

### 14.2 Target boundary

```text
Core Workspace orchestrator
  -> signed, short-lived release manifest
  -> local authenticated channel
  -> frostgate-ai-egress
       -> verify identity, signature, expiry, nonce, and payload hash
       -> validate destination, model, region, tools, and retention class
       -> re-run mandatory envelope safety checks
       -> apply required transformation
       -> establish outbound TLS
       -> collect response through the same boundary
       -> produce release receipt
```

### 14.3 Required enforcement properties

1. Provider credentials exist only in the egress gateway or provider-specific secret
   boundary, never in browser, Console, Portal, or general workers.
2. Core and workers cannot directly reach external AI provider networks.
3. Network policy permits provider egress only from the gateway identity.
4. Gateway destinations are allowlisted by resolved IP/domain and authenticated TLS.
5. Redirects, alternate hosts, user-supplied base URLs, and SSRF targets are denied.
6. Release manifests are signed, short-lived, nonce-bound, and payload-hash-bound.
7. The gateway does not accept an arbitrary raw URL.
8. The gateway emits no raw content to logs, metrics, or traces.
9. The response returns through output DLP before user release.
10. Gateway unavailability fails closed.

### 14.4 TLS limitation

Network monitoring below TLS cannot inspect prompt content. Complete-envelope inspection
must occur before encryption, at the controlled egress boundary. Host/network policy
still provides destination and process enforcement.

### 14.5 Optional Go implementation

Go is a strong implementation candidate because it supports a small native binary,
concurrency, predictable deployment, and access to operating-system networking controls.
Go is not inherently the policy authority and does not replace correct DLP design.

Possible infrastructure controls include network namespaces, seccomp, Linux capabilities,
cgroups, eBPF observation/enforcement, Kubernetes NetworkPolicy, firewall rules, Unix
sockets, mTLS workload identity, and hardware-backed signing keys.

---

## 15. RAG, Knowledge, and Provenance

### 15.1 Canonical RAG path

The visible Workspace MUST converge on one canonical path:

```text
authorized query
-> effective corpus policy
-> tenant/resource filtered retrieval
-> prompt-injection assessment
-> context budget and sensitivity filter
-> complete-envelope classification
-> execution routing
-> grounded response validation
-> citation/provenance enforcement
-> output DLP
-> receipt and ledger
```

The existing UI and AI-plane paths MUST NOT remain parallel authorities.

### 15.2 Corpus access

Retrieval MUST enforce:

- tenant ID;
- workspace/matter/engagement ID where used;
- actor/resource permissions;
- allowed and denied corpora;
- document lifecycle and current version;
- document classification;
- purpose-of-use restrictions;
- model/provider eligibility for each selected chunk;
- retention and legal hold; and
- portal grant restrictions.

Retrieval is not authorization. A semantically relevant chunk may still be forbidden.

### 15.3 Retrieval strategies

Supported strategy contracts may include lexical, semantic, hybrid weighted, hybrid RRF,
and reranking. Production UI MUST report the strategy actually executed, including any
degradation or fallback.

Production semantic retrieval requires a real approved embedding provider. The existing
deterministic stub is test-only and MUST remain impossible to represent as semantic
production success.

### 15.4 Prompt injection

All retrieved text and connector content is untrusted. The safety layer MUST:

- identify instruction-like content;
- score and filter suspect chunks;
- prevent retrieved text from changing system/tool policy;
- prevent secret requests and destination changes;
- constrain tool parameters to authorized contracts;
- emit safe injection events; and
- return review/no-answer when safe context is insufficient.

The existing `api/rag/safety.py::constrain_answer_context` logic SHOULD be reused or
adapted, but its application must be proven in the actual provider-dispatch path.

### 15.5 Provenance

Every evidence-backed answer SHOULD expose:

- source and chunk identifiers;
- source content/version hash;
- retrieval rank and strategy;
- inclusion-in-prompt status;
- citation validation result;
- grounding status;
- confidence and limitations;
- model and policy version; and
- operation/release receipt IDs.

Raw source excerpts in the UI are subject to the viewer's resource authority and output
DLP. A citation is not permission to disclose source content.

---

## 16. Identity, Authorization, and Purpose

The canonical browser flow remains:

```text
browser -> Console/Portal BFF -> Admin-Gateway -> Core
```

Workspace operations MUST consume canonical actor context from the existing identity
authority. At minimum:

- `principal_id`;
- `tenant_id`;
- `membership_id`;
- `actor_type`;
- roles and capabilities;
- authentication source and assurance level;
- delegation/capability proof where applicable;
- device trust state;
- request ID; and
- portal grant or engagement scope where applicable.

User-supplied email, tenant ID, role, department, provider, or device identifiers are
never authoritative.

### 16.1 Purpose binding

Sensitive operations MUST bind to an approved purpose such as:

- internal analysis;
- client engagement delivery;
- compliance assessment;
- legal matter support;
- healthcare operations;
- incident investigation; or
- approved research.

Purpose is a controlled identifier, not arbitrary text. Policy may require data-owner,
privacy, legal, or security approval for specific combinations.

### 16.2 Tool authorization

Model tool requests are proposals. FrostGate authorizes and executes tools. Each tool
contract defines:

- accepted operation types;
- required actor capability;
- permitted resources;
- input schema;
- output classification;
- side-effect and approval class;
- rate and resource limits;
- idempotency requirements; and
- audit event family.

Arbitrary shell, network, SQL, filesystem, browser, and connector actions are
`PROHIBITED` unless separately constrained by a specific approved tool contract.

---

## 17. Canonical Data Model

The names below are target logical entities. Exact ORM and migration naming MAY follow
repository conventions, but ownership and semantics MUST remain stable.

### 17.1 Entity relationships

```text
WorkspaceSession
  -> WorkspaceOperation
       -> AuthorizedResourceReference
       -> ClassificationResult
       -> PolicyDecision
       -> AnalysisPlan
       -> ExecutionAttempt
       -> RetrievalRecord
       -> ProviderCallRecord
       -> OutputDecision
       -> ReleaseReceipt
       -> ActivityEvent(s)

Dataset
  -> DatasetVersion
       -> StructuralInventory
       -> ClassificationResult(s)
       -> AnalysisPlan(s)

ProviderDeployment
  -> ProviderPostureVersion
       -> EvidenceReference(s)
```

### 17.2 `ai_workspace_sessions`

Purpose: user-visible conversation/analysis session without making conversation history
an implicit authority.

Required fields:

- `session_id`;
- `tenant_id`;
- optional `workspace_id`, `matter_id`, or `engagement_id`;
- `created_by_principal_id`;
- `purpose_id`;
- `status` (`active|closed|expired|legal_hold`);
- `default_processing_mode`;
- `policy_version_id`;
- `created_at`, `updated_at`, `expires_at`; and
- safe title/label or title hash.

Session state MUST NOT authorize access to a document that the actor can no longer
access. Resource and actor authorization is re-evaluated on every operation.

### 17.3 `ai_workspace_operations`

Purpose: canonical state of one user or automated AI operation.

Required fields:

- `operation_id` and `session_id`;
- `tenant_id` and optional sub-boundary IDs;
- canonical actor snapshot reference;
- `purpose_id`;
- operation type;
- requested and actual processing modes;
- state and terminal outcome;
- idempotency key;
- input-envelope hash;
- output hash when released;
- effective policy decision ID;
- selected execution/provider deployment ID;
- release receipt ID when applicable;
- parent/retry/reconciliation operation IDs;
- timestamps; and
- safe failure/reason code.

This mutable state row is an operational projection. Its transitions MUST also be
represented in append-only activity events.

### 17.4 `ai_classification_results`

Required fields:

- `classification_id`;
- `tenant_id`, operation ID, and resource reference;
- sensitivity level;
- category set;
- confidence and uncertainty state;
- direct/quasi-identifier counts;
- classifier and ruleset versions;
- customer-label inputs;
- conflict result;
- content hash, never raw classified values;
- recommended processing constraints; and
- timestamp.

Classification results are immutable. Reclassification creates a new version linked to
the prior result.

### 17.5 `ai_policy_decisions`

Required fields:

- `decision_id`;
- tenant and operation IDs;
- ordered policy version references;
- classification IDs;
- actor/purpose/resource authority snapshot hashes;
- requested destination and operation;
- decision action;
- stable reason codes and matched rule IDs;
- required transformations;
- approved provider/deployment/tool IDs;
- retention and logging class;
- approval requirement and approval references;
- decision input and output hashes;
- deterministic evaluator version; and
- timestamp.

Policy decisions are immutable. A changed decision requires a new operation attempt or
explicit superseding decision with complete linkage.

### 17.6 `ai_analysis_datasets` and versions

Dataset identity is separate from uploaded object identity. Required attributes include:

- tenant and sub-boundary ownership;
- encrypted object reference;
- original-byte and normalized-content hashes;
- format and parser version;
- structural inventory reference;
- classification state;
- quarantine state;
- current version and supersession linkage;
- retention/expiry/legal-hold state;
- data owner; and
- permitted purposes.

Raw data MUST NOT be copied into general event, usage, or search tables.

### 17.7 `ai_analysis_plans`

Required fields:

- plan ID, operation ID, and dataset version ID;
- typed operation graph;
- requested and approved fields by logical identifier;
- validation result and reason codes;
- resource limits;
- privacy transformations;
- plan hash and validator version;
- execution engine/version; and
- timestamps.

The persisted plan contains logical operations, not raw spreadsheet data.

### 17.8 `ai_provider_deployments` and posture versions

Provider identity, deployment identity, and posture version MUST be distinct. A provider
may have multiple endpoints with different regions, contracts, retention, tools, and
eligibility.

Posture changes create immutable versions. Routing binds to the exact posture version
used for the decision.

### 17.9 `ai_release_receipts`

Purpose: evidence of a release decision and execution, not a copy of released content.

Required fields:

- receipt ID and schema version;
- operation and tenant IDs;
- actor snapshot reference;
- purpose, resource, and classification references;
- effective policy decision and version hashes;
- processing mode;
- provider/deployment/model/runtime versions;
- destination class and region;
- raw records/bytes accessed locally as bounded counts;
- values, records, or bytes approved for external release as bounded counts;
- transformation types and counts;
- input-envelope and released-payload hashes;
- response/output hash;
- grounding/provenance result;
- DLP input and output decision reason codes;
- timestamps and latency;
- signer/key ID, signature, previous receipt hash or anchor reference; and
- final outcome.

The receipt MUST NOT include raw prompts, raw rows, redacted source values, API keys,
authorization tokens, or unrestricted source excerpts.

Example safe receipt:

```json
{
  "schema_version": "1.0",
  "receipt_id": "fgrel_01",
  "operation_id": "fgop_01",
  "tenant_id": "tenant_01",
  "processing_mode": "PROTECTED_AGGREGATE",
  "decision": "ALLOW_AGGREGATE_ONLY",
  "policy_versions": ["platform:3", "healthcare:2", "tenant:7"],
  "classifications": ["RESTRICTED", "PHI"],
  "local_records_accessed": 48210,
  "external_values_released": 18,
  "transformations": ["direct_identifier_removal", "small_cell_suppression"],
  "provider_deployment_id": "azure_us_healthcare_01",
  "request_hash": "sha256:...",
  "response_hash": "sha256:...",
  "input_dlp": "PASSED_AFTER_TRANSFORMATION",
  "output_dlp": "PASSED",
  "signature_key_id": "fg-release-2026-03",
  "signature": "..."
}
```

### 17.10 `ai_activity_events`

Purpose: canonical append-only AI governance event ledger.

Required base fields align to `docs/architecture/audit_model.md`:

- event ID and schema version;
- tenant ID;
- operation/session ID;
- actor snapshot ID and actor type;
- UTC timestamp;
- stable action;
- outcome;
- reason codes;
- request/trace ID;
- safe metadata;
- previous hash, entry hash, signature key ID, and signature/anchor reference.

Required event families include:

- session created/closed;
- operation received/authorized/denied;
- resource access allowed/denied;
- dataset received/quarantined/indexed/deleted;
- classification completed/conflicted/failed;
- policy allowed/redacted/routed/reviewed/blocked;
- analysis plan proposed/validated/rejected/executed;
- retrieval requested/filtered/completed/failed;
- prompt injection detected;
- provider egress requested/verified/denied/completed/uncertain;
- output allowed/redacted/quarantined/blocked;
- receipt finalized/verification failed;
- approval requested/granted/denied/expired;
- policy/provider posture changed;
- retention deletion/legal hold;
- break-glass accessed; and
- export generated/accessed.

### 17.11 Quarantine storage

Raw content retained for investigation MUST live outside the activity ledger in a
separately encrypted, access-controlled quarantine store. Metadata references use opaque
IDs. Quarantine supports:

- tenant-scoped encryption key selection;
- short default TTL;
- legal hold;
- dual approval for access;
- access justification;
- copy/export prohibition by default;
- immutable access events; and
- verified deletion or cryptographic erasure.

### 17.12 Database controls

Every new tenant-owned table MUST have:

- non-null `tenant_id`;
- explicit foreign keys where lifecycle permits;
- uniqueness constrained within tenant;
- required indexes beginning with tenant scope;
- RLS enabled and forced;
- `USING` and `WITH CHECK` policies;
- no global fallback query;
- platform-authority access through a separately proven path;
- migration and ORM parity tests; and
- cross-tenant negative tests against PostgreSQL, not SQLite alone.

Append-only claims require database-level enforcement. ORM-only guards are insufficient.

---

## 18. API and Contract Design

### 18.1 API principles

1. Browser actions use Console/Portal BFF allowlists.
2. Human identity terminates at Admin-Gateway.
3. Core never accepts payload tenant identity as authority.
4. Request and response schemas forbid unknown security-relevant fields.
5. Every mutation and dispatch accepts an idempotency key.
6. Stable reason codes are separate from user-facing messages.
7. Raw provider errors are never returned to clients.
8. Every response carries operation ID and terminal or current state.
9. Async work provides status, cancellation, and recovery contracts.
10. Contract generation and frontend clients use the same source schemas.

### 18.2 Target user APIs

| Method and route | Purpose | Required authority |
| --- | --- | --- |
| `POST /v1/ai-workspace/sessions` | Create purpose-bound session | `ai.workspace` plus tenant membership |
| `GET /v1/ai-workspace/sessions/{id}` | Read authorized session | Session/resource authority |
| `POST /v1/ai-workspace/sessions/{id}/operations` | Submit question or analysis | `ai.chat` or operation-specific capability |
| `GET /v1/ai-workspace/operations/{id}` | Poll state/result | Operation actor or approved reviewer |
| `POST /v1/ai-workspace/operations/{id}/cancel` | Cancel pending/running operation | Actor or AI admin |
| `POST /v1/ai-workspace/datasets` | Start authorized upload | `ai.document_ingestion` |
| `POST /v1/ai-workspace/datasets/{id}/complete` | Finalize multipart upload | Upload owner/capability |
| `GET /v1/ai-workspace/datasets/{id}` | View inventory/classification | Resource authority |
| `POST /v1/ai-workspace/datasets/{id}/analyses` | Analyze dataset | Dataset and purpose authority |
| `GET /v1/ai-workspace/receipts/{id}` | View safe release receipt | Actor, compliance, or security authority |
| `GET /v1/ai-workspace/operations/{id}/sources` | View authorized provenance | Source/resource authority |

### 18.3 Target policy/admin APIs

| Method and route | Purpose |
| --- | --- |
| `GET /v1/ai-governance/effective-policy` | Explain effective platform/profile/tenant policy |
| `GET/POST /v1/ai-governance/policy-versions` | Read/create immutable policy version |
| `POST /v1/ai-governance/policies/{id}/validate` | Validate without activation |
| `POST /v1/ai-governance/policies/{id}/activate` | Approved atomic activation |
| `GET /v1/ai-governance/providers` | Provider deployment/posture inventory |
| `POST /v1/ai-governance/providers/{id}/posture-versions` | Create reviewed posture version |
| `POST /v1/ai-governance/providers/{id}/suspend` | Fail-closed provider suspension |
| `GET /v1/ai-governance/activity` | Filter safe activity events |
| `GET /v1/ai-governance/dlp-events` | Filter enforcement outcomes |
| `GET /v1/ai-governance/usage` | Aggregated usage/cost/adoption |
| `GET /v1/ai-governance/posture` | Verified control posture and exceptions |
| `POST /v1/ai-governance/approvals/{id}/decision` | Approve/deny exceptional operation |
| `POST /v1/ai-governance/exports` | Generate tenant-scoped evidence export |

### 18.4 Operation request contract

```json
{
  "session_id": "fgsess_01",
  "operation_type": "spreadsheet_analysis",
  "purpose_id": "healthcare_operations",
  "message": "Which categories drove the quarter-over-quarter increase?",
  "resource_refs": [{"type": "dataset", "id": "fgds_01"}],
  "requested_processing_mode": "PROTECTED_AGGREGATE",
  "requested_provider": null,
  "idempotency_key": "client-generated-opaque-value"
}
```

`requested_provider` is a preference only. It cannot override policy. The user SHOULD
normally choose a protection mode or outcome, not a vendor.

### 18.5 Operation response contract

```json
{
  "operation_id": "fgop_01",
  "state": "RELEASED",
  "outcome": "PROTECTED_AGGREGATE",
  "answer": "...",
  "processing": {
    "mode": "PROTECTED_AGGREGATE",
    "provider": "azure_openai",
    "model": "deployment-model-id",
    "raw_data_left_boundary": false
  },
  "policy": {
    "decision": "ALLOW_AGGREGATE_ONLY",
    "reason_codes": ["PHI_LOCAL_ANALYSIS_REQUIRED"],
    "effective_policy_id": "fgpol_07"
  },
  "provenance": {
    "status": "PROVENANCE_VALID",
    "source_count": 2,
    "confidence": 0.88,
    "limitations": ["Groups below threshold were suppressed"]
  },
  "release_receipt_id": "fgrel_01"
}
```

### 18.6 Compatibility migration

The current routes remain temporary adapters:

```text
/ui/ai/chat -> canonical Workspace operation service
/ai/infer   -> canonical Workspace operation service
/ai/chat    -> canonical Workspace operation service
```

Adapters MUST NOT independently classify, route, call providers, or persist authority.
After all consumers migrate and production proof succeeds, duplicate route behavior may
be deprecated through normal compatibility policy.

`services.ai.dispatch.call_provider` initially becomes an internal implementation behind
the canonical egress interface. Once infrastructure enforcement exists, direct provider
network calls from Core become prohibited.

---

## 19. Compliance and AI Usage Dashboard

### 19.1 Purpose

The dashboard is the operational proof surface for Workspace governance. It MUST answer,
without exposing protected content:

- How is AI being used?
- Which users, tenants, departments, matters, and purposes are responsible?
- What data classifications are involved?
- What was allowed, transformed, routed locally, quarantined, or blocked?
- Which provider and model processed each released operation?
- Did protected data leave the approved trust boundary?
- Which policies, exceptions, or classifier versions controlled the decision?
- What requires investigation, policy adjustment, or user education?

The dashboard is not a raw prompt surveillance tool. Its default views MUST expose
metadata, reason codes, aggregates, and controlled evidence references rather than prompt,
document, retrieved chunk, or response bodies.

### 19.2 Required views

| View | Required content | Primary user |
| --- | --- | --- |
| Overview | Operations, active users, release rate, block rate, local/private share, top purposes, freshness | Tenant admin, compliance |
| AI Usage | Usage by user, group, purpose, model, provider, mode, and time | Tenant admin, AI governance |
| DLP Activity | Blocked, transformed, quarantined, and aggregate-only decisions with reason codes | Security, DLP analyst |
| Compliance Posture | Policy coverage, exceptions, expiring approvals, unclassified sources, control evidence | Compliance, risk |
| Providers | Approved deployments, posture status, routing share, failures, drift, last verification | Platform and tenant admin |
| Investigations | Event timeline, evidence references, related operations, disposition, legal hold | Security, privacy |
| Policies and Exceptions | Versions, scope, simulation results, approvals, activation, expiry | Policy administrator |
| Evidence and Exports | Signed summaries, release receipts, chain verification, scoped exports | Auditor, compliance |

### 19.3 Global filters

Every view SHOULD support filters appropriate to the actor's scope:

- time range;
- tenant and organizational unit;
- user or service principal;
- purpose and matter or engagement;
- operation type;
- processing mode;
- provider and model deployment;
- classification and industry profile;
- policy action and reason code;
- status, severity, exception, and investigation state.

Filters MUST preserve tenant and matter authorization. A filter parameter is never an
authority grant.

### 19.4 Blocked event record

A blocked-event detail view SHOULD display:

```text
Event ID
Timestamp
Actor identity and organizational unit
Declared purpose and matter/engagement
Operation type and source type
Detected classification labels and detector confidence
Policy decision and reason codes
Requested and resolved processing mode
Requested provider, if any, and whether it was refused
Content fingerprint and evidence reference, not raw content
User-facing message
Investigation and disposition state
Policy, classifier, route, and software versions
```

Raw content MAY be available only through an explicit, separately authorized evidence
workflow with purpose binding, step-up authentication, access logging, retention controls,
and legal basis. It MUST NOT appear in dashboard lists, browser telemetry, analytics, or
ordinary support tooling.

### 19.5 Role visibility

| Role | Default visibility |
| --- | --- |
| Workforce user | Own activity, decisions, safe explanations, and approved output |
| Manager | Authorized organizational aggregates; no raw content by default |
| Tenant admin | Tenant configuration and metadata-level usage |
| Compliance/risk | Tenant-wide posture, exceptions, evidence, and signed exports |
| Security/DLP analyst | Blocked-event metadata and controlled investigation workflow |
| Matter/engagement member | Activity only within authorized matter scope |
| Platform operator | Service health and de-identified operational metadata; no tenant content by default |
| Auditor | Time-bound, read-only, explicitly scoped evidence and receipts |

### 19.6 Dashboard truth requirements

1. The append-only activity ledger is the source of truth. Frontend analytics events are
   not governance evidence.
2. Every metric MUST expose a data freshness timestamp and source scope.
3. Missing or delayed data MUST render as `INCOMPLETE`, never as zero or compliant.
4. Unknown classifications and unknown provider outcomes MUST remain unknown.
5. Deleted or retention-expired content MUST not make immutable event metadata misleading;
   tombstone state and evidence availability are explicit.
6. Aggregates MUST be protected against small-group disclosure and unauthorized drilldown.
7. Exports MUST be generated server-side from authorized ledger data and signed or hashed.
8. Dashboard authorization MUST be tested independently of API authorization assumptions.

### 19.7 Alerts

Initial alerts SHOULD include:

- attempted restricted-data egress;
- repeated blocks by an actor or application;
- provider posture expired or changed;
- policy or classifier version drift;
- local/private route unavailable when required;
- emergency or break-glass exception use;
- unexplained increase in unknown classification;
- ledger ingestion lag or event sequence gap;
- release receipt signature or chain verification failure;
- cross-tenant or cross-matter authorization denial spike.

Alert delivery MUST avoid including protected prompt or document content.

---

## 20. Workspace User Experience

### 20.1 Primary layout

The primary Console Workspace SHOULD use three stable work areas:

1. **Context and sources:** approved libraries, uploaded data, matter/engagement, and
   classification state.
2. **Conversation and analysis:** user request, plan, progress, response, citations,
   limitations, and recovery actions.
3. **Protection and provenance:** processing mode, provider/model, policy decision,
   protected-data boundary, source coverage, and release receipt.

On smaller screens these areas may become tabs or drawers, but the protection state MUST
remain visible before submission and with every released result.

### 20.2 Required controls

- purpose or approved use-case selector;
- matter/engagement selector when required by policy;
- source and dataset picker;
- attachment upload with classification progress;
- processing-mode selector limited to modes permitted for the operation;
- provider preference only where tenant policy allows choice;
- output format and analysis intent;
- submit, cancel, retry, and report-problem actions;
- explicit confirmation for controlled release or declassification workflows.

Controls MUST use policy-derived availability. A disabled option SHOULD explain the policy
reason without disclosing sensitive configuration.

### 20.3 Protection indicators

The UI MUST distinguish these states clearly:

```text
Classifying
Local only
Private approved provider
Protected aggregate only
External provider approved
Blocked by policy
Quarantined for review
Released with limitations
Provider or policy state unavailable
```

Provider logos or model names are secondary. The primary user decision is the permitted
data-handling mode.

### 20.4 Safe denial and recovery

A denial SHOULD state:

- what category of policy prevented the action;
- whether the user can remove or tokenize fields, choose an approved local/private mode,
  request an exception, or contact a named organizational role;
- what was and was not sent externally;
- the operation/event identifier for support and audit.

It MUST NOT echo the protected substring that caused the denial.

### 20.5 Spreadsheet experience

The spreadsheet flow SHOULD provide:

1. local upload completion and malware/file validation;
2. sheet and column discovery;
3. proposed type and sensitivity labels with confidence;
4. an analysis plan describing which computations remain local;
5. a visible disclosure budget and suppressed-group rules;
6. preview of the exact aggregate artifact eligible for model egress;
7. answer with formulas, lineage, limitations, and downloadable controlled result;
8. release receipt showing that row-level data did or did not leave the boundary.

The UI MUST never imply that a file is protected merely because a provider promises not to
train on it. Boundary, retention, authorization, and release controls are separate claims.

### 20.6 Portal experience

Portal Workspace access, if enabled, is a strict subset of Console capability:

- engagement-bound sources only;
- no tenant-wide provider or policy administration;
- no cross-engagement search;
- no raw DLP investigation access;
- explicit report and evidence sharing authority;
- separate contract and tests for Portal-to-Core actor provenance.

### 20.7 Accessibility and recovery

- Every status must be represented by text, not color alone.
- Long-running operations require durable progress and resumable status polling.
- Browser refresh must not duplicate provider execution.
- Cancellation semantics must distinguish queued, executing, provider-called, and released.
- Error messages must separate user-correctable input, policy denial, provider failure,
  local-compute failure, and internal failure.
- Keyboard navigation, focus management, screen-reader labels, and table alternatives are
  required for customer readiness.

---

## 21. Security and Privacy Threat Model

### 21.1 Protected assets

- raw prompts, responses, files, rows, cells, and retrieved chunks;
- PHI, PII, financial, legal, government, credential, and customer-confidential data;
- tenant, matter, engagement, and organizational boundaries;
- identity, roles, capabilities, delegated authority, and purpose;
- policy definitions, exceptions, classifier behavior, and provider credentials;
- evidence lineage, release receipts, audit events, findings, and reports;
- model deployment posture and infrastructure trust claims.

### 21.2 Threats and required controls

| Threat/failure path | Required control | Proof required |
| --- | --- | --- |
| Cross-tenant retrieval or event access | Tenant-bound actor, RLS, scoped indexes, negative tests | Two-tenant adversarial suite |
| Cross-matter legal disclosure | Matter membership and ethical-wall policy on upload, retrieval, generation, export | Denied cross-matter corpus |
| System-prompt or hidden-context leakage | Whole-envelope classification, non-disclosure policy, adversarial extraction tests | Prompt-injection corpus |
| RAG retrieves a secret absent from user text | Classify retrieved chunks and assembled prompt before provider dispatch | Canary secret never reaches provider double |
| User prompt overrides DLP instructions | DLP outside the model, deterministic policy decision, constrained output release | Jailbreak tests |
| Direct provider call bypasses policy | Single egress interface, network allow-list/proxy, CI import rule | Blocked direct-network proof |
| Secure provider silently falls back | No fallback across trust classes; explicit unavailable state | Provider outage test |
| SSRF through URL/document connector | Allow-listed destinations, DNS/IP validation, redirect checks, egress controls | Internal-address denial tests |
| Tool invocation exceeds user authority | Tool-specific capability and argument authorization, least privilege | Confused-deputy tests |
| Spreadsheet active content or malicious archive | Type verification, size/depth limits, malware scan, no macro execution | Malformed-file corpus |
| CSV/formula injection in exports | Neutralize formulas and dangerous cells, controlled MIME/content disposition | Spreadsheet export tests |
| Small-group or differencing disclosure | Minimum cohort, query history budget, suppression, rate limits | Repeated-query attack suite |
| Tokenized fields can be reidentified | Vault separation, scoped detokenization, no provider access, indirect-ID analysis | Reidentification review |
| Raw prompt logging leaks secrets | Metadata-only ledger, content references, redaction, sink validation | Log capture test |
| Output reconstructs protected input | Deterministic output scanner, release policy, quarantine | Reconstruction corpus |
| Header or client field spoofs tenant | Gateway provenance proof and server-side actor construction | Forged-header tests |
| Receipt or evidence tampering | Signed canonical payload, chain links, immutable storage controls | Signature and mutation tests |
| Policy changes during execution | Version pinning at admission; re-evaluate before release where required | Race test |
| Provider posture changes unnoticed | Deployment registry, expiry, periodic verification, fail closed | Expired-posture test |
| Model or classifier supply-chain drift | Version pinning, artifact hashes, approved registry, eval gates | Reproducibility test |
| Cache leaks across tenants | Tenant/matter/policy/version in key; encrypted scoped stores | Cache collision tests |
| Queue payload exposes raw data | Reference-based jobs, encrypted durable queue, worker identity | Queue inspection test |
| Browser or analytics captures content | No content in URLs/telemetry; CSP and upload isolation | Browser network review |
| Privileged analyst abuses investigation view | Step-up auth, purpose, reason, approval, full access audit | Privileged-access test |

### 21.3 Security boundaries

The architecture MUST treat these as separate decisions:

1. May this actor perform this operation?
2. May this operation use these sources for this purpose?
3. May this data be processed in this trust zone?
4. May this transformed artifact leave that zone?
5. May this output be released to this actor?

Passing one decision does not imply passing another.

### 21.4 Explicit limitations

No implementation can truthfully promise that leakage is impossible. FrostGate can make
egress constrained, observable, deny-by-default, independently testable, and materially
harder to bypass. Claims MUST be scoped to the exact deployment, policy, provider endpoint,
and tested operation. Endpoint contract controls do not defend against FrostGate software,
operator, customer endpoint, identity, or configuration compromise.

---

## 22. Privacy, Logging, Retention, and Deletion

### 22.1 Store-by-store policy

| Store | Raw content default | Minimum metadata | Retention owner | Encryption | Tenant isolation |
| --- | --- | --- | --- | --- | --- |
| Activity ledger | Prohibited | Actor, purpose, classification, decision, route, versions, hashes | Tenant policy | Required | RLS + application scope |
| Evidence store | Allowed only when required | Evidence ID, owner, hash, type, legal state | Evidence/record policy | Required | RLS + object-store policy |
| Quarantine | Controlled temporary | Reason, owner, expiry, reviewers | Security/privacy | Required | Strong scoped access |
| Provider request staging | Minimized and ephemeral | Operation and attempt IDs | System policy | Required | Isolated by operation/tenant |
| RAG index | Chunk content only when approved | Source, chunk, ACL, classification, version | Knowledge owner | Required | Retrieval-time ACL + physical/logical controls |
| Token vault | Sensitive mapping | Token type, owner, expiry | Privacy/security | Separate keys required | No model/provider access |
| Cache | No raw by default | Scoped derived value and expiry | System policy | Required | Tenant/matter-scoped key |
| Operational logs | Prohibited | Correlation IDs, reason codes, timings | Platform operations | Required in transit/at rest | Access-controlled sink |
| Analytics | Prohibited | Aggregated product events | Product/privacy | Required | De-identified and scoped |

### 22.2 Raw `ai_query_log` disposition

The current raw query/response/email logging pattern MUST NOT become the long-term Workspace
audit authority. Before regulated customer use:

1. stop new raw persistence by default;
2. introduce the metadata ledger and controlled evidence references;
3. classify existing records without exposing values;
4. define lawful retention and migration/deletion handling;
5. apply tenant RLS and least-privilege access during transition;
6. prove backups, replicas, exports, and logs follow the same disposition;
7. retain a documented compatibility window and retirement condition.

Migration must not silently destroy records subject to contract, investigation, legal hold,
or evidence-integrity requirements.

### 22.3 Retention rules

- Retention is selected by data class, record purpose, jurisdiction, contract, and legal hold.
- Provider retention is deployment-specific and verified, not assumed from a vendor name.
- Ephemeral does not mean unlogged; governance metadata and receipts may outlive content.
- Expiry jobs MUST be idempotent, observable, tenant-scoped, and tested against backups.
- Legal holds MUST prevent deletion of the governed object while preserving access controls.
- A retention failure MUST alert and expose incomplete status to administrators.

### 22.4 Deletion and evidence integrity

Deletion MUST distinguish content erasure from immutable proof that a governed event occurred.
Where lawful, retain hashes, identifiers, policy decisions, signatures, and tombstones without
retaining reconstructable content. Signed reports and evidence manifests must state when a
referenced source has expired or been deleted.

---

## 23. Deployment Models and Trust Zones

### 23.1 Supported target models

| Model | Data plane | Model execution | Best fit | Relative effort |
| --- | --- | --- | --- | --- |
| FrostGate managed cloud | FrostGate tenant-isolated environment | Approved managed or FrostGate-hosted endpoint | Standard mid-market | Lowest |
| Customer-controlled VPC | Customer cloud account/network | Private endpoint or local model | Regulated enterprise | High |
| Customer on-premises | Customer data center | On-premises/local model | Restricted legal, healthcare, government | Higher |
| Disconnected/sovereign | No public network path | Approved local model only | Classified or sovereign environments | Highest |

The codebase SHOULD remain one policy and evidence product with deployable components, not
four divergent products.

### 23.2 Trust-zone rules

```text
Browser/client zone
  -> authenticated application/API zone
  -> quarantine and local analysis zone
  -> retrieval/index zone
  -> secure AI egress zone
  -> approved provider/private model zone
  -> controlled release zone
```

Every transition requires an authenticated workload identity, authorized operation,
classification result, policy decision, and correlated event. Trust is not inherited merely
because two components run in the same cloud account.

### 23.3 Network policy matrix

| Component | Internet egress | Provider egress | Database | Object/evidence store | Token vault |
| --- | ---: | ---: | ---: | ---: | ---: |
| Console/Portal browser | Normal web only | No | No | Signed/scoped upload only | No |
| Core API | Restricted | Through gateway only | Yes | Scoped | No direct detokenization by default |
| Classifier/local analysis worker | Deny by default | No | Scoped | Scoped | Tokenization service only |
| RAG/index worker | Deny by default | Embedding endpoint only if approved | Scoped | Scoped | No |
| AI egress gateway | Allow-listed endpoints | Yes | Policy/deployment metadata only | No raw source access by default | No |
| Release service | Deny by default | No | Scoped | Controlled output/evidence | Scoped detokenization only if approved |
| Dashboard service | Deny by default | No | Ledger/read models | Evidence metadata only | No |

### 23.4 Infrastructure requirements

- workload identity and separate service principals;
- encryption keys scoped by environment and, where required, tenant;
- private networking and allow-listed DNS/egress for private modes;
- independently verifiable image and source provenance;
- infrastructure policy preventing Core/worker provider bypass;
- immutable or append-protected evidence and ledger storage;
- deployment-specific readiness checks that validate required trust dependencies;
- restore and key-loss procedures exercised in a non-production environment.

---

## 24. Resilience and Operations

### 24.1 Failure behavior

| Failure | Required behavior | Prohibited behavior |
| --- | --- | --- |
| Classifier unavailable | Reject/quarantine protected operations | Assume public |
| Policy engine unavailable | Fail closed | Use stale permissive default without authorization |
| Local model unavailable | Queue or deny with explicit status | Fall back to public provider |
| Provider unavailable | Retry within policy or expose unavailable | Cross trust-class fallback |
| RAG index unavailable | State that grounded answer cannot be produced | Ungrounded confident answer |
| Ledger unavailable | Do not release governed output unless durable outbox proof exists | Release unrecorded output |
| Release scanner unavailable | Quarantine output | Return unchecked output |
| Receipt signer unavailable | Hold release or mark non-releasable | Invent/omit receipt silently |
| Dashboard projection delayed | Show stale/incomplete timestamp | Display zero or green status |
| Upload scan timeout | Quarantine and expire safely | Parse or index unscanned file |

### 24.2 Transaction and outbox model

Durable state transitions, side-effect intents, and governance events SHOULD use a
transactional outbox where they share a database. Provider execution MUST use an idempotency
key tied to the operation and attempt. A retry must not create an untracked second release.

The operation state machine MUST distinguish:

```text
QUEUED -> ADMITTED -> CLASSIFIED -> AUTHORIZED -> PREPARED -> DISPATCHED
       -> PROVIDER_COMPLETED -> OUTPUT_SCANNED -> RELEASE_AUTHORIZED -> RELEASED
```

Terminal and exception states include `DENIED`, `QUARANTINED`, `FAILED`, `CANCELLED`, and
`EXPIRED`. State transitions require monotonic version checks.

### 24.3 Initial SLO candidates

These are targets to validate with customer needs, not current claims:

- 99.9% monthly availability for admission, policy decision, and ledger APIs;
- 99.5% successful completion for valid operations excluding provider outages;
- 99% of dashboard events visible within five minutes;
- 100% of released governed outputs linked to a valid release receipt;
- zero unauthorized cross-tenant or cross-matter retrievals;
- defined recovery time and recovery point objectives per deployment tier.

### 24.4 Readiness and health

Liveness only proves a process is running. Workspace readiness MUST separately report, without
secret values:

- database and migration compatibility;
- policy bundle loaded and signature/version valid;
- classifier bundle available;
- activity ledger/outbox writable;
- release scanner and receipt signer available;
- required local/private/provider deployments healthy and posture-current;
- RAG index compatibility;
- object store/quarantine availability;
- worker queue lag and stale leases.

Required dependencies fail closed for the affected operation mode. An optional provider may
be unavailable without making a local-only mode unavailable.

### 24.5 Backup, restore, and incident response

- Backup coverage includes database, evidence objects, policy bundles, index metadata,
  receipts, keys/configuration metadata, and deletion/hold state.
- Restore tests MUST prove tenant ownership, RLS, signatures, object references, and ledger
  ordering, not only database readability.
- Indexes derived from source evidence SHOULD be rebuildable and versioned.
- Incident runbooks cover suspected egress, provider compromise, policy misconfiguration,
  cross-tenant exposure, signing-key compromise, and audit-ledger gaps.
- Customer notification and evidence-preservation responsibilities MUST be contractually and
  operationally assigned before production use.

---

## 25. Observability and Evidence

### 25.1 Safe telemetry

Telemetry MUST be useful without becoming a secondary content store. Approved dimensions
include tenant pseudonym, operation type, mode, provider deployment ID, policy action,
reason code, classifier/model/policy version, state, latency, token count, cost estimate,
queue delay, and error class. Prompt text, response text, document names, cell values,
retrieved chunks, email addresses, access tokens, and provider credentials are prohibited.

High-cardinality identifiers belong in controlled logs or traces, not metric labels.

### 25.2 Candidate metrics

```text
fg_ai_operations_total
fg_ai_policy_decisions_total
fg_ai_release_total
fg_ai_release_denied_total
fg_ai_dlp_detections_total
fg_ai_processing_mode_total
fg_ai_provider_requests_total
fg_ai_provider_failures_total
fg_ai_operation_duration_seconds
fg_ai_classification_duration_seconds
fg_ai_queue_lag_seconds
fg_ai_ledger_projection_lag_seconds
fg_ai_receipt_verification_failures_total
fg_ai_unknown_classification_total
fg_ai_local_analysis_rows_total
fg_ai_protected_aggregate_suppressions_total
```

Metric names are targets. Existing telemetry conventions take precedence where they provide
the same semantics.

### 25.3 Evidence is not telemetry

A metric proves that software reported a count. It does not prove the underlying governance
decision. Customer-visible claims require ledger events, pinned versions, source/evidence
references, signed release receipts, and reproducible verification procedures. Monitoring
alerts are operational signals; signed evidence is the assurance artifact.

### 25.4 Correlation identifiers

The following identifiers MUST be linked but independently scoped:

- request and trace ID;
- Workspace session ID;
- operation and attempt ID;
- actor/principal and tenant ID;
- matter/engagement and purpose ID;
- dataset/source/evidence IDs;
- policy decision and classification IDs;
- provider deployment/request ID;
- release receipt and activity event IDs.

External provider request identifiers are retained as metadata when permitted and MUST never
be treated as tenant authority.

---

## 26. Testing Strategy

### 26.1 Test layers

| Layer | What it must prove |
| --- | --- |
| Unit | Deterministic classifier, minimizer, policy, state transition, suppression, receipt, and parser behavior |
| Contract | Stable request/response, error, event, provider-adapter, and release-receipt schemas |
| Persistence | Constraints, migrations, RLS, idempotency, outbox, retention, legal hold, and restore behavior |
| Integration | Actor through policy, retrieval, dispatch, release, ledger, and dashboard projection |
| Security | Tenant/matter isolation, bypass attempts, injection, SSRF, upload abuse, privilege escalation, and log leakage |
| Golden corpus | Expected industry classifications, decisions, transformations, citations, and output releases |
| E2E | Browser/Portal through BFF/Core to durable evidence using production-like dependencies |
| Production proof | Deployed SHA, configured dependencies, real boundary behavior, receipt verification, and restart/recovery |

Tests that only assert HTTP 200 or mock all authority, storage, and provider boundaries do not
prove customer readiness.

### 26.2 Whole-envelope DLP corpus

The test corpus MUST cover sensitive content in:

- user message;
- system and engagement prompt;
- conversation history;
- retrieved chunks and metadata;
- document name and parsed properties;
- spreadsheet headers, values, formulas, comments, and hidden sheets;
- tool arguments and connector responses;
- transformed provider request;
- model output and citations;
- error text, logs, traces, dashboard projections, and exports.

Each positive detection requires negative near-neighbors to measure false positives. Each
policy action requires proof of the exact provider payload or proof that no payload was sent.

### 26.3 Industry golden corpora

Healthcare cases include direct identifiers, dates, record numbers, free-text clinical notes,
de-identification edge cases, minimum-necessary purpose, BAA posture, and local-only fallback
denial.

Financial cases include account/card identifiers, nonpublic personal information, material
nonpublic information, customer lists, suspicious transactions, and combinations that become
identifying only together.

Legal cases include client names, matter identifiers, privileged advice, work product,
conflicts/ethical walls, inadvertent disclosure, and cross-matter retrieval.

Government cases include CUI markings, distribution statements, export-controlled content,
contract-specific handling, approved destinations, and disconnected operation.

The corpus MUST be synthetic or specifically approved for testing. It must not become an
uncontrolled collection of real customer secrets.

### 26.4 Spreadsheet tests

- CSV, XLSX, XLS, ODS only when explicitly supported;
- encrypted, corrupt, oversized, deeply nested, sparse, merged, and multi-sheet files;
- macros, external links, hidden rows/sheets, comments, formulas, and date/locale ambiguity;
- type inference, missing values, duplicate rows, encodings, and large integers;
- deterministic calculations compared with known results;
- source-cell lineage and reproducibility;
- minimum cohort and differencing attacks across repeated queries;
- formula injection in generated CSV/XLSX;
- cancellation, restart, timeout, and partial-result cleanup;
- proof that row-level confidential data never reaches the provider test double.

### 26.5 RAG tests

- retrieval ACL and tenant/matter filters are applied before ranking;
- no unauthorized chunks appear in candidates, traces, cache, prompt, answer, or citations;
- stale/deleted sources cannot be cited as current;
- lexical, semantic, and hybrid modes expose their actual mode;
- absent evidence produces `NOT_PROVEN`, not an invented answer;
- conflicting sources remain explicit;
- prompt injection inside documents cannot change policy or tool authority;
- every material answer claim maps to an authorized source span;
- embedding and index version changes trigger compatibility/rebuild behavior.

### 26.6 Gateway and provider tests

- direct provider imports/network calls are rejected by CI and network policy;
- provider request body equals the approved transformed artifact;
- deployment posture, region, retention, BAA/contract, endpoint, and model are pinned;
- timeout/retry does not duplicate release;
- provider failure never causes a weaker trust-class fallback;
- provider response is scanned before any user-visible persistence or streaming;
- streaming uses buffered/controlled release for protected workflows;
- model and endpoint changes fail until evaluated and approved.

### 26.7 Frontend and dashboard tests

- UI controls cannot request modes or sources outside server authority;
- status text matches actual persisted state;
- refresh/resume does not duplicate work;
- no protected content appears in URLs, browser logs, analytics, or error reporting;
- dashboard totals reconcile to ledger events;
- delayed projections show incomplete/freshness state;
- role and scope matrices are tested with direct URL/API attempts;
- exports preserve filters, authorization, suppression, provenance, and signatures.

---

## 27. Production-Proof Gates

### 27.1 Customer-One Workspace gate

Before the first customer receives production Workspace access:

- [ ] one canonical operation path is used by the visible Console;
- [ ] actor, tenant, purpose, and source authority are server-derived and persisted;
- [ ] complete-envelope classification and pre-release scanning are active;
- [ ] no raw prompt/response/email is logged by default;
- [ ] provider dispatch cannot bypass the canonical egress interface;
- [ ] activity events and release receipts reconcile for every released operation;
- [ ] two-tenant and unauthorized-source negative suites pass;
- [ ] provider posture and required dependencies fail closed;
- [ ] deletion, retention, backup, restore, restart, and incident procedures are exercised;
- [ ] deployed source/build/runtime SHA provenance is captured;
- [ ] customer-facing limitations and support ownership are approved.

### 27.2 Regulated spreadsheet gate

- [ ] upload parser and malware/archive defenses pass the hostile-file corpus;
- [ ] row/cell data remains in the approved local/private zone;
- [ ] only an approved aggregate artifact reaches the provider double and real endpoint;
- [ ] suppression and repeated-query budget defeat the defined disclosure attacks;
- [ ] calculations and lineage reproduce from the source fixture;
- [ ] result release scanner blocks seeded reconstruction attempts;
- [ ] dashboard and signed receipt accurately show the data boundary;
- [ ] customer security/privacy stakeholders approve the deployment-specific data flow.

### 27.3 Private/local deployment gate

- [ ] model artifacts, runtime, hardware assumptions, and licenses are pinned;
- [ ] public egress is technically blocked for local-only workloads;
- [ ] quality, safety, latency, load, and failure evals meet the approved profile;
- [ ] patching, rollback, vulnerability response, and model replacement are documented;
- [ ] customer/FrostGate responsibility matrix is signed;
- [ ] restore and degraded-mode tests pass in the actual deployment class.

### 27.4 Dashboard gate

- [ ] every displayed number reconciles to the ledger;
- [ ] raw content is absent from normal views and exports;
- [ ] all roles and scope combinations pass positive and negative tests;
- [ ] stale, partial, deleted, held, and unknown states are rendered truthfully;
- [ ] alerts are delivered without protected content;
- [ ] a customer auditor can verify a sampled event and receipt end to end.

No checklist item can be waived by changing the test expectation. Exceptions require a named
owner, risk acceptance authority, expiry, compensating control, and explicit customer impact.

---

## 28. Dependency-Aware PR Sequence

This sequence extends the current implementation. It does not require a language rewrite or
replacement of working evidence, identity, tenant, and RAG foundations.

| Order | PR | Purpose | Effort | Dependency | Customer impact | Revenue impact | Moat impact |
| ---: | --- | --- | --- | --- | --- | --- | --- |
| 1 | AW-001 Canonical Workspace contracts | One operation, policy, event, and receipt vocabulary | M | None | Removes UI/API ambiguity | Enables credible scope | Medium |
| 2 | AW-002 Privacy-safe activity ledger | Durable metadata authority and RLS | L | AW-001 | Enables compliance visibility | Required for managed offering | High |
| 3 | AW-003 Raw query-log containment | Stop default sensitive prompt/response storage; controlled migration | M | AW-002 | Reduces immediate privacy risk | Required before regulated use | Medium |
| 4 | AW-004 Canonical orchestrator | Converge visible UI, RAG, policy, dispatch, and state machine | L | AW-001, AW-002 | Makes product behavior coherent | Enables Customer One | High |
| 5 | AW-005 Whole-envelope DLP | Inspect prompt, history, RAG, tools, provider payload, output | L | AW-004 | Defensible egress controls | Core premium value | High |
| 6 | AW-006 RAG convergence | Make visible Workspace use authorized RAG and explicit provenance | L | AW-004, AW-005 | Evidence-backed answers | Strong assessment/Workspace value | High |
| 7 | AW-007 Production embedding service | Approved local/private embeddings and index lifecycle | M-L | AW-006 | Real semantic/hybrid retrieval | Improves answer quality | Medium |
| 8 | AW-008 Spreadsheet ingestion | Safe CSV/XLSX parsing, schema/classification, lineage | L | AW-004, AW-005 | Unlocks high-value analysis | Strong sales demo and use case | Medium |
| 9 | AW-009 Local analytical engine | Deterministic dataframe/SQL computations in protected zone | L | AW-008 | Raw data stays local | Unlocks regulated Workspace | High |
| 10 | AW-010 Protected aggregate release | Suppression, disclosure budget, output scanning, receipts | L | AW-002, AW-009 | Defensible external reasoning | Premium recurring value | High |
| 11 | AW-011 Compliance dashboard | Usage, DLP, policy, investigation, provider, export views | L | AW-002, AW-004 | Customer control and proof | Major MRR feature | High |
| 12 | AW-012 Enforced egress gateway | Independent network enforcement and provider posture | L | AW-004, AW-005 | Stronger than app-only policy | Enterprise credibility | High |
| 13 | AW-013 Healthcare profile | PHI expansion, purpose, minimum necessary, BAA/deployment gates | L | AW-010, AW-012 | Healthcare pilot readiness | Vertical premium | Medium |
| 14 | AW-014 Private/local model path | Approved private inference deployment | L | AW-012 | Supports no-public-egress customers | Higher ACV | Medium |
| 15 | AW-015 Customer VPC package | Repeatable private deployment and responsibility model | L | AW-014 | Enterprise deployment option | Expansion revenue | Medium |
| 16 | AW-016 Legal profile | Matter walls, privilege handling, legal review and corpus | L | AW-010, AW-012 | Legal pilot readiness | Vertical premium | Medium |
| 17 | AW-017 Financial profile | NPI/MNPI, account data, service-provider controls and corpus | L | AW-010, AW-012 | Financial pilot readiness | Vertical premium | Medium |
| 18 | AW-018 Government profile | CUI flow controls, sovereign/disconnected proof | L+ | AW-014, AW-015 | Government readiness | Large but slower contracts | High |

Effort is relative: S is days, M is roughly one to two focused weeks, L is multiple weeks or
cross-subsystem work. Estimates require refinement after contract and migration design.

### 28.1 Priority bands

**DO NOW:** AW-001 through AW-005. They remove false claims and create a single enforceable
runtime.

**DO BEFORE CUSTOMER ONE USES WORKSPACE:** AW-006, the relevant subset of AW-007, AW-011,
and the Customer-One gate. A narrow pilot may exclude spreadsheets by contract and feature
flag.

**DO BEFORE CONFIDENTIAL SPREADSHEET SALES:** AW-008 through AW-010 and AW-012.

**DO AFTER CUSTOMER ONE:** Build only the first industry profile justified by a paid design
partner, then AW-014/AW-015 if the buyer requires private deployment.

**DEFER:** disconnected government, arbitrary provider marketplace, unrestricted agent tools,
real-time token streaming for protected workflows, and a Python-to-Go rewrite.

---

## 29. Commercial Packaging, ROI, and MRR

### 29.1 Sellable packages

| Offer | Outcome | Current readiness | Recurring fit | Build priority |
| --- | --- | --- | --- | --- |
| Verified AI Governance Baseline | Evidence-backed current-state assessment and remediation plan | Nearest to sellable through existing assessment system | Acquisition offer | Highest now |
| Verified AI Workspace | Governed AI access, RAG, DLP decisions, activity dashboard | Partial architecture, not yet defensible end to end | Strong | Highest Workspace target |
| Verified Workspace Private | Customer-controlled/private processing with receipts | Target only | Strong premium | After first regulated demand |
| Sovereign Workspace | Disconnected/local operation for CUI/restricted data | Target only | High ACV, high burden | Defer |
| Continuous Governance | Remediation monitoring, reassessment, governance deltas | Emerging across platform | Strongest MRR/moat | Build from real customer cycles |

### 29.2 Revenue logic

Workspace should be sold as a governed outcome, not seats plus model access:

- enable employees to use approved AI without assembling a separate DLP, RAG, model-routing,
  evidence, and compliance stack;
- keep restricted data in its approved boundary;
- show what was used, stopped, transformed, released, and why;
- produce verifiable evidence for security, privacy, risk, and audit teams.

Pricing remains a hypothesis until buyers pay. A useful validation range is approximately
`$3,000-$6,000/month` for a managed standard deployment and `$8,000-$15,000+/month` for
private/regulated operation, plus onboarding and assessment work. These are packaging tests,
not forecasts.

Two premium customers or three standard managed customers can cross `$10,000 MRR`.
The practical path is:

```text
Paid Baseline
  -> prioritized remediation
  -> narrow Verified Workspace pilot
  -> managed governance and usage oversight
  -> verification/reassessment
```

This produces services revenue before recurring conversion and gathers the operational data
needed to improve delivery margin.

### 29.3 ROI order

1. **Truth and containment:** canonical path, safe logging, whole-envelope DLP.
2. **Proof and visibility:** activity ledger, release receipts, dashboard.
3. **High-value workflow:** RAG-backed confidential spreadsheet analysis.
4. **Independent enforcement:** egress gateway.
5. **One paid vertical:** customer-selected industry profile.
6. **Private deployment:** only when contract value supports the operational burden.
7. **Additional verticals and sovereignty:** after repeatable delivery.

### 29.4 Unit economics to measure

- onboarding and integration hours;
- expert review hours per 100 operations and per investigation;
- classifier false-positive/false-negative review cost;
- provider, local compute, storage, and observability cost;
- support incidents and time to resolve;
- gross margin by deployment mode;
- baseline-to-pilot and pilot-to-managed conversion;
- expansion, retention, and time to verified remediation.

Founder labor and manual interventions MUST be included. Automation that removes measured
delivery labor has higher ROI than broad feature expansion.

---

## 30. Market Position and Competitive Boundaries

### 30.1 Category

The recommended category is **Independent AI Governance Assurance**.

The product promise is:

> FrostGate verifies AI governance, not just documents it.

FrostGate should complement rather than require replacement of Microsoft, OpenAI, Anthropic,
ServiceNow, OneTrust, SIEM, DLP, document, ticketing, and cloud systems. Those systems become
identity, content, provider, workflow, or evidence sources. FrostGate owns the cross-system
policy decision, verified data boundary, evidence chain, remediation/reassessment, and
governance outcome history.

### 30.2 Differentiation chain

```text
authorized source
  -> classified evidence
  -> deterministic policy decision
  -> constrained processing
  -> explicit unknowns and limitations
  -> controlled release
  -> signed receipt
  -> remediation
  -> new evidence
  -> independent verification
  -> signed governance delta
  -> longitudinal outcome history
```

Individual pieces are reproducible. The integrated, independently verifiable lifecycle and
the resulting outcome dataset are the defensible asset.

### 30.3 Vendor-native controls are dependencies, not substitutes

Provider retention settings, enterprise RBAC, sensitivity labels, DLP, compliance APIs, and
private endpoints are valuable controls. They do not by themselves provide FrostGate's
cross-provider policy, local analytical boundary, customer-specific evidence lineage,
release receipts, remediation verification, or longitudinal governance delta.

FrostGate MUST consume native controls and posture evidence rather than claiming they do not
exist. Provider and suite vendors will continue improving quickly; differentiation cannot
depend on a static list of missing vendor features.

### 30.4 Claims allowed after proof

- policy-routed access to approved AI deployments;
- visible allow, block, local, private, and transformed decisions;
- evidence-backed answers from authorized sources;
- verified statement of whether raw spreadsheet data left the defined FrostGate boundary;
- signed, reproducible release and governance evidence;
- deployment-specific support for an approved industry profile.

### 30.5 Claims not allowed yet

- bulletproof, zero-risk, or impossible-to-leak AI;
- universal compliance with HIPAA, GLBA, attorney ethics, FedRAMP, CMMC, or any framework;
- autonomous governance;
- complete prevention of all insider misuse or reidentification;
- superior accuracy to named competitors without controlled comparative evidence;
- production local/private/sovereign support before deployment gates pass;
- continuous assurance before recurring collection and reassessment operate in production.

---

## 31. Product, Governance, and Business Metrics

### 31.1 Customer value metrics

- time from approved upload/source connection to useful answer;
- percentage of answers with complete source provenance;
- time saved on approved spreadsheet analysis;
- time from DLP block to safe alternative or disposition;
- percentage of remediation items with verified outcome;
- audit evidence preparation time;
- user adoption among approved workforce cohorts.

### 31.2 Governance metrics

- released operations with valid receipts;
- unknown/unclassified rate;
- blocked, transformed, local, private, and aggregate-only rates;
- unauthorized source and tenant/matter denials;
- policy exception count, age, use, and expiry;
- provider posture freshness;
- stale source and unsupported claim rate;
- classifier precision/recall by industry corpus;
- release scanner escape rate;
- ledger completeness and reconciliation rate.

### 31.3 Business metrics

- qualified opportunities and sales cycle;
- paid Baseline conversion;
- Baseline-to-Workspace and Workspace-to-managed conversion;
- recurring revenue and expansion by deployment/profile;
- gross margin including expert and founder labor;
- logo and revenue retention;
- implementation time and support burden;
- verified governance outcomes accumulated per customer;
- reusable evidence mappings and remediation-pattern coverage.

Metrics MUST expose sample size and period. Early customer results are evidence about those
customers, not universal market performance.

---

## 32. Governance and Change Control

### 32.1 Policy lifecycle

```text
DRAFT
  -> VALIDATED AGAINST CORPUS
  -> SIMULATED AGAINST RECENT METADATA
  -> REVIEWED
  -> APPROVED
  -> SCHEDULED
  -> ACTIVE
  -> SUPERSEDED or REVOKED
```

Activation requires separation of author and approver for production-regulated profiles.
Every operation pins the effective policy version. Rollback creates a new governed activation
event; history is not rewritten.

Policy simulation MUST report expected allow, deny, transform, local/private route, unknown,
and false-positive changes without exposing historical raw content to unauthorized reviewers.

### 32.2 Classifier, model, and route lifecycle

Every classifier, embedding model, generative model, parser, transformation, and release
scanner version requires:

- artifact identity and integrity hash;
- source/license and supported deployment modes;
- owner and approval record;
- relevant golden-corpus and regression results;
- known limitations and prohibited uses;
- activation and retirement dates;
- rollback plan;
- compatibility with indexes, policies, and receipts;
- production observation and drift review.

A vendor alias that can move to a different model is not sufficient provenance for regulated
operations. Pin a deployment/snapshot where the provider supports it and record actual response
metadata.

### 32.3 Exception lifecycle

Exceptions MUST be narrow, time-bound, and visible. Each records:

- requester, owner, approver, and affected tenant;
- business purpose and exact policy/resource scope;
- risk, compensating controls, and customer impact;
- start and expiry;
- usage count and linked operations;
- review, revocation, and incident history.

There is no permanent wildcard exception. Break-glass access requires stronger authentication,
explicit reason, immediate audit event, alert, and retrospective review.

### 32.4 Documentation discipline

This document is the canonical target and current-state index for Workspace. Every Workspace PR
MUST update the relevant component status, contract, decision, test gate, and repository path in
the same change. Runtime behavior wins over this document when they conflict, and that conflict
must be registered and resolved rather than hidden.

Generated OpenAPI and client types must be regenerated from canonical contracts. Operator,
customer, security, privacy, deployment, and incident documentation must not claim capability
before the corresponding production-proof gate passes.

---

## 33. Decisions and Open Questions

### 33.1 Established decisions

| ID | Decision | Rationale |
| --- | --- | --- |
| `AW-D-001` | FrostGate authorizes; external IdPs authenticate | Keeps tenant policy and governance authority inside FrostGate |
| `AW-D-002` | One canonical Workspace operation service | Eliminates divergent UI, RAG, DLP, and persistence behavior |
| `AW-D-003` | Classify the complete execution envelope | Sensitive data can enter through context, retrieval, tools, and output |
| `AW-D-004` | No weaker trust-class fallback | Availability must not silently defeat data policy |
| `AW-D-005` | Local deterministic analysis precedes external reasoning for protected tables | Raw rows need not leave the approved boundary |
| `AW-D-006` | Raw content is not the compliance ledger | Oversight should not create a second leakage repository |
| `AW-D-007` | Every release has a verifiable receipt | Makes the actual processing claim inspectable |
| `AW-D-008` | Provider is deployment posture, not brand | Retention, region, endpoint, contract, and features differ |
| `AW-D-009` | Industry profiles are additive policy packages | Preserve one product while supporting distinct obligations |
| `AW-D-010` | Visible unknowns are a feature | Unproven facts must not become reassuring fiction |
| `AW-D-011` | Keep Python for the application/domain path | A rewrite adds risk without improving policy semantics |
| `AW-D-012` | Go is optional for a hardened egress component | Language choice helps implementation properties, not policy authority by itself |
| `AW-D-013` | Build one paid vertical before several speculative ones | Concentrates proof, corpus quality, and commercial learning |
| `AW-D-014` | Assessment leads; Workspace expands | Fastest path to cash and qualified recurring use |

### 33.2 Product questions requiring buyer evidence

| Question | Decision evidence needed | Default until resolved |
| --- | --- | --- |
| Which vertical is first? | Paid design partner, data flow, buyer urgency, contract value | Remain vertical-neutral; no compliance claim |
| Which three spreadsheet jobs matter most? | Observed customer workflows and acceptable outputs | Summary, reconciliation, exception analysis only |
| Who owns DLP investigations? | Customer operating model and liability allocation | Tenant security/compliance role |
| Is end-user provider choice valuable? | Buyer/user research | Show processing mode; hide arbitrary provider choice |
| What dashboard retention is required? | Contract, legal/privacy review, buyer audit process | Metadata only with configurable policy |
| What level of human review is required? | Use-case risk and buyer acceptance | Human review for material external decisions |
| What recurring package converts? | Paid Baseline follow-through | Managed governance with narrow Workspace pilot |

### 33.3 Technical questions requiring spikes or tests

| Question | Required proof |
| --- | --- |
| Policy engine technology and ownership | Determinism, explainability, versioning, performance, operator ergonomics |
| PostgreSQL RLS shape for ledger partitions | Cross-tenant tests, migration plan, query performance, restore behavior |
| Local analytics engine | Parser safety, deterministic results, resource isolation, supported formulas/types |
| Aggregate disclosure budget | Industry/privacy review and adversarial differencing tests |
| Embedding deployment | Quality, isolation, licensing, cost, latency, index compatibility |
| Receipt signature/key architecture | Rotation, compromise recovery, external verification, retention |
| Egress gateway language/runtime | Measured enforcement, operability, throughput, and bypass resistance |
| Customer VPC control plane | Upgrade, telemetry, support, secret/key ownership, failure responsibilities |

Open questions are not permission to invent permissive defaults. Unknown security-relevant
configuration fails closed for the affected operation.

---

## 34. Repository Ownership and Maintenance Map

### 34.1 Current implementation owners

| Area | Current repository location | Required evolution |
| --- | --- | --- |
| Console Workspace | `apps/console/app/dashboard/assistant/page.tsx` | Canonical operation contract, sources, modes, protection/provenance UI |
| Portal assistant | `apps/portal/app/assistant/page.tsx` | Engagement-scoped subset and explicit Portal authority |
| Visible UI API | `api/ui_ai_console.py` | Thin adapter to canonical orchestrator |
| AI-plane API | `api/ai_plane_extension.py` | Thin adapter or retirement after consumer migration |
| AI-plane domain service | `services/ai_plane_extension/` | Reuse policy/provenance logic behind canonical operation |
| Provider dispatch | `services/ai/dispatch.py` | Canonical egress interface and eventual gateway client |
| Provider adapters | `services/ai/providers/` | Deployment posture, idempotency, telemetry, controlled payload |
| Tenant AI policy/routing | `services/ai/policy.py`, `services/ai/routing.py` | Versioned effective policy and data-class routes |
| PHI controls | `services/phi_classifier/`, `services/provider_baa/` | Detector expansion and healthcare profile integration |
| RAG context | `services/ai/rag_context.py` | Canonical authorized retrieval and envelope classification |
| RAG APIs | `api/rag_retrieval.py`, `api/rag_corpus_ingestion.py` | Classification, ACL, spreadsheet pipeline, canonical operations |
| RAG safety/answering | `api/rag/safety.py`, `api/rag/answering.py` | Active provider path integration and adversarial proof |
| Semantic/hybrid retrieval | `api/rag_semantic_retrieval.py`, `api/rag_hybrid_retrieval.py` | Production embedding dependency and lifecycle |
| Embeddings | `api/embeddings/` | Replace test stub in production modes |
| Provenance/validation | `services/ai/provenance.py`, `services/ai/response_validation.py` | Release receipt and full operation linkage |
| Provider governance UI/API | `api/ui_provider_governance.py`, Console provider pages | Deployment posture registry and drift evidence |
| Go sidecar | `supervisor-sidecar/main.go` | Keep non-authoritative unless a separately scoped gateway is approved |
| Migrations | `migrations/postgres/` | Ledger, operation, policy, receipt, dataset, RLS, retention additions |
| Operator docs | `docs/operators/console_user_guide.md` | Correct runtime contradictions and document proven behavior |

### 34.2 Required new logical ownership

Repository placement should follow established local conventions after maintainers review it,
but these boundaries must exist:

- Workspace contracts and operation state machine;
- canonical Workspace orchestrator;
- classification aggregation and policy decision service;
- local file quarantine and spreadsheet analysis worker;
- secure provider egress interface/gateway;
- controlled output release and receipt signer;
- privacy-safe activity ledger and dashboard projections;
- versioned industry profiles and golden corpora;
- provider deployment posture verifier;
- Workspace production-proof harness.

### 34.3 Migration discipline

1. Introduce new contracts and tables without changing existing consumer behavior.
2. Dual-write only when reconciliation and rollback are explicit.
3. Move one route/consumer at a time to the canonical service.
4. Compare old/new behavior with privacy-safe fixtures.
5. Stop raw writes before removing old readers.
6. Preserve required evidence and legal holds.
7. Remove compatibility code only after runtime telemetry proves no consumer remains.

---

## 35. External Control References

These references constrain profile design; they do not certify FrostGate or replace legal,
privacy, security, or customer-specific review. They were verified on 2026-09-08.

### 35.1 Healthcare

- [HHS HIPAA cloud-computing guidance](https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/cloud-computing/index.html)
  explains that a cloud service creating, receiving, maintaining, or transmitting ePHI for a
  covered entity/business associate is itself a business associate and generally requires a
  HIPAA-compliant BAA.
- [HHS minimum necessary guidance](https://www.hhs.gov/hipaa/for-professionals/privacy/guidance/minimum-necessary-requirement/index.html)
  requires reasonable steps to limit many uses, disclosures, and requests for PHI to what is
  needed for the purpose, subject to defined exceptions.

Design implication: PHI detection alone is insufficient. Purpose, minimum-necessary
transformation, service-provider contract posture, access, audit, incident, and deployment
controls are required.

### 35.2 Financial services

- [FTC Safeguards Rule](https://www.ftc.gov/legal-library/browse/rules/safeguards-rule)
  requires covered financial institutions under FTC jurisdiction to protect customer
  information and address service-provider safeguards.
- [FTC business guidance](https://www.ftc.gov/business-guidance/resources/ftc-safeguards-rule-what-your-business-needs-know)
  describes a written information-security program appropriate to business complexity and
  information sensitivity.

Design implication: a financial profile requires more than card-number regexes. It needs
information inventory, provider governance, written policy evidence, monitoring, retention,
incident handling, and customer-specific regulatory scoping.

### 35.3 Legal services

- [ABA Formal Opinion 512](https://www.americanbar.org/content/dam/aba/administrative/professional_responsibility/ethics-opinions/aba-formal-opinion-512.pdf)
  addresses competence, confidentiality, communication, supervision, candor, and fees when
  lawyers use generative AI.

Design implication: legal Workspace design needs matter authority, ethical walls, vendor/input
review, explicit limitations, competent human review, and client/engagement policy. FrostGate
cannot claim that a technical control alone satisfies professional obligations.

### 35.4 Government and CUI

- [NIST SP 800-171 Rev. 3](https://csrc.nist.gov/pubs/sp/800/171/r3/final) defines security
  requirements for protecting CUI in nonfederal systems.
- [NIST SP 800-171 Rev. 3 HTML, Information Flow Enforcement](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/800-171r3/NIST.SP.800-171r3.html)
  distinguishes access from information-flow control and calls for approved flow enforcement
  within and between connected systems.

Design implication: application DLP is not enough for a CUI claim. The deployment boundary,
authorized destinations, network enforcement, system scope, assessment evidence, contractual
requirements, and incident/operations controls all matter.

### 35.5 Current provider and suite controls

- [OpenAI API data controls](https://platform.openai.com/docs/models/default-usage-policies-by-endpoint)
  document endpoint-specific application-state and abuse-monitoring retention, Zero Data
  Retention eligibility, and data-residency limitations. Eligibility differs by endpoint and
  feature.
- [OpenAI Compliance API and audit events](https://learn.chatgpt.com/docs/enterprise/compliance-api)
  provides Enterprise/Edu compliance logs and state APIs for integration with DLP, SIEM, and
  eDiscovery workflows.
- [Anthropic API data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention)
  documents standard, ZDR, and HIPAA-ready arrangements with feature-specific eligibility.
- [Anthropic Workspaces](https://platform.claude.com/docs/en/manage-claude/workspaces) documents
  workspace-scoped members, service accounts, keys, roles, limits, and usage separation.
- [Microsoft Purview DLP for Microsoft 365 Copilot](https://learn.microsoft.com/en-us/purview/dlp-microsoft365-copilot-location-learn-about)
  documents controls for prompts, web search, labeled files/email, uploads, and supported
  policy actions.
- [Microsoft default Copilot DLP policy](https://learn.microsoft.com/en-us/purview/dlp-microsoft365-copilot-location-default-policy)
  warns that the default starts in simulation and must be placed in enforce mode to block.

Design implication: vendor name and enterprise plan are not a data-handling proof. FrostGate
must verify the exact organization/project/workspace, endpoint, deployment, feature, region,
retention arrangement, policy mode, and contract, then record that posture with the operation.

---

## 36. Definitions of Done

### 36.1 Feature done

A Workspace feature is done only when:

- its customer outcome and non-goals are explicit;
- authority, tenant/matter boundary, and purpose are enforced server-side;
- input, complete envelope, provider payload, and output release are governed;
- state and side effects are durable, idempotent, and recoverable;
- privacy-safe events and evidence/provenance are generated;
- failure states are visible and fail closed where required;
- unit, negative, integration, contract, and appropriate E2E tests pass;
- deployed production-like proof covers the real dependencies;
- observability, operations, incident, retention, and deletion behavior are documented;
- customer-facing claims match the proven deployment.

### 36.2 Customer-One done

Customer One is ready only when the contracted narrow use case passes section 27, a named
operator can onboard and support it without SQL or source changes, the customer accepts the
data flow and responsibility matrix, and FrostGate can reproduce the release evidence after
restart and restore.

Features outside that contract must be disabled or clearly unavailable, not presented as
almost complete.

### 36.3 MRR-ready done

Workspace is MRR-ready when at least one customer has:

- used the governed workflow repeatedly;
- accepted the dashboard and evidence as useful;
- renewed or converted to a paid recurring package;
- completed an incident/support/recovery exercise or equivalent proof;
- produced measured delivery cost and gross-margin data;
- generated at least one baseline-to-remediation-to-verification history.

Three signed subscriptions without repeatable delivery are bookings, not proof of a
supportable recurring product.

---

## 37. Final Build Direction

Build the Workspace as a constrained, evidence-producing system around the code that already
exists:

```text
canonical operation
  -> canonical actor and purpose
  -> complete-envelope classification
  -> deterministic policy
  -> approved local/private/provider execution
  -> controlled output release
  -> privacy-safe activity event
  -> signed release receipt
  -> customer dashboard
```

The shortest defensible path is not a total redesign, a Python-to-Go migration, every industry
profile, or a local foundation model. It is convergence and proof:

1. unify the existing Workspace, RAG, DLP, provider, and persistence paths;
2. contain raw logging and create the governance ledger;
3. enforce policy over the whole data path;
4. make real RAG and provenance visible;
5. build safe local spreadsheet computation and aggregate release;
6. expose truthful compliance oversight;
7. add independent network enforcement;
8. validate one paid industry profile;
9. add private/local deployment only when a customer requirement and contract support it.

The business outcome is a product that lets an organization use multiple AI capabilities
without independently assembling every control, while preserving the organization's
responsibility and choice. FrostGate should never sell delegated confidence. It should sell a
verifiable record of what was authorized, what data crossed which boundary, what produced the
answer, what was stopped, and whether governance outcomes improved.

**Trust, but Verify.**
