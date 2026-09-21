# CLIENT-READINESS-001 — Client Readiness & Billable Assessment Audit

## 1. Executive Summary

**Audit date:** 2026-09-19

**Branch:** `audit/client-readiness-billable-assessment`

**Starting SHA:** `4560cf763bc8a453ffe01765d03a5f05b370e9cf`

**Commercial target:** The High Table Financial

**Principle:** Trust, but verify.

FrostGate has a credible, tenant-isolated Field Assessment spine. The tested
production handlers can create a tenant-bound engagement, ingest synthetic
evidence, compute a server-side evidence fingerprint, generate a signed report
whose result-truth gate is `PASS`, create an immutable report version, submit
it for review, and record QA approval. A second tenant cannot read the
engagement or report. A delivery attempt without production qualification is
rejected without changing the approved version or its delivery history.

That is not yet a complete billable enterprise assessment. The first native
golden path stops at production qualification. Generated reports always embed
`production_qualification.status=NOT_REQUESTED`; no application authority was
found that can independently produce the four required attestations and move a
specific report to `QUALIFIED`. The delivery operation is therefore correctly
blocked. Even after qualification, the current delivery handler records a
generic `downloaded` event and timestamp; it does not record a recipient,
delivery channel, receipt, or actual artifact transfer.

The audit found one external identity-integrity blocker, CR-707-001: the
legacy `POST /identity/invitations/accept` endpoint was public and accepted a
caller-supplied `accepted_by`. IDENTITY-ACCEPT-002 removed that route after
confirming no production consumers. Possession of a valid invitation token was
still required and the invited identity was established earlier, so this was
not a proven arbitrary tenant takeover; it did permit invitation consumption
and forged acceptance attribution. The canonical route remains protected by
the admin gateway and a verified named user; regression proof now records the
legacy authority as retired.
be retired or brought under that authority.

**Disposition of product readiness:** first managed paid client **BLOCKED**.
The repository can safely support an internal/design-partner rehearsal through
QA and a truth-passing report, but it cannot yet complete a governed customer
delivery without either bypassing an explicit gate or using an unimplemented
external delivery control. Neither is acceptable.

**Disposition of this audit artifact:** ready for review when its focused test
and documentation gates are green. No production behavior is changed by this
work item.

## 2. Audit Scope

This audit traced the customer journey from Platform Admin provisioning through
tenant administration, engagement creation, evidence, assessment, findings,
remediation, reporting, QA, result truth, production qualification, delivery,
and recovery. It inspected the Console, BFF, Core routes, services,
persistence, tests, runbooks, and prior proof artifacts. It used only synthetic
tenants and data:

- Tenant A: The High Table Financial / `high-table-financial-707`
- Tenant B: Continental Holdings / `continental-holdings-707`
- Operator: FrostGate Operator
- Sentinel: `HIGH_TABLE_ONLY_707`

No production system, customer data, qualification record, or delivery state
was modified. #703–#706 authority controls are inherited evidence and were
rechecked only where the golden path crosses them.

## 3. Methodology

1. Synchronized clean `main`, recorded the base SHA, preserved every stash,
   and created the audit branch.
2. Traced runtime mounts and production callers rather than inferring behavior
   from filenames.
3. Built the topology and state machine from production handlers and services.
4. Exercised focused real FastAPI handlers with real security decisions and
   repository persistence; external infrastructure was not invoked.
5. Reused #706 tenant-isolation evidence and ran its Core and Console suites.
6. Ran existing provisioning, identity, evidence, reporting, remediation,
   backup, recovery, and determinism suites.
7. Added one #707 boundary test that intentionally stops at the first native
   commercial blocker. It does not seed qualification or bypass result truth.

## 4. Evidence Labels

| Label | Meaning |
| --- | --- |
| PROVEN | Exercised across a production decision and persistence boundary in this audit or a current-base inherited proof |
| TESTED | Automated test exercised the stated component or boundary |
| INSPECTED | Production implementation and callers were traced, but not executed end to end here |
| INFERRED | Conclusion follows from multiple inspected facts but lacks direct execution |
| PARTIAL | Some required links exist and others do not |
| BLOCKED | A required authority, control, or transition prevents safe completion |
| NOT IMPLEMENTED | No native capability was found |
| NOT TESTED | In scope, but no reliable execution evidence was obtained |
| DEFERRED | Intentionally outside #707 implementation scope |

## 5. System Topology

| Stage | UI | BFF/API | Core service | Persistence | Authority | Tests | Operational dependency | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Provision client | Console tenant administration | `/api/admin/provision-tenant` | tenant create, identity binding, credential issue, initial role | Core DB + Auth0 + Redis/Upstash registry | Platform Admin only | 110 Python + 24 Node focused | Auth0 M2M, Core, Redis/Upstash, secrets | TESTED |
| Activate tenant admin | invitation UI | Console Core proxy; canonical `/identity/invitations/{token}/accept` | invitation flow, principal/membership binding, projection outbox | identity, tenant users, audit, outbox | named human + admin gateway | invitation and identity suites | Auth0, email, projection worker | TESTED |
| Legacy invite acceptance | none required | retired `/identity/invitations/accept` | none (route removed) | none | no authority | IDENTITY-ACCEPT-002 regression suite | none | PROVEN (retired) |
| Tenant workspace | Console | tenant-aware BFF | tenant admin/lifecycle/credential services | tenant, identity, credential, portal tables | #703–#706 canonical authority | #704 45; #705 66; #706 81 + 5 | session, Core, tenant credential | PROVEN |
| Engagement | Field Assessment Console | `/api/core/field-assessment/*` | Field Assessment store/routes | `fa_engagements` + audit | tenant credential scopes/permissions | focused FA suites | Core DB | TESTED |
| Scope | Field Assessment metadata/playbooks/targets | Field Assessment routes | engagement metadata, verified targets, questionnaires | `fa_*` | tenant scope | component tests | operator judgment | PARTIAL |
| Evidence request/collection | questionnaire, scan, upload views | Field Assessment routes | scan ingestion, artifact upload, provenance, evidence links | `fa_scan_results`, artifacts, provenance, links | tenant scope + evidence permissions | evidence/provenance suites | connectors; local artifact filesystem by default | TESTED |
| Assessment execution | Field Assessment | scan/questionnaire/report routes | normalization, scoring, readiness, epistemic and truth engines | findings, questionnaire, report records | tenant scope | extensive component tests | some connector/LLM dependencies | TESTED |
| Findings | Field Assessment/Portal | finding routes | finding store, status and evidence links | normalized findings + audit | tenant scope | closed-loop/forensic tests | human review | TESTED |
| Remediation | roadmap UI + separate authority APIs | Field finding routes and `/remediation-authority/*` | hints/status/roadmap plus separate plan/task engine | separate `fa_*` authorities | tenant scope/RBAC | 78 portal tests alone + remediation suites | operator coordination | PARTIAL |
| Report generation | Field Assessment | report generate/export/version routes | deterministic report compiler, signing, manifest | report record, evidence-report links, versions | report permissions | report/truth/determinism suites | signing key; PDF library; optional Anthropic summary | TESTED |
| Human QA | Field Assessment | QA and version approval routes | approval decision + immutable version state | report version, delivery event, audit | `report.qa_approve` | focused tests | human reviewer | PARTIAL |
| Result truth | no independent UI required | report generation/delivery | result-truth gate | embedded signed report state | deterministic gate | #707 real path + truth suites | complete evidence/claims | PROVEN |
| Production qualification | no complete UI found | delivery reads qualification | validation only; no native writer found | embedded report field only | four required production authorities | negative tests | independent attestations absent | BLOCKED |
| Controlled delivery | report-version endpoint | `/deliver` | qualification check then status/event | report version + delivery history | report generation permission | secure-refusal proof | recipient/channel not modeled | BLOCKED |
| Supersession/history | Field Assessment | version/supersede/history routes | immutable version lineage | versions + append-only events | tenant/report permissions | existing tests blocked at truth baseline | prerequisite delivery | PARTIAL |
| Operations/recovery | operator scripts/runbooks | backup tooling and job status | durable scan-job ledger, lease/orphan logic | DB backup; local artifact bytes separate | operator | 313 focused tests; 2026-08-06 restore drill | offsite backup, scheduler, artifact backup | PARTIAL |
| Billing | no canonical enterprise engagement UI | generic billing/Stripe paths | parallel subscription/payment services | billing tables | mixed | component evidence only | Stripe or manual invoice | PARTIAL |

The Field Assessment system is the strongest enterprise-assessment spine. The
generic `/assessment` and legacy report/payment flows are parallel product
paths; they were not treated as authority for the enterprise golden path. In
particular, a development payment bypass and process-local report task do not
prove enterprise billing or delivery.

## 6. Golden-Path State Machine

The repository does not implement the convenient linear state machine implied
by product language. The actual connected path is:

```text
tenant created
  -> identity binding / initial membership active
  -> engagement(in_progress)
  -> evidence + questionnaire + findings evolve while engagement remains in_progress
  -> signed report record generated
  -> report version(draft)
  -> report version(internal_review)
  -> report version(approved)
  -> delivery requires truth PASS + production QUALIFIED
  -> BLOCKED because generated qualification is NOT_REQUESTED

If all delivery/readiness gates passed:
  engagement delivered -> remediation | monitoring | closed
  remediation -> monitoring | closed
  monitoring -> remediation | closed

Manual in_progress transition:
  in_progress -> cancelled
```

| From | Action | Actor | Required authority | Validation | Persistence/audit | Output / next state | Failure/retry |
| --- | --- | --- | --- | --- | --- | --- | --- |
| no tenant | provision | Platform Admin | positive Platform Admin gate | tenant/input/identity/provider checks | tenant, identity binding, credential, role, registry events | provisioned tenant | staged failure responses; one stuck-slot case requires engineering |
| invited | accept canonical invite | invited named human | gateway + verified subject/email + token | token, email, membership lifecycle | principal/membership/audit/outbox | active bound membership | expired/revoked/replayed fail closed |
| no engagement | create | assessor/operator or permitted credential | governance write + engagement create permission | bound tenant, input schema | engagement + audit | `in_progress` | request retry; idempotency not established for create |
| in_progress | collect evidence | assessor/customer/operator | evidence permissions | engagement tenant/state, evidence schema/hash | scan/artifact/provenance/link + audit | evidence available | scan jobs have ledger/retry subset; interactive scans non-retryable |
| in_progress | generate report | assessor/operator | report generate | evidence population, trust/readiness/truth compilation | signed report + evidence links | report record | regenerate creates a new report record/version context |
| report record | create version | assessor/operator | report generate | tenant/report existence | version, manifest hash, generated event | draft | conflict returns 409/retry |
| draft | submit | assessor/operator | report generate | exact draft state | reviewed event + audit | internal_review | invalid state returns 409 |
| internal_review | approve | QA-capable actor | report QA approve | exact state | immutable approved version + actor metadata + audit | approved | invalid state returns 409; no structural different-person rule |
| approved | deliver | report actor | report generate | result truth PASS; qualification QUALIFIED; four production gates | only on success: delivered timestamp/event/audit | delivered | 422 before mutation when qualification absent |
| delivered | supersede | report actor | report generate | newer approved version | parent/successor lineage + event | superseded | prerequisite state enforced |

## 7. Actor and Authority Matrix

| Action | Initiator | Authorizer | Tenant authority | Human identity retained? | Customer self-service? | Separation concern |
| --- | --- | --- | --- | --- | --- | --- |
| Provision tenant | Platform Admin | Console + Core platform authority | selected customer | yes in provisioning path | no | appropriate managed-service operation |
| Invite/administer users | Tenant Admin or Platform Admin | canonical membership and role | canonical own tenant or explicit platform selection | yes on #703 delegated admin paths | yes, within delegation ceiling | last-admin and role ceilings enforced |
| Accept canonical invite | invited user | gateway + verified named subject | invitation tenant | yes | yes | legacy public route bypasses this attribution model |
| Create engagement | Field Assessment user via Console | tenant service credential in Core | BFF-selected canonical tenant | **no; service credential substitutes for browser human** | UI-capable, attribution incomplete | audit actor can be the credential rather than named human |
| Upload/ingest evidence | assessor/customer/operator | tenant credential + permissions | engagement tenant | incomplete on Console path | partial | same attribution gap |
| Generate report | assessor/operator | tenant credential + report permission | engagement tenant | incomplete on Console path | partial | generator and reviewer capabilities may coexist |
| Approve report | QA actor in API model | `report.qa_approve` | engagement tenant | actor is recorded, but Console path may be service credential | no proven independent reviewer | self-approval is structurally possible |
| Produce qualification | unknown | no native authority found | report/result/evidence should be bound | N/A | no | NOT IMPLEMENTED |
| Deliver | report actor | report generate + gates | engagement tenant | incomplete on Console path | no proven customer delivery | no recipient/receipt; event says downloaded |
| Remediate | tenant/operator actors | multiple field and remediation authorities | tenant | varies by route | partial | fragmented lifecycle authority |

Service credentials prove the tenant-scoped application caller. They do not by
themselves prove which human performed the action. #706 explicitly recorded
this residual for non-administrative tenant-credential route families. #707
confirms Field Assessment is commercially affected by it.

## 8. Tenant and Client Provisioning

**TESTED.** The Console provisioning route positively requires Platform Admin,
creates the Core tenant, establishes an Auth0 organization binding, issues a
tenant-scoped credential, assigns an initial tenant-admin role, and persists
the credential/registry material in Redis or Upstash. Successful responses do
not return the raw Core key. Focused provisioning and identity suites passed.

**Operational dependencies:** Auth0 Management API, Core API, Redis/Upstash,
gateway/platform credentials, email, and the identity projection worker.

**Friction:** a revoked credential occupying a provisioning slot can produce a
`SLOT_STUCK` response whose operator remediation is literal SQL. This is an
engineering workaround, not a managed-service step.

## 9. Tenant Admin Experience

**PROVEN by inherited current-base #703–#706 tests.** A tenant administrator can
enter only its workspace, manage permitted users/access/credentials, and reach
Field Assessment without receiving the global customer registry, tenant
creation controls, a tenant switcher, foreign data, or operator fallback.
Missing tenant context does not select `CORE_TENANT_ID`. Direct hidden routes
remain authorization-protected.

This audit did not repeat every #706 attack. It ran the canonical #704, #705,
and #706 suites and added a real two-tenant Field Assessment read/delivery
boundary test.

## 10. Engagement Lifecycle

**TESTED/PARTIAL.** Engagement creation binds `tenant_id` from authenticated
context and persists an audit event. Cross-tenant reads return the same 404
shape used for absent resources in the tested path. The lifecycle enum and
transition table are explicit.

Scope is not a single authoritative object/state transition. It is distributed
across engagement metadata, playbooks, questionnaires, verified targets, and
operator judgment. Scope changes can be reflected in those records, but this
audit did not find one versioned, approved scope baseline whose mutation
automatically invalidates QA/qualification. Engagement creation idempotency was
not established.

## 11. Evidence Pipeline

**TESTED.** The tested scan path stores collection source/time, tenant and
engagement binding, raw evidence, a server-computed deterministic evidence
hash, provenance records, and evidence/report links. Uploaded files compute
SHA-256 server-side and compare any caller-supplied digest in constant time.
Artifact metadata and provenance are database-backed.

**PARTIAL operational durability.** Uploaded bytes default to
`FG_ARTIFACTS_DIR` (otherwise local `artifacts/evidence_files`). Database backup
proof does not by itself prove backup/restore of these bytes. A production
object-storage/backup binding was not proven in this audit.

**Confidentiality finding.** Scan ingestion returns the submitted `raw_payload`
in its browser-visible response. Tenant isolation still applies, but this
unnecessarily expands sensitive evidence into browser memory and payload logs.

## 12. Assessment Execution

**TESTED.** Framework/questionnaire population, finding normalization,
readiness, scoring, evidence sufficiency, epistemic state, material claims,
result snapshots, report hashes, and policy/schema metadata have substantial
component coverage. FGA-025–028 fixed and test the previously identified
semantic inversion and complete-evidence/report grounding boundaries.

The strongest reproducible part is deterministic report truth and manifests.
Some executive narrative can be AI-generated when Anthropic is configured and
falls back to a template when it is not. The system distinguishes evidence
truth fields from the narrative layer, but a full reviewer reproduction from a
fresh production tenant was not performed here.

## 13. Findings

**TESTED.** Findings are tenant/engagement bound and support severity,
confidence, evidence linkage, controls, status, remediation hint, audit events,
and report inclusion. The tested report derives findings and claims from the
complete eligible evidence population. A finding can be created/imported
without an evidence link in some paths; readiness/truth layers must therefore
continue to label unsupported claims rather than silently treating them as
verified.

## 14. Remediation

**PARTIAL.** Field Assessment offers deterministic remediation guidance,
finding status transitions, closure evidence observations, and a roadmap. A
separate remediation-authority subsystem implements plans, tasks, assignments,
dependencies, and verification. No single, tested production path was found
that automatically creates and maintains a canonical remediation plan from a
Field Assessment finding through verified closure. Status vocabularies also
differ between the parallel models.

The portal remediation suite passes alone (78/78) but produced six failures and
63 setup errors when composed after the large remediation/isolation batch due
to leaked unscoped-key fixture state. This is test non-hermeticity, not evidence
of a product regression.

## 15. Report Generation

**TESTED.** The report binds tenant, engagement, evidence population and
fingerprints, findings, claims, epistemic states, policy/schema versions,
signatures, manifest, and version identifiers. Determinism/signing/manifest
focused suites passed.

**Customer-quality gap.** The Field Assessment report does not expose a clear,
first-class, approved engagement scope/methodology/limitations section in the
tested report document. It must not imply certification, legal compliance,
exhaustiveness, guaranteed security, or independent attestation. Those limits
need to be version-bound report content, not only operator knowledge or a
generic disclaimer elsewhere.

## 16. Human QA

**PARTIAL/BLOCKED for a defensible external release.** Approval binds a
specific immutable report version and records approval time, actor, reviewer
name/role, notes, and audit/delivery events. Changes require a new version.

There is no structural rule requiring the reviewer to differ from the report
generator or submitter. The #707 test uses one credential containing both
`report.generate` and `report.qa_approve`, which the production routes accept.
Reviewer name and role are caller-provided metadata. A version-bound,
canonical-person separation rule is required for an independently reviewed
enterprise deliverable.

## 17. Result Truth

**PROVEN for the tested synthetic path.** An internally consistent Microsoft
Graph-shaped scan containing one clearly synthetic user and `object_count=1`
produced a report whose result-truth decision was `PASS`, without direct
database writes, fabricated evidence, or mocked gate logic. The report
contained one eligible evidence item. Delivery then reached the next gate.

The four historical report-delivery tests still construct reports that do not
satisfy current result-truth requirements and fail with
`RESULT_TRUTH_GATE_BLOCKED`. Secure refusal is the correct behavior; #707 does
not weaken or reclassify the gate.

## 18. Production Qualification

**BLOCKED / NOT IMPLEMENTED as an end-to-end authority.** Production report
generation always initializes:

```json
{"status": "NOT_REQUESTED", "qualified": false}
```

Delivery requires `QUALIFIED`, `qualified=true`, result truth `PASS`, and all
four authorities:

- `PRODUCTION_DEPENDENCY_SECURITY`
- `PRODUCTION_SCHEMA_AND_RLS`
- `CANONICAL_ASSESSMENT_PROOF`
- `DURABLE_EXECUTION_AND_RECOVERY`

No native route/service was found that independently requests, produces,
attests, binds, invalidates, and reproduces those qualification facts for a
specific report/result/evidence fingerprint. This is `PROD-QUAL-001`.

`PROD-QUAL-001` is required before any use of the existing in-product delivery
transition. It is not logically required before performing paid assessment
work if FrostGate implements a separate, governed, human-reviewed, auditable
managed-delivery authority. That alternative does not exist today, so one of
those two capabilities is required before the first paid deliverable. The
shortest path is to complete `PROD-QUAL-001` and retain the existing gate.

## 19. Controlled Delivery

**BLOCKED correctly.** In the #707 test, delivery returned HTTP 422
`PRODUCTION_QUALIFICATION_BLOCKED`; the version stayed `approved`,
`delivered_at` remained null, history was unchanged, and no `downloaded` event
was created.

**Additional missing proof:** the success implementation changes state and
records a `downloaded` event. It has no request model for recipient, channel,
destination, receipt, or artifact fingerprint acknowledged by the recipient,
and it does not itself transfer the artifact. Therefore a successful state
transition would not by itself prove that the customer received the report.

## 20. Audit and Lineage Reconstruction

```text
TENANT                         PROVEN
  -> ENGAGEMENT                PROVEN
    -> ASSESSMENT/FRAMEWORK    TESTED
      -> CONTROL/CLAIM         TESTED
        -> EVIDENCE            PROVEN (tested scan path)
          -> RESULT/TRUTH      PROVEN
            -> FINDING         TESTED
              -> REMEDIATION   PARTIAL (parallel authorities)
                -> REPORT      PROVEN
                  -> QA        PARTIAL (actor/SoD)
                    -> QUALIFICATION  MISSING
                      -> DELIVERY     MISSING/BLOCKED
```

An independent reviewer can reconstruct tenant, engagement, evidence hash,
report inputs, result-truth decision, findings, report/version hashes, and QA
metadata for the tested path. They cannot reconstruct a canonical browser
human for ordinary Field Assessment Console calls because the BFF substitutes
the tenant service credential, and there is no qualification or recipient
receipt to reconstruct.

## 21. Security and Isolation Recheck

**PASS for tested boundaries.** Tenant B received 404 for Tenant A's engagement
and report; the Tenant A sentinel was absent from both foreign responses. The
PR #706 Core suite (5/5) and Console suite (81/81), plus #704 (45/45) and #705
(66/66), passed. Existing cross-tenant mutation suites were also exercised in
the larger batch; no product isolation failure was observed. Missing tenant
does not inherit FrostGate operator authority on current base.

The audit does not claim universal noninterference. The focused database is
SQLite; the 150-table PostgreSQL RLS check is inherited from #706 evidence.

## 22. Operational Readiness

**PARTIAL.** Backup/restore tooling, encrypted manifests, recovery scripts,
durable scan-job records, lease/retry/orphan logic, report determinism, and
signing have strong focused coverage. The committed 2026-08-06 drill restored
a backup into a scratch PostgreSQL instance with matching row counts. The
CLIENT-READINESS-001 backup/report reliability batch passed 313 tests.

Remaining concerns are local artifact-byte durability, no proven scheduled
worker invoking orphan recovery in this audit, interactive scans that cannot be
automatically replayed, external email/storage failures, and no end-to-end
partial-delivery recovery because customer delivery is not implemented.

## 23. Manual Intervention Census

| Step | Manual intervention | Actor | Reason | Customer visible? | Audited? | Revenue impact | Required before first client? |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Provision tenant | select/create client and initial admin | Platform Admin | managed onboarding | partly | yes | acceptable friction | yes |
| Auth0/email setup | provider secrets and invitation delivery | Operator | external identity dependency | partly | provider + app events | onboarding dependency | yes |
| Resolve stuck credential slot | run supplied SQL | Developer/DB operator | missing recovery API | no | not inherently | delays onboarding; unsafe workaround | must be eliminated or runbook-governed |
| Create engagement/scope | enter metadata, targets, playbook | Assessor/operator | professional judgment | yes | partial | acceptable managed service | yes |
| Connector authorization | customer IT/device-code steps | Customer IT + assessor | source access | yes | partial | acceptable managed service | as scoped |
| Evidence curation | review/link evidence and claims | Assessor | quality judgment | mostly no | partial | core billable work | yes |
| Findings review | validate severity/support | Assessor | professional judgment | output visible | yes/partial actor identity | core billable work | yes |
| Report QA | review and approve | reviewer | quality control | no | yes, attribution incomplete | required | yes |
| Production qualification | no supported operation | unknown | authority missing | no | no | hard stop | yes |
| Deliver report | no real recipient transfer/receipt | operator | capability missing | would be visible | state event only | hard stop | yes |
| Invoice | manual invoice outside golden path | Operator | enterprise billing not integrated | yes | external | acceptable for first clients | yes |
| Backup artifacts | coordinate DB plus file/object storage | Operator | split persistence | no | partial | recovery risk | yes for uploaded files |

Platform provisioning, assessor-led evidence work, human review, connector
authorization, and manual invoicing are acceptable managed-service operations
when documented and audited. SQL repair, qualification fabrication, direct DB
state changes, and unrecorded file/email delivery are engineering workarounds
and are not part of a safe golden path.

## 24. Commercial Operating Models

| Model | Capabilities already proven | Required humans | Blockers | Current disposition |
| --- | --- | --- | --- | --- |
| A. Fully self-service SaaS | tenant workspace, bounded administration, assessment UI | customer admins/users | provisioning dependencies, scope/evidence curation, remediation integration, QA, qualification, delivery, operations | BLOCKED |
| B. FrostGate-managed enterprise assessment | provisioning, tenant isolation, engagement/evidence/report/truth spine | Platform Admin, assessor, reviewer, operator | invite integrity, named-human audit, QA SoD, qualification, governed delivery | BLOCKED today; shortest target |
| C. Hybrid customer + FrostGate | tenant admin workspace plus managed assessment | customer admin/IT + FrostGate team | same release blockers; customer handoffs incomplete | BLOCKED |
| D. Internal pilot/design partner | full rehearsal through approved truth-passing report, no external delivery claim | FrostGate team + consenting design partner | must stop before qualified delivery | SUPPORTABLE TODAY |

## 25. Findings Inventory

### CR-707-001 — Legacy public invitation acceptance trusts caller attribution

- **Severity / category / status:** P1 / External Safety Blocker / REMEDIATED by IDENTITY-ACCEPT-002
- **Affected component:** retired `api/identity_administration/routes/invitations.py`
- **Observed (audit baseline):** mounted public `POST /identity/invitations/accept` accepted a valid
  token plus caller-controlled `accepted_by`; the legacy route test performed
  the mutation without authentication.
- **Expected:** acceptance actor must be the verified named identity bound to
  the invite, as in the newer canonical route.
- **Root cause:** parallel legacy and canonical invitation authorities remain
  mounted.
- **Security impact:** valid-token invitation consumption and forged acceptance
  attribution; arbitrary tenant takeover was not demonstrated.
- **Commercial impact:** identity/audit integrity is not defensible for an
  external onboarding path.
- **Evidence / reproduction:** source trace, public-path allowlist, and the
  former route tests. No production consumer was found.
- **Remediation / proposed PR / dependencies:** IDENTITY-ACCEPT-002 removed the
  route registration and exact public-path entry, removed its route tests, and
  retained only `POST /identity/invitations/{token}/accept` from
  `api/identity_acceptance.py`. Dedicated regression tests prove no lookup,
  mutation, binding, or caller-attributed acceptance is possible through the
  retired path; canonical verified named-user checks remain covered by P-113.8.

### CR-707-002 — Native production qualification authority is absent

- **Severity / category / status:** P1 / Billable Workflow Blocker / OPEN
- **Affected component:** report generation and delivery.
- **Observed:** reports initialize qualification as `NOT_REQUESTED`; delivery
  reads and enforces qualification, but no producer authority was found.
- **Expected:** independently produced, immutable, fingerprint-bound,
  invalidatable attestations can legitimately reach `QUALIFIED`.
- **Root cause:** enforcement shipped before the qualification workflow.
- **Security impact:** none while fail-closed; bypassing it would be a serious
  integrity defect.
- **Commercial impact:** no native customer delivery can complete.
- **Evidence / reproduction:** `tests/test_client_readiness_001.py` reaches
  truth PASS and receives `PRODUCTION_QUALIFICATION_BLOCKED` without mutation.
- **Remediation / proposed PR / dependencies:** implement `PROD-QUAL-001` with
  positive authority and report/result/evidence fingerprint binding; depends on
  named actors and operational attestation sources.

### CR-707-003 — Field Assessment Console loses named-human attribution

- **Severity / category / status:** P1 / Billable Workflow Integrity / REMEDIATED — FA-ACTOR-001
- **Affected component:** Console Core proxy and Field Assessment audit events.
- **Observed:** ordinary Field Assessment paths previously used a tenant service
  credential without attaching delegation-v3 named-human proof. Core labeled
  some events `human_operator` while the actor could be the service credential.
- **Expected:** every material assessment, evidence, QA, and delivery action
  retains the canonical human actor while tenant/service authentication remains
  independently verified.
- **Root cause:** #703 delegation was scoped to administrative route families;
  #706 explicitly deferred expansion.
- **Security impact:** no cross-tenant bypass observed; attribution and
  non-repudiation are incomplete.
- **Commercial impact:** audit reconstruction and reviewer accountability are
  insufficient for a defensible paid engagement.
- **Evidence / reproduction:** `apps/console/app/api/core/[...path]/route.ts`
  now sends Field Assessment mutations through the existing v3 proof path;
  Core derives mutation/audit actors from `ActorContext.subject`, binds tenant
  context to that authority, and classifies verified human/service actors
  explicitly. Caller-supplied reviewer/approval identity remains metadata.
- **Remediation:** `fix(field-assessment): enforce canonical human actor authority`.
  Focused FA-ACTOR-001 tests prove canonical subject selection, fail-closed
  anonymous actors, tenant consistency, BFF delegation, and non-authoritative
  caller attribution. REPORT-QA-001 remains responsible for reviewer
  independence and separation-of-duties policy.
- **Follow-up correction:** delegated transport credentials no longer grant
  platform-admin capabilities to Field Assessment actors. Core resolves current
  bound canonical membership roles; unbound internal actors cannot mutate Field
  Assessment. Existing internal-console behavior on non-Field-Assessment routes
  remains covered by the security suite.

### CR-707-004 — Delivery is a state flag, not a customer receipt

- **Severity / category / status:** P1 / Billable Workflow Blocker / OPEN
- **Affected component:** enterprise report delivery.
- **Observed:** success would stamp `delivered_at` and write `downloaded`; no
  recipient, channel, destination, transfer, or receipt is captured.
- **Expected:** an immutable artifact is transferred through an approved
  channel with recipient and receipt lineage.
- **Root cause:** lifecycle state was implemented without a governed transport.
- **Security impact:** risk of false delivery claims or uncontrolled manual
  transfer.
- **Commercial impact:** cannot prove the customer received the deliverable.
- **Evidence / reproduction:** inspected `deliver_report_version_route` and its
  request/response/event models.
- **Remediation / proposed PR / dependencies:** `GOV-DELIVERY-001`; depends on
  `PROD-QUAL-001`, artifact storage, and named-human attribution.

### CR-707-005 — QA does not enforce separation of duties

- **Severity / category / status:** P2 / Billable Workflow Blocker / OPEN
- **Affected component:** report version review/approval.
- **Observed:** one credential can generate, submit, and approve; reviewer name
  and role are request body fields.
- **Expected:** canonical reviewer identity differs from generator/submitter or
  an explicit, audited exception is approved.
- **Root cause:** permission separation exists nominally but is not enforced
  against actor identity.
- **Security impact:** self-approval and misleading independence metadata.
- **Commercial impact:** weak external QA claim.
- **Evidence / reproduction:** #707 test completes all three transitions with
  one tenant credential.
- **Remediation / proposed PR / dependencies:** `REPORT-QA-001`; depends on
  `FA-ACTOR-001`.

### CR-707-006 — Billable report lacks version-bound scope and limitations

- **Severity / category / status:** P2 / Billable Workflow Blocker / OPEN
- **Affected component:** Field Assessment report schema/rendering.
- **Observed:** rich evidence/findings/truth metadata exists, but no clear
  first-class approved scope, methodology, and limitations section was found in
  the tested report document.
- **Expected:** customer artifact states what was assessed, methodology,
  exclusions, evidence limits, and non-certification language.
- **Root cause:** report authority emphasizes technical provenance over the
  engagement contract boundary.
- **Security impact:** unsupported or overbroad claims.
- **Commercial impact:** deliverable is not yet defensible as an enterprise
  assessment conclusion.
- **Evidence / reproduction:** inspected report assembly active sections and
  generated #707 JSON.
- **Remediation / proposed PR / dependencies:** include in `REPORT-QA-001` and
  bind content to report hash/version; depends on a canonical scope baseline.

### CR-707-007 — Scan ingestion echoes raw evidence to the browser

- **Severity / category / status:** P2 / Post-Launch Hardening / OPEN
- **Affected component:** scan-result response model.
- **Observed:** the response echoes submitted `raw_payload` despite the Console
  client comment that evidence hashes, not payloads, are displayed.
- **Expected:** mutation response returns identifiers, counts, and hashes only
  unless raw retrieval is explicitly required and authorized.
- **Root cause:** persistence model is reused as response shape.
- **Security impact:** expands sensitive evidence into browser memory/logging;
  no cross-tenant exposure observed.
- **Commercial impact:** avoidable customer-data handling surface.
- **Evidence / reproduction:** observed in the initial #707 focused run and
  confirmed in production route serialization.
- **Remediation / proposed PR / dependencies:** `FA-EVIDENCE-RESPONSE-001`;
  narrow response schema, no architecture dependency.

### CR-707-008 — Uploaded evidence bytes default to local filesystem

- **Severity / category / status:** P2 / Scale and Recovery Blocker / OPEN
- **Affected component:** Field Assessment artifact upload.
- **Observed:** bytes are written under `FG_ARTIFACTS_DIR` or local
  `artifacts/evidence_files`; database provenance references the path.
- **Expected:** durable encrypted object storage, retention/deletion controls,
  and backup/restore proof bind bytes to the database record.
- **Root cause:** local storage implementation remains production-selectable.
- **Security impact:** availability/retention mismatch and possible orphaned
  metadata after host loss.
- **Commercial impact:** uploaded-evidence engagements are not recoverable from
  the database drill alone.
- **Evidence / reproduction:** inspected `_artifact_store_path()` and upload
  route; DB restore evidence does not include artifact bytes.
- **Remediation / proposed PR / dependencies:** `EVIDENCE-STORAGE-001`; depends
  on chosen provider and retention policy.

### CR-707-009 — Provisioning recovery exposes direct SQL workaround

- **Severity / category / status:** P2 / Managed-Service Friction / OPEN
- **Affected component:** tenant provisioning credential slot recovery.
- **Observed:** `SLOT_STUCK` tells an operator to mutate state with SQL.
- **Expected:** idempotent, audited recovery operation or safe compensation.
- **Root cause:** credential issuance and external registry persistence cannot
  always be atomically compensated.
- **Security impact:** privileged manual mutation can bypass lifecycle audit.
- **Commercial impact:** onboarding can require a developer/DB operator.
- **Evidence / reproduction:** inspected Console provisioning failure branch.
- **Remediation / proposed PR / dependencies:** `PROVISION-RECOVERY-001`; no
  first-client dependency if preflight proves clean, but the SQL path must not
  be the operational plan.

### CR-707-010 — Remediation authority is fragmented

- **Severity / category / status:** P2 / Self-Service Blocker / OPEN
- **Affected component:** finding status, remediation roadmap, and
  remediation-authority plans/tasks.
- **Observed:** useful capabilities exist, but no tested canonical link carries
  a Field Assessment finding through a plan/task/verification/closure lifecycle.
- **Expected:** one tenant-scoped, auditable closure authority with evidence.
- **Root cause:** parallel feature stacks evolved independently.
- **Security impact:** state divergence can misrepresent whether risk is closed.
- **Commercial impact:** remediation is operator-managed and hard to reconstruct.
- **Evidence / reproduction:** route/service/test inventory and status-vocabulary
  comparison.
- **Remediation / proposed PR / dependencies:** `FA-REMEDIATION-BRIDGE-001`;
  post-first-delivery if remediation is explicitly out of initial scope.

### CR-707-011 — Cross-tenant export helper omits selected tenant context

- **Severity / category / status:** P2 / Managed-Service Friction / OPEN
- **Affected component:** `apps/console/lib/fieldAssessmentApi.ts`.
- **Observed:** JSON requests append selected `tenant_id`; `requestBlob()` does
  not. Platform Admin exports can therefore resolve operator context rather than
  the selected customer context.
- **Expected:** export uses the same canonical tenant selection as the report
  being viewed.
- **Root cause:** separate request helpers implement inconsistent context.
- **Security impact:** no foreign-data leak was demonstrated; fail-closed tenant
  lookup or wrong-tenant output is expected.
- **Commercial impact:** managed report export can fail or export the wrong
  operator-context resource.
- **Evidence / reproduction:** direct comparison of `request()` and
  `requestBlob()`.
- **Remediation / proposed PR / dependencies:** include a focused fix/test in
  `GOV-DELIVERY-001`; preserve #706 resolver semantics.

### CR-707-012 — Some suites and fixtures do not compose hermetically

- **Severity / category / status:** P3 / Test Quality / OPEN
- **Affected component:** portal remediation and historical delivery tests.
- **Observed:** portal remediation passes alone but fails after a broad batch
  because unscoped-key state leaks; four delivery tests manufacture reports
  that no longer satisfy result truth.
- **Expected:** tests isolate global state and create only legitimate lifecycle
  prerequisites.
- **Root cause:** shared environment/global fixtures and stale state builders.
- **Security impact:** noisy suites can obscure genuine regressions.
- **Commercial impact:** slower, less trustworthy release decisions.
- **Evidence / reproduction:** broad batch `6 failed, 923 passed, 63 errors`;
  isolated portal rerun `78 passed`; focused report batch contains only the four
  known truth failures.
- **Remediation / proposed PR / dependencies:** `TEST-AUTHORITY-001`; preserve
  truth gates and repair fixture authority rather than forcing PASS.

## 26. Revenue, Self-Service, and Scale Blockers

**External safety blocker:** CR-707-001.

**Billable workflow blockers:** CR-707-002 through CR-707-006, plus export and
artifact-recovery constraints where the engagement uses those paths.

**Managed-service friction:** Platform Admin provisioning, operator-led scope,
connector authorization, evidence curation, manual invoicing (acceptable);
direct SQL recovery and wrong-context blob export (unacceptable workarounds).

**Self-service blockers:** operator provisioning/dependencies, professional
scope/evidence curation, QA, qualification/delivery, and remediation
fragmentation.

**Scale blockers:** local artifact storage, manual operations, incomplete
worker/runtime proof, manual billing, and fragmented parallel product stacks.

## 27. Minimum Safe Revenue PR Sequence

### Must have before first paid client

Roadmap authority represents `FG_RESULT_TRUTH_GATE` as an open parent operational-acceptance
objective. `FA-ACTOR-001` is complete through #710/#711 and post-merge proof; the canonical
actor chain now protects material Field Assessment mutations. `REPORT-QA-001` is the sole
immediate engineering prerequisite. This reconciliation changes governance state only; it
does not implement reviewer independence, production qualification, delivery, or truth-gate
semantics. `PROD-QUAL-001` and `GOV-DELIVERY-001` remain blocked.

FA-ACTOR-001 completion evidence: #710 and #711 are merged at `49fe1fcf32a2d28cb74f40523dc2f1cd0c5f4522`; focused actor/Field Assessment proof is 92 passed, with fg-fast 496/2, fg-security 1239/1, fg-contract PASS, and diff-check PASS. The next bounded authority is REPORT-QA-001; no reviewer-independence claim is made here.

| PR ID | Title | Goal / root cause | Exact scope | Dependencies | Security impact | Commercial impact | Complexity | Why now |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| IDENTITY-ACCEPT-002 | Retire legacy caller-attributed invitation acceptance | eliminate parallel public mutation authority | migrate consumers; disable legacy route; canonical subject/token tests | none | closes identity/audit P1 | safe onboarding | S–M | external safety |
| FA-ACTOR-001 | Bind Field Assessment actions to canonical human actors | tenant credential hides human | delegation-v3 on material FA routes; Core actor validation; audit tests | #703–#706 | non-repudiation, no broadened roles | defensible engagement record | M | QA/qualification need real actors |
| REPORT-QA-001 | Version-bound scope, limitations, and independent QA | report contract and SoD incomplete | canonical scope snapshot; report sections; different-person rule or governed exception; invalidation tests | FA-ACTOR-001 | prevents self-approval/overclaim | defensible report | M | external deliverable quality |
| PROD-QUAL-001 | Production Qualification Authority | enforcement has no legitimate producer | request/attest/state machine; independent authorities; fingerprint binding; invalidation/reproduction | FA-ACTOR-001; operational evidence | preserves fail-closed release | unblocks existing delivery gate | L | native hard stop |
| GOV-DELIVERY-001 | Governed client delivery and receipt | delivery is only a state flag | tenant-correct export; immutable artifact; recipient/channel/receipt; idempotency; partial-failure recovery | PROD-QUAL-001, artifact store | prevents false/uncontrolled delivery | completes billable journey | M | payment requires deliverable |

Before contracting the first client, either fix CR-707-008 or explicitly exclude
file-upload evidence and use only sources whose durable persistence/backup is
proven. That constraint must be in scope and customer-facing limitations.

### Must have before self-service

- `PROVISION-RECOVERY-001`: audited recovery instead of SQL.
- `FA-REMEDIATION-BRIDGE-001`: canonical finding-to-closure lifecycle.
- Customer-facing scope/evidence-request ownership and support escalation.
- Invitation/email failure recovery and full browser golden-path proof.

### Must have before scale

- `EVIDENCE-STORAGE-001`: durable encrypted artifact object storage and restore.
- Scheduled durable workers, observed orphan recovery, dead-letter operations.
- Automated retention/deletion, monitoring/SLOs, delivery reconciliation.
- Consolidation or explicit retirement boundaries for parallel assessment,
  report, remediation, and billing stacks.

### Post-launch

- Minimize scan mutation response payloads (`FA-EVIDENCE-RESPONSE-001`).
- Test hermeticity/fixture authority cleanup (`TEST-AUTHORITY-001`).
- Broader UX polish and automation after the managed path has real usage data.

## 28. Negative Golden Path

| Condition | Expected failure | Actual evidence | Persistence/audit effect | Recovery |
| --- | --- | --- | --- | --- |
| missing/insufficient evidence | truth not PASS | known delivery tests fail `RESULT_TRUTH_GATE_BLOCKED` | no delivery mutation | collect legitimate evidence/regenerate |
| foreign engagement/report | indistinguishable not-found | #707 returns 404, sentinel absent | no foreign mutation | use authorized tenant |
| missing tenant/operator fallback | deny or canonical own tenant | #706 suites pass | no operator exposure | restore valid context |
| no qualification | 422 before delivery | #707 exact result | approved version/history unchanged | obtain legitimate qualification |
| duplicate/stale delivery | state transition rejected | existing route/state tests | immutable history | create/supersede valid version |
| evidence/report changed after QA | new version/invalidation required | immutable approved version exists; automatic cross-authority invalidation not fully proven | PARTIAL | REPORT-QA-001 |
| inactive/revoked membership | next request denied | inherited identity/tenant-access tests | no authorized business mutation | authorized reactivation |
| connector/job failure | durable failure/dead-letter state | service/tests inspected | job state persists | retry eligible jobs or operator intervention |

## 29. Data and Claim Boundaries

The report model distinguishes raw evidence, normalized findings, material
claims, epistemic states, confidence, executive narrative, QA metadata, truth,
and qualification. This is materially stronger than treating every customer
answer as verified fact. The following boundaries still require operating
discipline:

- Customer assertions and questionnaire answers are not automatically system
  observations.
- Evidence-backed claims must retain evidence IDs/hashes and epistemic state.
- AI-generated executive prose is advisory narrative, not an independent
  attestation.
- Human judgment must be attributed to a canonical human, not merely a tenant
  service credential.
- A truth `PASS` does not mean production qualification or certification.
- An approved version does not mean it was delivered.

## 30. Test Gap Analysis

| Workflow stage | Existing tests | What they prove | Missing proof |
| --- | --- | --- | --- |
| Provisioning | tenant create, IA-1, golden path, Console source/runtime tests | staged creation, role/identity behavior, Platform Admin UI policy | live clean provisioning with all external dependencies and compensation |
| Tenant admin | #703–#706 suites | canonical authority, isolation, fail-closed missing context | ordinary FA named-human delegation |
| Engagement/evidence | Field Assessment/provenance/forensic suites | tenant binding, hashing, provenance, readiness components | one production browser journey and durable external artifact restore |
| Assessment/truth | FGA-025–028, truth tests, #707 | grounded complete evidence and legitimate truth PASS | expert-approved real-client corpus/current production proof |
| Findings/remediation | closed-loop and remediation suites | component lifecycle and tenant checks | canonical bridge across parallel authorities |
| Report/QA | report/signing/version tests | hashes, immutability, transitions | independent canonical reviewer and scope invalidation |
| Qualification | negative enforcement tests | invalid/missing qualification blocks | legitimate attestation production |
| Delivery | four historical tests plus #707 | secure refusal; intended version model | successful legitimate delivery, recipient receipt, supersession after it |
| Recovery | backup/job/report reliability suites | DB restore and component recovery/determinism | artifact-byte restore and observed production worker recovery |

Tests that direct-write database rows or construct otherwise unreachable states
remain useful unit/component evidence, but they are not golden-path proof. #707
adds a real route/persistence chain and deliberately does not create impossible
qualification state.

## 31. Client Readiness Scorecard

```text
CLIENT READINESS
============================================================

External safety             BLOCKED
Tenant isolation            PASS
Client provisioning         PASS
Tenant administration       PASS
Engagement creation         PASS
Assessment execution        PASS
Evidence integrity          PASS
Evidence lineage            PASS
Findings                    PASS
Remediation                 BLOCKED
Report generation           PASS
Human QA                    BLOCKED
Result truth                PASS
Production qualification    BLOCKED
Controlled delivery         BLOCKED
Audit reconstruction        BLOCKED
Operational recovery        BLOCKED

FIRST MANAGED PAID CLIENT
    BLOCKED

SELF-SERVICE CUSTOMER
    BLOCKED

SCALE-READY
    BLOCKED
```

`PASS` means the tested requirement is adequate for this scoped stage; it does
not imply universal production proof. Evidence integrity/lineage PASS is scoped
to the synthetic scan path and report chain. Uploaded artifact recovery remains
an operational blocker.

## 32. Exact Answer for The High Table Financial

If The High Table Financial signed tomorrow, FrostGate could safely provision
its tenant through the Platform Admin flow, establish an Auth0 organization and
tenant administrator, let that administrator enter only its own workspace and
administer permitted access, create a tenant-bound Field Assessment engagement,
record scope metadata, collect supported scan/questionnaire/upload evidence,
hash and link that evidence, calculate findings and claims, generate a signed
versioned report, submit it for human review, and obtain a truth-gate `PASS`
when the evidence genuinely supports the result. Continental Holdings and the
FrostGate operator tenant would remain outside the tested customer boundary.

The workflow would stop after QA approval and before delivery. Production
qualification cannot be legitimately created through a native authority, and
the delivery operation correctly refuses to mutate state. FrostGate could not
truthfully claim that an approved report was production-qualified, delivered,
received, or independently reviewed merely from the current fields.

Manual intervention would include Platform Admin onboarding, Auth0/email
operations, assessor-led scope and evidence curation, connector authorization
with customer IT, findings review, human QA, operational backup checks, and a
manual invoice. Those are acceptable for a managed service if named and
audited. Direct SQL repair, fabricated qualification, forcing truth PASS,
editing database state, or emailing/copying an artifact without a governed
receipt are not acceptable.

The minimum engineering is: close the legacy invitation acceptance authority;
retain canonical named-human actors across Field Assessment; bind report scope,
limitations, and independent QA to the version; implement `PROD-QUAL-001`; and
implement an actual governed delivery/receipt path. Durable artifact storage is
also required if uploaded files are in scope. Until then, FrostGate can run a
design-partner rehearsal and produce an internal approved report, but should
not promise a completed paid enterprise deliverable.

## 33. Residual Risks and Deferred Work

- No live Auth0, Redis/Upstash, email, Stripe, connector, object storage,
  Railway, or Vercel operation was performed.
- No timing side-channel analysis was performed.
- PostgreSQL RLS conclusions are inherited from #706; #707 used local test
  persistence for its vertical proof.
- Browser navigation and UI behavior are inherited from #704–#706 tests; no
  Playwright session against a deployed environment was run.
- Actual PDF visual QA, accessibility, and customer comprehension were not
  tested with a human client.
- Microsoft/third-party evidence collection was not exercised against a real
  synthetic external tenant.
- Enterprise invoicing remains an operating process, not a connected golden
  path.

## 34. Evidence, Commands, and Results

### Repository safety

- `BASE_SHA=4560cf763bc8a453ffe01765d03a5f05b370e9cf`
- `main == origin/main` at branch creation.
- Working tree was clean before creating
  `audit/client-readiness-billable-assessment`.
- Existing stashes were preserved; no stash was applied, popped, dropped, or
  modified. This includes `post-704-local-refinement-preserve`.

### Focused validation

- Provisioning/identity Python batch: **110 passed in 97.23s**.
- Provisioning Console Node batch: **24 passed, 0 failed**.
- Field Assessment evidence/report/truth batch: **203 passed, 4 failed in
  286.92s**. The four are exactly the known `tests/test_report_delivery.py`
  `RESULT_TRUTH_GATE_BLOCKED` failures.
- Remediation/isolation broad batch: **923 passed, 6 failed, 63 errors in
  818.85s**. Every failure/error was portal-remediation global fixture
  contamination. Isolated rerun: **78 passed in 12.12s**.
- Backup/report reliability batch: **313 passed in 5.88s**.
- #706 Core: **5 passed in 10.95s**.
- #706 Console: **81/81**; #704: **45/45**; #705: **66/66**.
- Review-corrected #707 vertical boundary proof: **1 passed in 5.97s**. The
  payload contains one synthetic Graph user matching `object_count=1`.

### Strict and repository gates

No production code changed. The review correction exposed a CI metadata policy
failure, so the exact Guard command `make fg-fast-full` was run and **PASSED**:
**496 passed, 2 skipped, 22192 deselected in 370.70s**; all contract,
production-profile, SOC, RLS, route, audit, formatting, and budget checks in the
lane passed. `fg-security`, standalone `fg-contract`, and the three-hour strict
suite were not rerun. The inherited #706 strict result remains red: ruff,
format, and mypy passed; pytest reported **5 failed, 22592 passed, 92 skipped**,
comprising the four known truth-gate failures plus an MCIM registration issue
fixed after that run. #707 does not describe strict as green.

- Ruff lint: **PASS** for the changed Python files.
- Ruff format check: **PASS** (2 files already formatted).
- Audit-document Markdown lint: **PASS**.
- MCIM changed-path governance final rerun: **5 passed in 3.46s**.
- MCIM + SOC sync tests after review correction: **24 passed in 3.61s**.
- `make soc-review-sync`: **PASS**.
- `make fg-fast-full`: **PASS** (496 passed, 2 skipped).
- `git diff --check`: **PASS**.

## REPORT-QA-001 — canonical report QA authority

REPORT-QA-001 establishes version-bound QA evidence for the enterprise report
version workflow. Approval evidence is append-only and records the canonical
reviewer subject, actor type, tenant, engagement, report, exact version,
report/manifest hashes, QA stage, decision, and timestamp. The version approval
route rejects explicit platform service-principal actors; request reviewer
names, roles, and notes remain descriptive metadata only. Replays of an approved
immutable version fail closed, and the existing production-qualification and
delivery gates are unchanged.

The legacy engagement `qa-approve` workflow remains an explicitly attributed
service-compatible automation path for existing clients; it now writes the
same immutable QA evidence ledger with its canonical actor and exact report
version/hash. Reviewer independence beyond the repository's existing
permission separation, production qualification, and governed delivery remain
out of scope and blocked by their respective roadmap authorities.
