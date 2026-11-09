# L14-CUSTOMER-ZERO-E2E-001 — Customer-Zero End-to-End Acceptance

**Verdict: PARTIAL.** A synthetic customer was provisioned and driven through the backend journey using canonical routes and authorities:
- engagement;
- collection;
- evidence;
- 14 findings;
- report and PDF;
- QA, qualification and delivery controls;
- the customer-portal access path.

Every control that should block a synthetic or unverified report did block it.

The acceptance run also surfaced three findings:
- **P1:** the legacy trust-chain gate does not recognise runtime scanner evidence (CZ-23);
- **P1:** a dual-scope legacy credential can self-approve QA (CZ-12B);
- **P2:** a single-engagement portal grant can list all of its tenant's engagements (CZ-18).

Three things were not demonstrable here:
- browser-level portal acceptance;
- interactive OIDC login;
- a FINAL delivery to a real customer.

**FrostGate supports an internal synthetic demo today. A controlled pilot needs the P1 items closed and an operator-run OIDC/Postgres rehearsal (§19–§20).**

The acceptance matrix uses five statuses:

| Status | Meaning |
|---|---|
| `PASS` | A real control was exercised on the real path. |
| `SYNTHETIC_EXECUTED` | Real authorities ran over synthetic data or provenance. |
| `PARTIAL` | The step works, with a recorded limitation. |
| `FAIL` | A finding. |
| `NOT_TESTED` | Never implied to work. |

## 1. Objective and environment

Prove, by execution, whether FrostGate can onboard a realistic customer and deliver a controlled assessment experience on the platform as built.

- **Backend harness:** `tests/test_customer_zero_e2e/`. It uses the shared `build_app` fixture: an isolated SQLite file per test, `FG_ENV=test`, and the admin plane enabled with a tmp tenant registry.
- **Real Postgres:** `tests/test_migrations_postgres_replay.py::test_customer_zero_postgres_provisioning_and_authorization`, run by the CI *Migrations Replay* job. It runs inside a rolled-back transaction.
- **Browser:** `tests/test_customer_zero_e2e/browser_acceptance.py` is opt-in and not collected by pytest. It runs the real core API, the portal (Next.js dev) and headless Chromium on 127.0.0.1.

Throughout: no production database, no external scan, no network egress, no message, no billing mutation, no real credential.

## 2. Canonical architecture exercised

| Concern | Canonical authority (unchanged) |
|---|---|
| Tenant | `POST /admin/tenants` → R7 `TenantRepository` (Postgres) / transition JSON registry (SQLite) |
| Lifecycle | `/admin/tenants/{id}/suspend\|activate` → R3 `tenant_lifecycle.execute_transition` (Postgres-only) |
| Credentials and roles | `/admin/tenants/{id}/credentials`, `…/credentials/{cid}/role` → `credential_authority`, `tenant_rbac` → `ActorContext` via `_LEGACY_ROLE_MAP` |
| Engagement | `POST /field-assessment/engagements` |
| Consent | `services/field_assessment/customer_authorization.py` (#812, Postgres SQL) |
| Collection | production bridges (`connectors/*_bridge.py`) + `_c6_capture_runtime_evidence` (#813) |
| Evidence | `fa_scan_evidence_envelopes`, `fa_evidence_custody_events`, evidence manifest |
| Report | `POST /…/reports` → `report_proof` (#814) → `export_pdf_bytes` |
| QA, qualification, delivery | `/qa-approve`, `/qualify/*`, `/versions/*`, `/governed-delivery` |
| Customer portal | `apps/portal` BFF → `/portal/authenticate` → `PortalClientScopeMiddleware` → `/field-assessment/engagements/{id}/*` |

## 3. Customer journey matrix

| Step | Authority | API / UI | Role | Status | Blocker |
|---|---|---|---|---|---|
| CZ-01 Tenant create and lookup | R7 repo / registry | `/admin/tenants` | platform admin | PARTIAL (SQLite seam) | — |
| CZ-02 Lifecycle suspend/activate | R3 lifecycle | `/admin/tenants/{id}/suspend` | platform admin | NOT_TESTED on SQLite; Postgres slice in CI | — |
| CZ-03 Personas and roles | tenant_rbac | admin credential and role routes | platform admin | SYNTHETIC_EXECUTED | OIDC not tested |
| CZ-04 Engagement | FA store | `POST /engagements` | assessor | PASS | — |
| CZ-05 Customer consent | customer_authorization | receipt request/approve | customer (OIDC) | NOT_TESTED here; Postgres slice in CI | interactive approval unverified |
| CZ-06 Collection, envelopes, custody | bridges + runtime evidence | worker path | assessor | SYNTHETIC_EXECUTED | — |
| CZ-07 14-finding reconciliation | report_proof | `POST /reports` | assessor | SYNTHETIC_EXECUTED | — |
| CZ-08 Evidence proof / confidence | evidence manifest | — | — | SYNTHETIC_EXECUTED | integrity-only |
| CZ-09 Coverage truth (8 states) | report_proof.coverage | — | — | SYNTHETIC_EXECUTED | — |
| CZ-10 Remediation | roadmap route + findings | `GET /remediation-roadmap` | assessor | SYNTHETIC_EXECUTED | no ownership field |
| CZ-11 Executive PDF | export_pdf_bytes | `GET /export?format=pdf` | assessor | SYNTHETIC_EXECUTED | — |
| CZ-12 Independent QA | qa-approve | `POST /qa-approve` | qa_reviewer | PASS | — |
| CZ-12B Self-approval, dual-scope key | qa-approve | `POST /qa-approve` | legacy key | **FAIL** | **P1** |
| CZ-13 Qualification of a synthetic report | truth gate | `/qualify/*` | compliance_reviewer | PASS (refused) | — |
| CZ-14 Delivery of a synthetic report | delivery gate | `/versions/*/deliver`, `/governed-delivery` | assessor | PASS (refused) | — |
| CZ-15 Portal access (grant → session) | portal grants + middleware | `/portal/authenticate` + portal GETs | customer | SYNTHETIC_EXECUTED | pnu1 / OIDC not tested |
| CZ-16 Portal access controls | middleware + RBAC | portal GET/POST | customer | PASS | — |
| CZ-17 Customer draft download | export route | portal GET export | customer | PARTIAL | **P1** |
| CZ-18 Grant-scoped engagement list | middleware | portal `GET /engagements` | customer | **FAIL** | **P2** |
| CZ-19 `/portal/engagement/*` workspace | engagement_portal | `GET /portal/engagement/reports` | customer | PARTIAL | P2 |
| CZ-20 Audit trail | engagement audit | `GET /audit-events` | assessor | PASS | — |
| CZ-21 Portal browser experience | apps/portal | Next.js + Chromium | customer | NOT_TESTED (§14) | — |
| CZ-22 Billing / entitlements | — | — | — | NOT_TESTED (safety) | — |
| CZ-23 Trust-chain gate vs runtime evidence | trust_enforcement_adapter | export/QA gates | — | **FAIL** | **P1** |

The machine-readable matrix is `acceptance_matrix.json` (§22).

## 4. Synthetic tenant

`synthetic-northstar-mfg`: **SYNTHETIC — Northstar Manufacturing Group (NOT A REAL CUSTOMER)**. A fictional mid-sized manufacturer with:
- 15 managed endpoints;
- 4 servers and 2 network devices (RFC 5737 addresses);
- 5 web applications (`*.northstar-mfg.example`);
- the corporate domain and its email configuration;
- Exchange Online and SharePoint Online.

A second tenant, `synthetic-contoso-other`, is used for isolation probes.

The canonical asset authority (`governance_assets`) models AI/SaaS asset types only. So infrastructure assets are represented as scanner observations, the canonical evidence representation. No parallel asset store was created; this is recorded as a gap.

## 5. Identity and role model

Personas are role-bound tenant API keys issued and assigned through the admin plane. No role was invented.

| Persona | API-key role | Identity-authority role |
|---|---|---|
| Customer security administrator | `tenant_admin` | `tenant_admin` |
| Customer executive | `read_only` | `viewer` |
| FrostGate assessor | `analyst` | `assessor` |
| Independent QA reviewer | `auditor` | `qa_reviewer` |
| Qualifier | `governance_admin` | `compliance_reviewer` |
| Portal BFF | `read_only` | `viewer` |
| Platform administrator | scoped `admin:read/write` credential | — |

`client_executive` and `client_security_owner` exist only as OIDC roles. **Interactive OIDC login is NOT_TESTED.** Tenant-scoped admin operations use a scoped admin credential. The bare global key cannot perform them, because the admin audit requires actor and scope (FG-AUDIT-ADMIN-001).

## 6. Engagement creation

The assessor creates the engagement, and re-runs reuse it. The customer executive receives 403 on create. The engagement is tenant-bound: the other tenant gets 404 or 403 on every route probed.

## 7. Assessment fixture

`tests/test_customer_zero_e2e/_northstar.py` defines six collectors that together cover all eight collection states:

| Collector | Collection | Evidence |
|---|---|---|
| Entra governance | status absent → **UNKNOWN** | scan-level |
| Endpoint inventory | **PARTIAL** (Intune **DENIED**) | scan-level |
| SharePoint | **NOT_ASSESSED** (excluded by customer) | scan-level |
| Network | **CANCELLED**, 3 targets not started; one host altered out of band | per host; one **INVALID** |
| DNS / email | **PARTIAL** with one **TIMEOUT** domain | capture **fails closed** (no authorization context) → **MISSING** |
| Web headers | **PARTIAL**, one target **DENIED**, the rest **COMPLETE** | per target |
| OAuth inventory job | **FAILED** before producing a result | — |

The 14 findings break down as 2 critical, 3 high, 4 medium, 3 low and 2 informational. They are realistic conditions: privileged admin without phishing-resistant MFA, exposed RDP, an unsupported server OS, missing EDR, an excessive app permission, guest access without review, incomplete encryption evidence, a stale inventory, weak DMARC/SPF, patch lag, no DNSSEC, a missing CSP, and two banner disclosures. Remediation guidance is recorded on 13 of the 14; one has none by design.

## 8. Authorization flow

The receipt flow uses Postgres-only SQL, so it can't run on the SQLite harness. On real Postgres (CI), the slice proves:
- An **API-key** customer admin, the **requester**, a **platform operator**, and an approver with an **unverified email** are all refused.
- Approval by a **simulated** interactive customer identity (`client_security_owner`, `oidc_auth0`, constructed `ActorContext`, no real IdP token) succeeds, with a payload digest and proof level.
- A double approval is refused, and the receipt can be revoked.
- With no approved scope, the execution-time check fails closed.

Target-scanner provenance in the harness is explicitly `SYNTHETIC_FIXTURE_NO_CUSTOMER_AUTHORIZATION`. No consent was fabricated.

## 9. Scanner simulation boundaries

No scanner executed and no address was contacted. Payloads are synthetic and flagged `synthetic: true`. They pass through the same bridge functions and the same `_c6_capture_runtime_evidence` adapter the production workers call. Every synthetic step is labelled `SYNTHETIC_EXECUTED`, never `PASS`.

## 10. Evidence validation

- 13 envelopes and 38 custody events. Every envelope carries the correct tenant and engagement, and every envelope has custody.
- DNS capture failed closed, with no envelope, and its findings are UNKNOWN.
- The altered network host's evidence is **INVALID**: that finding is capped from CONFIRMED to SUSPECTED, and severity is unchanged.
- Provenance classes: `VERIFIED_INTEGRITY_ONLY` 11, `MISSING` 2, `INVALID` 1. `VERIFIED_AUTHENTIC` is never produced, because there is no Vault Transit signature (L14-SCAN-VAULT-001).

Four claims are kept separate:

| Claim | Proven here? |
|---|---|
| Integrity verified | SHA-256 only |
| Source authenticated | no |
| Customer authorized | synthetic here; simulated on Postgres |
| QA approved | role-separated approval, not independence-proven |

## 11. Findings reconciliation

14 persisted, 14 included, 0 excluded, reconciled. Confidence breaks down as CONFIRMED 4, PROBABLE 7, SUSPECTED 1 and UNKNOWN 2. Graph-family and partial collection keep findings at PROBABLE, and CONFIRMED requires integrity-verified evidence on COMPLETE collection. Severity distribution and finding IDs match the persisted records exactly.

## 12. Report generation

The report was generated through the real route and signed through the existing trust binding. Its proof records:
- 11 coverage limitations;
- `coverage_percentage = null`;
- `may_claim_full_coverage = false`;
- release blockers `SYNTHETIC_DATA` and `EVIDENCE_INTEGRITY_FAILED`;
- truth gate FAIL.

## 13. PDF visual results

The Northstar report is 12 pages. Automated checks:
- all 14 IDs present, with exactly 14 finding blocks;
- every required section present;
- no "100%";
- the signed record hash and every evidence ID present;
- marking, Page X of Y and footer geometry correct on every page;
- no blank page (rasterized);
- `X-Report-State: DRAFT_SYNTHETIC`.

Visual review on this run found:
- **Fixed in this PR:** machine codes wrapped mid-word in narrow table cells (`NOT_ASSESS|ED`, `VERIFIED_INTEGRIT|Y_ONLY`). Cells now show readable labels, and exact codes remain in the limitations list and the JSON.
- **Open (P2):** Graph-family findings show "Affected: Not recorded", because their evidence is scan-level. Pages 4, 10 and 12 are sparse because of forced section breaks.

## 14. Portal acceptance

**Backend: SYNTHETIC_EXECUTED / PASS.** The real access path works. The assessor creates a portal grant (the secret is shown once), the BFF exchanges it at `/portal/authenticate`, and portal-scoped reads succeed with the BFF key plus `X-FG-Portal-Session` (summary, findings: 14, reports, roadmap, and the PDF marked on every page). These are denied (403):
- a non-granted engagement;
- a missing or forged session;
- a write via the portal;
- QA via the portal;
- the session with another tenant's key.

A revoked grant immediately loses access, and its secret can't re-authenticate.

Findings:
- **CZ-17 (P1):** customers can download unapproved drafts. The DRAFT marking is the only control, and there is no canonical policy on draft visibility.
- **CZ-18 (P2):** the legacy grant-session path validates only `/engagements/{id}/*`, so `GET /field-assessment/engagements` lists every engagement of the tenant to a single-engagement grant.
- **CZ-19 (P2):** `/portal/engagement/*` reads `fa_report` (report authority), not `governance_reports`, and returns 0 reports while the field-assessment report exists. The portal UI uses `/field-assessment/*` routes, so two report authorities face customers (L14-FA-REPORT-BRIDGE-001).

**Browser: NOT_TESTED.** `browser_acceptance.py` started the real core API, the portal and headless Chromium:
- The login page rendered (screenshot).
- The development grant login returned 200.
- Every authenticated page failed to compile **locally**, because `@vercel/edge-config` (declared in `apps/portal/package.json`) is missing from the local `node_modules`. That is an environment gap, not a verified product defect.

Completing browser acceptance requires an `npm install` in `apps/portal`, which was not run here because it fetches from the public registry. The run also showed a UX defect (P2): the login page shows the full authenticated navigation to a signed-out visitor. Production login is OIDC named-user only; grant-secret login is disabled in production-like environments.

## 15. QA and delivery safety

| Control | Observed |
|---|---|
| Assessor QA-approves | 403 (no `report.qa_approve`) |
| Independent reviewer approves | 200; the report stays `DRAFT_SYNTHETIC` |
| Dual-scope legacy key generates then self-approves | **200: FAIL P1 (CZ-12B).** `_enforce_report_qa_independence` covers human actors on version-approve only |
| Qualification of a synthetic report | request 201; finalize 422 |
| Versioned deliver / governed delivery | 422 (`REPORT_PROOF_BLOCKED`) |
| QA rejection | **no rejection route exists** (approve or supersede only): gap |
| Report content edited after signing | export 403 |

**Preview success is not delivery success.** The synthetic report never reached FINAL, by design.

## 16. Failure and recovery

`test_customer_zero_resilience.py` (7 tests) covers:
- duplicate seeding creates no duplicates;
- invalid tenant ID gives 422; non-admin tenant create gives 401/403; an unknown role gives 400/422;
- invalid or unauthenticated engagement creation gives 422 / 401/403;
- signing authority unavailable gives 503;
- an unknown version gives 404, and a corrupted report gives 403;
- a revoked portal grant gives 403, and re-authentication gives 401;
- `X-Request-ID` is echoed, for correlation.

**Reset** means a new isolated database. No in-place delete is provided, because audit and custody tables are append-only by design.

## 17. Security results

- Tenant isolation holds on every route probed.
- RBAC separation holds between assessor, QA and viewer.
- Consent approval refuses API-key, requester, operator and unverified identities (Postgres).
- Release gates refuse synthetic and invalid evidence.
- Portal session binding holds per engagement.
- **Open:** CZ-12B (P1), CZ-23 (P1), CZ-17 (P1), CZ-18 (P2).

**CZ-23 detail.** The export/QA trust gate (`derive_engagement_trust_inputs`) reads only `evidence_provenance`. The manual ingest routes write it, but the scanner worker path never does. Every scanner-only engagement therefore scores 0:
- in default `warn` mode, 16 critical warnings were audited on this run;
- under `FG_PROVENANCE_MODE=strict`, the customer's report export returns **403 TRUST_ENFORCEMENT_BLOCKED**.

## 18. Readiness scorecard

| Area | State |
|---|---|
| Tenant provisioning | PARTIAL (Postgres path proven in CI only) |
| Identity and access | PARTIAL (API-key personas; OIDC NOT_TESTED) |
| Engagement workflow | READY |
| Authorization (consent) | PARTIAL (Postgres, simulated approver; interactive NOT_TESTED) |
| Scanner collection | PARTIAL (synthetic only; live collection untested) |
| Evidence integrity | PARTIAL (integrity-only; trust-gate split CZ-23) |
| Finding accuracy | PARTIAL (confidence truthful; Graph resources unrecorded) |
| Report completeness | READY |
| Coverage transparency | READY |
| QA | BLOCKED for an "independent" claim (CZ-12B, FVA-05; no rejection route) |
| Portal usability | NOT_TESTED (browser) / PARTIAL (API) |
| PDF delivery | PARTIAL (FINAL path proven in #814 tests only; draft visibility CZ-17) |
| Security isolation | PARTIAL (CZ-18) |
| Audit trail | READY |
| Recovery/retry | READY (harness scope) |
| Billing readiness | NOT_TESTED |

| Offer | Readiness |
|---|---|
| **A. Internal synthetic demo** | **Supported now.** Backend journey, report and portal API; the browser needs `npm install` locally. |
| **B. Controlled customer pilot** | **Not yet.** Needs CZ-12B, CZ-17 and CZ-23 decided or closed, plus an operator rehearsal of OIDC login, customer consent and Postgres provisioning. |
| **C. Unrestricted production onboarding** | **Not supported.** It additionally needs FVA-05/06, authenticated provenance and billing. |

## 19. Launch blockers

| ID | Level | Evidence | Minimum remediation |
|---|---|---|---|
| CZ-23 | P1 | strict-mode export 403; 16 critical warnings | Bind runtime evidence envelopes into trust-chain inputs (or write provenance from the worker path) |
| CZ-12B | P1 | self-approval 200 | Enforce author ≠ reviewer for every actor type on every QA route |
| CZ-17 | P1 | draft downloadable by the customer | Decide and enforce customer visibility of non-FINAL reports |
| QA reject | P1 | no route | Add a rejection / changes-requested transition |
| OIDC + consent rehearsal | P1 | NOT_TESTED | Operator-run staging rehearsal (no code) |
| CZ-18 | P2 | 2 engagements listed for a 1-engagement grant | Scope the list route for grant sessions |
| CZ-19 | P2 | 0 reports in `/portal/engagement/reports` | L14-FA-REPORT-BRIDGE-001 |
| Graph affected resources | P2 | "Not recorded" in the PDF | Per-object Graph evidence |
| Login nav | P2 | screenshot | Hide authenticated navigation pre-login |

## 20. First-client operational playbook (controlled pilot, after the P1s)

1. Provision the tenant on Postgres (`POST /admin/tenants`) with a scoped platform-admin credential, then issue role-bound credentials.
2. Invite the customer security owner through the named-user invitation (OIDC).
3. The assessor creates the engagement and records the scope.
4. The customer approves the consent receipt interactively; verify the receipt shows `approver_auth_source` = an IdP.
5. Run collection with `FG_PROVENANCE_MODE` decided per CZ-23.
6. Generate the report and review the DRAFT PDF internally.
7. An independent reviewer (different person) runs QA, then a separate qualifier runs qualification.
8. Deliver through `governed-delivery`, then verify the portal shows only what policy allows.
9. Hand off remediation; schedule the reassessment.

No billing step is automated here.

## 21. Commands

```
# Backend acceptance harness (8 tests); artifacts kept when FG_CUSTOMER_ZERO_OUT is set
FG_CUSTOMER_ZERO_OUT=<dir> FG_ENV=test .venv/bin/pytest -q tests/test_customer_zero_e2e/

# Real-Postgres slice (CI Migrations Replay job; needs FG_DB_URL to an isolated database)
FG_DB_URL=<isolated postgres url> .venv/bin/pytest -q \
  tests/test_migrations_postgres_replay.py::test_customer_zero_postgres_provisioning_and_authorization

# Opt-in browser run (local only; requires apps/portal dependencies installed)
FG_CUSTOMER_ZERO_OUT=<dir> .venv/bin/python -m tests.test_customer_zero_e2e.browser_acceptance
```

## 22. Artifacts

Artifacts are not committed. They are reproducible with the commands above.

- **Harness output** (`$FG_CUSTOMER_ZERO_OUT`):
  - `acceptance_matrix.json`;
  - `northstar_report.pdf` and `page-NN.png`;
  - `report_export.json`;
  - `evidence_manifest.json`;
  - `finding_reconciliation.json`;
  - `report_validation.json`;
  - `audit_events.json`.
- **Browser output:**
  - `browser_acceptance.json`;
  - `portal_*.png` (only `portal_login_page.png` is valid on this run);
  - `browser_core.log`, `browser_portal.log`.

## 23. Follow-up workstreams

1. **L14-ASSESSMENT-ASSURANCE-001** (next): QA independence for every actor and route, a QA rejection transition, customer draft-visibility policy, and runtime-evidence binding into the trust-chain gate (CZ-12B, CZ-17, CZ-23).
2. Operator staging rehearsal: OIDC login, interactive consent and Postgres provisioning (no code).
3. L14-FA-REPORT-BRIDGE-001: one customer-facing report authority (CZ-19).
4. Portal: scope the engagement list (CZ-18); pre-login navigation.
5. L14-SCAN-VAULT-001: authenticated provenance.
6. Billing and entitlement acceptance on a test billing account.
