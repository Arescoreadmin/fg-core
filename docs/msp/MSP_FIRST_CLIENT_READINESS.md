# MSP first-client readiness gate

**Verdict**:

- **Internal synthetic validation: READY.** Every control below passes against synthetic tenants.
- **A real external MSP with real customer data: NOT READY.** It is blocked by 4 controls and has 3 deferred.

Unit and route tests do not make the platform customer-ready, and nothing here claims they do.

All tests cited are in `tests/security/test_msp_001_foundation.py` unless stated otherwise. The tests use synthetic tenants on SQLite.

## Controls

| # | Control | Synthetic validation | Real MSP + real customer data | Evidence or blocker |
|---|---|---|---|---|
| 1 | Tenant provisioning | PASS | PASS (mechanism) | The MSP is an ordinary tenant provisioned through the existing `POST /admin/tenants`, then designated through `PUT /admin/msp/organizations/{id}`. Tests 17b, 21; route inventory regenerated. |
| 2 | Customer approval workflow | PASS | **BLOCKED** | Tests 04, 05, 06. Blocker: there is no console UI. `/admin/msp/*` is a control-plane API reached through the admin gateway, so a real customer administrator cannot approve without operator help. Addressed in MSP-002. |
| 3 | Role and scope enforcement | PASS | PASS | Tests 06, 11, 11b; existing TENANT-ADMIN-001, RBAC and identity suites green (Tier A). |
| 4 | Relationship revocation | PASS | PASS | Tests 07, 08, 08b, 10 (membership and partner kill switch), 16 (no cached authority). |
| 5 | Tenant isolation | PASS | **BLOCKED** | Tests 02, 13, 14, 15, plus the control-plane v2 tests. Blocker: the forced RLS policies of migration 0206 have not yet been shown on Postgres. Three probe tests are added (`tests/test_migrations_postgres_replay.py -k 0206`): parties-only visibility, `WITH CHECK` refusal, and authority plus cross-chain audit under a `NOBYPASSRLS` role. They skip locally (no `FG_DB_URL`) and run in the CI Postgres job. Blocked until that run passes. |
| 6 | Audit attribution | PASS | PASS | Test 19: events on both chains bind actor, membership, MSP, customer, relationship, capabilities, operation and correlation id; `verify_identity_audit_chain` holds for both tenants. |
| 7 | Evidence ownership | PASS | PASS | Test 20: revocation leaves the customer's decision evidence row, file, SHA-256 and audit chain intact. MSP-001 exposes no evidence through MSP authority. |
| 8 | Operational rollback | PASS | PASS | The PR revert is self-contained, and migration 0206 is additive (`MSP_001_ARCHITECTURE.md` → Rollback). No live rollback drill was run. |
| 9 | Backup and restore dependencies | NOT APPLICABLE | DEFERRED | The new tables are ordinary Postgres tables covered by existing backups. No restore drill exists for them. |
| 10 | Production deployment dependencies | NOT APPLICABLE | **BLOCKED** | Before first use: migration 0206 applied; `FG_INTERNAL_GATEWAY_SECRET` configured (the designation route is gateway-protected); an `msp.multi_tenant` entitlement bundle assigned to each MSP tenant; MSP staff onboarded as bound members of the MSP tenant. None of these is done. |
| 11 | Support and incident response ownership | NOT APPLICABLE | DEFERRED | No named owner for partner incidents (suspect MSP, mistaken approval). The kill switch exists (organization suspension, test 10); the runbook does not. |
| 12 | Open CodeQL findings on MSP entry points | PASS | PASS (pending CI) | See below. The new files have no CodeQL result until the PR's analysis runs. |
| 13 | Commercial readiness (billing an MSP) | NOT APPLICABLE | **BLOCKED** | No partner pricing, contract terms or usage attribution (MSP-006). Only the entitlement gate exists. |
| 14 | Customer data access through MSP authority | NOT APPLICABLE | NOT APPLICABLE | MSP-001 deliberately exposes none. The first data route (MSP-002) must call `resolve_actor_access` on every request. |
| 15 | Background jobs and queued work | NOT APPLICABLE | DEFERRED | No MSP job path exists. The bounded revocation contract is in `MSP_001_ARCHITECTURE.md`. |

## CodeQL impact on MSP entry points

Checked against the 93 open alerts on `main` `e241e43b`.

| Alert | Location | Reachable from `/admin/msp/*` or the re-based control-plane path? | Effect on MSP-001 |
|---|---|---|---|
| #124 `py/sql-injection` | `api/rag_corpus_ingestion.py:964` | No. RAG corpus ingestion only. | None. Triaged as a false-positive candidate (sort direction is allowlisted); not dismissed. |
| #91–#94 path injection | `api/billing.py` | No | None |
| #98, #99 path injection | `services/ai/policy.py` | No | None |
| #86–#90 path injection | `api/admin.py` (`_load_config_change`, `revert_config_change`) | No. MSP imports only `require_internal_admin_gateway` from that module. | None |
| #49–#51 `py/clear-text-logging-sensitive-data` | `api/auth_scopes/resolution.py` (`_tenant_denial_log`, `_log_auth_event`) | **Yes**, through `resolve_authoritative_tenant`, which every authenticated tenant route uses | Not introduced or worsened. Already triaged as false-positive candidates (structured, normalized auth logs). MSP code logs no subjects, tokens or capabilities. |

No reachable vulnerability required blocking an MSP integration. The one reachable defect found, the control-plane v2 MSP scope, is fixed in this PR (see the capability audit).

## Known risks carried forward

- **Legacy scope-to-platform mapping.** `admin:write` API keys satisfy `platform.admin` through the legacy scope mapping. Without the internal gateway secret, in non-production, any such key can designate an MSP. Designation grants nothing without customer approval. Production requires the gateway.
- **Tenant id oracle.** A designated MSP's `tenant_admin` can learn whether a customer tenant id exists by proposing to it (404 vs 200). This is limited to platform-vetted MSPs; MSP-002 should consider invitation codes instead of raw tenant ids.
- **No live Postgres validation** of 0206 in this session (control 5).
