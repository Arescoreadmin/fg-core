# Security and Tenant Safety Assessment

**Overall: security maturity 7/10 · tenant safety 7/10.** This is the platform's strongest dimension — unusual for a pre-revenue product. The remaining risk is concentrated in *operational* security (rotation, verification-on-current-stack), not in missing controls.

Evidence references: `EVIDENCE_INDEX.md` E1–E15.

---

## Verified strong (implementation-checked)

| Control | Implementation | Evidence |
|---------|----------------|----------|
| Tenant isolation (DB) | RLS ENABLE + **FORCE** on tenant tables; policies on `current_setting('app.tenant_id')`; context set via parameterized `set_config` | E1, E2 |
| Tenant isolation (app) | Tenant predicates in queries + BFF header injection server-side; console BFF `resolveAuthorizedTenant()` validates URL tenant params against session (#548) | E9, ROADMAP PR A+B |
| Cross-tenant denial tests | 15 `test_fa_forensic_*` modules incl. tenant write isolation; CGIN payloads use tenant fingerprints, CI-gated (17.7A) | E13 |
| AuthN — console | Auth0 OIDC via next-auth v5, middleware-protected; JWKS RS256 validation core-side (H14) | Console audit §2 |
| AuthN — portal | Fail-closed middleware; prod password login hard-disabled; opaque `pnu1.` tokens stored server-side as HMAC fingerprints; membership-version instant revocation (P1.1) | E4–E7 |
| AuthZ | Permission-based (not role-string) via ActorContext; 6-role model with SoD invariants (assessor ≠ self-approver, tenant_admin ≠ compliance authority); CI sprawl guard keeps registry/roles in sync (#513); audit-coverage CI gate (H13.5, "100% coverage") | E9, ROADMAP H14 |
| Service principal boundary | Canonical `platform_service` machine identity bound to `frostgate-internal` authority tenant; 5 explicit permissions; append-only audit (PR #586, hardened same week) | ROADMAP #585/#586 |
| Audit integrity | HMAC-chained ledger; append-only DB triggers; audit atomicity service (H13) closing split-commit paths; transaction/entity correlation columns | E10, E11 |
| Evidence integrity | SHA-256 raw-payload hashes; Ed25519 provenance signing (fail-closed in prod); lifecycle locks (collected→locked→legal_hold) with DB triggers; verification bundles with tamper detection | E12, E15, E46 |
| SSRF | Centralized `SafeTargetValidationService` — private/CGNAT/link-local/metadata ranges, DNS-rebinding all-IP validation, per-host CIDR checks, redirect revalidation contract; no env bypasses | E8 |
| Secrets in repo | None live: `env/prod.env` is placeholders; CI plaintext-secret gate | E14 |
| Error discipline | `services/error_sanitizer.py`; provisioning error taxonomy distinguishes failure modes without leaking internals (R0.1) | SI |
| Prod config validation | 1,283-line startup validator, fail-closed in prod; DoS-guard required; migration/RLS/append-only assertions available | E24 |
| DoS/input limits | Body/header/query caps, request timeout, concurrency cap in prod env contract | env/prod.env template |
| Webhook security | Stripe webhook signature-verified, idempotent, no entitlement side-effects (P1.5 design) | ROADMAP P1.5 |
| File handling | Tenant-scoped opaque blob paths (SHA-256); audio evidence validators; transcribe endpoint auth (Sprint 1) | ROADMAP items 40–41 |

## Residual risks (honest accounting)

1. **Assessment lead-funnel endpoints** (`/ingest/assessment/*`): now scope-gated (`ingest:assessment`) with per-assessment `lead:{uuid}` tenant namespaces — the UUID remains the effective bearer for a lead's data. Bounded blast radius (one lead's own pre-payment answers), fails closed for bound tenants. Acceptable; revisit if the self-serve funnel is ever marketed (FG-LR-023 hides it).
2. **Session-cookie bearer contract (portal)**: `pnu1.` token in an HttpOnly cookie is the credential; disclosure = session until revocation. Mitigated by fingerprint storage, membership-version bump revocation, and logout revocation — standard and fine; listed for completeness.
3. **Legacy session shapes still parse**: `verifySessionToken` accepts legacy `ok:{exp}` HMAC payloads at the middleware edge. Issuance is prod-disabled, and BFF-to-core calls need more than the cookie, but removing legacy parse post-launch shrinks the surface (fold into FG-LR-025-class cleanup).
4. **Secret rotation** — no procedure; a dozen high-blast-radius secrets across Railway/Vercel; July incident handling may have exposed values in side channels (FG-LR-012, P1).
5. **`FG_DB_MIGRATIONS_RISK_ACCEPTED=1` in prod** (CLIENT_READINESS A7): the validator's migration assertion is soft-bypassed. Migrations *do* auto-apply at startup (E16), so exposure is a silent partial-failure scenario; run `migration_status` against prod during the dry run and then unset the risk flag (fold into FG-LR-001).
6. **Internal tenant authority correctness** depends on `CORE_TENANT_ID` configuration — misconfiguration class caused the #587 prod login failures; now startup-validated. Verified fixed on main; dry run confirms in prod.
7. **Unverified-on-current-stack** items: portal OIDC chain (FG-LR-002), report signing on export path. Code present; production behavior pending the dry run.
8. **admin_gateway** ships OIDC/invitation enforcement code that prod may not run (FG-LR-019) — decide the topology so security review has one story.

## Replay & privileged operations

Replay protection: invitation replay protection (Identity PR 2), webhook idempotency keys, membership-version session invalidation, append-only ledgers with hash chains, verification-bundle deterministic snapshots. Privileged ops (QA approve, risk accept, exception grant, bundle generate) route through the governance decision ledger with full actor attribution sourced from JWT (spoofing eliminated — actor fields stripped from request bodies, H14). **Verified in code structure; behavior trusted from the 75-test H14 suite + CI.**

## Minimum security actions for launch

1. Dry-run the auth chain in prod (FG-LR-001/002) — 0 extra days (inside P0 plan).
2. Rotate the top-5 blast-radius secrets and write the rotation doc (FG-LR-012) — 1 day.
3. Run `python -m api.db_migrations status` (via `migration_status`) against prod; clear `FG_DB_MIGRATIONS_RISK_ACCEPTED` — inside dry run.
4. Post-launch: remove legacy session parsing; delete deprecated `/remediation/*`; admin_gateway decision.

Nothing here justifies delaying launch beyond the P0 plan.
