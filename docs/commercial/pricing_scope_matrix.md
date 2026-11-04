# Pricing and Scope Matrix

**Date:** 2026-11-03
**Authority:** `docs/plans/revenue_first_roadmap_20261103.md` Section 2
**Status:** OFFER B pricing deferred pending infrastructure cost authorization

---

## Feature Availability Matrix

| Feature | OFFER A — Design Partner | OFFER A — Pilot | OFFER B — Premium | Notes |
|---------|--------------------------|-----------------|-------------------|-------|
| **Price** | $2,500 | $5,000 | TBD | OFFER B pricing deferred — awaiting HCP Vault Dedicated cost authorization |
| **Availability** | NOW (pending production gate attestations + Vault Transit) | NOW (same gates) | BLOCKED | OFFER B blocked on CUSTOMER-ZERO-TRUST-003 (cost NOT_AUTHORIZED) |

---

## Connector Coverage

| Connector | OFFER A | OFFER B | Current code status |
|-----------|---------|---------|---------------------|
| DNS and Email Security | Included | Included | COMPLETE |
| Web Security Headers | Included | Included | COMPLETE |
| Network Scan | Included | Included | COMPLETE |
| MS Graph Core (identity) | Included | Included | COMPLETE |
| MS Graph MFA | Included | Included | COMPLETE |
| MS Graph Conditional Access | Included | Included | COMPLETE |
| MS Graph Devices | Included | Included | COMPLETE |
| MS Graph SharePoint | Included | Included | COMPLETE |
| MS Graph OAuth Inventory | Included | Included | COMPLETE |
| MS Graph OAuth Risk | Included | Included | COMPLETE |
| MS Graph Entra Governance | Included | Included | COMPLETE |
| MS Graph Identity Protection | Included | Included | COMPLETE |
| NIST AI RMF Questionnaire (69 controls) | Included | Included | COMPLETE |

**Total connectors: 13**

---

## Assessment Content

| Content | OFFER A | OFFER B | Notes |
|---------|---------|---------|-------|
| 6-domain risk scoring | Yes | Yes | COMPLETE |
| 69-control NIST AI RMF questionnaire | Yes | Yes | COMPLETE |
| AI executive summary (Claude) | Yes | Yes | COMPLETE |
| HIPAA playbook | Yes | Yes | COMPLETE |
| SOC 2 playbook | Yes | Yes | COMPLETE |
| CMMC 2.0 playbook | Yes | Yes | COMPLETE |
| ISO 27001 playbook | Yes | Yes | COMPLETE |
| NIST AI RMF playbook | Yes | Yes | COMPLETE |

---

## Report and Signing

| Capability | OFFER A | OFFER B | Notes |
|-----------|---------|---------|-------|
| PDF report generation | Yes | Yes | COMPLETE — requires Anthropic API key |
| AI executive summary | Yes | Yes | COMPLETE |
| NIST AI RMF coverage matrix | Yes | Yes | COMPLETE |
| Findings with evidence citations | Yes | Yes | COMPLETE |
| Report signed via Vault Transit (IDENTITY domain) | Yes (single-authority) | Yes (triple-authority) | Vault Transit not yet provisioned in production |
| Assessor attestation (Ed25519) | No | Yes | OFFER B only — TRUST-BINDING-001 (#731) code complete; production BLOCKED |
| Independent reviewer attestation | No | Yes | OFFER B only — same blocker |
| FrostGate issuance seal (Vault Transit, ACCEPTANCE domain) | No (IDENTITY only) | Yes | OFFER B only |
| Verification bundle (offline-replayable) | No | Yes | OFFER B only — verify_evidence.py code complete; production BLOCKED |
| HSM-backed key custody | No | Yes | OFFER B only — requires HCP Vault Dedicated |
| Key rotation and revocation chain | No | Yes | OFFER B only |

---

## Portal Features

| Feature | OFFER A | OFFER B | Notes |
|---------|---------|---------|-------|
| Password-protected secure portal | Yes | Yes | COMPLETE — named-user invitation flow |
| Risk posture dashboard | Yes | Yes | COMPLETE |
| Findings with severity classification | Yes | Yes | COMPLETE |
| Remediation roadmap | Yes | Yes | COMPLETE |
| Finding explainers | Yes | Yes | COMPLETE |
| Remediation tracking (mark resolved) | Yes | Yes | COMPLETE |
| Report download | Yes | Yes | COMPLETE |
| 90-day access window | Yes | Yes | COMPLETE |
| Verification bundle visible in portal | No | Yes | OFFER B only |

---

## Delivery and Workflow

| Feature | OFFER A | OFFER B | Notes |
|---------|---------|---------|-------|
| QA review by operator before delivery | Yes | Yes | COMPLETE — REPORT-QA-001 (#713) |
| Separation of duties (assessor cannot self-approve) | Yes | Yes | COMPLETE — SoD enforced by platform |
| Governed delivery with audit trail | Yes | Yes | COMPLETE — GOV-DELIVERY-001 (#726) |
| Append-only audit ledger | Yes | Yes | COMPLETE — HMAC-chained audit records |
| 30-day check-in and re-scan | Yes | Yes | Included in scope |
| Founder QA approval required | Yes | Yes | See `docs/commercial/founder_approval_checklist.md` |

---

## What Is Explicitly NOT Available in Either Offer

| Feature | Reason |
|---------|--------|
| Continuous monitoring | No live client yet; deferred to Phase 2 |
| Automated recurring scans | Deferred to Phase 2 |
| SAML/SSO | Deferred — no current client requirement |
| Real-time alerting | Deferred |
| Penetration testing | Out of scope for assessment service |
| Compliance certification | Not offered — assessment only |
| RAG/AI workspace | Deferred — no live client |
| Multi-tenant environments | One Microsoft 365 tenant per engagement |

---

## Three-Tier Pricing Summary

| Tier | Price | Availability | Key difference |
|------|-------|--------------|----------------|
| Design Partner | $2,500 | NOW (pending gates) | Full OFFER A scope; feedback + reference rights required |
| Pilot (OFFER A) | $5,000 | NOW (pending gates) | Full OFFER A scope; standard commercial terms |
| Premium (OFFER B) | TBD | BLOCKED | Triple-signing, offline verification bundle, HSM key custody |

**OFFER B pricing note:** OFFER B requires HCP Vault Dedicated (cost NOT_AUTHORIZED, pricing unconfirmed — FP-001 open). Until cost authorization is confirmed by founder, OFFER B pricing is not set and OFFER B cannot be contracted.

---

## Production Gate Status (required for all offers)

| Gate | OFFER A required | OFFER B required | Status |
|------|-----------------|-----------------|--------|
| Vault Transit provisioned | Yes (any compliant instance) | Yes (HCP Vault Dedicated) | NOT PROVISIONED |
| PRODUCTION_DEPENDENCY_SECURITY attested | Yes | Yes | ATTESTABLE NOW (P0-DEP-REM-001 #786) |
| PRODUCTION_SCHEMA_AND_RLS attested | Yes | Yes | NOT_PROVEN |
| CANONICAL_ASSESSMENT_PROOF attested | Yes | Yes | NOT_PROVEN |
| DURABLE_EXECUTION_AND_RECOVERY attested | Yes | Yes | NOT_PROVEN |
| Mode B production authentication (PRODAUTH-RUN-001) | Yes | Yes | NOT_PROVEN |
| Portal live verification (PORTAL-RUN-001) | Yes | Yes | NOT_PROVEN |
| CUSTOMER-ZERO-ACCEPT-001 | No | Yes | BLOCKED |
| Cost authorization for HCP Vault Dedicated | No | Yes | NOT_AUTHORIZED |
