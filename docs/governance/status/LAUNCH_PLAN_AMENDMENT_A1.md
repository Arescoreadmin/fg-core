# Launch Plan Amendment A-1 — Insert IA-v1 Console-Managed Identity Authority

**Amendment ID:** A-1  
**Date:** 2026-07-31  
**Author:** admin@arescore.ai  
**Status:** APPROVED — inserted into critical path

---

## Reason

The existing portal deployment route (`CORE_TENANT_ID` env var + manually constructed `pni1.` accept-invite URL) cannot satisfy the required Console-owned client/user lifecycle. Specifically:

1. **No invitation email**: the console email route has no `portal_invite` type; operator must manually construct and deliver accept-invite URLs. Not scalable and not auditable as a client lifecycle event.
2. **No Auth0 connection between clients and Auth0 Organizations**: the portal's Auth0 app (pending configuration) has no mechanism to scope an OIDC login to a specific client's organizational context. Without Auth0 Organizations, every portal login is tenant-context-blind at the Auth0 layer.
3. **No Console control plane for invitation, suspension, or revocation**: current portal user lifecycle calls are direct API calls, not Console-initiated governed operations with audit evidence.
4. **Orphaned schema columns**: `tenant_identity_configs.auth0_organization_id`, `tenant_identity_providers.organization_id`/`connection_id`, and `tenant_invitations.auth0_invitation_id` exist in the DB schema but are entirely unpopulated — confirming Auth0 organization integration was planned but never built.

Without IA-v1, T4's proof would exercise a manually wired one-off path that is not the production client onboarding flow. L1 and L2 DoD evidence would not represent the actual launch-day operator experience.

---

## What Changes

### Inserted milestone: IA-v1 (7.5 engineering days)

| PR | Name | Estimate |
|----|------|----------|
| IA-0 | Capability and contract audit (no code) | 0.5d |
| IA-1 | Client organization provisioning | 1.5d |
| IA-2 | User invitation and membership authority | 2.0d |
| IA-3 | Modify, suspend, revoke, offboard | 1.5d |
| IA-4 | Console UX and reconciliation | 1.0d |
| T4-revised | Full named-user lifecycle proof via IA-v1 | 1.0d |

IA-v1 is inserted between the current T3 state and T4. T4 is revised from a one-user manual proof to a full lifecycle proof via Console-managed authority.

### T4 status

T4 (`ops/t4-portal-named-user-proof`) is **revised**. The branch and runbook created in PR to-be-opened are replaced by the IA-v1 sequence plus T4-revised. The evidence manifest structure (`docs/governance/status/L01_evidence_manifest.md`) is retained and will be filled after IA-4.

---

## Added Effort

| Phase | Original estimate (days remaining) | After amendment |
|-------|-------------------------------------|-----------------|
| T4 (original) | 2.0 | superseded |
| IA-v1 | 0 | 7.5 |
| T4-revised | — | 1.0 |
| Net change | — | +6.5 |

Engineering days remaining before amendment: **16.0**  
Engineering days remaining after amendment: **16.0 − 6.5 = 9.5** (budget consumed: 3.0 T1–T3; 6.5 IA-v1 net)

---

## Displaced Work

The following is pushed to later or descoped from launch:

- `docs/operators/credential_delivery.md` named-user rewrite (T14) — now blocked on IA-2 completion; pushed post-IA-4.
- Stage 2 UI enhancements — depend on IA-4 reconciliation panel; pushed post-launch.
- Synthetic portal login monitor (mentioned in FG-LR-002 ideal-later-state) — post-launch.

---

## New Risks

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Auth0 Organizations gated by plan | **CRITICAL** | Confirm in Auth0 dashboard before IA-1 starts. If unavailable, stop and re-scope. |
| Auth0 Management API rate limits during IA-1/IA-2 testing | Medium | Use correlation IDs; implement exponential backoff; test against dev tenant only |
| `tenant_identity_configs` legacy columns conflict with new `tenant_identity_bindings` table | Low | IA-0 audit resolves schema authority; old columns remain as read-only legacy until deprecated |
| Auth0 eventual consistency on organization membership reads | Medium | IA-2 must implement bounded retry on membership verification after invite acceptance |
| Management API session-delete endpoints require Enterprise plan | Medium | FrostGate must revoke `pnu1.` sessions independently (already designed); do not depend on Auth0 session management |
| IA-v1 scope creep | High | Hard cut list enforced: no per-client Auth0 apps, no SCIM, no SAML automation, no self-service admin, no auto-heal |

---

## Revised Critical Path

```
IA-0 (audit/ADR, 0.5d)
  → IA-1 (client organization provisioning, 1.5d)
    → IA-2 (invitation/membership/RBAC, 2.0d)
      → IA-3 (lifecycle/revocation, 1.5d)
        → IA-4 (Console UX + reconciliation, 1.0d)
          → T4-revised (full lifecycle proof, 1.0d)
            → finish L12 (FG_SIGNING_SECRET + FG_KEY_PEPPER rotation)
              → T5 (Railway infra headroom)
                → T6 (H1–H18 dry run)
```

---

## Unchanged Non-Waivable Gates

These four DoD items remain non-waivable regardless of amendment:

| Gate | Requirement |
|------|------------|
| L1 | Real external identity through full named-user lifecycle — now via T4-revised/IA-v1 |
| L2 | Full H1–H18 dry run on production stack — unchanged, requires T6 |
| L4 | Backup/restore proof — PASS (complete) |
| L13 | Audit/evidence integrity — unchanged |

No written risk acceptance exists for failures in these four classes.

---

## Revised Target Date

Original: 2026-08-27  
Revised: **2026-09-05** (contingent on IA-0 Auth0 plan confirmation; 9-day buffer remains if scope held)

---

## Immediate Next Action

**IA-0 only.** Do not start IA-1 until IA-0 exit criteria are met:

- [ ] Auth0 Organizations availability confirmed in dashboard.
- [ ] Auth0 M2M application (`FrostGate Identity Authority`) created with least-privilege Management API scopes.
- [ ] IA-0 audit document complete: all integration points documented, no duplicate authorities introduced.
- [ ] ADR written and committed.

See `docs/governance/ia_v1/IA_0_audit.md`.

---

## Cut List (IA-v1 hard scope boundary)

Do not build in IA-v1:

- Per-client Auth0 applications
- Per-client Auth0 tenants
- SCIM
- SAML connection automation
- Self-service customer admins
- Custom domains per client
- Automatic hard deletion
- Global Auth0 session management via Management API
- Background auto-healing reconciliation
- Bulk import
- Role-builder UI
- Mobile identity flows
