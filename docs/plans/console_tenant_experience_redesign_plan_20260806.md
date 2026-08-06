# Console Tenant Experience Redesign Plan - 2026-08-06

## Design objectives

- Make route/session tenant authority the only tenant authority for tenant administration actions.
- Restore the required T9 console invitation workflow without weakening authorization.
- Remove editable tenant/client IDs from scoped actions.
- Replace typed engagement IDs with tenant-scoped selection and server-side ownership validation.
- Show clear permission, success, failure, lifecycle, and audit states.
- Preserve the 8-item launch navigation and existing FrostGate architecture conventions.
- Align console and portal onboarding with the future Unified Invitation Authority.

## Non-goals

- No global admin fallback for tenant operations.
- No broadening tenant portal keys to include unrelated admin powers.
- No production default credentials.
- No route, permission, API, schema, or UI implementation in this planning artifact.
- No visual redesign of the whole Console.

## Proposed IA

Keep the launch sidebar at 8 visible items:

- Command Center
- Readiness
- Field Assessments
- Workforce Intel
- Audit & Forensics
- Clients
- Keys
- Settings

Inside `Clients > {Client}`:

- Header: client name, tenant ID, lifecycle/health, breadcrumb to All clients.
- Tabs:
  - Overview
  - Console users
  - Portal access
  - Identity governance
  - Audit history, if backed by a scoped event endpoint and kept concise.

Keep `Clients` as the navigation label. Use `Tenant ID` as secondary immutable identifier. Do not introduce a visible `Tenants` nav item before launch.

## Proposed tenant context model

One tenant resolution path per request:

1. Browser route contains `/admin/tenants/{tenant_id}`.
2. BFF validates session authority for that route tenant.
3. BFF calls a Core endpoint whose route/header context carries the tenant.
4. Core binds tenant from server-side auth context or explicit trusted route/header.
5. Payload tenant/client IDs are absent or rejected.
6. All persistence and audit writes use the Core-bound tenant only.

Rules:

- Payload cannot override route/session tenant authority.
- `tenant_id` may remain in BFF query during compatibility, but it must be validated and stripped before Core mutation payloads.
- Long term, prefer route-authoritative paths such as `/admin/tenants/{tenant_id}/...`.
- Production must fail closed if route tenant and authenticated tenant authority disagree.

## Proposed console invitation flow

UI:

- Open `Clients > Odin Financial Group > Console users`.
- Click `Invite console user`.
- Modal fields:
  - Tenant: Odin Financial Group, read-only.
  - Tenant ID: `odin-financial-group`, read-only secondary text.
  - Email.
  - Display name.
  - Console role.
  - Role description and practical access.
- Submit `Send invitation`.
- Success state shows: invitation status, delivery status, expiration, request ID/audit event ID.

Backend:

- BFF must not call `POST /workforce/users` with a tenant portal key for admin invitation writes.
- Smallest safe option: introduce or route to a tenant-scoped admin invitation endpoint backed by an authority principal limited to invitation administration.
- Core must continue requiring `admin:write` and `identity.scim` or the equivalent unified permission.
- Core must derive tenant from route/auth, not body.

## Proposed portal access flow

UI:

- Open `Clients > Odin Financial Group > Portal access`.
- Click `Create portal access`.
- Modal fields:
  - Tenant: Odin Financial Group, read-only.
  - Engagement selector: searchable list of Odin-owned engagements.
  - Portal access policy/view type.
  - Expiration/duration.
  - Recipient email.
  - Recipient name.
  - Optional note.
- Submit `Send invitation`.
- Do not display an editable `Client ID`.
- Do not require a typed `Engagement ID`.
- Show raw IDs only as secondary copyable details in tables or detail drawers.

Backend:

- Derive `client_id` from the route tenant or eliminate `client_id` from create payload.
- Validate `engagement_id` by querying `fa_engagements` with `(tenant_id, engagement_id)` before issuing a grant/invitation.
- If tenant-scoped portal access is supported, model it explicitly as policy `scope=tenant`; otherwise default to engagement-scoped access.
- Prefer named-user portal invitations (`POST /portal/invitations`) over emailing raw grant credentials.

## Proposed authorization model

- Platform/internal Administrator and Support may administer clients only through explicit BFF/Core tenant-admin authority.
- Tenant administrator behavior must be explicit: either not supported in launch tenant admin UI, or supported with a tenant-bound identity and action-level permissions.
- API-key principals cannot exceed their bound tenant and must not receive broad platform authority merely for Console UX.
- Missing scope/capability remains 403 with stable error code.
- Tenant mismatch remains 403 with stable `TENANT_MISMATCH`-style code.
- Missing tenant context remains fail-closed.

## Proposed API/authority changes

Candidate routes, subject to repository convention:

- `POST /admin/tenants/{tenant_id}/console-user-invitations`
- `GET /admin/tenants/{tenant_id}/console-users`
- `POST /admin/tenants/{tenant_id}/portal-invitations`
- `POST /admin/tenants/{tenant_id}/portal-grants`
- `GET /admin/tenants/{tenant_id}/engagements`

Compatibility option:

- Keep existing `/workforce/users` and `/portal/grants` for direct Core clients.
- Add BFF/Core wrappers that enforce route-authoritative tenant context and call existing services internally.
- Reject or ignore tenant/client fields in payloads on new routes.

Required stable errors:

- `TENANT_MISMATCH`
- `ENGAGEMENT_NOT_FOUND`
- `ENGAGEMENT_TENANT_MISMATCH`
- `INVITATION_AUTHORITY_DENIED`
- `PORTAL_ACCESS_AUTHORITY_DENIED`
- `IDENTITY_CONFIGURATION_REQUIRED`
- `DUPLICATE_INVITATION`
- `ALREADY_MEMBER`
- `EMAIL_DELIVERY_FAILED`

## Proposed data/schema changes, only if required

No mandatory schema change is proven for the first PR.

Possible later changes:

- Add invitation lifecycle fields or views if current `TenantInvitation` and portal invitation models do not expose pending/sent/accepted/expired/revoked uniformly.
- Add idempotency keys to console invitation authority if missing.
- Add explicit portal access scope enum: `tenant` or `engagement`.

## Proposed audit events

Required:

- `console_invitation.created`
- `console_invitation.sent`
- `console_invitation.delivery_failed`
- `console_invitation.accepted`
- `console_invitation.expired`
- `console_invitation.revoked`
- `console_membership.created`
- `console_membership.role_changed`
- `console_membership.deactivated`
- `portal_access.created`
- `portal_invitation.sent`
- `portal_invitation.accepted`
- `portal_access.revoked`
- `portal_access.expired`
- `tenant_scope_mismatch.rejected`
- `engagement_scope_mismatch.rejected`

Each event should include tenant, actor, affected email/user/grant, request ID, and safe reason code. Avoid logging raw secrets.

## Proposed error contracts

BFF and Core should converge on:

```json
{
  "code": "INVITATION_AUTHORITY_DENIED",
  "message": "You do not have permission to invite console users for this tenant.",
  "request_id": "..."
}
```

UI should map stable codes to operator guidance and keep raw status secondary.

## Proposed UI states

- Loading skeletons for users, grants, and engagements.
- Empty console users: "No console users invited yet" with role-aware CTA.
- Empty portal access: "No portal access has been issued for this client" with CTA if authorized.
- Permission denied inline panel with request ID and required authority.
- Success state with delivery state and audit/request ID.
- Duplicate invitation state with resend option.
- Revoked/expired state in lifecycle tables.

## Accessibility requirements

- Dialog role and labelled title.
- Focus trap and escape-to-close.
- Keyboard reachable buttons and selectors.
- Error text associated with fields.
- Read-only tenant context accessible to screen readers.
- Tables retain semantic headers.
- Mobile modal uses full-width sheet with no horizontal clipping.

## Migration and compatibility strategy

- Phase new BFF/Core routes behind feature flag.
- Keep existing Core routes until direct clients are migrated.
- Block editable tenant/client IDs in the new UI even if legacy endpoints still accept them.
- Log mismatch rejections before removing legacy payload fields.
- Update contract/openapi only in implementation PRs, not in this plan.

## Feature-flag/rollout strategy

- `FG_CONSOLE_TENANT_ADMIN_V2`: enables new tenant-scoped BFF/Core route.
- `FG_CONSOLE_PORTAL_ACCESS_SELECTOR`: enables engagement selector and body simplification.
- `FG_CONSOLE_INVITATION_LIFECYCLE_UI`: enables lifecycle table/status.

Roll out on staging tenant first, then Odin/design-partner tenant, then all production clients.

## Test strategy

Authorization:

- Authorized tenant admin can invite console user.
- Unauthorized role receives 403.
- Action visibility matches permission.
- Platform admin behavior is explicit.
- API-key principal cannot exceed intended scope.

Tenant isolation:

- Route tenant A plus payload tenant B rejected.
- Tenant A cannot invite membership into tenant B.
- Tenant A cannot create portal grant for tenant B.
- Tenant A cannot select tenant B engagement.
- Forged engagement ID rejected.
- Stale engagement ownership rejected.
- Direct API request cannot bypass UI constraints.
- List endpoints never return cross-tenant data.
- Revocation affects only intended tenant.

Invitation lifecycle:

- Issue, resend, accept, expire, revoke.
- Duplicate invite.
- Already-member behavior.
- Email delivery failure.
- Idempotency/retry.
- Audit events.

Portal access:

- Correct tenant binding.
- Correct engagement binding.
- Correct view policy.
- Expiration and revocation.
- Login/session enforcement.
- No access after revocation.
- No access outside granted engagement or tenant.

UX:

- Tenant name/ID prefilled.
- Tenant/client fields read-only or absent.
- Engagement selector scoped.
- Useful errors.
- Loading, empty, success states.
- Keyboard and accessible labels.
- Responsive modal.

Regression:

- T4 named-user proof remains valid.
- T6 Gold Path remains valid.
- T9 launch navigation stays <=9.
- Contract and authority gates remain valid.
- Auth0, Resend, Railway, and Vercel flows remain compatible.

## Observability and metrics

- Count invitation attempts by outcome code, not email.
- Count tenant/engagement mismatch rejections.
- Track BFF/Core request IDs across invite/grant actions.
- Track email delivery state.
- Track action latency.
- Track UI permission-denied render counts.

No metric labels should contain raw tenant IDs or emails unless existing policy permits.

## Security review checklist

- No payload tenant override.
- No raw secret persisted or logged.
- No broad platform key introduced.
- API key scope/capability remains least privilege.
- Tenant mismatch rejects and audits.
- Engagement ownership validated server-side.
- Direct API tests cover forged payloads.
- Revocation invalidates active sessions.
- Error messages do not leak credential details.

## Phased implementation roadmap

Phase 0, before RC1:

- Fix console invitation 403 authority path.
- Add regression tests.
- Add actionable error mapping.

Phase 1, before or immediately after RC1 if portal access is launch-critical:

- Align `/portal/grants` BFF/Core authority route.
- Remove editable `Client ID`.
- Add tenant-scoped engagement selector and server validation.

Phase 2, design-partner launch:

- Improve invitation lifecycle table.
- Add audit confirmation.
- Tighten terminology and accessibility.

Phase 3, post-launch:

- Converge console and portal flows into Unified Invitation Authority.
- Add advanced lifecycle automation.

## PR decomposition

See `docs/plans/console_tenant_experience_pr_sequence_20260806.md`.

## Effort estimates

- PR 1: 1-2 days.
- PR 2: 1-2 days.
- PR 3: 1-2 days.
- PR 4: 2-3 days.
- PR 5: 1-2 days.
- PR 6: 2-3 days.
- PR 7: 2 days.
- PR 8: 1-2 days.

## Dependencies

- Core/BFF route contract agreement.
- Existing identity configuration for target tenants.
- Engagement list endpoint suitable for tenant-scoped selector.
- Resend/Auth0 test environments for non-production lifecycle checks.
- Contract and route inventory updates in implementation PRs.

## Risks

- Making the Console key too broad while trying to fix UX.
- Breaking direct Core clients that use existing routes.
- Mismatched admin/internal path lists recurring.
- Overloading portal grant concepts instead of moving to named-user invitations.
- Under-testing direct API bypass paths.

## Rollback plan

- Feature flags allow returning to current UI.
- Existing Core routes remain until replacements prove stable.
- If invitation BFF route fails, hide CTA with actionable admin message rather than exposing broken submit.
- No data migration is required for PR 1 rollback.

## RC1 recommendation

T9 should be blocked until console invitation succeeds for an authorized operator with least-privilege authority and a clear failure state for unauthorized users. Portal access should be blocked or explicitly removed from RC1 walkthrough until client/engagement authority-bearing payloads are eliminated or validated server-side.

## Definition of done

- Authorized Odin operator can invite a console user in non-production without real delivery side effects.
- Unauthorized user receives stable 403 and UI guidance.
- Tenant cannot be changed through body, forged request, stale state, or direct API.
- Portal access create uses selected tenant and owned engagement only.
- Tests listed above pass for touched surfaces.
- T9 visible nav remains <=9.
- Audit events and request IDs are visible or documented for operator verification.

## Validation record

- `git diff --check`: PASS.
- `node_modules/.bin/markdownlint docs/audits/console_tenant_ux_authority_audit_20260806.md docs/plans/console_tenant_experience_redesign_plan_20260806.md docs/plans/console_tenant_experience_pr_sequence_20260806.md docs/plans/console_tenant_experience_wireframes_20260806.md`: PASS.
- `make paste-garbage`: PASS.
- Full CI gate suite: SKIP, documentation-only audit/planning artifacts and no runtime code changes.
- Runtime Console/Core verification: SKIP, requires operator credentials and could create invitations or grants if not performed against a safe fixture tenant.
