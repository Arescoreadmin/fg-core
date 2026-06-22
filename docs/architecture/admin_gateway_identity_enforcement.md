# Provider-Neutral Admin Gateway Identity Enforcement

## Authority Boundary

Admin Gateway is the only authority for human tenant-session issuance. Generic OIDC authentication, Console requests, invitation references, email matches, and tenant query parameters do not grant tenant access.

The default provider-neutral adapter returns deterministic start metadata but fails callback validation with PROVIDER_CALLBACK_NOT_CONFIGURED. A provider adapter must return a verified AuthenticatedIdentity; request JSON is never accepted as identity authority by itself. No vendor management API is called by this layer.

## Runtime Flow

1. POST /identity/invitations/{id}/start-auth records a digest-only short-lived state, moves the invitation to auth_started, and issues no session.
2. POST /identity/invitations/{id}/callback verifies adapter context, then validates state, expiry, tenant, verified email, invite email, provider, issuer, connection, organization, domain, membership, and human identity type. Success moves the invitation to accepted_identity_pending_binding and issues no session.
3. POST /identity/invitations/{id}/bind binds provider + issuer + subject to the active membership, moves the invitation to bound, and only then issues a signed tenant-governed Admin Gateway session.
4. GET /identity/session/current returns safe governed session context and does not trust a query tenant.
5. POST /identity/session/logout records logout and clears session and CSRF cookies.

Invite links never activate users and never issue tenant sessions.

## Invitation State Machine

pending -> auth_started -> accepted_identity_pending_binding -> bound

Terminal safe states remain expired, revoked, and failed. Rejected, expired, or consumed callback state cannot be replayed to revive an invitation. Repeated start is safe; repeated callback/bind for the same verified authority is idempotent; a different authority is rejected.

## Tenant Session Shape

A governed session contains tenant ID, membership ID, user ID, provider, issuer, subject, human identity type, role, scopes, binding status, issue/expiry timestamps, and session ID. It excludes provider tokens, invite tokens, refresh tokens, authorization headers, secrets, and private keys.

Generic /auth/callback and /auth/token-exchange sessions are authentication-only: tenant claims and token-derived scopes are stripped and cannot authorize tenant operations. The explicit local development bypass creates a marked governed development session and remains prohibited in production.

## Failure Codes

Failures are deterministic and fail closed. Codes cover missing, expired, revoked, or replayed invitations; unverified or mismatched email; unauthorized provider, issuer, connection, organization, or identity type; missing or disabled membership; identity conflicts; missing scopes; unavailable provider verification; and missing governed session context.

## Audit And Isolation

Identity transitions use the PR 1 append-only hash-chain audit ledger. Events cover callback receipt/rejection, binding pending/bound/rejection, session issue/rejection/logout, and invitation auth transitions. Payload allowlisting excludes tokens and secrets.

The tenant_identity_auth_states table stores only SHA-256 state digests and validated identity metadata, expires records, prevents state/correlation reuse, and enforces forced PostgreSQL RLS. Invitation routes require an explicit tenant header and always query by both tenant and invitation ID.

## Console BFF Enforcement Seam

The Console Core BFF removes incoming tenant_id and reinjects only server-authoritative CORE_TENANT_ID. URL query parameters cannot override tenant authority. Full Console adoption of Admin Gateway governed session context remains a later UI/BFF migration; existing machine/internal API-key flows are unchanged.

## Auth0 Adapter (PR 3)

PR 3 added Auth0 as a provider behind the provider-neutral adapter seam. See `docs/architecture/auth0_adapter.md` for the complete Auth0 adapter specification.

The Auth0 adapter implements the ProviderAdapter protocol without replacing the provider-neutral architecture. Auth0 authenticates; Admin Gateway authorizes. Provisioning failures leave tenant identity configs and memberships in pending/not-ready states — they do not partially activate.

Future provider adapters (Keycloak, Okta) follow the same seam. SCIM provisioning, JIT provisioning governed by explicit tenant policy, and full enterprise IdP onboarding lifecycle automation remain future work.
