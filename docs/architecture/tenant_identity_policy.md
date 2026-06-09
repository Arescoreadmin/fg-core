# Tenant Identity Policy Foundation

## Boundary

Admin Gateway remains the only human authentication boundary. Core stores tenant identity policy, invitation lifecycle, membership bindings, and audit evidence; it does not issue human sessions from invitations.

**Invite links do not activate users.** An invite token is legacy transport context only. It is not identity proof, permanent identity authority, or permission to issue a tenant session.

## Tenant Identity Configuration

`tenant_identity_configs` stores one explicit provider-neutral governance root per tenant:

- `identity_mode`: `managed`, `sso`, or `hybrid`
- `maturity_level`: additive readiness marker (`level_0` through future `level_5`)
- `capability_flags`: JSON feature envelope for managed, SSO, federation, agent, and future identity-governance capabilities
- `provider`: provider adapter identifier; initially `auth0`, not hardwired into policy decisions
- optional OIDC issuer, Auth0 organization ID, and connection ID for backward-compatible primary provider lookup
- provisioning state: `not_configured`, `pending`, `ready`, `failed`, or `disabled`

The table contains no client secrets, private keys, refresh tokens, invite tokens, or authorization headers. A missing or non-ready policy fails closed in `require_identity_configured()`.

## Provider And Domain Governance

`tenant_identity_providers` normalizes provider/issuer/organization/connection records under the tenant governance root. This avoids assuming one tenant has one provider or one provider has one connection. The PR does not implement federation; it only prevents future federation from requiring a replacement schema.

`tenant_identity_domains` normalizes domain governance as separate records with `domain_type` (`trusted`, `blocked`, `verified`, `federated`) and `verification_status`. The legacy `allowed_email_domains` config field remains a compatibility input, but policy resolution can consume normalized domain records first. Email remains invitation verification context, not identity authority.

## Invitation Lifecycle

`tenant_invitations` is separate from `tenant_users` because an invitation is not a membership identity.

```text
pending -> auth_started -> accepted_identity_pending_binding -> bound
   |            |                       |
   +------------+-----------------------+-> expired | revoked | failed
```

Only valid state-machine transitions are accepted. Invitation creation always starts at `pending`. Session issuance and invite-token activation are outside this service and are not implemented by this foundation.

## Membership Identity Binding

`tenant_users` gains provider, issuer, subject, verified identity email, binding timestamps, and `identity_binding_status` (`unbound`, `pending`, `bound`, `disabled`, `failed`). It also includes schema-only governance fields for `identity_type` (`human`, `service`, `agent`, `system`), provider/config/connection lineage, trust level, verification level, risk state, approval metadata, and revocation timestamp.

Email verifies an invitation match but is not permanent identity authority. The provider/issuer/subject tuple is the identity authority and is globally unique once bound because the repository has no explicit cross-tenant human-membership allowance. Existing memberships remain usable and `unbound`; no identity is inferred from email.

`tenant_identity_role_assignments` records optional role lineage without implementing a role engine. It can distinguish manual, inherited, SSO-mapped, and governance-assigned roles through assignment and approval source fields.

`can_membership_be_activated_from_identity()` permits future activation only when the invitation and membership are bound, email is verified and matches, provider/connection policy passes, and the email domain is allowed.

## Audit Events

`tenant_identity_audit_events` is tenant-scoped, append-only, and hash-linked. Supported events cover identity configuration, provider/domain configuration, provisioning, invitation lifecycle, membership binding, and role assignment lineage. Payloads are allowlisted and exclude raw tokens, secrets, and authorization headers.

Audit rows include stable references for future governance graph construction: invitation, membership, provider record, policy config, role assignment, identity subject/type, and correlation ID. `event_hash` plus `previous_event_hash` make identity events usable as tamper-evident evidence artifacts, while PostgreSQL append-only triggers block UPDATE and DELETE. `verify_identity_audit_chain()` lets future reporting detect payload or linkage tampering. Migration-generated events use the same canonical payload and chain format as runtime events, so verification remains continuous from migration evidence through later identity activity.

## Tenant Isolation

Migration `0099` forces RLS on the new identity governance tables and on `tenant_users`, where membership identity binding metadata lives. PostgreSQL regression coverage uses a non-bypass role to prove wrong-tenant identity records are invisible when `app.tenant_id` is set to another tenant.

## Migration 0099

- Creates identity config, provider, domain, role-assignment, invitation, and append-only audit tables with RLS.
- Adds nullable binding, lineage, identity type, trust, verification, risk, approval, and revocation columns to existing memberships.
- Seeds only repository-evidenced `demo-bank` and `demo-healthcare` tenants as explicit `managed`/`ready` policies.
- Leaves unknown tenants without a guessed policy; policy lookup fails closed.
- Copies existing pending invite metadata into pending invitation records without copying raw invite tokens.
- Does not create invitation records for accepted users and does not bind existing identities.
- Uses deterministic IDs and `ON CONFLICT DO NOTHING` for replay safety.

## Governance Graph Readiness

Identity records use stable string identifiers and tenant-scoped references so future systems can correlate identity lineage with assessment, evidence, AI-system, agent, decision, and control lineage. This PR intentionally does not build the graph. It stores the stable anchors needed to construct one later without changing the identity schema.


## PR 2 Runtime Enforcement

The policy foundation is enforced at runtime by Admin Gateway as documented in admin_gateway_identity_enforcement.md. Policy records resolve allowed providers, issuers, connections, organizations, and domains before callback binding. Human invitation flows reject service, agent, and system identities. Provider + issuer + subject remains identity authority; email is only invitation verification input. Admin Gateway alone issues tenant-governed human sessions after an active membership reaches bound status.
