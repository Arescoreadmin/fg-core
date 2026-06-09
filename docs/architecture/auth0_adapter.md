# Auth0 Adapter — Admin Gateway Identity Enforcement

## Authority Boundary (unchanged from PR 2)

**Auth0 authenticates. Admin Gateway authorizes. Admin Gateway alone issues tenant sessions.**

Auth0 is a provider behind the provider-neutral adapter seam. It may:
- Authenticate a user via OIDC / organization-aware login
- Return a verified ID token for claim normalization
- Create or associate an Auth0 Organization for SSO tenants
- Attach an enterprise connection to an organization

Auth0 must not:
- Issue tenant sessions
- Activate tenant membership
- Be the authority for tenant access decisions

## Architecture

```
Router
  └─ InvitationFlow (provider-neutral)
       └─ ProviderAdapter (protocol)
            └─ Auth0Adapter  ──► Auth0ManagementClient ──► Auth0 Management API v2
                              └─ Auth0Config (env vars only)
```

All Auth0-specific code is contained in:

- `admin_gateway/identity/auth0_config.py` — configuration from env vars only
- `admin_gateway/identity/auth0_management.py` — Management API client
- `admin_gateway/identity/auth0_adapter.py` — ProviderAdapter implementation
- `admin_gateway/identity/auth0_models.py` — safe provisioning data types

Routers never call Auth0 directly. They call `start_invitation_auth` / `validate_callback` in `invitation_flow.py`, which delegates to the adapter.

## Configuration

All Auth0 configuration is loaded from environment variables. No secrets are stored in tenant-facing records or database rows.

| Variable | Purpose |
|---|---|
| `AUTH0_DOMAIN` | Auth0 tenant domain |
| `AUTH0_AUDIENCE` | API audience |
| `AUTH0_CLIENT_ID` | Application client ID |
| `AUTH0_CLIENT_SECRET` | Application client secret — **never logged or stored** |
| `AUTH0_MGMT_AUDIENCE` | Management API audience |
| `AUTH0_MGMT_CLIENT_ID` | Management client ID |
| `AUTH0_MGMT_CLIENT_SECRET` | Management client secret — **never logged or stored** |
| `AUTH0_CALLBACK_URL` | OIDC redirect URI |
| `AUTH0_LOGOUT_RETURN_URL` | Post-logout return URL |
| `AUTH0_ORG_LOGIN` | Require org-aware login (`true`/`false`) |
| `AUTH0_ALLOWED_CONNECTIONS` | Comma-separated allowed connection strategies |

Tenant-facing records may store: Auth0 organization ID, Auth0 connection ID, provisioning status, last error code, last attempt timestamp.

## Identity Mode Behavior

### SSO Tenants

- Organization-aware login URL is built with `organization=<org_id>` and `connection=<conn_id>`.
- Callback validation enforces both organization ID and connection ID against tenant policy.
- SSO tenant cannot fall back to managed (database) login — rejected at callback.

### Managed Tenants

- Managed signup/login URL is built without an enterprise connection.
- `screen_hint=signup` is included for new users.
- Email verified is enforced.
- Invite email match is enforced.

### Hybrid Tenants

- Policy-selected path (SSO or managed) is used.
- Unauthorized fallback from SSO to managed is rejected.

## Provisioning Flow

```
provision_tenant_identity()
  1. ensure_organization() — create or associate Auth0 Org
  2. ensure_connection_attached() — attach enterprise connection
  3. Return Auth0ProvisioningResult(status, org_id, connection_id, error_code)
```

**Failure behavior is fail-closed:**
- Org creation failure → `status="failed"`, no org_id, no connection_id
- Connection attach failure → `status="partial"`, org_id preserved, no connection_id
- Caller must NOT mark tenant identity config as `ready` on non-success result
- Membership remains `unbound` / `pending` until full provisioning succeeds and bind completes

Provisioning is idempotent: calling with an existing `org_id` routes through `associate_organization` rather than `create_organization`.

## Callback Validation

The `validate_callback` method:
1. Extracts `id_token` from the callback payload
2. Fetches JWKS from Auth0
3. Verifies signature, issuer, audience, expiry using PyJWT
4. Enforces `email_verified=True`
5. Enforces issuer matches configured Auth0 domain
6. Extracts `org_id` from verified token claims — NOT from raw callback body
7. Returns `AuthenticatedIdentity` for Admin Gateway binding

The `invitation_flow.validate_callback` layer additionally enforces:
- State digest match (replay protection)
- Invite email match
- Provider, issuer, connection, organization policy match
- Human identity type
- Active, unbound membership

## Audit Events

Auth0-specific audit events (added to the PR 1/PR 2 hash-chain ledger):

- `auth0.organization.create_requested`
- `auth0.organization.created`
- `auth0.organization.associated`
- `auth0.connection.attach_requested`
- `auth0.connection.attached`
- `auth0.provisioning_failed`
- `auth0.invitation_auth_started`
- `auth0.callback_received`
- `auth0.callback_rejected`
- `auth0.identity_validated`
- `auth0.identity_bound`
- `auth0.session_issued`
- `auth0.session_rejected`

Audit payloads include only safe fields: tenant_id, invitation_id, membership_id, provider, organization_id, connection_id, issuer, subject hash, safe reason code, correlation_id, timestamp.

Audit payloads exclude: access token, ID token, refresh token, authorization header, client secret, management API token, raw callback payload, raw invite token, plaintext state.

## Invariants Preserved From PR 1 / PR 2

- Invite links do not activate users.
- Invite tokens do not issue tenant sessions.
- `tenant_id` query parameters are ignored/rejected for tenant authority.
- Auth state stores only SHA-256 digest, never raw state value.
- Auth state expiry, replay, and consumption constraints are unchanged.
- RLS and tenant isolation are unchanged.
- Provider-neutral interface is unchanged.
- Generic OIDC sessions remain authentication-only and cannot access tenant resources.
- Admin Gateway is the only tenant session authority.
