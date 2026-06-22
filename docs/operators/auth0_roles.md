# Auth0 Role Setup Guide — FrostGate Enterprise RBAC

## Overview

Auth0 is the identity authority for FrostGate. It owns user lifecycle, authentication,
MFA, SSO, and role assignment. FrostGate validates Auth0 JWTs and enforces permissions
based on role claims.

This guide covers:
1. Auth0 application and API setup
2. Creating the FrostGate role set
3. The Login Action that injects role claims
4. Environment variable configuration
5. Enterprise upgrade path

---

## 1. Auth0 Application and API Setup

### Create the API resource

1. Auth0 Dashboard → **Applications → APIs → Create API**
2. Name: `FrostGate API`
3. Identifier (audience): `https://api.frostgate.ai`
4. Signing algorithm: RS256

### Create the SPA / Regular Web App

1. Auth0 Dashboard → **Applications → Applications → Create Application**
2. Type: Regular Web Application (for Next.js console)
3. Allowed Callback URLs: `https://your-domain.com/api/auth/callback/auth0`
4. Allowed Logout URLs: `https://your-domain.com`
5. Note the **Domain**, **Client ID**, and **Client Secret**

---

## 2. Create the FrostGate Roles

Auth0 Dashboard → **User Management → Roles → Create Role**

Create exactly these roles (names must match exactly):

| Role Name | Description |
|-----------|-------------|
| `viewer` | Read-only access to all assessments and reports |
| `assessor` | Create findings, upload evidence, trigger scans, generate bundles |
| `qa_reviewer` | Approve findings, QA-approve reports, approve bundles |
| `compliance_reviewer` | Accept risks, grant exceptions, make governance decisions |
| `tenant_admin` | User administration, connector management, key management |
| `platform_admin` | All permissions — platform operations only |

**Do not create these role names with different capitalisation.** FrostGate's
`ROLE_PERMISSIONS` mapping is case-sensitive.

Future roles (create when needed — no code changes required):
- `auditor`
- `executive_reviewer`
- `external_assessor`
- `autonomous_governance_operator`

---

## 3. Login Action — Inject Role Claims

Auth0 Dashboard → **Actions → Flows → Login → + (Add Action) → Build from scratch**

Name: `FrostGate — Inject Role Claims`

```javascript
/**
 * FrostGate role injection Action.
 * 
 * Injects roles and tenant_id into both the ID token and the Access Token.
 * The Access Token is what FrostGate's backend validates.
 * 
 * The namespace must match FG_AUTH0_NAMESPACE in your environment.
 */
exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://frostgate.ai';
  
  // Inject roles from Auth0 RBAC
  const roles = event.authorization?.roles ?? [];
  api.idToken.setCustomClaim(`${namespace}/roles`, roles);
  api.accessToken.setCustomClaim(`${namespace}/roles`, roles);
  
  // Optional: inject tenant_id from user app_metadata
  // Set this on the user: Auth0 Dashboard → Users → {user} → app_metadata → {"tenant_id": "..."}
  const tenantId = event.user.app_metadata?.tenant_id ?? null;
  if (tenantId) {
    api.accessToken.setCustomClaim(`${namespace}/tenant_id`, tenantId);
  }
};
```

Click **Deploy**, then drag the action into the Login flow.

### Verify the claim injection

After login, decode a sample access token at jwt.io. You should see:

```json
{
  "iss": "https://your-domain.auth0.com/",
  "sub": "auth0|507f1f77bcf86cd799439011",
  "aud": "https://api.frostgate.ai",
  "email": "user@bank.com",
  "name": "Jane Smith",
  "https://frostgate.ai/roles": ["qa_reviewer"],
  "https://frostgate.ai/tenant_id": "tenant-bank-001"
}
```

---

## 4. Environment Variables

Add these to Railway (or your deployment environment):

```bash
# Auth0 JWT validation
FG_AUTH0_DOMAIN=your-domain.auth0.com
FG_AUTH0_AUDIENCE=https://api.frostgate.ai
FG_AUTH0_NAMESPACE=https://frostgate.ai

# Next.js console (next-auth)
AUTH0_CLIENT_ID=<from Auth0 application>
AUTH0_CLIENT_SECRET=<from Auth0 application>
AUTH0_ISSUER=https://your-domain.auth0.com
NEXTAUTH_SECRET=<random 32 bytes: openssl rand -base64 32>
NEXTAUTH_URL=https://your-console-domain.com
```

---

## 5. Assigning Roles to Users

Auth0 Dashboard → **User Management → Users → {user} → Roles → Assign Roles**

Or via Auth0 Management API:

```bash
# Assign qa_reviewer to a user
curl -X POST \
  "https://your-domain.auth0.com/api/v2/users/{user_id}/roles" \
  -H "Authorization: Bearer {management_api_token}" \
  -H "Content-Type: application/json" \
  -d '{"roles": ["rol_qa_reviewer_id"]}'
```

---

## 6. Enterprise Upgrade Path

| Tier | Configuration |
|------|--------------|
| **Today** | Auth0 Free/Essentials → OIDC + RBAC |
| **Mid-market** | Auth0 Professional → MFA (TOTP, SMS), custom domains |
| **Enterprise** | Auth0 Enterprise → SAML federation, SCIM provisioning, custom DB |
| **GovCon** | Auth0 Enterprise → Conditional Access, PIV/CAC, FedRAMP |

No FrostGate code changes are required as you upgrade tiers. Auth0 is the
abstraction layer. FrostGate validates the JWT regardless of how Auth0
authenticated the user.

---

## 7. Separation of Duties — Role Assignment Policy

Per FrostGate's SoD requirements:

- `tenant_admin` and `compliance_reviewer` **must not** be assigned to the same user
  unless explicitly reviewed and approved by the platform administrator
- The separation exists because: regulated industries (banking, healthcare) require
  that the person who configures the system cannot approve governance decisions
- For small teams where one person plays multiple roles: document the exception
  in your risk acceptance record with a compensating control (e.g., dual approval
  with an external party for risk acceptances)

---

## 8. Troubleshooting

**403 PERMISSION_DENIED on a route the user should have access to:**
1. Check the user's roles in Auth0 Dashboard → Users → {user} → Roles
2. Verify the Login Action is deployed and appears in the Login flow
3. Decode the access token at jwt.io — confirm `https://frostgate.ai/roles` claim is present
4. Check FG_AUTH0_NAMESPACE matches the namespace in the Action

**401 INVALID_JWT on a valid token:**
1. Verify FG_AUTH0_DOMAIN matches the Auth0 tenant domain exactly (no https://)
2. Verify FG_AUTH0_AUDIENCE matches the API Identifier exactly
3. Check token expiry — Auth0 default is 24 hours for access tokens

**Actor attribution shows empty email/name:**
1. Ensure the user's Auth0 profile has email and name populated
2. The Login Action must be active — if removed, claims are not injected
