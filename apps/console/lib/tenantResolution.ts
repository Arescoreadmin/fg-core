/**
 * AUTH-TENANT-CONTEXT-001: Server-side tenant resolution from canonical principal.
 *
 * The Auth0 Post-Login Action (login-claim-projection/index.js) explicitly does not
 * project tenant_id into the JWT (invariant 10). This module implements the resolution
 * described in that invariant: "tenant_id is never projected by Auth0 — FrostGate
 * resolves it from principal_id."
 *
 * Called ONLY from the auth.ts JWT callback (Node.js context, never Edge middleware).
 * Queries the Core API's canonical tenant_users table via an internal-only endpoint.
 * Returns null on network/service errors; a null return leaves token.tenantId unset,
 * which causes the BFF to deny all tenant-scoped requests (TENANT_AUTHORITY_MISSING).
 * The Core API also enforces authoritative access control on every BFF request.
 *
 * Security properties:
 *   - Validates UUID v4 format before making any request.
 *   - Uses X-FG-Internal-Token (never exposed to browser).
 *   - Ambiguous results (>1 active bound membership) resolve to null; Core API enforces.
 *   - Network failures resolve to null; Core API enforces.
 *   - Never logs principalId in error paths.
 */

import { internalGatewaySecret } from './internal-gateway-secret';

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const _UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const _RESOLUTION_TIMEOUT_MS = 5_000;

export type PrincipalTenantBinding = {
  tenantId: string;
  role: string;
  membershipId: string;
};

/**
 * Resolve the active tenant binding for a canonical FrostGate principal.
 *
 * Returns null when:
 *   - principalId is not a valid UUID v4
 *   - internal gateway secret is not configured
 *   - no active bound membership exists (404)
 *   - principal has multiple active bound memberships (409 — ambiguous)
 *   - Core API is unreachable or returns an unexpected error
 *
 * A null return leaves token.tenantId as null, which causes the console
 * middleware to classify the session as unsupported until the condition clears
 * (e.g., projection worker delivers roles and the user re-authenticates).
 */
export async function resolvePrincipalTenant(
  principalId: string,
): Promise<PrincipalTenantBinding | null> {
  if (!_UUID_V4_RE.test(principalId)) return null;

  const token = internalGatewaySecret();
  if (!token) return null;

  try {
    const resp = await fetch(
      `${CORE_API_URL}/admin/identity/principal-tenant/${encodeURIComponent(principalId)}`,
      {
        method: 'GET',
        headers: {
          'X-FG-Internal-Token': token,
          'X-Admin-Gateway-Internal': 'true',
        },
        signal: AbortSignal.timeout(_RESOLUTION_TIMEOUT_MS),
      },
    );

    if (resp.status === 404 || resp.status === 409) return null;
    if (!resp.ok) return null;

    const data = (await resp.json()) as {
      tenant_id?: unknown;
      role?: unknown;
      membership_id?: unknown;
    };

    const tenantId = typeof data.tenant_id === 'string' ? data.tenant_id : null;
    if (!tenantId) return null;

    return {
      tenantId,
      role: typeof data.role === 'string' ? data.role : '',
      membershipId: typeof data.membership_id === 'string' ? data.membership_id : '',
    };
  } catch {
    return null;
  }
}
