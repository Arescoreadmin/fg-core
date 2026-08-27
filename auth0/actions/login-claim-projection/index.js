/**
 * AUTH-ROLE-001A: FrostGate Post-Login Claim Projection
 *
 * Invariants enforced:
 *   1.  Source is app_metadata exclusively — never user_metadata, never DB.
 *   2.  No Management API calls; read-only event access only.
 *   3.  app_metadata.roles must be a JSON array; non-array → no claims set (fail closed).
 *   4.  Each role value is string-matched against the strict ALLOWED_ROLES allowlist.
 *   5.  Unknown roles are silently dropped; they cannot propagate to the token.
 *   6.  If the normalized roles array is empty after filtering → no claims set.
 *   7.  principal_id is projected only when present and passes UUID v4 regex.
 *   8.  Both id_token and access_token receive the same claims (symmetric projection).
 *   9.  Claims use the https://frostgate.ai/ namespace; no bare claim names.
 *  10.  tenant_id is never projected by Auth0 — FrostGate resolves it from principal_id.
 *  11.  bootstrap (env-var override) is not this action's concern; it lives in NextAuth.
 *  12.  Any unexpected error leaves the login flow intact; no claims are set on error.
 */

const ALLOWED_ROLES = new Set([
  // Internal console roles
  'Administrator',
  'Operator',
  'CISO',
  'Executive',
  'Auditor',
  'Developer',
  'Support',
  'Compliance',
  'AssessmentEngineer',
  'FieldAssessor',
  'Consultant',
  // Client console roles
  'tenant_admin',
  'client_executive',
  'client_compliance',
  'client_auditor',
  'client_remediation_owner',
  'client_security_owner',
  'client_read_only',
]);

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

exports.onExecutePostLogin = async (event, api) => {
  try {
    const metadata = event.user.app_metadata ?? {};

    // Invariant 3: roles must be an array.
    const rawRoles = metadata.roles;
    if (!Array.isArray(rawRoles)) return;

    // Invariants 4–5: allowlist filter; unknown roles are silently dropped.
    const roles = rawRoles.filter(
      (r) => typeof r === 'string' && ALLOWED_ROLES.has(r),
    );

    // Invariant 6: nothing to project.
    if (roles.length === 0) return;

    // Invariants 8–9: symmetric projection under namespaced claim.
    api.idToken.setCustomClaim('https://frostgate.ai/roles', roles);
    api.accessToken.setCustomClaim('https://frostgate.ai/roles', roles);

    // Invariant 7: principal_id projected only when valid UUID.
    const principalId = metadata.principal_id;
    if (typeof principalId === 'string' && UUID_RE.test(principalId)) {
      api.idToken.setCustomClaim(
        'https://frostgate.ai/principal_id',
        principalId,
      );
      api.accessToken.setCustomClaim(
        'https://frostgate.ai/principal_id',
        principalId,
      );
    }
  } catch (_err) {
    // Invariant 12: never block login on projection errors.
  }
};
