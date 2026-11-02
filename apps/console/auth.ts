import NextAuth from 'next-auth';
import Auth0 from 'next-auth/providers/auth0';
import { authConfig } from './auth.config';
import { resolvePrincipalTenant } from './lib/tenantResolution';

/**
 * AUTH-SECRET-ISOLATION-001
 *
 * Invariants enforced here:
 *   AUTH-001: Auth.js uses a dedicated AUTH_SECRET env var.
 *   AUTH-002: FG_INTERNAL_AUTH_SECRET is never used as a session-signing secret.
 *   AUTH-004: Missing, empty, or whitespace-only session secrets cannot result in
 *             authenticated access — startup-validation.ts also enforces this at boot.
 *   AUTH-008: No silent fallback to unrelated environment variables.
 *
 * The session secret must be set explicitly.  No fallback to internal gateway
 * credentials is permitted — those serve a different trust boundary.
 *
 * In production: startup-validation.ts will abort the process before any request
 * is handled if AUTH_SECRET is absent (validateProductionConfig checks it).
 * In all environments: NextAuth will throw [auth][error] MissingSecret if
 * process.env.AUTH_SECRET is undefined, preventing silent misauthentication.
 */
export const { handlers, auth, signIn, signOut } = NextAuth({
  ...authConfig,
  secret: process.env.AUTH_SECRET,
  providers: [
    Auth0({
      clientId: process.env.AUTH0_CLIENT_ID,
      clientSecret: process.env.AUTH0_CLIENT_SECRET,
      issuer: process.env.AUTH0_ISSUER_BASE_URL,
    }),
  ],
  callbacks: {
    ...authConfig.callbacks,
    // AUTH-TENANT-CONTEXT-001: Async tenant resolution — Node.js context only.
    //
    // The Auth0 Post-Login Action (login-claim-projection/index.js, invariant 10)
    // never projects tenant_id into the JWT. This override resolves it from
    // principal_id via a server-side call to Core API.
    //
    // Runs in Node.js (this file is never imported by middleware.ts, which uses
    // auth.config.ts directly). Edge middleware reads the already-resolved
    // tenantId from the signed JWT cookie — no DB or network call at the Edge.
    async jwt(params) {
      // Run the base Edge-compatible callback first (synchronous).
      // It sets token.roles, token.tenantId, token.experienceClass, token.principalId.
      const token = await Promise.resolve(authConfig.callbacks!.jwt!(params));
      const result = token ?? params.token;

      // Resolve tenant_id for client console sessions that lack it.
      // Conditions: console_enabled_client + no tenantId + has principalId.
      // Retry on refresh if tenantId is still absent (handles projection-in-flight race).
      if (
        result.experienceClass === 'console_enabled_client' &&
        !result.tenantId &&
        typeof result.principalId === 'string'
      ) {
        const binding = await resolvePrincipalTenant(result.principalId);
        if (binding) {
          result.tenantId = binding.tenantId;
        }
      }

      return result;
    },
  },
});
