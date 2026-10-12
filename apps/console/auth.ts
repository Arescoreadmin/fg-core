import NextAuth from 'next-auth';
import Auth0 from 'next-auth/providers/auth0';
import { authConfig } from './auth.config';

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
});
