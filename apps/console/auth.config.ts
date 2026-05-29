import type { NextAuthConfig } from 'next-auth';

// Edge-compatible config: no providers (OIDC providers use Node.js crypto).
// Used by middleware only. Full provider config lives in auth.ts.
export const authConfig = {
  providers: [],
  pages: {
    signIn: '/login',
  },
} satisfies NextAuthConfig;
