import type { NextAuthConfig } from 'next-auth';
import { getSessionClaims } from '@/lib/consoleAccess';

const DEFAULT_SESSION_MAX_AGE_SECONDS = 8 * 60 * 60;
const DEFAULT_SESSION_UPDATE_AGE_SECONDS = 15 * 60;

function boundedEnvInt(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
}

export const consoleSessionMaxAgeSeconds = boundedEnvInt(
  'AUTH_SESSION_MAX_AGE_SECONDS',
  DEFAULT_SESSION_MAX_AGE_SECONDS,
  15 * 60,
  24 * 60 * 60,
);

export const consoleSessionUpdateAgeSeconds = boundedEnvInt(
  'AUTH_SESSION_UPDATE_AGE_SECONDS',
  DEFAULT_SESSION_UPDATE_AGE_SECONDS,
  5 * 60,
  60 * 60,
);

// Edge-compatible config: no providers (OIDC providers use Node.js crypto).
// Used by middleware only. Full provider config lives in auth.ts.
export const authConfig = {
  providers: [],
  pages: {
    signIn: '/login',
  },
  callbacks: {
    jwt({ token, user, profile }) {
      const claims = getSessionClaims({ token, user, profile });
      token.roles = claims.roles;
      token.tenantId = claims.tenantId;
      token.experienceClass = claims.experienceClass;
      return token;
    },
    session({ session, token }) {
      const roles = Array.isArray(token.roles) ? token.roles : [];
      const tenantId = typeof token.tenantId === 'string' ? token.tenantId : null;
      const experienceClass =
        typeof token.experienceClass === 'string' ? token.experienceClass : 'unsupported';

      session.roles = roles;
      session.tenantId = tenantId;
      session.experienceClass = experienceClass;
      session.user = {
        ...session.user,
        roles,
        tenantId,
        experienceClass,
      };
      return session;
    },
  },
  session: {
    strategy: 'jwt',
    maxAge: consoleSessionMaxAgeSeconds,
    updateAge: consoleSessionUpdateAgeSeconds,
  },
  jwt: {
    maxAge: consoleSessionMaxAgeSeconds,
  },
} satisfies NextAuthConfig;
