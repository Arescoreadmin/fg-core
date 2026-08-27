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
      // Allow env-configured subjects or emails to receive a bootstrap role when no
      // Auth0 Post-Login Action is injecting claims (e.g. during setup).
      const bootstrapSubjects = (process.env.FG_CONSOLE_BOOTSTRAP_ADMIN_SUBJECTS ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const bootstrapEmails = (process.env.FG_CONSOLE_BOOTSTRAP_ADMIN_EMAILS ?? '')
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      let bootstrapped = false;
      if (bootstrapSubjects.length > 0 || bootstrapEmails.length > 0) {
        // token.sub may be unset; fall back to profile/user
        const subject =
          (typeof token.sub === 'string' ? token.sub : undefined) ??
          (profile as Record<string, unknown> | undefined)?.['sub'] as string | undefined ??
          (user as Record<string, unknown> | undefined)?.['id'] as string | undefined;
        const email =
          (typeof token.email === 'string' ? token.email : undefined) ??
          (profile as Record<string, unknown> | undefined)?.['email'] as string | undefined ??
          (user as Record<string, unknown> | undefined)?.['email'] as string | undefined;
        const subjectMatch = typeof subject === 'string' && bootstrapSubjects.includes(subject);
        const emailMatch = typeof email === 'string' && bootstrapEmails.includes(email.toLowerCase());
        if (subjectMatch || emailMatch) {
          token['https://frostgate.ai/roles'] = ['Administrator'];
          bootstrapped = true;
        }
      }
      const claims = getSessionClaims({ token, user, profile });
      token.roles = bootstrapped ? ['Administrator'] : claims.roles;
      token.tenantId = claims.tenantId;
      token.experienceClass = bootstrapped ? 'internal_console' : claims.experienceClass;
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
