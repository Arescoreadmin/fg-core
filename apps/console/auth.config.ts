import type { NextAuthConfig } from 'next-auth';

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
  session: {
    strategy: 'jwt',
    maxAge: consoleSessionMaxAgeSeconds,
    updateAge: consoleSessionUpdateAgeSeconds,
  },
  jwt: {
    maxAge: consoleSessionMaxAgeSeconds,
  },
} satisfies NextAuthConfig;
