import { NextRequest, NextResponse } from 'next/server';
import { COOKIE_NAME, getPnuSessionToken } from '@/lib/session';

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
// Bound the upstream logout call so a slow/unavailable Core never blocks the
// browser from clearing its cookie. Value chosen to be short but survive one
// TCP handshake round-trip in prod.
const REVOKE_TIMEOUT_MS = Math.max(
  500,
  parseInt(process.env.PORTAL_LOGOUT_REVOKE_TIMEOUT_MS || '2000', 10) || 2000,
);

/**
 * POST /api/auth/logout
 *
 * Clears the local session cookie AND, when the cookie carries a pnu1. named-
 * user session token, revokes the server-side portal_user_sessions row via
 * Core's DELETE /portal/named-sessions/self endpoint so the token is unusable
 * on any subsequent request even if the cookie were leaked or replayed.
 *
 * Fail-open contract: the fg_portal_session cookie is ALWAYS cleared on the
 * response, regardless of whether the Core revocation call succeeds, fails, or
 * times out. Never leave a user stuck logged in because Core is slow. Core
 * errors are logged server-side only.
 *
 * Legacy grant sessions (non-pnu1. cookies) do not touch Core here — grant
 * revocation is handled elsewhere and this route stays a cookie-only logout
 * for them, matching prior behavior.
 */
export async function POST(request: NextRequest) {
  const cookieValue = request.cookies.get(COOKIE_NAME)?.value;
  const pnuToken = getPnuSessionToken(cookieValue);

  if (pnuToken) {
    // Fire-and-forget from the caller's perspective — we await it so we can
    // log the outcome, but the response is unaffected by success or failure.
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REVOKE_TIMEOUT_MS);
    try {
      const upstream = await fetch(`${CORE_API_URL}/portal/named-sessions/self`, {
        method: 'DELETE',
        headers: {
          // The pnu1. token is the credential; no service-account API key
          // or tenant header — Core resolves both from the session record.
          'X-FG-Portal-Session': pnuToken,
        },
        cache: 'no-store',
        signal: controller.signal,
      });
      if (!upstream.ok && upstream.status !== 404) {
        // 204 → revoked; 404 → already expired/revoked (still idempotent OK).
        // Anything else: log and continue with cookie clearing.
        console.warn(
          `[portal-logout] Core revocation returned ${upstream.status} — clearing cookie anyway`,
        );
      }
    } catch (err) {
      // Fetch aborted, network error, DNS failure, etc. Fail-open: clear cookie.
      const reason = err instanceof Error ? err.message : 'unknown error';
      console.warn(`[portal-logout] Core revocation call failed (${reason}) — clearing cookie anyway`);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  const res = NextResponse.json({ ok: true });
  res.cookies.delete(COOKIE_NAME);
  return res;
}
