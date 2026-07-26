import { NextResponse } from 'next/server';
import { COOKIE_NAME } from '@/lib/session';

/**
 * POST /api/auth/logout
 *
 * Clears the local session cookie. The core-side pnu1. session record has
 * its own 14-day TTL and can be invalidated explicitly by an admin via
 * DELETE /portal/named-sessions/{id} or by bumping the membership
 * auth_version — either mechanism causes validate_session to fail closed on
 * the next request even if the cookie were somehow replayed.
 */
export function POST() {
  const res = NextResponse.json({ ok: true });
  res.cookies.delete(COOKIE_NAME);
  return res;
}
