/**
 * POST /api/auth/activate
 *
 * BFF activation endpoint for L14-PORTAL-HANDOFF-001.
 *
 * Contract:
 *   - Body: { assessment_id: string, activation_token: string }
 *   - Requires the fg_oidc_bootstrap HttpOnly cookie set by
 *     /api/auth/oidc/callback (mode=activate). Cookie carries the Auth0
 *     access_token; this route consumes and clears it.
 *   - Calls core: POST /ingest/assessment/{id}/activate (public endpoint)
 *     Body: { access_token, activation_token, oidc_provider }
 *   - On success: sets fg_portal_session cookie with pnu1. token returned by core.
 *   - Clears fg_oidc_bootstrap cookie.
 */
import { NextRequest, NextResponse } from 'next/server';
import { COOKIE_NAME } from '@/lib/session';

const CORE_API_URL = (process.env.CORE_API_URL || 'http://localhost:8000').replace(/\/$/, '');
const IS_PROD = process.env.NODE_ENV === 'production';
const OIDC_BOOTSTRAP_COOKIE = 'fg_oidc_bootstrap';

function badRequest(message: string, code: string, status = 400): NextResponse {
  return NextResponse.json(
    { error: message, code },
    { status, headers: { 'Cache-Control': 'no-store' } },
  );
}

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  const assessmentId = String(body?.assessment_id ?? '').trim();
  const activationToken = String(body?.activation_token ?? '').trim();

  if (!assessmentId) {
    return badRequest('assessment_id is required', 'ASSESSMENT_ID_REQUIRED');
  }
  if (!activationToken) {
    return badRequest('activation_token is required', 'ACTIVATION_TOKEN_REQUIRED');
  }

  // Consume the OIDC bootstrap cookie set by /api/auth/oidc/callback mode=activate.
  const accessToken = request.cookies.get(OIDC_BOOTSTRAP_COOKIE)?.value ?? '';
  if (!accessToken) {
    return badRequest(
      'OIDC bootstrap missing — please restart the activation flow.',
      'OIDC_BOOTSTRAP_MISSING',
      401,
    );
  }

  // Call core activation endpoint (public — no API key needed).
  const upstream = await fetch(
    `${CORE_API_URL}/ingest/assessment/${encodeURIComponent(assessmentId)}/activate`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        access_token: accessToken,
        activation_token: activationToken,
        oidc_provider: 'auth0',
      }),
      cache: 'no-store',
    },
  );

  if (!upstream.ok) {
    const err = await upstream.json().catch(() => ({}));
    const detail = typeof err?.detail === 'string' ? err.detail : (err?.detail?.message ?? 'Activation failed.');
    const errRes = NextResponse.json(
      { error: detail, code: 'ACTIVATION_FAILED' },
      { status: upstream.status, headers: { 'Cache-Control': 'no-store' } },
    );
    // Terminal states: clear the bootstrap cookie to bound replay window.
    if ([402, 403, 409, 410].includes(upstream.status)) {
      errRes.cookies.delete(OIDC_BOOTSTRAP_COOKIE);
    }
    return errRes;
  }

  const payload = (await upstream.json()) as {
    activated: boolean;
    session_token: string;
    expires_at: string;
    tenant_id: string;
    assessment_id: string;
    portal_user_id: string;
  };

  const sessionToken = (payload.session_token || '').trim();
  if (!sessionToken.startsWith('pnu1.')) {
    return NextResponse.json(
      { error: 'Malformed session token from core.', code: 'ACTIVATE_MALFORMED' },
      { status: 502, headers: { 'Cache-Control': 'no-store' } },
    );
  }

  const response = NextResponse.json({ ok: true, assessment_id: assessmentId });
  response.cookies.set(COOKIE_NAME, sessionToken, {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD,
    path: '/',
    maxAge: 8 * 60 * 60, // 8 hours
  });
  // Clear the single-use OIDC bootstrap cookie.
  response.cookies.delete(OIDC_BOOTSTRAP_COOKIE);
  return response;
}
