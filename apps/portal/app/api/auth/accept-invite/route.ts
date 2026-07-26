/**
 * POST /api/auth/accept-invite
 *
 * Consume a portal named-user invitation (pni1. token) and issue a pnu1.
 * session cookie.
 *
 * Contract (PR B — production named-user cutover):
 *   - Body: { invite_token: string, tenant_id?: string }
 *   - Requires the fg_oidc_bootstrap HttpOnly cookie set by
 *     /api/auth/oidc/callback (mode=accept). Cookie carries the Auth0
 *     access_token; this route consumes and clears it. The browser JS never
 *     handles the access_token.
 *   - Calls core: POST /portal/invitations/{token}/accept
 *     Body: { access_token, oidc_provider, tenant_id }
 *     Auth: none (invitation token IS the credential per public_paths.py)
 *   - Sets fg_portal_session to the raw pnu1. token returned by core.
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
  const token = String(body?.invite_token ?? '').trim();
  const bodyTenantId = String(body?.tenant_id ?? '').trim();

  if (!token) {
    return badRequest('invite_token is required', 'INVITE_TOKEN_REQUIRED');
  }
  // pni1. is the only supported invitation format; reject cross-token confusion.
  if (!token.startsWith('pni1.')) {
    return badRequest('invitation token format invalid', 'INVITE_TOKEN_FORMAT');
  }

  // Consume the OIDC bootstrap cookie (Auth0 access_token) set by the
  // /api/auth/oidc/callback mode=accept branch. Missing → user hasn't run OIDC.
  const accessToken = request.cookies.get(OIDC_BOOTSTRAP_COOKIE)?.value ?? '';
  if (!accessToken) {
    return badRequest(
      'OIDC bootstrap missing — restart the invitation link.',
      'OIDC_BOOTSTRAP_MISSING',
      401,
    );
  }

  // tenant_id may come from the URL param (invitee provides) OR the OIDC
  // callback's persisted state hint. Either way the core API validates the
  // invitation exists under that tenant_id before consuming it.
  const tenantId = bodyTenantId || process.env.CORE_TENANT_ID || '';
  if (!tenantId) {
    return badRequest('tenant_id is required to accept the invitation', 'TENANT_REQUIRED');
  }

  // Call core with the invitation token AS the credential (this route is a
  // public path server-side; the token IS the authorization).
  const encoded = encodeURIComponent(token);
  const upstream = await fetch(`${CORE_API_URL}/portal/invitations/${encoded}/accept`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      access_token: accessToken,
      oidc_provider: 'auth0',
      tenant_id: tenantId,
    }),
    cache: 'no-store',
  });

  if (!upstream.ok) {
    const err = await upstream.json().catch(() => ({}));
    const detail = typeof err?.detail === 'object' ? err.detail : {};
    const errRes = NextResponse.json(
      {
        error: detail?.message ?? err?.detail ?? 'Invalid or expired invite link.',
        code: detail?.code ?? 'INVITE_ACCEPT_FAILED',
      },
      {
        status: upstream.status,
        headers: { 'Cache-Control': 'no-store' },
      },
    );
    // Terminal invitation states (409 accepted, 410 revoked/expired, 404 not
    // found) invalidate the bootstrap access_token too — clear it to bound
    // replay window even if the invitee retries.
    if ([404, 409, 410].includes(upstream.status)) {
      errRes.cookies.delete(OIDC_BOOTSTRAP_COOKIE);
    }
    return errRes;
  }

  const payload = (await upstream.json()) as {
    portal_user_id: string;
    membership_id: string;
    session_token: string;
    expires_at: string;
    portal_role: string;
    engagement_id: string | null;
  };

  const sessionToken = (payload.session_token || '').trim();
  if (!sessionToken.startsWith('pnu1.')) {
    return NextResponse.json(
      { error: 'Malformed session token from core.', code: 'INVITE_ACCEPT_MALFORMED' },
      { status: 502, headers: { 'Cache-Control': 'no-store' } },
    );
  }

  const response = NextResponse.json({
    ok: true,
    portal_role: payload.portal_role,
    engagement_id: payload.engagement_id,
  });
  // Store the raw pnu1. session token as the portal session cookie value.
  response.cookies.set(COOKIE_NAME, sessionToken, {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD,
    path: '/',
    maxAge: 8 * 60 * 60,
  });
  // Clear the bootstrap cookie — the Auth0 access_token is single-use here.
  response.cookies.delete(OIDC_BOOTSTRAP_COOKIE);
  return response;
}
