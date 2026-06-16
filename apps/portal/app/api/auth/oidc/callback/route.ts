/**
 * GET /api/auth/oidc/callback
 *
 * Auth0 OIDC callback handler for portal named users (P1).
 *
 * Flow:
 *   1. Validates CSRF state from fg_oidc_state cookie.
 *   2. Exchanges authorization code for tokens (Auth0 /oauth/token).
 *   3. Calls POST /portal/identity/login on the core API with the access_token.
 *      Core API verifies the JWT via JWKS and resolves tenant_users membership.
 *   4. On success: issues a signed fg_portal_session cookie (createUserSessionToken).
 *   5. On failure: redirects to /login with a typed error param.
 *
 * Required environment variables:
 *   PORTAL_AUTH0_DOMAIN        — Auth0 tenant domain
 *   PORTAL_AUTH0_CLIENT_ID     — OAuth2 client_id
 *   PORTAL_AUTH0_CLIENT_SECRET — OAuth2 client_secret
 *   PORTAL_AUTH0_CALLBACK_URL  — this route's absolute URL
 *   CORE_API_URL               — base URL of the FrostGate core API
 *   CORE_API_KEY               — API key with governance:read scope
 *   CORE_TENANT_ID             — tenant to resolve membership against
 */
import { NextRequest, NextResponse } from 'next/server';
import { COOKIE_NAME, createUserSessionToken, type SessionUser } from '@/lib/session';

const IS_PROD = process.env.NODE_ENV === 'production';

function getConfig() {
  return {
    domain: process.env.PORTAL_AUTH0_DOMAIN || '',
    clientId: process.env.PORTAL_AUTH0_CLIENT_ID || '',
    clientSecret: process.env.PORTAL_AUTH0_CLIENT_SECRET || '',
    callbackUrl: process.env.PORTAL_AUTH0_CALLBACK_URL || '',
    coreApiUrl: (process.env.CORE_API_URL || '').replace(/\/$/, ''),
    coreApiKey: process.env.CORE_API_KEY || '',
    coreTenantId: process.env.CORE_TENANT_ID || '',
  };
}

function loginError(req: NextRequest, code: string): NextResponse {
  const url = new URL('/login', req.url);
  url.searchParams.set('error', code);
  return NextResponse.redirect(url);
}

export async function GET(req: NextRequest) {
  const cfg = getConfig();

  if (!cfg.domain || !cfg.clientId || !cfg.clientSecret || !cfg.callbackUrl) {
    return loginError(req, 'oidc_not_configured');
  }

  const { searchParams } = req.nextUrl;
  const code = searchParams.get('code');
  const returnedState = searchParams.get('state');
  const authError = searchParams.get('error');

  if (authError) {
    return loginError(req, encodeURIComponent(authError));
  }

  if (!code || !returnedState) {
    return loginError(req, 'missing_params');
  }

  // Validate CSRF state from cookie
  const rawStateCookie = req.cookies.get('fg_oidc_state')?.value;
  if (!rawStateCookie) {
    return loginError(req, 'session_expired');
  }

  let statePayload: { state: string; codeVerifier: string; returnTo?: string };
  try {
    statePayload = JSON.parse(rawStateCookie);
  } catch {
    return loginError(req, 'invalid_state');
  }

  if (statePayload.state !== returnedState) {
    return loginError(req, 'state_mismatch');
  }

  // Exchange authorization code for tokens
  let accessToken: string;
  try {
    const tokenResp = await fetch(`https://${cfg.domain}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
        redirect_uri: cfg.callbackUrl,
        code,
        code_verifier: statePayload.codeVerifier,
      }),
    });
    if (!tokenResp.ok) {
      return loginError(req, 'token_exchange_failed');
    }
    const tokens = (await tokenResp.json()) as { access_token?: string };
    accessToken = tokens.access_token || '';
    if (!accessToken) throw new Error('no access_token in response');
  } catch {
    return loginError(req, 'token_exchange_failed');
  }

  // Verify membership via core API
  if (!cfg.coreApiUrl || !cfg.coreApiKey || !cfg.coreTenantId) {
    return loginError(req, 'core_api_not_configured');
  }

  let userInfo: {
    user_id: string;
    email: string;
    display_name: string;
    role: string;
    tenant_id: string;
    membership_id: string;
  };
  try {
    const identityResp = await fetch(`${cfg.coreApiUrl}/portal/identity/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': cfg.coreApiKey,
        'X-Tenant-ID': cfg.coreTenantId,
      },
      body: JSON.stringify({ access_token: accessToken }),
      cache: 'no-store',
    });

    if (identityResp.status === 401) return loginError(req, 'invalid_token');
    if (identityResp.status === 403) return loginError(req, 'membership_inactive');
    if (identityResp.status === 404) return loginError(req, 'membership_not_found');
    if (!identityResp.ok) return loginError(req, 'identity_verification_failed');

    userInfo = await identityResp.json();
  } catch {
    return loginError(req, 'identity_verification_failed');
  }

  // Issue signed portal session cookie
  const sessionUser: SessionUser = {
    userId: userInfo.user_id,
    email: userInfo.email,
    displayName: userInfo.display_name,
    role: userInfo.role,
  };

  const sessionToken = await createUserSessionToken(sessionUser);

  const returnTo = statePayload.returnTo && statePayload.returnTo.startsWith('/') && !statePayload.returnTo.startsWith('//')
    ? statePayload.returnTo
    : '/';

  const res = NextResponse.redirect(new URL(returnTo, req.url));
  res.cookies.delete('fg_oidc_state');
  res.cookies.set(COOKIE_NAME, sessionToken, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    maxAge: 8 * 60 * 60, // 8 hours
    path: '/',
  });
  return res;
}
