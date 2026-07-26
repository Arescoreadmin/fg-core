/**
 * GET /api/auth/oidc/callback
 *
 * Auth0 OIDC callback handler for portal named users.
 *
 * Flow (PR B — production named-user cutover):
 *   1. Validates CSRF state from fg_oidc_state cookie.
 *   2. Exchanges authorization code for tokens (Auth0 /oauth/token).
 *   3. Branches on state.mode:
 *      - mode='accept' → sets a short-lived HttpOnly bootstrap cookie carrying
 *        the Auth0 access_token, then redirects to /accept-invite?token=...
 *        The invitation page's server-side handler consumes and clears the
 *        cookie during POST /api/auth/accept-invite. The access_token never
 *        touches browser JS.
 *      - default (login) → POST /portal/named-users/enroll on the core API
 *        with the access_token. Core resolves/creates the portal_users row
 *        (distinct from tenant_users) and returns a pnu1. session token.
 *   4. On enroll success: sets fg_portal_session cookie to the raw pnu1. token.
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
import { COOKIE_NAME } from '@/lib/session';

const IS_PROD = process.env.NODE_ENV === 'production';

/** Short-lived bootstrap cookie used to hand off the Auth0 access_token from
 *  this callback to the invitation acceptance handler. Never sent to the
 *  browser JS; consumed and cleared inside the /api/auth/accept-invite route. */
const OIDC_BOOTSTRAP_COOKIE = 'fg_oidc_bootstrap';
const OIDC_BOOTSTRAP_TTL_SECONDS = 300; // 5 minutes

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

function acceptInviteError(req: NextRequest, token: string, code: string): NextResponse {
  const url = new URL('/accept-invite', req.url);
  if (token) url.searchParams.set('token', token);
  url.searchParams.set('error', code);
  return NextResponse.redirect(url);
}

/** Validate an internal returnTo path — must be site-relative, no protocol. */
function safeReturnTo(candidate: string | undefined): string {
  if (!candidate) return '/';
  if (!candidate.startsWith('/')) return '/';
  if (candidate.startsWith('//')) return '/';
  return candidate;
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

  let statePayload: {
    state: string;
    codeVerifier: string;
    returnTo?: string;
    mode?: string;
    inviteToken?: string;
    tenantId?: string;
  };
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

  // ─── Invitation-acceptance branch ──────────────────────────────────────────
  // Hand the access_token to the accept-invite handler via a short-lived
  // HttpOnly cookie; do NOT put the access_token in the URL or in browser JS.
  if (statePayload.mode === 'accept') {
    const inviteToken = (statePayload.inviteToken || '').trim();
    if (!inviteToken) {
      return acceptInviteError(req, '', 'missing_invite_token');
    }

    const dest = new URL('/accept-invite', req.url);
    dest.searchParams.set('token', inviteToken);
    if (statePayload.tenantId) dest.searchParams.set('tenant_id', statePayload.tenantId);

    const res = NextResponse.redirect(dest);
    res.cookies.delete('fg_oidc_state');
    res.cookies.set(OIDC_BOOTSTRAP_COOKIE, accessToken, {
      httpOnly: true,
      secure: IS_PROD,
      sameSite: 'lax',
      maxAge: OIDC_BOOTSTRAP_TTL_SECONDS,
      path: '/',
    });
    return res;
  }

  // ─── Standard login branch — enroll and mint a pnu1. session ───────────────
  if (!cfg.coreApiUrl || !cfg.coreApiKey || !cfg.coreTenantId) {
    return loginError(req, 'core_api_not_configured');
  }

  let sessionToken: string;
  try {
    const enrollResp = await fetch(`${cfg.coreApiUrl}/portal/named-users/enroll`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': cfg.coreApiKey,
        'X-Tenant-ID': cfg.coreTenantId,
      },
      body: JSON.stringify({ access_token: accessToken, oidc_provider: 'auth0' }),
      cache: 'no-store',
    });

    if (enrollResp.status === 401) return loginError(req, 'invalid_token');
    if (enrollResp.status === 403) return loginError(req, 'membership_inactive');
    if (enrollResp.status === 404) return loginError(req, 'membership_not_found');
    if (!enrollResp.ok) return loginError(req, 'identity_verification_failed');

    const enroll = (await enrollResp.json()) as { session_token?: string };
    sessionToken = (enroll.session_token || '').trim();
    if (!sessionToken.startsWith('pnu1.')) throw new Error('malformed session_token');
  } catch {
    return loginError(req, 'identity_verification_failed');
  }

  const res = NextResponse.redirect(new URL(safeReturnTo(statePayload.returnTo), req.url));
  res.cookies.delete('fg_oidc_state');
  // Store the raw pnu1. token as the session cookie value. The token is a
  // random 32-byte hex string; the core API stores only its HMAC-SHA256
  // fingerprint. Bearer disclosure risk is standard-session-cookie shaped.
  res.cookies.set(COOKIE_NAME, sessionToken, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    maxAge: 8 * 60 * 60, // 8 hours
    path: '/',
  });
  return res;
}
