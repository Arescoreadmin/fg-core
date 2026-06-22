/**
 * GET /api/auth/oidc
 *
 * Initiates the Auth0 PKCE login flow for portal named users (P1).
 * Generates a cryptographic state + code_verifier, stores them in a
 * short-lived httpOnly cookie, then redirects to Auth0's authorize endpoint.
 *
 * Required environment variables:
 *   PORTAL_AUTH0_DOMAIN      — Auth0 tenant domain (e.g. frostgate.auth0.com)
 *   PORTAL_AUTH0_CLIENT_ID   — OAuth2 client_id registered in Auth0
 *   PORTAL_AUTH0_CALLBACK_URL — absolute URL of /api/auth/oidc/callback
 */
import { NextRequest, NextResponse } from 'next/server';

const IS_PROD = process.env.NODE_ENV === 'production';

function getConfig() {
  return {
    domain: process.env.PORTAL_AUTH0_DOMAIN || '',
    clientId: process.env.PORTAL_AUTH0_CLIENT_ID || '',
    callbackUrl: process.env.PORTAL_AUTH0_CALLBACK_URL || '',
    audience: process.env.PORTAL_AUTH0_AUDIENCE || process.env.FG_AUTH0_AUDIENCE || '',
  };
}

function toBase64Url(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

export async function GET(req: NextRequest) {
  const { domain, clientId, callbackUrl, audience } = getConfig();

  if (!domain || !clientId || !callbackUrl) {
    return NextResponse.json(
      { error: 'Portal OIDC authentication is not configured.' },
      { status: 503 },
    );
  }

  // PKCE code verifier (32 random bytes → base64url)
  const verifierBytes = crypto.getRandomValues(new Uint8Array(32));
  const codeVerifier = toBase64Url(verifierBytes.buffer);

  // Code challenge = BASE64URL(SHA-256(codeVerifier))
  const challengeBytes = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(codeVerifier),
  );
  const codeChallenge = toBase64Url(challengeBytes);

  // CSRF state
  const stateBytes = crypto.getRandomValues(new Uint8Array(16));
  const state = toBase64Url(stateBytes.buffer);

  const returnTo = req.nextUrl.searchParams.get('returnTo') || '/';

  const paramsObj: Record<string, string> = {
    response_type: 'code',
    client_id: clientId,
    redirect_uri: callbackUrl,
    scope: 'openid profile email',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  };
  // audience is required when Auth0 is configured to mint API JWTs (not just OIDC tokens).
  // Without it, Auth0 returns an opaque token that validate_auth0_token() rejects as
  // invalid_audience. PORTAL_AUTH0_AUDIENCE takes precedence; falls back to FG_AUTH0_AUDIENCE.
  if (audience) {
    paramsObj['audience'] = audience;
  }
  const params = new URLSearchParams(paramsObj);

  const authUrl = `https://${domain}/authorize?${params}`;

  const statePayload = JSON.stringify({ state, codeVerifier, returnTo });
  const res = NextResponse.redirect(authUrl);
  res.cookies.set('fg_oidc_state', statePayload, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    maxAge: 600, // 10 minutes — OIDC state TTL
    path: '/',
  });
  return res;
}
