import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

// next-auth v5 signOut in server actions doesn't follow external redirectTo URLs —
// it clears the session cookie but the browser never reaches Auth0, so Auth0's
// SSO session stays alive. This route handler bypasses that restriction:
// it deletes the authjs cookies directly and issues a hard redirect to Auth0's
// /v2/logout endpoint, which clears the Auth0 session and returns to /login.
export async function GET() {
  let issuer = (process.env.AUTH0_ISSUER_BASE_URL ?? '').replace(/\/$/, '');
  if (issuer && !issuer.startsWith('https://') && !issuer.startsWith('http://')) {
    issuer = `https://${issuer}`;
  }
  const clientId = process.env.AUTH0_CLIENT_ID ?? '';
  const base = (process.env.CONSOLE_BASE_URL || process.env.NEXTAUTH_URL || process.env.NEXT_PUBLIC_APP_URL || 'https://console.frostgate.ai').replace(/\/$/, '');
  const returnTo = encodeURIComponent(`${base}/login`);

  const response = NextResponse.redirect(
    `${issuer}/v2/logout?client_id=${clientId}&returnTo=${returnTo}`,
    { status: 302 }
  );

  // Delete all authjs session cookies so next-auth also considers the user signed out.
  for (const name of [
    '__Secure-authjs.session-token',
    'authjs.session-token',
    '__Host-authjs.csrf-token',
    '__Secure-authjs.callback-url',
  ]) {
    response.cookies.delete(name);
  }

  return response;
}
