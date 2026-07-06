'use server';

import { signOut } from '@/auth';

export async function federatedSignOut() {
  const issuer = (process.env.AUTH0_ISSUER_BASE_URL || '').replace(/\/$/, '');
  const clientId = process.env.AUTH0_CLIENT_ID || '';
  const base = (process.env.CONSOLE_BASE_URL || process.env.NEXTAUTH_URL || process.env.NEXT_PUBLIC_APP_URL || 'https://console.frostgate.ai').replace(/\/$/, '');
  const returnTo = encodeURIComponent(`${base}/login`);

  // signOut clears the next-auth session cookie, then redirects the browser to
  // Auth0's logout endpoint which clears the Auth0 session before returning to /login.
  await signOut({ redirectTo: `${issuer}/v2/logout?client_id=${clientId}&returnTo=${returnTo}` });
}
