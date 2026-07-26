'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

/**
 * Accept-invite page (PR B — production named-user cutover).
 *
 * Contract:
 *   URL: /accept-invite?token=<pni1....>&tenant_id=<optional>
 *
 * Flow:
 *   1. If the browser has no OIDC bootstrap cookie yet (first landing),
 *      redirect to /api/auth/oidc?mode=accept&inviteToken=...&tenantId=...
 *      which stores state server-side and jumps to Auth0.
 *   2. Auth0 redirects back to /api/auth/oidc/callback which sees mode=accept,
 *      stashes the access_token in a short-lived HttpOnly bootstrap cookie,
 *      and redirects back HERE with the same ?token=&tenant_id=.
 *   3. Browser sees status='ready-to-accept' (via server-set marker cookie
 *      readable client-side ONLY as presence, not value — we simply call
 *      /api/auth/accept-invite and let the BFF consume the HttpOnly cookie).
 *   4. On success: the BFF sets fg_portal_session=<pnu1...>; we route home.
 */

function AcceptInviteForm() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const token = searchParams.get('token') ?? '';
  const tenantHint = searchParams.get('tenant_id') ?? '';
  const arrivedFromOidc = searchParams.get('from') === 'oidc';
  const priorError = searchParams.get('error') ?? '';

  const [status, setStatus] = useState<'idle' | 'loading' | 'error' | 'redirecting'>('idle');
  const [error, setError] = useState('');

  useEffect(() => { if (priorError) setError(priorError); }, [priorError]);

  function startOidc() {
    setStatus('redirecting');
    const url = new URL('/api/auth/oidc', window.location.origin);
    url.searchParams.set('mode', 'accept');
    url.searchParams.set('inviteToken', token);
    if (tenantHint) url.searchParams.set('tenantId', tenantHint);
    // returnTo brings the browser back to /accept-invite with from=oidc so we
    // know to attempt the acceptance call instead of looping back to Auth0.
    const back = new URL('/accept-invite', window.location.origin);
    back.searchParams.set('token', token);
    if (tenantHint) back.searchParams.set('tenant_id', tenantHint);
    back.searchParams.set('from', 'oidc');
    url.searchParams.set('returnTo', back.pathname + back.search);
    window.location.assign(url.toString());
  }

  async function completeAccept() {
    setStatus('loading');
    setError('');
    const res = await fetch('/api/auth/accept-invite', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        invite_token: token,
        tenant_id: tenantHint || undefined,
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      router.replace('/');
      return;
    }
    setError(data?.error ?? 'The invite link is invalid or has expired.');
    setStatus('error');
  }

  const canContinue = !!token;

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-sm space-y-5 rounded-xl border border-border bg-surface p-8">
        <div className="text-center space-y-1">
          <h1 className="text-lg font-semibold text-foreground">Accept your invitation</h1>
          <p className="text-sm text-muted">
            You&apos;ve been invited to access the FrostGate client portal.
          </p>
        </div>

        {!token && (
          <div className="rounded border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-300">
            No invite token in the URL. Please use the link from your invitation email.
          </div>
        )}

        {status === 'error' && (
          <div className="rounded border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-300">
            {error}
          </div>
        )}

        {arrivedFromOidc ? (
          <button
            onClick={completeAccept}
            disabled={!canContinue || status === 'loading'}
            className="w-full rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {status === 'loading' ? 'Finalizing…' : 'Complete acceptance'}
          </button>
        ) : (
          <button
            onClick={startOidc}
            disabled={!canContinue || status === 'redirecting'}
            className="w-full rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {status === 'redirecting' ? 'Redirecting…' : 'Continue with SSO'}
          </button>
        )}

        <p className="text-center text-xs text-muted">
          Invite links are single-use and expire after 7 days.
        </p>
      </div>
    </div>
  );
}

export default function AcceptInvitePage() {
  return (
    <Suspense>
      <AcceptInviteForm />
    </Suspense>
  );
}
