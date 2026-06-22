'use client';

import { Suspense, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

function AcceptInviteForm() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const token = searchParams.get('token') ?? '';

  const [status, setStatus] = useState<'idle' | 'loading' | 'error'>('idle');
  const [error, setError] = useState('');

  async function handleAccept() {
    if (!token) {
      setError('No invite token found in the URL.');
      setStatus('error');
      return;
    }
    setStatus('loading');
    const res = await fetch('/api/auth/accept-invite', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ invite_token: token }),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      router.replace('/');
    } else {
      setError(data?.error ?? 'The invite link is invalid or has expired.');
      setStatus('error');
    }
  }

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

        <button
          onClick={handleAccept}
          disabled={!token || status === 'loading'}
          className="w-full rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {status === 'loading' ? 'Accepting…' : 'Accept Invitation & Sign In'}
        </button>

        <p className="text-center text-xs text-muted">
          Invite links are single-use and expire after 72 hours.
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
