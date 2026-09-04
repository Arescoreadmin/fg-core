'use client';

import { useSession, signIn } from 'next-auth/react';
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

interface PreflightData {
  tenant_display_name: string;
  invited_role_display_name: string;
  email_masked: string;
  expires_at: string;
  status: string;
}

export default function InvitationAcceptancePage({ params }: { params: { token: string } }) {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [preflight, setPreflight] = useState<PreflightData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [accepting, setAccepting] = useState(false);
  const token = params.token;

  useEffect(() => {
    if (status === 'unauthenticated') {
      signIn('auth0', { callbackUrl: `/identity/invitations/${token}` });
      return;
    }
    if (status !== 'authenticated') return;

    fetch(`/api/core/identity/invitations/${token}`)
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(setPreflight)
      .catch(() => setError('This invitation link is invalid, expired, or has already been used.'));
  }, [status, token]);

  const handleAccept = async () => {
    setAccepting(true);
    try {
      const res = await fetch(`/api/core/identity/invitations/${token}/accept`, {
        method: 'POST',
      });
      if (res.ok) {
        const data = await res.json();
        router.push(`/admin/tenants/${data.tenant_id}`);
        return;
      }
      const body = await res.json().catch(() => ({}));
      if (body.error === 'CORE_ACCESS_DENIED' || body.code === 'INVITATION_EMAIL_MISMATCH') {
        setError(`This invitation was sent to a different email address. You are signed in as ${session?.user?.email ?? 'unknown'}.`);
      } else if (body.error === 'CORE_ACCESS_DENIED' || body.code === 'IDENTITY_UNVERIFIED') {
        setError('Your email address has not been verified. Verify your email with your identity provider and try again.');
      } else {
        setError('This invitation link is invalid, expired, or has already been used.');
      }
    } catch {
      setError('An unexpected error occurred. Please try again.');
    } finally {
      setAccepting(false);
    }
  };

  if (status === 'loading' || (status === 'unauthenticated')) {
    return <div>Redirecting to sign in&hellip;</div>;
  }

  if (error) {
    return (
      <div style={{ maxWidth: 480, margin: '80px auto', padding: '0 24px' }}>
        <h1 style={{ fontSize: 20, fontWeight: 600 }}>Invitation unavailable</h1>
        <p style={{ color: '#555' }}>{error}</p>
      </div>
    );
  }

  if (!preflight) {
    return <div style={{ maxWidth: 480, margin: '80px auto', padding: '0 24px' }}>Loading&hellip;</div>;
  }

  return (
    <div style={{ maxWidth: 480, margin: '80px auto', padding: '0 24px', fontFamily: 'system-ui, sans-serif' }}>
      <h1 style={{ fontSize: 22, fontWeight: 600, marginBottom: 8 }}>Accept invitation</h1>
      <p style={{ color: '#555', marginTop: 0 }}>
        You have been invited to <strong>{preflight.tenant_display_name}</strong> as{' '}
        <strong>{preflight.invited_role_display_name}</strong>.
      </p>
      <p style={{ color: '#555', fontSize: 14 }}>
        Sent to {preflight.email_masked} &middot; Expires {new Date(preflight.expires_at).toLocaleDateString()}
      </p>
      <button
        onClick={handleAccept}
        disabled={accepting}
        style={{
          background: '#0f62fe', color: '#fff', border: 'none', borderRadius: 4,
          padding: '12px 24px', fontSize: 15, fontWeight: 500, cursor: 'pointer',
          marginTop: 24,
        }}
      >
        {accepting ? 'Accepting…' : 'Accept Invitation'}
      </button>
    </div>
  );
}
