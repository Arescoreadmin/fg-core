'use client';

import { useSession, signIn } from 'next-auth/react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';

interface PreflightData {
  tenant_display_name: string;
  invited_role_display_name: string;
  email_masked: string;
  expires_at: string;
  status: string;
}

type PrefError = 'EXPIRED' | 'CONSUMED' | 'INVALID' | 'UNKNOWN';

type InvitationState =
  | { phase: 'loading' }
  | { phase: 'redirect_to_auth' }
  | { phase: 'preflight_loading' }
  | { phase: 'preflight_error'; code: PrefError }
  | { phase: 'resend_sending' }
  | { phase: 'resend_sent' }
  | { phase: 'resend_error'; message: string }
  | { phase: 'ready' }
  | { phase: 'accepting' }
  | { phase: 'email_mismatch'; signedInAs: string }
  | { phase: 'email_unverified' }
  | { phase: 'session_expired' }
  | { phase: 'tenant_unavailable' }
  | { phase: 'accepted'; tenantId: string }
  | { phase: 'error'; message: string };

const PREF_ERROR_MESSAGES: Record<PrefError, string> = {
  EXPIRED: 'This invitation has expired.',
  CONSUMED: 'This invitation has already been accepted or revoked.',
  INVALID: 'This invitation link is not valid. Check that you copied the full URL.',
  UNKNOWN: 'This invitation link is not available.',
};

const INTENT_KEY = (token: string) => `invitation-intent-${token}`;

function prefErrorFromCode(code: string | undefined): PrefError {
  if (code === 'INVITATION_EXPIRED') return 'EXPIRED';
  if (code === 'INVITATION_CONSUMED') return 'CONSUMED';
  if (code === 'INVITATION_NOT_FOUND') return 'INVALID';
  return 'UNKNOWN';
}

const s = {
  page: { maxWidth: 480, margin: '80px auto', padding: '0 24px' } as React.CSSProperties,
  card: {
    maxWidth: 480,
    margin: '80px auto',
    padding: '0 24px',
    fontFamily: 'system-ui, sans-serif',
  } as React.CSSProperties,
  heading: { fontSize: 20, fontWeight: 600 } as React.CSSProperties,
  body: { color: '#555', lineHeight: 1.6 } as React.CSSProperties,
  meta: { color: '#888', fontSize: 14 } as React.CSSProperties,
  btn: {
    background: '#0f62fe',
    color: '#fff',
    border: 'none',
    borderRadius: 4,
    padding: '12px 24px',
    fontSize: 15,
    fontWeight: 500,
    cursor: 'pointer',
    marginTop: 16,
  } as React.CSSProperties,
  btnDisabled: { opacity: 0.6, cursor: 'not-allowed' } as React.CSSProperties,
};

export default function InvitationAcceptancePage({ params }: { params: { token: string } }) {
  const { data: session, status: sessionStatus } = useSession();
  const router = useRouter();
  const token = params.token;

  const [state, setState] = useState<InvitationState>({ phase: 'loading' });
  const [preflight, setPreflight] = useState<PreflightData | null>(null);

  const sessionRef = useRef(session);
  sessionRef.current = session;
  const inFlight = useRef(false);

  // Effect 1: session watch + preflight load
  useEffect(() => {
    if (sessionStatus === 'loading') return;
    if (sessionStatus === 'unauthenticated') {
      setState({ phase: 'redirect_to_auth' });
      signIn('auth0', { callbackUrl: `/identity/invitations/${token}` });
      return;
    }

    setState({ phase: 'preflight_loading' });
    fetch(`/api/core/identity/invitations/${token}`)
      .then(async (r) => {
        if (r.ok) return r.json() as Promise<PreflightData>;
        let code: string | undefined;
        try {
          const body = (await r.json()) as { detail?: { code?: string } };
          code = body.detail?.code;
        } catch {
          /* unparseable body — fall through to UNKNOWN */
        }
        return Promise.reject(prefErrorFromCode(code));
      })
      .then((data: PreflightData) => {
        setPreflight(data);
        setState({ phase: 'ready' });
      })
      .catch((code: unknown) => {
        setState({
          phase: 'preflight_error',
          code: (typeof code === 'string' ? code : 'UNKNOWN') as PrefError,
        });
      });
  }, [sessionStatus, token]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleAccept = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setState({ phase: 'accepting' });
    try {
      const res = await fetch(`/api/core/identity/invitations/${token}/accept`, {
        method: 'POST',
      });

      if (res.ok) {
        const data = (await res.json()) as { tenant_id: string };
        setState({ phase: 'accepted', tenantId: data.tenant_id });
        return;
      }

      let body: { error?: string; detail_code?: string } = {};
      try {
        body = await res.json();
      } catch {
        /* unparseable — fall through to generic error */
      }

      if (res.status === 401 && body.error === 'SESSION_EXPIRED') {
        sessionStorage.setItem(INTENT_KEY(token), 'accept');
        setState({ phase: 'session_expired' });
        signIn('auth0', { callbackUrl: `/identity/invitations/${token}` });
        return;
      }

      if (res.status === 403 && body.error === 'INVITATION_DENIED') {
        const detail = body.detail_code ?? '';
        if (detail === 'INVITATION_EMAIL_MISMATCH') {
          setState({
            phase: 'email_mismatch',
            signedInAs: sessionRef.current?.user?.email ?? '',
          });
          return;
        }
        if (detail === 'IDENTITY_UNVERIFIED') {
          sessionStorage.setItem(INTENT_KEY(token), 'accept');
          setState({ phase: 'email_unverified' });
          return;
        }
        if (detail === 'TENANT_NOT_AVAILABLE') {
          setState({ phase: 'tenant_unavailable' });
          return;
        }
      }

      if (res.status === 404) {
        // State changed between preflight and accept (race or concurrent attempt)
        setState({ phase: 'preflight_error', code: 'CONSUMED' });
        return;
      }

      setState({ phase: 'error', message: 'An unexpected error occurred. Please try again.' });
    } catch {
      setState({ phase: 'error', message: 'A network error occurred. Please try again.' });
    } finally {
      inFlight.current = false;
    }
  }, [token]);

  const handleResend = useCallback(async () => {
    setState({ phase: 'resend_sending' });
    try {
      const res = await fetch(`/api/core/identity/invitations/${token}/request-resend`, {
        method: 'POST',
      });
      if (res.ok) {
        setState({ phase: 'resend_sent' });
        return;
      }
      if (res.status === 429) {
        setState({ phase: 'resend_error', message: 'Too many resend requests. Please wait a moment and try again.' });
        return;
      }
      setState({ phase: 'resend_error', message: 'Unable to resend the invitation. Please try again.' });
    } catch {
      setState({ phase: 'resend_error', message: 'A network error occurred. Please try again.' });
    }
  }, [token]);

  // Effect 2: auto-continuation after re-auth return
  useEffect(() => {
    if (state.phase !== 'ready') return;
    const intent = sessionStorage.getItem(INTENT_KEY(token));
    if (intent !== 'accept') return;
    sessionStorage.removeItem(INTENT_KEY(token));
    handleAccept();
  }, [state.phase, token, handleAccept]);

  // Effect 3: navigate after accepted
  useEffect(() => {
    if (state.phase !== 'accepted') return;
    router.push(`/admin/tenants/${state.tenantId}`);
  }, [state, router]);

  // --- Render ---

  if (
    state.phase === 'loading' ||
    state.phase === 'redirect_to_auth' ||
    state.phase === 'session_expired'
  ) {
    return <div style={s.page}>Redirecting to sign in&hellip;</div>;
  }

  if (state.phase === 'preflight_loading') {
    return <div style={s.page}>Loading&hellip;</div>;
  }

  if (state.phase === 'accepted') {
    return <div style={s.page}>Invitation accepted. Redirecting&hellip;</div>;
  }

  if (state.phase === 'resend_sending') {
    return <div style={s.page}>Sending new invitation&hellip;</div>;
  }

  if (state.phase === 'resend_sent') {
    return (
      <div style={s.card}>
        <h1 style={s.heading}>New invitation sent</h1>
        <p style={s.body}>
          Check your email for a new invitation link. This page will no longer work — use the
          link in the new email.
        </p>
      </div>
    );
  }

  if (state.phase === 'resend_error') {
    return (
      <div style={s.card}>
        <h1 style={s.heading}>Resend failed</h1>
        <p style={s.body}>{state.message}</p>
        <button style={s.btn} onClick={() => setState({ phase: 'preflight_error', code: 'EXPIRED' })}>
          Back
        </button>
      </div>
    );
  }

  if (state.phase === 'preflight_error') {
    if (state.code === 'EXPIRED') {
      return (
        <div style={s.card}>
          <h1 style={s.heading}>Invitation expired</h1>
          <p style={s.body}>{PREF_ERROR_MESSAGES.EXPIRED}</p>
          <button style={s.btn} onClick={handleResend}>
            Send me a new invitation
          </button>
        </div>
      );
    }
    return (
      <div style={s.card}>
        <h1 style={s.heading}>Invitation unavailable</h1>
        <p style={s.body}>{PREF_ERROR_MESSAGES[state.code]}</p>
      </div>
    );
  }

  if (state.phase === 'email_mismatch') {
    return (
      <div style={s.card}>
        <h1 style={s.heading}>Wrong account</h1>
        <p style={s.body}>
          This invitation is for a different email address. You are signed in as{' '}
          <strong>{state.signedInAs || 'an unknown account'}</strong>.
        </p>
        <p style={s.body}>Sign in with the invited address to continue.</p>
        <button
          style={s.btn}
          onClick={() => {
            sessionStorage.setItem(INTENT_KEY(token), 'accept');
            signIn(
              'auth0',
              { callbackUrl: `/identity/invitations/${token}` },
              { prompt: 'login' },
            );
          }}
        >
          Switch accounts
        </button>
      </div>
    );
  }

  if (state.phase === 'email_unverified') {
    return (
      <div style={s.card}>
        <h1 style={s.heading}>Email not verified</h1>
        <p style={s.body}>
          Your email address has not been verified. Verify your email with your identity provider,
          then retry sign-in to continue.
        </p>
        <button
          style={s.btn}
          onClick={() =>
            signIn(
              'auth0',
              { callbackUrl: `/identity/invitations/${token}` },
              { prompt: 'login' },
            )
          }
        >
          Retry sign-in
        </button>
      </div>
    );
  }

  if (state.phase === 'tenant_unavailable') {
    return (
      <div style={s.card}>
        <h1 style={s.heading}>Workspace unavailable</h1>
        <p style={s.body}>
          This workspace is not currently accepting new members. Contact your workspace admin.
        </p>
      </div>
    );
  }

  if (state.phase === 'error') {
    return (
      <div style={s.card}>
        <h1 style={s.heading}>Something went wrong</h1>
        <p style={s.body}>{state.message}</p>
      </div>
    );
  }

  // phase === 'ready' | 'accepting'
  if (!preflight) return <div style={s.page}>Loading&hellip;</div>;
  const isAccepting = state.phase === 'accepting';

  return (
    <div style={s.card}>
      <h1 style={{ fontSize: 22, fontWeight: 600, marginBottom: 8 }}>Accept invitation</h1>
      <p style={s.body}>
        You have been invited to <strong>{preflight.tenant_display_name}</strong> as{' '}
        <strong>{preflight.invited_role_display_name}</strong>.
      </p>
      <p style={s.meta}>
        Sent to {preflight.email_masked} &middot; Expires{' '}
        {new Date(preflight.expires_at).toLocaleDateString()}
      </p>
      {session?.user?.email && <p style={s.meta}>Signing in as {session.user.email}</p>}
      <button
        onClick={handleAccept}
        disabled={isAccepting}
        style={{ ...s.btn, ...(isAccepting ? s.btnDisabled : {}) }}
      >
        {isAccepting ? 'Accepting…' : 'Accept Invitation'}
      </button>
    </div>
  );
}
