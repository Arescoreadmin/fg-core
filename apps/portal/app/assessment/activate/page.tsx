'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

/**
 * Assessment activation page (L14-PORTAL-HANDOFF-001).
 *
 * Contract:
 *   URL: /assessment/activate?id=<assessment_id>&at=<raw_activation_token>
 *        or after OIDC: /assessment/activate?id=<assessment_id>&from=oidc
 *
 * Flow:
 *   1. On first landing: stash `at` in sessionStorage; remove it from URL
 *      (prevents referrer leakage / browser history exposure).
 *   2. Poll GET /api/core/ingest/assessment/{id}/payment-status.
 *   3. If payment_status === 'paid':
 *      a. If not yet OIDC-verified: show "Activate account" button which
 *         redirects to /api/auth/oidc?mode=activate&assessmentId={id}.
 *      b. If arrived from OIDC (from=oidc): call POST /api/auth/activate
 *         with the activation_token from sessionStorage; on success redirect home.
 *   4. If payment_status === 'unpaid': show "Payment pending" message.
 *   5. If payment_status === 'not_found': show error.
 */

function ActivateForm() {
  const searchParams = useSearchParams();
  const router = useRouter();

  const assessmentId = searchParams.get('id') ?? '';
  const rawToken = searchParams.get('at') ?? '';
  const arrivedFromOidc = searchParams.get('from') === 'oidc';
  const priorError = searchParams.get('error') ?? '';

  const [status, setStatus] = useState<
    'idle' | 'loading' | 'polling' | 'paid' | 'unpaid' | 'not_found' | 'activating' | 'error' | 'redirecting'
  >('idle');
  const [error, setError] = useState('');

  // On first render: stash raw token in sessionStorage then scrub it from the URL.
  useEffect(() => {
    if (rawToken) {
      try {
        sessionStorage.setItem('fg_activation_token', rawToken);
      } catch {
        // sessionStorage not available — will retry from URL on next step
      }
      // Replace URL without the `at` param to prevent referrer leakage.
      const clean = new URL(window.location.href);
      clean.searchParams.delete('at');
      window.history.replaceState(null, '', clean.toString());
    }
    if (priorError) {
      setError(priorError);
      setStatus('error');
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Poll payment status.
  useEffect(() => {
    if (!assessmentId) return;
    setStatus('polling');
    let cancelled = false;

    async function poll() {
      try {
        const res = await fetch(`/api/core/ingest/assessment/${encodeURIComponent(assessmentId)}/payment-status`, {
          cache: 'no-store',
        });
        if (cancelled) return;
        if (!res.ok) {
          setStatus('error');
          setError('Could not reach payment service. Please try again.');
          return;
        }
        const data = (await res.json()) as { payment_status: string };
        if (cancelled) return;
        if (data.payment_status === 'paid') {
          setStatus('paid');
        } else if (data.payment_status === 'not_found') {
          setStatus('not_found');
        } else {
          setStatus('unpaid');
        }
      } catch {
        if (!cancelled) {
          setStatus('error');
          setError('Network error checking payment status.');
        }
      }
    }

    poll();
    return () => {
      cancelled = true;
    };
  }, [assessmentId]);

  // If arrived from OIDC and payment is confirmed: auto-activate.
  useEffect(() => {
    if (arrivedFromOidc && status === 'paid') {
      void completeActivation();
    }
  }, [arrivedFromOidc, status]); // eslint-disable-line react-hooks/exhaustive-deps

  function startOidc() {
    setStatus('redirecting');
    const url = new URL('/api/auth/oidc', window.location.origin);
    url.searchParams.set('mode', 'activate');
    url.searchParams.set('assessmentId', assessmentId);
    const back = new URL('/assessment/activate', window.location.origin);
    back.searchParams.set('id', assessmentId);
    back.searchParams.set('from', 'oidc');
    url.searchParams.set('returnTo', back.pathname + back.search);
    window.location.assign(url.toString());
  }

  async function completeActivation() {
    setStatus('activating');
    setError('');

    // Retrieve activation token from sessionStorage.
    let activationToken = '';
    try {
      activationToken = sessionStorage.getItem('fg_activation_token') ?? '';
    } catch {
      // ignore
    }
    if (!activationToken) {
      setError('Activation token missing. Please use the original payment confirmation link.');
      setStatus('error');
      return;
    }

    const res = await fetch('/api/auth/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        assessment_id: assessmentId,
        activation_token: activationToken,
      }),
    });

    const data = await res.json().catch(() => ({}));

    if (res.ok) {
      // Clear activation token — it's single-use.
      try {
        sessionStorage.removeItem('fg_activation_token');
      } catch {
        // ignore
      }
      router.replace('/');
      return;
    }

    const errMsg =
      data?.error ??
      (res.status === 402
        ? 'Payment has not been confirmed yet. Please wait a moment and try again.'
        : res.status === 410
          ? 'This activation link has expired. Please contact support.'
          : res.status === 409
            ? 'This assessment has already been activated.'
            : 'Activation failed. Please try again or contact support.');
    setError(errMsg);
    setStatus('error');
  }

  if (!assessmentId) {
    return (
      <Card>
        <h1 className="text-lg font-semibold text-foreground">Invalid link</h1>
        <p className="text-sm text-muted mt-1">No assessment ID in the URL.</p>
      </Card>
    );
  }

  return (
    <Card>
      <div className="text-center space-y-1">
        <h1 className="text-lg font-semibold text-foreground">Activate your FrostGate account</h1>
        <p className="text-sm text-muted">
          Complete your purchase to access your AI governance assessment report.
        </p>
      </div>

      {status === 'polling' && (
        <p className="text-center text-sm text-muted">Verifying payment&hellip;</p>
      )}

      {status === 'unpaid' && (
        <div className="rounded border border-yellow-500/30 bg-yellow-500/5 p-3 text-sm text-yellow-300">
          Payment is still being processed. Please wait a moment and refresh.
        </div>
      )}

      {status === 'not_found' && (
        <div className="rounded border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-300">
          Assessment not found. Please check the link in your confirmation email.
        </div>
      )}

      {(status === 'error') && error && (
        <div className="rounded border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {status === 'paid' && !arrivedFromOidc && (
        <>
          <div className="rounded border border-green-500/30 bg-green-500/5 p-3 text-sm text-green-300">
            Payment confirmed. Continue to create your account and access your report.
          </div>
          <button
            onClick={startOidc}
            className="w-full rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white hover:bg-primary/90 transition-colors"
          >
            Continue with SSO to activate
          </button>
        </>
      )}

      {(status === 'activating' || (arrivedFromOidc && status === 'paid')) && (
        <p className="text-center text-sm text-muted">Activating your account&hellip;</p>
      )}

      {status === 'redirecting' && (
        <p className="text-center text-sm text-muted">Redirecting to login&hellip;</p>
      )}

      <p className="text-center text-xs text-muted">
        Activation links are single-use and expire after 24 hours.
      </p>
    </Card>
  );
}

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-sm space-y-5 rounded-xl border border-border bg-surface p-8">
        {children}
      </div>
    </div>
  );
}

export default function AssessmentActivatePage() {
  return (
    <Suspense>
      <ActivateForm />
    </Suspense>
  );
}
