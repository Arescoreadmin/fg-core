'use client';

import { signIn } from 'next-auth/react';
import { useSearchParams } from 'next/navigation';
import { Suspense } from 'react';
import { FrostGateShield } from '@/components/governance/FrostGateShield';

function LoginForm() {
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get('callbackUrl') || '/dashboard';

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-sm space-y-6 rounded-xl border border-border bg-surface p-8 text-center shadow-sm">
        <div className="flex flex-col items-center gap-3">
          <FrostGateShield size={40} />
          <h1 className="text-xl font-semibold text-foreground">FrostGate Console</h1>
          <p className="text-sm text-muted">Operator access only</p>
        </div>
        <button
          onClick={() => signIn('auth0', { callbackUrl })}
          className="w-full rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white hover:bg-primary/90 transition-colors"
        >
          Sign in with Auth0
        </button>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
