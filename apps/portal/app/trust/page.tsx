'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { portalApi, PortalApiError, type VerificationBundle } from '@/lib/portalApi';
import { getStoredEngagementId } from '@/lib/engagementStore';
import TrustVerificationCenter, { type TrustVerificationData } from '@/components/portal/TrustVerificationCenter';

function bundleToVerificationData(bundle: VerificationBundle): TrustVerificationData {
  return {
    reportVerified: bundle.verification_status === 'verified',
    evidenceIntegrity: bundle.verification_status === 'tamper_detected' ? 'tampered' : 'intact',
    chainIntegrity:
      bundle.coverage_status === 'tampered' ? 'broken' :
      bundle.verification_status === 'verified' ? 'valid' : 'unknown',
    transparencyStatus: bundle.has_report ? 'published' : 'pending',
    signatureStatus: bundle.report_artifact_hash_status === 'available' ? 'valid' : 'missing',
    manifestHash: bundle.manifest_hash,
    signedHash: bundle.bundle_hash,
    generatedAt: bundle.generated_at,
  };
}

function TrustPageInner() {
  const params = useSearchParams();
  // UX hint — URL param takes priority; localStorage is session-continuity fallback only.
  // Authorization is enforced server-side: invalid IDs fail closed at the BFF.
  const engagementId = params.get('e') || getStoredEngagementId();
  const [data, setData] = useState<TrustVerificationData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | undefined>();

  useEffect(() => {
    if (!engagementId) return;
    setLoading(true);
    setError(null);
    portalApi
      .getVerificationBundle(engagementId)
      .then((bundle) => {
        setData(bundleToVerificationData(bundle));
        setLastUpdated(new Date().toISOString());
      })
      .catch((e) => {
        if (e instanceof PortalApiError && e.status === 404) {
          setData(null);
        } else {
          setError('Failed to load trust verification data.');
        }
      })
      .finally(() => setLoading(false));
  }, [engagementId]);

  return (
    <div data-testid="trust-page" aria-label="trust-verification-page">
      <div className="mb-4">
        <h1 className="text-base font-semibold text-foreground">Trust Verification</h1>
        <p className="text-xs text-muted mt-0.5">Engagement integrity and evidence chain status.</p>
      </div>

      {error && !loading && (
        <div className="mb-4 rounded border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-200">
          {error}
        </div>
      )}

      <TrustVerificationCenter
        data={data}
        loading={loading}
        lastUpdated={lastUpdated}
      />
    </div>
  );
}

export default function TrustPage() {
  return (
    <Suspense fallback={<div className="h-48 rounded border border-border bg-surface-2 animate-pulse" aria-busy="true" />}>
      <TrustPageInner />
    </Suspense>
  );
}
