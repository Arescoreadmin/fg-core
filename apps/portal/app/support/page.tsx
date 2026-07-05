'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { portalApi, PortalApiError } from '@/lib/portalApi';
import { getStoredEngagementId } from '@/lib/engagementStore';
import SupportCenter, { type SupportTopic } from '@/components/portal/SupportCenter';

const DEFAULT_TOPICS: SupportTopic[] = [
  {
    id: 'findings-what',
    title: 'What are findings?',
    category: 'findings',
    content:
      'Findings are governance gaps, risks, or concerns identified during the AI assessment. Each finding is mapped to relevant frameworks (e.g. NIST AI RMF) and includes a severity level and remediation guidance.',
  },
  {
    id: 'findings-severity',
    title: 'What do severity levels mean?',
    category: 'findings',
    content:
      'Critical and High findings represent significant governance risks requiring prompt attention. Medium findings are important but have lower immediate risk. Low and Info findings are advisory in nature.',
  },
  {
    id: 'reports-what',
    title: 'What is in my assessment report?',
    category: 'reports',
    content:
      'The assessment report summarises all findings, evidence collected, and framework coverage achieved during the engagement. It includes a manifest hash to verify integrity.',
  },
  {
    id: 'reports-verify',
    title: 'How do I verify my report?',
    category: 'reports',
    content:
      'Visit the Trust Verification page to confirm the report integrity hash matches the published manifest. This confirms no tampering has occurred since the report was compiled.',
  },
  {
    id: 'remediation-plan',
    title: 'How is the remediation plan structured?',
    category: 'remediation',
    content:
      'The remediation plan is organised into phases based on finding priority and effort level. Phase 1 covers critical items, subsequent phases address medium and low-priority gaps.',
  },
  {
    id: 'attestation-what',
    title: 'What is an attestation?',
    category: 'attestation',
    content:
      'An attestation is a formal acknowledgement that a governance control is in place. Attestations are submitted by asset owners and reviewed by your operator before being recorded.',
  },
  {
    id: 'portal-engagement',
    title: 'How do I switch engagements?',
    category: 'portal',
    content:
      'Return to the home page and select the engagement you want to view. Your portal session tracks one engagement at a time.',
  },
  {
    id: 'trust-what',
    title: 'What is trust verification?',
    category: 'trust',
    content:
      'Trust verification confirms the integrity of your engagement data using cryptographic hashes. It does not constitute legal certification — it is an internal governance audit mechanism.',
  },
];

function SupportPageInner() {
  const params = useSearchParams();
  // UX hint — URL param takes priority; localStorage is session-continuity fallback only.
  // Authorization is enforced server-side: invalid IDs fail closed at the BFF.
  const engagementId = params.get('e') || getStoredEngagementId();
  const [contactEmail, setContactEmail] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastUpdated] = useState<string | undefined>(new Date().toISOString());

  useEffect(() => {
    if (!engagementId) return;
    setLoading(true);
    portalApi
      .getEngagement(engagementId)
      .then((engagement) => {
        setContactEmail(engagement.assessor_id ?? null);
      })
      .catch((e) => {
        if (!(e instanceof PortalApiError)) return;
      })
      .finally(() => setLoading(false));
  }, [engagementId]);

  return (
    <div data-testid="support-page" aria-label="support-center-page">
      <div className="mb-4">
        <h1 className="text-base font-semibold text-foreground">Support Center</h1>
        <p className="text-xs text-muted mt-0.5">Guidance on using the portal and understanding your assessment.</p>
      </div>

      <SupportCenter
        topics={DEFAULT_TOPICS}
        contactEmail={contactEmail}
        loading={loading}
        lastUpdated={lastUpdated}
      />
    </div>
  );
}

export default function SupportPage() {
  return (
    <Suspense fallback={<div className="h-48 rounded border border-border bg-surface-2 animate-pulse" aria-busy="true" />}>
      <SupportPageInner />
    </Suspense>
  );
}
