'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-TRUST-VERIFY';
const AUTHORITY = 'Trust Verification Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/trust';
const customerSafe = true;

export interface TrustVerificationData {
  reportVerified: boolean | null;
  evidenceIntegrity: 'intact' | 'tampered' | 'unknown';
  chainIntegrity: 'valid' | 'broken' | 'unknown';
  transparencyStatus: 'published' | 'pending' | 'unavailable';
  signatureStatus: 'valid' | 'invalid' | 'missing';
  manifestHash: string | null;
  signedHash: string | null;
  generatedAt: string | null;
}

interface Props {
  data: TrustVerificationData | null;
  loading: boolean;
  lastUpdated?: string;
}

type IndicatorStatus =
  | 'intact' | 'valid' | 'published'
  | 'tampered' | 'broken' | 'invalid'
  | 'pending' | 'unknown' | 'missing'
  | 'yes' | 'no';

function statusClass(s: IndicatorStatus): string {
  if (s === 'intact' || s === 'valid' || s === 'published' || s === 'yes') {
    return 'border-green-500/40 bg-green-500/10 text-green-300';
  }
  if (s === 'tampered' || s === 'broken' || s === 'invalid' || s === 'no') {
    return 'border-red-500/40 bg-red-500/10 text-red-300';
  }
  return 'border-amber-500/40 bg-amber-500/10 text-amber-200';
}

function VerificationRow({
  label,
  status,
  value,
}: {
  label: string;
  status: IndicatorStatus;
  value?: string | null;
}) {
  const cls = statusClass(status);
  return (
    <div className="flex flex-wrap items-center gap-3 py-2 border-b border-border last:border-0">
      <span className="text-sm text-muted w-44 shrink-0">{label}</span>
      <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </span>
      {value && (
        <span className="font-mono text-xs text-muted truncate max-w-[200px]" title={value}>
          {value.slice(0, 20)}…
        </span>
      )}
    </div>
  );
}

export default function TrustVerificationCenter({ data, loading, lastUpdated }: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Trust Verification"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Trust Verification"
      lastUpdated={lastUpdated}
    >
      <section aria-label="trust-verification-center" data-testid="trust-verification-center">
      {/* Required disclaimer — always shown */}
      <div className="mb-4 rounded border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-200">
        Trust artifacts are internal audit and verification artifacts and do not constitute legal certification.
      </div>

      {loading && (
        <div className="space-y-2" aria-busy="true">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="h-10 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && !data && (
        <p className="text-sm text-muted text-center py-4">
          No verification data available for this engagement.
        </p>
      )}

      {!loading && data && (
        <div>
          <VerificationRow
            label="Report Verified"
            status={data.reportVerified === null ? 'unknown' : data.reportVerified ? 'yes' : 'no'}
          />
          <VerificationRow
            label="Evidence Integrity"
            status={data.evidenceIntegrity as IndicatorStatus}
          />
          <VerificationRow
            label="Chain Integrity"
            status={data.chainIntegrity as IndicatorStatus}
          />
          <VerificationRow
            label="Transparency Status"
            status={data.transparencyStatus as IndicatorStatus}
          />
          <VerificationRow
            label="Signature Status"
            status={data.signatureStatus as IndicatorStatus}
          />
          {data.manifestHash && (
            <VerificationRow
              label="Manifest Hash"
              status="valid"
              value={data.manifestHash}
            />
          )}
          {data.signedHash && (
            <VerificationRow
              label="Signed Hash"
              status="valid"
              value={data.signedHash}
            />
          )}
          {data.generatedAt && (
            <div className="py-2 text-xs text-muted">
              Generated: {new Date(data.generatedAt).toLocaleString()}
            </div>
          )}
        </div>
      )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
