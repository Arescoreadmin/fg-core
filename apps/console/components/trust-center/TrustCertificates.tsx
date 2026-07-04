'use client';

import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-CERTIFICATES';
const AUTHORITY = 'Trust Certificates Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/control-tower';

export interface TrustCertificate {
  certificateId: string;
  issuedAt: string;
  validUntil: string | null;
  mcimId: string;
  authority: string;
  signedHash: string;
  manifestHash: string;
  scope: string;
  tenantId: string;
}

interface TrustCertificatesProps {
  certificates: TrustCertificate[];
  loading?: boolean;
  lastUpdated?: string;
}

export function downloadCertificate(cert: TrustCertificate): void {
  const blob = new Blob([JSON.stringify(cert, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `trust-certificate-${cert.certificateId}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function TrustCertificates({ certificates, loading, lastUpdated }: TrustCertificatesProps) {
  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Internal trust certificate management"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Trust Certificates"
    >
      <div className="mb-3 rounded-md border border-warning/20 bg-warning/10 px-3 py-2 text-xs text-warning">
        These trust certificates are internal audit artifacts and do not constitute legal certification.
      </div>
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-24 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : certificates.length === 0 ? (
        <p className="text-sm text-muted">No trust certificates issued.</p>
      ) : (
        <div className="space-y-3">
          {certificates.map((cert) => (
            <div key={cert.certificateId} className="rounded-md border border-border bg-surface-2 p-3 text-xs space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-mono font-medium text-foreground">{cert.certificateId}</span>
                <button
                  type="button"
                  onClick={() => downloadCertificate(cert)}
                  className="text-primary hover:underline text-[10px]"
                >
                  Download JSON
                </button>
              </div>
              <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-muted">
                <span>Authority: {cert.authority}</span>
                <span>Scope: {cert.scope}</span>
                <span>Issued: {new Date(cert.issuedAt).toLocaleString()}</span>
                <span>Valid until: {cert.validUntil ? new Date(cert.validUntil).toLocaleString() : 'No expiry'}</span>
                <span className="font-mono">Signed: {cert.signedHash.slice(0, 16)}…</span>
                <span className="font-mono">Manifest: {cert.manifestHash.slice(0, 16)}…</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </TrustCenterShell>
  );
}

// Suppress unused variable warnings — these are required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
