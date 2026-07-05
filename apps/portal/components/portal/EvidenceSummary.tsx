'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-EVIDENCE';
const AUTHORITY = 'Evidence Summary Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/engagement';
const customerSafe = true;

export type EvidenceVerificationStatus = 'verified' | 'pending' | 'disputed' | 'unknown';
export type EvidenceClassification = 'confidential' | 'internal' | 'public' | 'restricted';

export interface EvidenceSummaryItem {
  id: string;
  category: string;
  count: number;
  verificationStatus: EvidenceVerificationStatus;
  freshness: string | null;
  sourceType: string;
  owner: string | null;
  classification: EvidenceClassification;
  chainOfCustodyReady: boolean;
  exportReady: boolean;
}

interface Props {
  items: EvidenceSummaryItem[];
  loading: boolean;
  lastUpdated?: string;
}

const VERIFICATION_CLASS: Record<EvidenceVerificationStatus, string> = {
  verified: 'border-green-500/40 bg-green-500/10 text-green-300',
  pending: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  disputed: 'border-red-500/40 bg-red-500/10 text-red-300',
  unknown: 'border-border bg-surface-2 text-muted',
};

function VerificationBadge({ status }: { status: EvidenceVerificationStatus }) {
  const cls = VERIFICATION_CLASS[status];
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

export default function EvidenceSummary({ items, loading, lastUpdated }: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Evidence Summary"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Evidence Summary"
      lastUpdated={lastUpdated}
    >
      <section aria-label="evidence-summary" data-testid="evidence-summary">
      <div className="mb-3 rounded border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-200">
        Raw evidence paths, internal metadata, provider payloads, and raw prompts are not displayed in this portal view.
      </div>

      {loading && (
        <div className="space-y-2" aria-busy="true">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-10 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && items.length === 0 && (
        <p className="text-sm text-muted text-center py-8">No evidence summary available.</p>
      )}

      {!loading && items.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className="border-b border-border text-muted">
                <th className="text-left py-2 pr-3 font-medium">Category</th>
                <th className="text-right py-2 pr-3 font-medium">Count</th>
                <th className="text-left py-2 pr-3 font-medium">Verification</th>
                <th className="text-left py-2 pr-3 font-medium">Freshness</th>
                <th className="text-left py-2 pr-3 font-medium">Source Type</th>
                <th className="text-left py-2 pr-3 font-medium">Owner</th>
                <th className="text-left py-2 pr-3 font-medium">Classification</th>
                <th className="text-center py-2 pr-3 font-medium">Chain Ready</th>
                <th className="text-center py-2 font-medium">Export Ready</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {items.map((item) => (
                <tr key={item.id} className="text-foreground">
                  <td className="py-2 pr-3">{item.category}</td>
                  <td className="py-2 pr-3 text-right font-mono">{item.count}</td>
                  <td className="py-2 pr-3">
                    <VerificationBadge status={item.verificationStatus} />
                  </td>
                  <td className="py-2 pr-3 text-muted">
                    {item.freshness
                      ? new Date(item.freshness).toLocaleDateString()
                      : '—'}
                  </td>
                  <td className="py-2 pr-3">{item.sourceType}</td>
                  <td className="py-2 pr-3 text-muted">{item.owner ?? '—'}</td>
                  <td className="py-2 pr-3 capitalize">{item.classification}</td>
                  <td className="py-2 pr-3 text-center">
                    {item.chainOfCustodyReady ? (
                      <span className="text-green-300">Yes</span>
                    ) : (
                      <span className="text-muted">No</span>
                    )}
                  </td>
                  <td className="py-2 text-center">
                    {item.exportReady ? (
                      <span className="text-green-300">Yes</span>
                    ) : (
                      <span className="text-muted">No</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
