'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-DOCUMENTS';
const AUTHORITY = 'Document Center Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/reports';
const customerSafe = true;

export interface PortalDocument {
  id: string;
  documentName: string;
  documentClassification: string;
  versionLabel: string | null;
  freshnessDate: string | null;
  documentHash: string | null;
  createdAt: string;
}

interface Props {
  documents: PortalDocument[];
  loading: boolean;
  lastUpdated?: string;
}

const CLASSIFICATION_CLASS: Record<string, string> = {
  public: 'border-green-500/40 bg-green-500/10 text-green-300',
  internal: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
  confidential: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  restricted: 'border-red-500/40 bg-red-500/10 text-red-300',
};

export default function DocumentCenter({ documents, loading, lastUpdated }: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Customer Document Center"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Document Center"
      lastUpdated={lastUpdated}
    >
      <section aria-label="document-center" data-testid="document-center">
        <div className="mb-3 rounded border border-border bg-muted/10 px-3 py-2 text-xs text-muted">
          Documents listed here are provided by your operator. Hash values confirm document integrity.
        </div>

        {loading && (
          <div className="space-y-2" aria-busy="true">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-16 rounded border border-border bg-surface-2 animate-pulse" />
            ))}
          </div>
        )}

        {!loading && documents.length === 0 && (
          <p className="text-sm text-muted text-center py-8">No documents available for this engagement.</p>
        )}

        {!loading && documents.length > 0 && (
          <div className="space-y-2">
            {documents.map((doc) => {
              const cls = CLASSIFICATION_CLASS[doc.documentClassification.toLowerCase()] ?? 'border-border bg-surface-2 text-muted';
              return (
                <div key={doc.id} className="rounded border border-border bg-surface-2 p-3 space-y-1.5">
                  <div className="flex flex-wrap items-start gap-2 justify-between">
                    <p className="text-sm font-medium text-foreground">{doc.documentName}</p>
                    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
                      {doc.documentClassification}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
                    {doc.versionLabel && <span>Version: {doc.versionLabel}</span>}
                    {doc.freshnessDate && (
                      <span>Fresh as of: {new Date(doc.freshnessDate).toLocaleDateString()}</span>
                    )}
                    <span>Added: {new Date(doc.createdAt).toLocaleDateString()}</span>
                  </div>
                  {doc.documentHash && (
                    <p className="text-[10px] font-mono text-muted" title={doc.documentHash}>
                      Hash: {doc.documentHash.slice(0, 12)}…
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
