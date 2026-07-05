'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-EXPORT';
const AUTHORITY = 'Customer Export Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/export';
const customerSafe = true;

export type ExportType =
  | 'report' | 'evidence-summary' | 'remediation' | 'trust-verification'
  | 'attestation' | 'portal-snapshot';

export interface ExportOption {
  type: ExportType;
  label: string;
  description: string;
  available: boolean;
  formats: ('json' | 'pdf' | 'csv' | 'zip')[];
}

interface Props {
  options: ExportOption[];
  onExport?: (type: ExportType, format: string) => void;
  loading: boolean;
  lastUpdated?: string;
}

const FORMAT_CLASS: Record<string, string> = {
  json: 'border-blue-500/30 bg-blue-500/5 text-blue-300',
  pdf: 'border-red-500/30 bg-red-500/5 text-red-300',
  csv: 'border-green-500/30 bg-green-500/5 text-green-300',
  zip: 'border-amber-500/30 bg-amber-500/5 text-amber-200',
};

export default function CustomerExportCenter({ options, onExport, loading, lastUpdated }: Props) {
  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Customer Export"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Export Center"
      lastUpdated={lastUpdated}
    >
      <section aria-label="customer-export-center" data-testid="customer-export-center">
      {loading && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3" aria-busy="true">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-24 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && options.length === 0 && (
        <p className="text-sm text-muted text-center py-8">No export options available.</p>
      )}

      {!loading && options.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {options.map((option) => (
            <div
              key={option.type}
              className={`rounded border p-3 space-y-2 ${option.available ? 'border-border bg-surface-2' : 'border-border bg-surface opacity-60'}`}
            >
              <div>
                <span className="text-sm font-medium text-foreground">{option.label}</span>
                <p className="text-xs text-muted mt-0.5">{option.description}</p>
              </div>

              {!option.available && (
                <p className="text-xs text-muted italic">Not available for this engagement.</p>
              )}

              {option.available && (
                <div className="flex flex-wrap gap-1.5">
                  {option.formats.map((fmt) => (
                    <button
                      key={fmt}
                      type="button"
                      className={`rounded border px-2 py-0.5 text-xs font-medium hover:opacity-80 transition-opacity ${FORMAT_CLASS[fmt] ?? 'border-border bg-surface-2 text-muted'}`}
                      onClick={() => onExport?.(option.type, fmt)}
                    >
                      {fmt.toUpperCase()}
                    </button>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="mt-4 space-y-1.5 border-t border-border pt-3">
        <p className="text-[11px] text-muted">
          All exports include generated timestamp, source authority, and manifest hash where available. No raw internal data is included.
        </p>
        <p className="text-[11px] text-amber-200">
          Exported artifacts are for customer use only and do not constitute legal certification.
        </p>
      </div>
      </section>
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
