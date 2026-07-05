'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-TRUST-REL';
const AUTHORITY = 'Trust Relationships Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/trust';
const customerSafe = true;

export interface TrustRelationshipNode {
  id: string;
  type: 'evidence' | 'control' | 'policy' | 'requirement' | 'framework' | 'business-risk';
  label: string;
  count: number | null;
  status: 'satisfied' | 'partial' | 'gap' | 'unknown';
  linkedTo: string[];
}

interface Props {
  nodes: TrustRelationshipNode[];
  loading: boolean;
  lastUpdated?: string;
}

const NODE_TYPE_ORDER = ['evidence', 'control', 'policy', 'requirement', 'framework', 'business-risk'] as const;

const STATUS_CLASS: Record<string, string> = {
  satisfied: 'border-green-500/40 bg-green-500/10 text-green-300',
  partial: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  gap: 'border-red-500/40 bg-red-500/10 text-red-300',
  unknown: 'border-border bg-surface-2 text-muted',
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_CLASS[status] ?? STATUS_CLASS.unknown;
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

const TYPE_LABEL: Record<string, string> = {
  'evidence': 'Evidence',
  'control': 'Control',
  'policy': 'Policy',
  'requirement': 'Requirement',
  'framework': 'Framework',
  'business-risk': 'Business Risk',
};

export default function TrustRelationships({ nodes, loading, lastUpdated }: Props) {
  // Group nodes by type, in the chain order
  const byType = NODE_TYPE_ORDER.map((type) => ({
    type,
    label: TYPE_LABEL[type],
    nodes: nodes.filter((n) => n.type === type),
  }));

  const hasAny = nodes.length > 0;

  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Trust Relationships"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Trust Relationships"
      lastUpdated={lastUpdated}
    >
      <p className="text-[11px] text-muted mb-4">
        Only authoritative relationships are shown. No relationships are inferred.
      </p>

      {loading && (
        <div className="space-y-2" aria-busy="true">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-12 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && !hasAny && (
        <p className="text-sm text-muted text-center py-8">
          No trust relationship data available.
        </p>
      )}

      {!loading && hasAny && (
        <>
          {/* Horizontal flow (wraps on mobile) */}
          <div className="flex flex-wrap items-start gap-2">
            {byType.map((group, gi) => (
              <div key={group.type} className="flex items-start gap-2">
                {/* Node group */}
                <div className="rounded border border-border bg-surface-2 p-2 min-w-[100px] space-y-2">
                  <p className="text-[10px] font-semibold text-muted uppercase tracking-wider">
                    {group.label}
                  </p>
                  {group.nodes.length === 0 ? (
                    <p className="text-xs text-muted">—</p>
                  ) : (
                    group.nodes.map((n) => (
                      <div key={n.id} className="space-y-1">
                        <p className="text-xs text-foreground">{n.label}</p>
                        {n.count != null && (
                          <p className="text-[10px] text-muted">{n.count} items</p>
                        )}
                        <StatusBadge status={n.status} />
                      </div>
                    ))
                  )}
                </div>

                {/* Arrow connector (not after last) */}
                {gi < byType.length - 1 && (
                  <span className="text-muted text-lg mt-3 select-none" aria-hidden="true">
                    →
                  </span>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
