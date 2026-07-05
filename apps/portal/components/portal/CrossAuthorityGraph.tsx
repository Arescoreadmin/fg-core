'use client';
import PortalShell from './PortalShell';

const MCIM_ID = 'MCIM-18.6-PORTAL-CROSS-AUTH';
const AUTHORITY = 'Cross-Authority Graph Authority';
const sourceOfTruth = '/api/core/field-assessment/engagements';
const drillDown = '/trust';
const customerSafe = true;

export type AuthorityNodeType =
  | 'assessment' | 'finding' | 'evidence' | 'report'
  | 'remediation' | 'decision' | 'portal';

export interface AuthorityGraphNode {
  id: string;
  nodeType: AuthorityNodeType;
  label: string;
  count: number | null;
  status: string;
  linkedEntityIds: string[];
}

interface Props {
  nodes: AuthorityGraphNode[];
  loading: boolean;
  lastUpdated?: string;
}

const NODE_TYPE_ORDER: AuthorityNodeType[] = [
  'assessment', 'finding', 'evidence', 'report', 'remediation', 'decision', 'portal',
];

const NODE_TYPE_LABEL: Record<AuthorityNodeType, string> = {
  assessment: 'Assessment',
  finding: 'Finding',
  evidence: 'Evidence',
  report: 'Report',
  remediation: 'Remediation',
  decision: 'Decision',
  portal: 'Portal',
};

const STATUS_CLASS: Record<string, string> = {
  active: 'border-green-500/40 bg-green-500/10 text-green-300',
  complete: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
  pending: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
  open: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_CLASS[status] ?? 'border-border bg-surface-2 text-muted';
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

export default function CrossAuthorityGraph({ nodes, loading, lastUpdated }: Props) {
  const byType = NODE_TYPE_ORDER.map((type) => ({
    type,
    label: NODE_TYPE_LABEL[type],
    nodes: nodes.filter((n) => n.nodeType === type),
  }));

  const hasAny = nodes.length > 0;

  return (
    <PortalShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Cross-Authority Graph"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      title="Cross-Authority Graph"
      lastUpdated={lastUpdated}
    >
      <p className="text-[11px] text-muted mb-4">
        No relationships are inferred. Only authority-backed connections shown.
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
          No cross-authority data available.
        </p>
      )}

      {!loading && hasAny && (
        <div className="flex flex-wrap items-start gap-2">
          {byType.map((group, gi) => (
            <div key={group.type} className="flex items-start gap-2">
              <div className="rounded border border-border bg-surface-2 p-2 min-w-[100px] space-y-2">
                <p className="text-[10px] font-semibold text-muted uppercase tracking-wider">
                  {group.label}
                </p>
                {group.nodes.length === 0 ? (
                  <p className="text-xs text-muted">—</p>
                ) : (
                  group.nodes.map((n) => (
                    <div key={n.id} className="space-y-1">
                      <p className="text-xs text-foreground font-medium">{n.label}</p>
                      {n.count != null && (
                        <p className="text-[10px] text-muted">{n.count} items</p>
                      )}
                      <StatusBadge status={n.status} />
                    </div>
                  ))
                )}
              </div>

              {gi < byType.length - 1 && (
                <span className="text-muted text-lg mt-3 select-none" aria-hidden="true">
                  →
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </PortalShell>
  );
}

void MCIM_ID; void AUTHORITY; void sourceOfTruth; void drillDown; void customerSafe;
