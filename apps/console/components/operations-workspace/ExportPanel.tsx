'use client';

import { Download, FileJson, FileSpreadsheet } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import WorkspaceShell from './WorkspaceShell';

const MCIM_ID = 'MCIM-18.6-EXPORT-PANEL';
const AUTHORITY = 'Export Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard';

export type ExportFormat = 'json' | 'csv';

export interface WorkspaceSnapshot {
  exportedAt: string;
  tenantId: string;
  queue: unknown[];
  cases: unknown[];
  timeline: unknown[];
  decisionLedger: unknown[];
  workflowState: unknown[];
  healthMap: unknown[];
  provenanceMetadata: {
    mcimId: string;
    authority: string;
    sourceOfTruth: string;
    exportedBy: string;
  };
}

interface ExportPanelProps {
  workspaceState: WorkspaceSnapshot | null;
  onExport?: (format: ExportFormat) => void;
  loading?: boolean;
}

const FORMAT_DETAILS: {
  format: ExportFormat;
  label: string;
  description: string;
  icon: React.ElementType;
}[] = [
  {
    format: 'json',
    label: 'JSON',
    description: 'Full structured export with provenance metadata',
    icon: FileJson,
  },
  {
    format: 'csv',
    label: 'CSV',
    description: 'Tabular export suitable for spreadsheet analysis',
    icon: FileSpreadsheet,
  },
];

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function handleDownload(format: ExportFormat, state: WorkspaceSnapshot) {
  const ts = new Date(state.exportedAt).toISOString().slice(0, 10);
  if (format === 'json') {
    const blob = new Blob([JSON.stringify(state, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `workspace-snapshot-${ts}.json`);
  } else {
    const rows: string[] = [
      'section,key,value',
      `provenance,mcimId,${state.provenanceMetadata.mcimId}`,
      `provenance,authority,${state.provenanceMetadata.authority}`,
      `provenance,sourceOfTruth,${state.provenanceMetadata.sourceOfTruth}`,
      `provenance,exportedBy,${state.provenanceMetadata.exportedBy}`,
      `provenance,exportedAt,${state.exportedAt}`,
      `provenance,tenantId,${state.tenantId}`,
      `summary,queueItems,${state.queue.length}`,
      `summary,cases,${state.cases.length}`,
      `summary,ledgerEntries,${state.decisionLedger.length}`,
      `summary,timelineEvents,${state.timeline.length}`,
      `summary,workflowStates,${state.workflowState.length}`,
    ];
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    downloadBlob(blob, `workspace-snapshot-${ts}.csv`);
  }
}

export default function ExportPanel({ workspaceState, onExport, loading }: ExportPanelProps) {
  return (
    <WorkspaceShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Export Panel"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      title="Export Workspace"
    >
      <section aria-label="export-panel">
        {loading && (
          <div
            className="h-24 w-full animate-pulse rounded border border-border bg-muted/20"
            aria-label="Loading export panel"
          />
        )}

        {!loading && (
          <div className="space-y-3">
            {/* Snapshot summary */}
            {workspaceState ? (
              <div className="rounded border border-border bg-surface-2 px-3 py-2 text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-foreground">Workspace Snapshot</span>
                  <Badge variant="success" className="text-[10px]">Ready</Badge>
                </div>
                <div className="text-muted space-y-0.5">
                  <div className="flex justify-between">
                    <span>Tenant</span>
                    <span className="font-mono">{workspaceState.tenantId}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Exported at</span>
                    <span>{new Date(workspaceState.exportedAt).toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Queue items</span>
                    <span>{workspaceState.queue.length}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Cases</span>
                    <span>{workspaceState.cases.length}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Ledger entries</span>
                    <span>{workspaceState.decisionLedger.length}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Timeline events</span>
                    <span>{workspaceState.timeline.length}</span>
                  </div>
                </div>
                <div className="pt-1 border-t border-border text-[10px] text-muted space-y-0.5">
                  <p className="font-semibold text-foreground">Provenance Metadata</p>
                  <div className="flex justify-between">
                    <span>MCIM</span>
                    <span className="font-mono">{workspaceState.provenanceMetadata.mcimId}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Authority</span>
                    <span>{workspaceState.provenanceMetadata.authority}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Source</span>
                    <span className="font-mono">{workspaceState.provenanceMetadata.sourceOfTruth}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Exported by</span>
                    <span>{workspaceState.provenanceMetadata.exportedBy}</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded border border-border bg-muted/10 px-3 py-2 text-xs text-muted">
                No workspace snapshot available. Load workspace data first.
              </div>
            )}

            {/* Export format buttons */}
            <div className="space-y-2">
              <p className="text-[10px] font-semibold uppercase tracking-wide text-muted/70">
                Export Format
              </p>
              <div className="grid grid-cols-2 gap-2">
                {FORMAT_DETAILS.map(({ format, label, description, icon: Icon }) => (
                  <Button
                    key={format}
                    variant="outline"
                    size="sm"
                    className="h-auto flex-col items-start gap-1 px-3 py-2 text-left"
                    onClick={() => {
                      if (onExport) {
                        onExport(format);
                      } else if (workspaceState) {
                        handleDownload(format, workspaceState);
                      }
                    }}
                    disabled={!workspaceState}
                    aria-label={`Export as ${label}`}
                  >
                    <span className="flex items-center gap-1.5 text-xs font-semibold">
                      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                      {label}
                    </span>
                    <span className="text-[10px] text-muted font-normal">{description}</span>
                  </Button>
                ))}
              </div>
            </div>

            <p className="text-[10px] text-muted/60">
              Every export includes provenance metadata (MCIM ID, authority, source of truth,
              exported by). Export includes{' '}
              <Download className="inline h-3 w-3" aria-hidden="true" /> no raw secrets or
              credentials.
            </p>
          </div>
        )}
      </section>
    </WorkspaceShell>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
