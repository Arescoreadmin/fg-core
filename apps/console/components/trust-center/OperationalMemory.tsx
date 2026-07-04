'use client';

import { Badge } from '@/components/ui/badge';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-MEMORY';
const AUTHORITY = 'Operational Memory Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/forensics';

// No browser storage used. All data is server-authoritative.

export type MemoryWindow = '30d' | '90d' | '180d' | '365d';

export interface MemoryEntry {
  id: string;
  period: string;
  snapshotAt: string;
  trustScore: number | null;
  controlPassRate: number | null;
  decisionCount: number;
  evidenceCount: number;
  authority: string;
  notes: string | null;
}

interface OperationalMemoryProps {
  entries: MemoryEntry[];
  activeWindow: MemoryWindow;
  onWindowChange?: (w: MemoryWindow) => void;
  loading?: boolean;
  lastUpdated?: string;
}

const WINDOWS: MemoryWindow[] = ['30d', '90d', '180d', '365d'];

export default function OperationalMemory({ entries, activeWindow, onWindowChange, loading, lastUpdated }: OperationalMemoryProps) {
  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Historical trust state memory — server-authoritative"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Operational Memory"
    >
      <section aria-label="operational-memory" data-testid="operational-memory">
      <div className="mb-3 flex gap-1">
        {WINDOWS.map((w) => (
          <button
            key={w}
            type="button"
            onClick={() => onWindowChange?.(w)}
            className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
              activeWindow === w
                ? 'bg-primary text-primary-foreground'
                : 'bg-muted/30 text-muted hover:bg-muted/50'
            }`}
          >
            {w}
          </button>
        ))}
      </div>
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-8 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : entries.length === 0 ? (
        <p className="text-sm text-muted">No historical data for this window.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-muted text-left">
                <th className="pb-2 pr-3 font-medium">Period</th>
                <th className="pb-2 pr-3 font-medium">Snapshot Date</th>
                <th className="pb-2 pr-3 font-medium">Trust Score</th>
                <th className="pb-2 pr-3 font-medium">Control Pass Rate</th>
                <th className="pb-2 pr-3 font-medium">Decisions</th>
                <th className="pb-2 pr-3 font-medium">Evidence</th>
                <th className="pb-2 pr-3 font-medium">Authority</th>
                <th className="pb-2 font-medium">Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {entries.map((e) => (
                <tr key={e.id} className="text-foreground">
                  <td className="py-2 pr-3">{e.period}</td>
                  <td className="py-2 pr-3">{new Date(e.snapshotAt).toLocaleDateString()}</td>
                  <td className="py-2 pr-3">{e.trustScore !== null ? e.trustScore : '—'}</td>
                  <td className="py-2 pr-3">{e.controlPassRate !== null ? `${e.controlPassRate}%` : '—'}</td>
                  <td className="py-2 pr-3">{e.decisionCount}</td>
                  <td className="py-2 pr-3">{e.evidenceCount}</td>
                  <td className="py-2 pr-3">{e.authority}</td>
                  <td className="py-2 text-muted">{e.notes ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      </section>
    </TrustCenterShell>
  );
}

// Suppress unused variable warnings — these are required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
