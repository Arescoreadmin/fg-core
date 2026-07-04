'use client';

import { Badge } from '@/components/ui/badge';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';
import TrustCenterShell from './TrustCenterShell';

const MCIM_ID = 'MCIM-18.6-TRUST-TIMELINE';
const AUTHORITY = 'Trust Timeline Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/forensics';

export type TrustEventType =
  | 'score-change' | 'control-drift' | 'evidence-added' | 'decision-made'
  | 'attestation' | 'remediation' | 'certificate-issued' | 'audit-review'
  | 'policy-change' | 'replay';

export interface TrustTimelineEvent {
  id: string;
  eventType: TrustEventType;
  authority: string;
  timestamp: string;
  actor: string | null;
  summary: string;
  impact: 'positive' | 'negative' | 'neutral';
  linkedEntityId: string | null;
}

interface TrustTimelineProps {
  events: TrustTimelineEvent[];
  loading?: boolean;
  lastUpdated?: string;
}

function ImpactIcon({ impact }: { impact: TrustTimelineEvent['impact'] }) {
  if (impact === 'positive') return <TrendingUp className="h-3.5 w-3.5 text-success" aria-hidden="true" />;
  if (impact === 'negative') return <TrendingDown className="h-3.5 w-3.5 text-danger" aria-hidden="true" />;
  return <Minus className="h-3.5 w-3.5 text-muted" aria-hidden="true" />;
}

export default function TrustTimeline({ events, loading, lastUpdated }: TrustTimelineProps) {
  const sorted = [...events].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  return (
    <TrustCenterShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Chronological trust event timeline"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="polling"
      lastUpdated={lastUpdated}
      title="Trust Timeline"
    >
      <section aria-label="trust-timeline" data-testid="trust-timeline">
      {loading ? (
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-14 animate-pulse rounded-md border border-border bg-muted/20" aria-hidden="true" />
          ))}
        </div>
      ) : sorted.length === 0 ? (
        <p className="text-sm text-muted">No trust timeline events.</p>
      ) : (
        <ol className="relative border-l border-border space-y-4 ml-3">
          {sorted.map((e) => (
            <li key={e.id} className="ml-4">
              <div className="absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full border border-border bg-surface-2" aria-hidden="true" />
              <div className="flex items-start gap-2 text-xs">
                <ImpactIcon impact={e.impact} />
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-muted">{new Date(e.timestamp).toLocaleString()}</span>
                    <span className="font-medium text-foreground">{e.eventType}</span>
                    <span className="text-muted">{e.authority}</span>
                  </div>
                  <p className="text-foreground">{e.summary}</p>
                  <p className="text-muted">Actor: {e.actor ?? 'System'}</p>
                  {e.linkedEntityId && (
                    <p className="font-mono text-muted">{e.linkedEntityId}</p>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ol>
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
