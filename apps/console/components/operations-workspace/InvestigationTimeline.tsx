'use client';

import {
  PlusCircle,
  Edit3,
  CheckCircle,
  Eye,
  ThumbsUp,
  Globe,
  Wrench,
  XCircle,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import WorkspaceShell from './WorkspaceShell';

const MCIM_ID = 'MCIM-18.6-INVESTIGATION-TIMELINE';
const AUTHORITY = 'Investigation Authority';
const sourceOfTruth = '/api/core/forensics/events';
const drillDown = '/dashboard/forensics';

export type TimelineEventType =
  | 'created'
  | 'modified'
  | 'verified'
  | 'reviewed'
  | 'approved'
  | 'published'
  | 'remediated'
  | 'closed';

export interface TimelineEvent {
  id: string;
  eventType: TimelineEventType;
  authority: string;
  timestamp: string;
  actor: string | null;
  confidence: number | null;
  correlationId: string | null;
  sourceObject: string | null;
  drillDown: string | null;
}

interface InvestigationTimelineProps {
  events: TimelineEvent[];
  loading?: boolean;
  lastUpdated?: string;
}

const EVENT_ICON: Record<TimelineEventType, React.ElementType> = {
  created: PlusCircle,
  modified: Edit3,
  verified: CheckCircle,
  reviewed: Eye,
  approved: ThumbsUp,
  published: Globe,
  remediated: Wrench,
  closed: XCircle,
};

const EVENT_BADGE_VARIANT: Record<TimelineEventType, 'default' | 'secondary' | 'success' | 'warning' | 'danger' | 'outline'> = {
  created: 'default',
  modified: 'warning',
  verified: 'success',
  reviewed: 'secondary',
  approved: 'success',
  published: 'default',
  remediated: 'success',
  closed: 'outline',
};

export default function InvestigationTimeline({
  events,
  loading,
  lastUpdated,
}: InvestigationTimelineProps) {
  const sorted = [...events].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
  );

  return (
    <WorkspaceShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Investigation Timeline"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Investigation Timeline"
    >
      <section aria-label="investigation-timeline-panel">
        {loading && (
          <div className="space-y-2" aria-label="Loading timeline">
            {[0, 1, 2, 4].map((i) => (
              <div
                key={i}
                className="h-12 w-full animate-pulse rounded border border-border bg-muted/20"
              />
            ))}
          </div>
        )}

        {!loading && sorted.length === 0 && (
          <p className="py-6 text-center text-sm text-muted">No timeline events.</p>
        )}

        {!loading && sorted.length > 0 && (
          <ol className="relative border-l border-border space-y-4 pl-5" aria-label="Investigation timeline">
            {sorted.map((event) => {
              const Icon = EVENT_ICON[event.eventType];
              const confidencePct =
                event.confidence !== null ? `${Math.round(event.confidence * 100)}%` : null;

              return (
                <li key={event.id} className="relative text-xs">
                  <span
                    className="absolute -left-[22px] flex h-4 w-4 items-center justify-center rounded-full bg-surface border border-border"
                    aria-hidden="true"
                  >
                    <Icon className="h-2.5 w-2.5 text-primary" />
                  </span>

                  <div className="rounded border border-border bg-surface-2 px-3 py-2 space-y-1">
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-1.5">
                        <Badge variant={EVENT_BADGE_VARIANT[event.eventType]} className="text-[10px]">
                          {event.eventType}
                        </Badge>
                        <Badge variant="outline" className="text-[10px]">
                          {event.authority}
                        </Badge>
                      </div>
                      <time
                        dateTime={event.timestamp}
                        className="text-[10px] text-muted shrink-0"
                      >
                        {new Date(event.timestamp).toLocaleString()}
                      </time>
                    </div>

                    <div className="flex flex-wrap gap-x-3 text-muted text-[10px]">
                      {event.actor && <span>Actor: {event.actor}</span>}
                      {confidencePct && <span>Confidence: {confidencePct}</span>}
                      {event.correlationId && (
                        <span className="font-mono">Corr: {event.correlationId}</span>
                      )}
                      {event.sourceObject && <span>Source: {event.sourceObject}</span>}
                    </div>
                  </div>
                </li>
              );
            })}
          </ol>
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
