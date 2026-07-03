'use client';

import { useState } from 'react';
import { HelpCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import WidgetShell from './WidgetShell';
import type { FeedItem, DecisionOut } from '@/lib/coreApi';

// MCIM reference: MCIM-18.6-CMD-CENTER
const MCIM_ID = 'MCIM-18.6-CMD-CENTER';
const AUTHORITY = 'Control Tower Authority';
const sourceOfTruth = '/api/core/feed/live';
const drillDown = '/dashboard/forensics';

type TimelineFilter = 'all' | 'assessments' | 'reports' | 'trust' | 'actions';

interface TimelineEntry {
  id: string;
  type: TimelineFilter;
  title: string;
  timestamp: string | null;
  severity: string | null;
  source: string | null;
}

function feedToTimeline(items: FeedItem[]): TimelineEntry[] {
  return items.map((item) => {
    const et = (item.event_type ?? '').toLowerCase();
    let type: TimelineFilter = 'all';
    if (et.includes('assessment') || et.includes('score')) type = 'assessments';
    else if (et.includes('report')) type = 'reports';
    else if (et.includes('trust') || et.includes('chain') || et.includes('verify')) type = 'trust';
    else if (et.includes('decision') || et.includes('action')) type = 'actions';

    return {
      id: String(item.id),
      type,
      title: item.title ?? item.event_type ?? `Event ${item.id}`,
      timestamp: item.timestamp ?? null,
      severity: item.severity ?? null,
      source: item.source ?? null,
    };
  });
}

function decisionsToTimeline(decisions: DecisionOut[]): TimelineEntry[] {
  return decisions.map((d) => ({
    id: `dec-${d.id}`,
    type: 'actions' as const,
    title: d.explain_summary ?? d.event_type ?? `Decision ${d.id.slice(0, 8)}`,
    timestamp: d.created_at ?? null,
    severity: d.threat_level ?? null,
    source: d.source ?? null,
  }));
}

function relativeTime(ts: string | null): string {
  if (!ts) return '';
  try {
    const diff = Date.now() - new Date(ts).getTime();
    const mins = Math.floor(diff / 60_000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  } catch {
    return '';
  }
}

function severityToVariant(s: string | null): 'critical' | 'high' | 'warning' | 'outline' {
  if (!s) return 'outline';
  const lower = s.toLowerCase();
  if (lower === 'critical') return 'critical';
  if (lower === 'high') return 'high';
  if (lower === 'medium') return 'warning';
  return 'outline';
}

const FILTERS: Array<{ id: TimelineFilter; label: string; testId: string }> = [
  { id: 'all', label: 'All', testId: 'timeline-all' },
  { id: 'assessments', label: 'Assessments', testId: 'timeline-assessments' },
  { id: 'reports', label: 'Reports', testId: 'timeline-reports' },
  { id: 'trust', label: 'Trust', testId: 'timeline-trust' },
  { id: 'actions', label: 'Actions', testId: 'timeline-actions' },
];

interface ExecutiveTimelineProps {
  feedItems: FeedItem[];
  decisions: DecisionOut[];
  loading?: boolean;
  lastUpdated?: string;
}

export default function ExecutiveTimeline({
  feedItems,
  decisions,
  loading = false,
  lastUpdated,
}: ExecutiveTimelineProps) {
  const [activeFilter, setActiveFilter] = useState<TimelineFilter>('all');

  const allEntries = [
    ...feedToTimeline(feedItems),
    ...decisionsToTimeline(decisions),
  ].sort((a, b) => {
    if (!a.timestamp) return 1;
    if (!b.timestamp) return -1;
    return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
  });

  const filtered =
    activeFilter === 'all'
      ? allEntries
      : allEntries.filter((e) => e.type === activeFilter);

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Executive Timeline"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Timeline"
    >
      <div aria-label="executive-timeline">
        {/* Filter tabs */}
        <div
          className="mb-3 flex flex-wrap gap-1"
          aria-label="timeline-filter"
          data-testid="timeline-filter"
          role="tablist"
        >
          {FILTERS.map((f) => (
            <Button
              key={f.id}
              variant={activeFilter === f.id ? 'default' : 'outline'}
              size="sm"
              className="h-6 px-2 text-[10px]"
              data-testid={f.testId}
              aria-label={f.testId}
              role="tab"
              aria-selected={activeFilter === f.id}
              onClick={() => setActiveFilter(f.id)}
            >
              {f.label}
            </Button>
          ))}
        </div>

        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-10 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-4 text-center text-sm text-muted">
            <HelpCircle className="mx-auto mb-2 h-6 w-6 text-muted/40" aria-hidden="true" />
            <p>No events in this category.</p>
          </div>
        ) : (
          <ul className="space-y-1.5" role="list">
            {filtered.slice(0, 10).map((entry) => (
              <li
                key={entry.id}
                className="flex items-start gap-2 border-b border-border py-2 last:border-0"
                data-testid="timeline-event"
                aria-label="timeline-event"
              >
                {entry.severity && (
                  <Badge
                    variant={severityToVariant(entry.severity)}
                    className="mt-0.5 shrink-0 text-[9px]"
                  >
                    {entry.severity}
                  </Badge>
                )}
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-foreground truncate">{entry.title}</p>
                  {entry.source && (
                    <p className="text-[10px] text-muted truncate">{entry.source}</p>
                  )}
                </div>
                <span className="shrink-0 text-[10px] text-muted/60">
                  {relativeTime(entry.timestamp)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </WidgetShell>
  );
}
