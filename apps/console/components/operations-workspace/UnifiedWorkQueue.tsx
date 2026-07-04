'use client';

import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import Link from 'next/link';
import WorkspaceShell from './WorkspaceShell';

const MCIM_ID = 'MCIM-18.6-WORK-QUEUE';
const AUTHORITY = 'Work Queue Authority';
const sourceOfTruth = '/api/core/feed/live';
const drillDown = '/dashboard/forensics';

export type WorkType =
  | 'assessment'
  | 'evidence-review'
  | 'verification'
  | 'report-review'
  | 'portal-publication'
  | 'remediation'
  | 'governance-approval'
  | 'trust-review'
  | 'transparency-review'
  | 'simulation-review'
  | 'replay-review'
  | 'customer-request'
  | 'notification'
  | 'policy-review';

export interface WorkQueueItem {
  id: string;
  workType: WorkType;
  title: string;
  authority: string;
  capability: string;
  mcimId: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  severity: string | null;
  sla: string | null;
  owner: string | null;
  dueDate: string | null;
  confidence: number | null;
  sourceObject: string | null;
  drillDown: string;
  workflowStage: string;
}

interface UnifiedWorkQueueProps {
  items: WorkQueueItem[];
  loading?: boolean;
  lastUpdated?: string;
}

const PRIORITY_ORDER: Record<WorkQueueItem['priority'], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const PRIORITY_VARIANT: Record<WorkQueueItem['priority'], 'critical' | 'high' | 'medium' | 'low'> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
};

type PriorityFilter = 'all' | WorkQueueItem['priority'];

export default function UnifiedWorkQueue({ items, loading, lastUpdated }: UnifiedWorkQueueProps) {
  const [filter, setFilter] = useState<PriorityFilter>('all');

  const filtered = items
    .filter((item) => filter === 'all' || item.priority === filter)
    .sort((a, b) => PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority]);

  return (
    <WorkspaceShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Work Queue"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-demand"
      lastUpdated={lastUpdated}
      title="Unified Work Queue"
    >
      <div className="space-y-3">
        {/* Priority filter */}
        <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by priority">
          {(['all', 'critical', 'high', 'medium', 'low'] as PriorityFilter[]).map((p) => (
            <Button
              key={p}
              variant={filter === p ? 'default' : 'outline'}
              size="sm"
              className="h-6 px-2 text-xs capitalize"
              onClick={() => setFilter(p)}
              aria-pressed={filter === p}
            >
              {p}
            </Button>
          ))}
        </div>

        {/* Loading skeletons */}
        {loading && (
          <div className="space-y-2" aria-label="Loading work queue">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className="h-16 w-full animate-pulse rounded border border-border bg-muted/20"
              />
            ))}
          </div>
        )}

        {/* Empty state */}
        {!loading && filtered.length === 0 && (
          <p className="py-6 text-center text-sm text-muted">No items in queue.</p>
        )}

        {/* Items */}
        {!loading && filtered.length > 0 && (
          <ul className="space-y-2" aria-label="Work queue items">
            {filtered.map((item) => (
              <li
                key={item.id}
                className="rounded border border-border bg-surface-2 px-3 py-2 text-xs"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <Link
                      href={item.drillDown}
                      className="font-medium text-foreground hover:underline truncate block"
                    >
                      {item.title}
                    </Link>
                    <div className="mt-1 flex flex-wrap gap-1">
                      <Badge variant={PRIORITY_VARIANT[item.priority]} className="text-[10px]">
                        {item.priority}
                      </Badge>
                      <Badge variant="secondary" className="text-[10px]">
                        {item.workType}
                      </Badge>
                      <Badge variant="outline" className="text-[10px] font-mono">
                        {item.mcimId}
                      </Badge>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-x-3 text-muted">
                      <span>Authority: {item.authority}</span>
                      {item.workflowStage && <span>Stage: {item.workflowStage}</span>}
                      {item.sla && <span>SLA: {item.sla}</span>}
                      {item.owner && <span>Owner: {item.owner}</span>}
                      {item.dueDate && (
                        <span>Due: {new Date(item.dueDate).toLocaleDateString()}</span>
                      )}
                    </div>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </WorkspaceShell>
  );
}

// Required MCIM declarations
void MCIM_ID;
void AUTHORITY;
void sourceOfTruth;
void drillDown;
