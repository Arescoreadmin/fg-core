// MCIM reference: MCIM-18.6-OPS-WORKSPACE
// Authority: Operations Workspace Authority
// sourceOfTruth: /api/core/control-tower/snapshot
// drillDown: /dashboard

import { Suspense } from 'react';
import { TopBar } from '@/components/layout/TopBar';
import WorkspaceCommandPalette from './WorkspaceCommandPalette';
import {
  getCommandCenterSnapshot,
  getRecentFeedEvents,
  type ControlTowerSnapshotV1,
  type FeedItem,
} from '@/lib/coreApi';

import UnifiedWorkQueue, { type WorkQueueItem } from '@/components/operations-workspace/UnifiedWorkQueue';
import CaseWorkspace, { type WorkspaceCase } from '@/components/operations-workspace/CaseWorkspace';
import DecisionLedger, { type LedgerEntry } from '@/components/operations-workspace/DecisionLedger';
import WorkflowProgress, { type WorkflowState } from '@/components/operations-workspace/WorkflowProgress';
import InvestigationTimeline, { type TimelineEvent } from '@/components/operations-workspace/InvestigationTimeline';
import AuthorityHealthMap from '@/components/operations-workspace/AuthorityHealthMap';
import CrossAuthorityNav from '@/components/operations-workspace/CrossAuthorityNav';
import CorrelationGraph2, { type GraphNode2, type GraphEdge2 } from '@/components/operations-workspace/CorrelationGraph2';
import PlaybookPanel, { type Playbook } from '@/components/operations-workspace/PlaybookPanel';
import DelegationPanel, { type DelegationAction } from '@/components/operations-workspace/DelegationPanel';
import ExportPanel, { type WorkspaceSnapshot } from '@/components/operations-workspace/ExportPanel';

// ─── Skeleton fallback ────────────────────────────────────────────────────────

function PanelSkeleton({ height = 'h-48' }: { height?: string }) {
  return (
    <div
      className={`${height} w-full animate-pulse rounded-lg border border-border bg-muted/20`}
      aria-hidden="true"
    />
  );
}

// ─── Server component — workspace overview ────────────────────────────────────

export default async function WorkspaceOverviewPage() {
  const now = new Date().toISOString();

  const [snapshotSettled, feedSettled] = await Promise.allSettled([
    getCommandCenterSnapshot(),
    getRecentFeedEvents(50),
  ]);

  const snapshot: ControlTowerSnapshotV1 | null =
    snapshotSettled.status === 'fulfilled' && snapshotSettled.value.ok
      ? snapshotSettled.value.data
      : null;

  const feedItems: FeedItem[] =
    feedSettled.status === 'fulfilled' && feedSettled.value.ok
      ? feedSettled.value.data.items
      : [];

  // These come from future API endpoints — pass empty arrays for now
  const queueItems: WorkQueueItem[] = [];
  const cases: WorkspaceCase[] = [];
  const ledgerEntries: LedgerEntry[] = [];
  const workflows: WorkflowState[] = [];
  const timelineEvents: TimelineEvent[] = [];
  const graphNodes: GraphNode2[] = [];
  const graphEdges: GraphEdge2[] = [];
  const playbooks: Playbook[] = [];
  const delegationActions: DelegationAction[] = [];

  // Derive timeline events from feed items where possible
  const derivedTimeline: TimelineEvent[] = feedItems.slice(0, 20).map((item) => ({
    id: String(item.id),
    eventType: 'created' as const,
    authority: 'Feed Authority',
    timestamp: item.timestamp ?? now,
    actor: item.source ?? null,
    confidence: null,
    correlationId: item.event_id ?? null,
    sourceObject: item.event_type ?? null,
    drillDown: '/dashboard/forensics',
  }));

  const allTimeline = [...timelineEvents, ...derivedTimeline];

  const workspaceSnapshot: WorkspaceSnapshot | null = snapshot
    ? {
        exportedAt: now,
        tenantId: snapshot.tenant.tenant_id,
        queue: queueItems,
        cases,
        timeline: allTimeline,
        decisionLedger: ledgerEntries,
        workflowState: workflows,
        healthMap: [],
        provenanceMetadata: {
          mcimId: 'MCIM-18.6-OPS-WORKSPACE',
          authority: 'Operations Workspace Authority',
          sourceOfTruth: '/api/core/control-tower/snapshot',
          exportedBy: 'console',
        },
      }
    : null;

  return (
    <main
      id="workspace-overview"
      aria-label="workspace-overview"
      data-testid="workspace-page"
    >
      <TopBar
        title="Operations Workspace"
        subtitle="Enterprise Operations Workspace — MCIM-18.6-OPS-WORKSPACE"
        actions={<WorkspaceCommandPalette />}
      />

      <div className="p-6 space-y-6">
        {/* === Workspace heading === */}
        <div data-testid="workspace-heading">
          <h1 className="text-lg font-bold text-foreground">Enterprise Operations Workspace</h1>
          <p className="text-sm text-muted mt-0.5">
            Unified authority-driven workspace for assessments, cases, decisions, and governance.
          </p>
        </div>

        {/* === Cross-Authority Navigation === */}
        <section>
          <Suspense fallback={<PanelSkeleton height="h-20" />}>
            <CrossAuthorityNav currentAuthority="Assessment" />
          </Suspense>
        </section>

        {/* === Work Queue === */}
        <section aria-labelledby="workspace-queue-heading">
          <h2
            id="workspace-queue-heading"
            data-testid="workspace-queue-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Unified Work Queue
          </h2>
          <Suspense fallback={<PanelSkeleton />}>
            <UnifiedWorkQueue items={queueItems} loading={false} lastUpdated={now} />
          </Suspense>
        </section>

        {/* === Cases + Decision Ledger === */}
        <div className="grid gap-6 lg:grid-cols-2">
          <section aria-labelledby="workspace-case-heading">
            <h2
              id="workspace-case-heading"
              data-testid="workspace-case-heading"
              className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
            >
              Case Workspace
            </h2>
            <Suspense fallback={<PanelSkeleton />}>
              <CaseWorkspace cases={cases} loading={false} lastUpdated={now} />
            </Suspense>
          </section>

          <section aria-labelledby="workspace-ledger-heading">
            <h2
              id="workspace-ledger-heading"
              data-testid="workspace-ledger-heading"
              className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
            >
              Decision Ledger
            </h2>
            <Suspense fallback={<PanelSkeleton />}>
              <DecisionLedger entries={ledgerEntries} loading={false} lastUpdated={now} />
            </Suspense>
          </section>
        </div>

        {/* === Workflow Progress === */}
        <section aria-labelledby="workspace-workflow-heading">
          <h2
            id="workspace-workflow-heading"
            data-testid="workspace-workflow-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Workflow Progress
          </h2>
          <Suspense fallback={<PanelSkeleton />}>
            <WorkflowProgress workflows={workflows} loading={false} lastUpdated={now} />
          </Suspense>
        </section>

        {/* === Investigation Timeline === */}
        <section aria-labelledby="workspace-timeline-heading">
          <h2
            id="workspace-timeline-heading"
            data-testid="workspace-timeline-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Investigation Timeline
          </h2>
          <Suspense fallback={<PanelSkeleton />}>
            <InvestigationTimeline events={allTimeline} loading={false} lastUpdated={now} />
          </Suspense>
        </section>

        {/* === Authority Health Map === */}
        <section aria-labelledby="workspace-health-heading">
          <h2
            id="workspace-health-heading"
            data-testid="workspace-health-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Authority Health Map
          </h2>
          <Suspense fallback={<PanelSkeleton />}>
            <AuthorityHealthMap snapshot={snapshot} loading={false} lastUpdated={now} />
          </Suspense>
        </section>

        {/* === Correlation Graph + Playbooks === */}
        <div className="grid gap-6 lg:grid-cols-2">
          <section>
            <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">
              Correlation Graph
            </h2>
            <Suspense fallback={<PanelSkeleton />}>
              <CorrelationGraph2
                nodes={graphNodes}
                edges={graphEdges}
                loading={false}
                lastUpdated={now}
              />
            </Suspense>
          </section>

          <section>
            <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">
              Playbooks
            </h2>
            <Suspense fallback={<PanelSkeleton />}>
              <PlaybookPanel playbooks={playbooks} loading={false} lastUpdated={now} />
            </Suspense>
          </section>
        </div>

        {/* === Delegation + Export === */}
        <div className="grid gap-6 lg:grid-cols-2">
          <section>
            <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">
              Delegation
            </h2>
            <Suspense fallback={<PanelSkeleton />}>
              <DelegationPanel actions={delegationActions} loading={false} />
            </Suspense>
          </section>

          <section>
            <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">
              Export
            </h2>
            <Suspense fallback={<PanelSkeleton />}>
              <ExportPanel workspaceState={workspaceSnapshot} loading={false} />
            </Suspense>
          </section>
        </div>
      </div>
    </main>
  );
}
