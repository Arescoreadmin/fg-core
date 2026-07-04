// MCIM reference: MCIM-18.6-TRUST-CENTER
// Authority: Trust Center Authority
// sourceOfTruth: /api/core/control-tower/snapshot
// drillDown: /trust-center

import { Suspense } from 'react';
import { TopBar } from '@/components/layout/TopBar';
import { getCommandCenterSnapshot, type ControlTowerSnapshotV1 } from '@/lib/coreApi';

import TrustScorecard, { type TrustScore } from '@/components/trust-center/TrustScorecard';
import ContinuousAssurancePanel, { type AssuranceControl } from '@/components/trust-center/ContinuousAssurancePanel';
import TrustEvidenceGraph, { type EvidenceNode } from '@/components/trust-center/TrustEvidenceGraph';
import DecisionProvenanceExplorer, { type DecisionProvenance } from '@/components/trust-center/DecisionProvenanceExplorer';
import GovernanceReplayCenter, { type ReplayEntry } from '@/components/trust-center/GovernanceReplayCenter';
import ChangeIntelligence, { type ChangeEvent } from '@/components/trust-center/ChangeIntelligence';
import TrustCertificates, { type TrustCertificate } from '@/components/trust-center/TrustCertificates';
import AuditReadinessWorkspace, { type AuditDomain } from '@/components/trust-center/AuditReadinessWorkspace';
import CustomerTrustView, { type CustomerTrustSummary } from '@/components/trust-center/CustomerTrustView';
import TrustTimeline, { type TrustTimelineEvent } from '@/components/trust-center/TrustTimeline';
import OperationalMemory, { type MemoryEntry } from '@/components/trust-center/OperationalMemory';
import DecisionEffectiveness, { type DecisionOutcome } from '@/components/trust-center/DecisionEffectiveness';
import BottleneckAnalysis, { type BottleneckEntry } from '@/components/trust-center/BottleneckAnalysis';
import TrustBenchmarks, { type TrustBenchmark } from '@/components/trust-center/TrustBenchmarks';
import CaseRelationships, { type CaseRelationship } from '@/components/trust-center/CaseRelationships';
import WorkspaceIntelligence, { type IntelligenceItem } from '@/components/trust-center/WorkspaceIntelligence';
import SLAForecasting, { type SLAForecast } from '@/components/trust-center/SLAForecasting';
import CommandCenterIntegration from '@/components/trust-center/CommandCenterIntegration';

// ─── Skeleton fallback ────────────────────────────────────────────────────────

function PanelSkeleton({ height = 'h-48' }: { height?: string }) {
  return (
    <div
      className={`${height} w-full animate-pulse rounded-lg border border-border bg-muted/20`}
      aria-hidden="true"
    />
  );
}

// ─── Server component — trust center overview ─────────────────────────────────

export default async function TrustCenterPage() {
  const now = new Date().toISOString();
  const snapshotSettled = await Promise.allSettled([getCommandCenterSnapshot()]);
  const snapshot: ControlTowerSnapshotV1 | null = snapshotSettled[0].status === 'fulfilled' && snapshotSettled[0].value.ok ? snapshotSettled[0].value.data : null;

  // Pass empty arrays / null for all data — future API endpoints will supply real data
  const trustScores: TrustScore[] = [];
  const controls: AssuranceControl[] = [];
  const evidenceNodes: EvidenceNode[] = [];
  const provenances: DecisionProvenance[] = [];
  const replayEntries: ReplayEntry[] = [];
  const changeEvents: ChangeEvent[] = [];
  const certificates: TrustCertificate[] = [];
  const auditDomains: AuditDomain[] = [];
  const customers: CustomerTrustSummary[] = [];
  const trustEvents: TrustTimelineEvent[] = [];
  const memoryEntries: MemoryEntry[] = [];
  const decisionOutcomes: DecisionOutcome[] = [];
  const bottleneckEntries: BottleneckEntry[] = [];
  const benchmarks: TrustBenchmark[] = [];
  const caseRelationships: CaseRelationship[] = [];
  const intelligenceItems: IntelligenceItem[] = [];
  const slaForecasts: SLAForecast[] = [];

  // snapshot is fetched but data is reserved for future API integration
  void snapshot;

  return (
    <main id="trust-center" aria-label="trust-center" data-testid="trust-center-page">
      <TopBar
        title="Enterprise Trust Center"
        subtitle="Enterprise Trust Center — MCIM-18.6-TRUST-CENTER"
      />
      <div className="p-6 space-y-6">
        <div data-testid="trust-center-heading">
          <h1 className="text-lg font-bold text-foreground">Enterprise Trust Center</h1>
          <p className="text-sm text-muted mt-0.5">
            Unified trust intelligence — scorecard, provenance, assurance, audit readiness, and governance replay.
          </p>
        </div>

        {/* Trust Scorecard */}
        <section aria-labelledby="tc-scorecard-heading">
          <h2 id="tc-scorecard-heading" data-testid="tc-scorecard-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Trust Scorecard</h2>
          <Suspense fallback={<PanelSkeleton />}><TrustScorecard scores={trustScores} loading={false} lastUpdated={now} /></Suspense>
        </section>

        {/* Continuous Assurance + Trust Evidence Graph side by side */}
        <div className="grid gap-6 lg:grid-cols-2">
          <section aria-labelledby="tc-assurance-heading">
            <h2 id="tc-assurance-heading" data-testid="tc-assurance-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Continuous Assurance</h2>
            <Suspense fallback={<PanelSkeleton />}><ContinuousAssurancePanel controls={controls} loading={false} lastUpdated={now} /></Suspense>
          </section>
          <section aria-labelledby="tc-evidence-heading">
            <h2 id="tc-evidence-heading" data-testid="tc-evidence-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Trust Evidence Graph</h2>
            <Suspense fallback={<PanelSkeleton />}><TrustEvidenceGraph nodes={evidenceNodes} loading={false} lastUpdated={now} /></Suspense>
          </section>
        </div>

        {/* Decision Provenance Explorer */}
        <section aria-labelledby="tc-provenance-heading">
          <h2 id="tc-provenance-heading" data-testid="tc-provenance-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Decision Provenance</h2>
          <Suspense fallback={<PanelSkeleton />}><DecisionProvenanceExplorer provenances={provenances} loading={false} lastUpdated={now} /></Suspense>
        </section>

        {/* Governance Replay + Change Intelligence */}
        <div className="grid gap-6 lg:grid-cols-2">
          <section aria-labelledby="tc-replay-heading">
            <h2 id="tc-replay-heading" data-testid="tc-replay-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Governance Replay</h2>
            <Suspense fallback={<PanelSkeleton />}><GovernanceReplayCenter entries={replayEntries} loading={false} lastUpdated={now} /></Suspense>
          </section>
          <section aria-labelledby="tc-change-intel-heading">
            <h2 id="tc-change-intel-heading" data-testid="tc-change-intel-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Change Intelligence</h2>
            <Suspense fallback={<PanelSkeleton />}><ChangeIntelligence events={changeEvents} loading={false} lastUpdated={now} /></Suspense>
          </section>
        </div>

        {/* Trust Certificates */}
        <section aria-labelledby="tc-certs-heading">
          <h2 id="tc-certs-heading" data-testid="tc-certs-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Trust Certificates</h2>
          <Suspense fallback={<PanelSkeleton />}><TrustCertificates certificates={certificates} loading={false} lastUpdated={now} /></Suspense>
        </section>

        {/* Audit Readiness + Customer Trust View */}
        <div className="grid gap-6 lg:grid-cols-2">
          <section aria-labelledby="tc-audit-ready-heading">
            <h2 id="tc-audit-ready-heading" data-testid="tc-audit-ready-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Audit Readiness</h2>
            <Suspense fallback={<PanelSkeleton />}><AuditReadinessWorkspace domains={auditDomains} loading={false} lastUpdated={now} /></Suspense>
          </section>
          <section aria-labelledby="tc-customer-trust-heading">
            <h2 id="tc-customer-trust-heading" data-testid="tc-customer-trust-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Customer Trust View</h2>
            <Suspense fallback={<PanelSkeleton />}><CustomerTrustView customers={customers} loading={false} lastUpdated={now} /></Suspense>
          </section>
        </div>

        {/* Trust Timeline */}
        <section aria-labelledby="tc-timeline-heading">
          <h2 id="tc-timeline-heading" data-testid="tc-timeline-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Trust Timeline</h2>
          <Suspense fallback={<PanelSkeleton />}><TrustTimeline events={trustEvents} loading={false} lastUpdated={now} /></Suspense>
        </section>

        {/* Operational Memory */}
        <section aria-labelledby="tc-memory-heading">
          <h2 id="tc-memory-heading" data-testid="tc-memory-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Operational Memory</h2>
          <Suspense fallback={<PanelSkeleton />}><OperationalMemory entries={memoryEntries} activeWindow="30d" loading={false} lastUpdated={now} /></Suspense>
        </section>

        {/* Decision Effectiveness + Bottleneck Analysis */}
        <div className="grid gap-6 lg:grid-cols-2">
          <section aria-labelledby="tc-effectiveness-heading">
            <h2 id="tc-effectiveness-heading" data-testid="tc-effectiveness-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Decision Effectiveness</h2>
            <Suspense fallback={<PanelSkeleton />}><DecisionEffectiveness outcomes={decisionOutcomes} activeWindow="30d" loading={false} lastUpdated={now} /></Suspense>
          </section>
          <section aria-labelledby="tc-bottleneck-heading">
            <h2 id="tc-bottleneck-heading" data-testid="tc-bottleneck-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Bottleneck Analysis</h2>
            <Suspense fallback={<PanelSkeleton />}><BottleneckAnalysis entries={bottleneckEntries} loading={false} lastUpdated={now} /></Suspense>
          </section>
        </div>

        {/* Trust Benchmarks + Case Relationships */}
        <div className="grid gap-6 lg:grid-cols-2">
          <section aria-labelledby="tc-benchmarks-heading">
            <h2 id="tc-benchmarks-heading" data-testid="tc-benchmarks-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Trust Benchmarks</h2>
            <Suspense fallback={<PanelSkeleton />}><TrustBenchmarks benchmarks={benchmarks} loading={false} lastUpdated={now} /></Suspense>
          </section>
          <section aria-labelledby="tc-case-rel-heading">
            <h2 id="tc-case-rel-heading" data-testid="tc-case-rel-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Case Relationships</h2>
            <Suspense fallback={<PanelSkeleton />}><CaseRelationships relationships={caseRelationships} loading={false} lastUpdated={now} /></Suspense>
          </section>
        </div>

        {/* Workspace Intelligence + SLA Forecasting */}
        <div className="grid gap-6 lg:grid-cols-2">
          <section aria-labelledby="tc-intel-heading">
            <h2 id="tc-intel-heading" data-testid="tc-intel-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Workspace Intelligence</h2>
            <Suspense fallback={<PanelSkeleton />}><WorkspaceIntelligence items={intelligenceItems} loading={false} lastUpdated={now} /></Suspense>
          </section>
          <section aria-labelledby="tc-sla-heading">
            <h2 id="tc-sla-heading" data-testid="tc-sla-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">SLA Forecasting</h2>
            <Suspense fallback={<PanelSkeleton />}><SLAForecasting forecasts={slaForecasts} hasHistoricalData={false} loading={false} lastUpdated={now} /></Suspense>
          </section>
        </div>

        {/* Command Center Integration */}
        <section aria-labelledby="tc-cmd-center-heading">
          <h2 id="tc-cmd-center-heading" data-testid="tc-cmd-center-heading" className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60">Command Center Integration</h2>
          <Suspense fallback={<PanelSkeleton />}><CommandCenterIntegration loading={false} /></Suspense>
        </section>
      </div>
    </main>
  );
}
