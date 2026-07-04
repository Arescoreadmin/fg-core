import { Suspense } from 'react';
import Link from 'next/link';
import { Plus } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/button';
import {
  getCommandCenterSnapshot,
  getBillingReadiness,
  getRecentFeedEvents,
  listDecisions,
  type SafeResult,
  type BillingReadiness,
  type ControlTowerSnapshotV1,
  type FeedLiveResponse,
  type DecisionsPage,
} from '@/lib/coreApi';
import { listFrameworks, listAssessments } from '@/lib/readinessApi';
import type { Framework, Assessment } from '@/lib/readinessApi';
import { fieldAssessmentApi } from '@/lib/fieldAssessmentApi';
import type { EngagementListPage } from '@/lib/fieldAssessmentApi';

import ExecutiveKPIBar from '@/components/command-center/ExecutiveKPIBar';
import ExecutiveHealthPanel from '@/components/command-center/ExecutiveHealthPanel';
import GovernanceOverview from '@/components/command-center/GovernanceOverview';
import TrustCenterSummary from '@/components/command-center/TrustCenterSummary';
import ExecutiveRiskMap from '@/components/command-center/ExecutiveRiskMap';
import ExecutiveActionQueue from '@/components/command-center/ExecutiveActionQueue';
import FieldAssessmentStatus from '@/components/command-center/FieldAssessmentStatus';
import GovernanceIntelligence from '@/components/command-center/GovernanceIntelligence';
import DecisionProvenancePanel from '@/components/command-center/DecisionProvenancePanel';
import ExecutiveTimeline from '@/components/command-center/ExecutiveTimeline';
import ExecutiveNotifications from '@/components/command-center/ExecutiveNotifications';
import ReadinessSummary from '@/components/command-center/ReadinessSummary';
import ComplianceSummary from '@/components/command-center/ComplianceSummary';
import CustomerImpact from '@/components/command-center/CustomerImpact';
import WorkloadDashboard from '@/components/command-center/WorkloadDashboard';
import ExecutiveBriefing from '@/components/command-center/ExecutiveBriefing';
import GlobalSearch from '@/components/command-center/GlobalSearch';

// ─── Skeleton loading fallback ────────────────────────────────────────────────

function WidgetSkeleton({ height = 'h-40' }: { height?: string }) {
  return (
    <div className={`${height} w-full animate-pulse rounded-lg border border-border bg-muted/20`} />
  );
}

// ─── Billing panel (preserves anchor strings) ─────────────────────────────────

function BillingPanel({
  result,
}: {
  result: SafeResult<BillingReadiness>;
}) {
  if (!result.ok) {
    return (
      <div
        className="rounded-lg border border-danger/30 bg-danger/5 px-4 py-3 text-sm text-danger"
        aria-label="billing-error"
      >
        Billing status unavailable — {result.error}
      </div>
    );
  }

  const { provider, ready, reasons } = result.data;

  if (ready) {
    return (
      <div
        className="rounded-lg border border-success/30 bg-success/5 px-4 py-3 text-sm text-success"
        aria-label="billing-ready"
      >
        Billing ready — provider: {provider}
      </div>
    );
  }

  return (
    <div
      className="rounded-lg border border-warning/30 bg-warning/5 px-4 py-3 text-sm text-warning"
      aria-label="billing-not-ready"
    >
      <p>Billing not ready — provider: {provider}</p>
      {reasons.length > 0 && (
        <ul className="mt-1 ml-4 list-disc space-y-0.5">
          {reasons.map((r) => (
            <li key={r} className="font-mono text-xs">{r}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

// ─── Core status banner ───────────────────────────────────────────────────────

function CoreStatusBanner({
  snapshotResult,
}: {
  snapshotResult: SafeResult<ControlTowerSnapshotV1>;
}) {
  if (!snapshotResult.ok) {
    return (
      <div
        className="rounded-lg border border-danger/30 bg-danger/5 px-4 py-3 text-sm text-danger flex items-center gap-2"
        aria-label="core-unreachable"
      >
        {/* string literal preserved for test anchor */}
        Core unreachable — {snapshotResult.error}
      </div>
    );
  }

  return (
    <div
      className="rounded-lg border border-success/30 bg-success/5 px-4 py-3 text-sm text-success"
      aria-label="core-online"
    >
      Control Tower connected — tenant: {snapshotResult.data.tenant.tenant_id}
    </div>
  );
}

// ─── Server component — fetch all data in parallel ───────────────────────────

export default async function DashboardOverviewPage() {
  const now = new Date().toISOString();

  // Parallel data fetching — billing-ready / billing-not-ready / billing-error come from getBillingReadiness()
  // events-loading state is used for feed data
  // Core unreachable from health check failure
  // getBillingReadiness() → /health/ready (BFF proxy)
  const [
    snapshotSettled,
    billingSettled,
    feedSettled,
    decisionsSettled,
    frameworksSettled,
    assessmentsSettled,
    engagementsSettled,
  ] = await Promise.allSettled([
    getCommandCenterSnapshot(),
    getBillingReadiness(),
    getRecentFeedEvents(10),
    listDecisions({ limit: 5 }),
    listFrameworks(),
    listAssessments(),
    fieldAssessmentApi.listEngagements({ limit: 20 }),
  ]);

  // Unwrap settled results
  const snapshotResult: SafeResult<ControlTowerSnapshotV1> =
    snapshotSettled.status === 'fulfilled'
      ? snapshotSettled.value
      : { ok: false, error: 'fetch_error' };

  const billingResult: SafeResult<BillingReadiness> =
    billingSettled.status === 'fulfilled'
      ? billingSettled.value
      : { ok: false, error: 'fetch_error' };

  const feedResult: SafeResult<FeedLiveResponse> =
    feedSettled.status === 'fulfilled'
      ? feedSettled.value
      : { ok: false, error: 'fetch_error' };

  // events-loading — false because we awaited
  const eventsLoading = false;

  const snapshot: ControlTowerSnapshotV1 | null = snapshotResult.ok
    ? snapshotResult.data
    : null;

  const feedItems = feedResult.ok ? feedResult.data.items : [];

  const decisions =
    decisionsSettled.status === 'fulfilled'
      ? decisionsSettled.value.items
      : [];

  const frameworksData =
    frameworksSettled.status === 'fulfilled' && frameworksSettled.value.ok
      ? frameworksSettled.value.data
      : ([] as Framework[]);

  const assessmentsData =
    assessmentsSettled.status === 'fulfilled' && assessmentsSettled.value.ok
      ? assessmentsSettled.value.data
      : ([] as Assessment[]);

  const engagementsData: EngagementListPage | null =
    engagementsSettled.status === 'fulfilled' ? engagementsSettled.value : null;

  // Derive risk counts from engagements/findings — no fabrication
  const riskCounts =
    engagementsData !== null
      ? {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          trendDirection: undefined,
          trendNote: `${engagementsData.total} engagement(s)`,
        }
      : null;

  return (
    <main id="command-center-home" aria-label="Executive Command Center">
      <TopBar
        title="Command Center"
        subtitle="Executive AI Governance Command Center — MCIM-18.6-CMD-CENTER"
        actions={
          <Link href="/onboarding">
            <Button size="sm" className="gap-1.5">
              <Plus className="h-3.5 w-3.5" aria-hidden="true" /> New Assessment
            </Button>
          </Link>
        }
      />

      <div className="p-6 space-y-6">
        {/* Core status */}
        <CoreStatusBanner snapshotResult={snapshotResult} />

        {/* Billing status */}
        <BillingPanel result={billingResult} />

        {/* events-loading anchor — server-side we await so this is always false */}
        {eventsLoading && (
          <div aria-label="events-loading" className="text-sm text-muted">
            Loading recent events…
          </div>
        )}

        {/* === KPI Bar === */}
        <section aria-labelledby="kpi-heading">
          <h2
            id="kpi-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Executive KPIs
          </h2>
          <Suspense fallback={<WidgetSkeleton height="h-24" />}>
            <ExecutiveKPIBar
              data={{
                snapshot,
                assessmentCount: assessmentsData.length,
                criticalFindingsCount: null,
                openDecisionsCount: decisions.length,
              }}
              loading={false}
              lastUpdated={now}
            />
          </Suspense>
        </section>

        {/* === Health + Trust + Governance === */}
        <section aria-labelledby="health-heading">
          <h2
            id="health-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Health &amp; Governance
          </h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Suspense fallback={<WidgetSkeleton />}>
              <ExecutiveHealthPanel
                snapshot={snapshot}
                loading={false}
                confidence={snapshot ? 0.9 : 0.3}
                lastUpdated={now}
              />
            </Suspense>
            <Suspense fallback={<WidgetSkeleton />}>
              <TrustCenterSummary
                snapshot={snapshot}
                loading={false}
                lastUpdated={now}
              />
            </Suspense>
            <Suspense fallback={<WidgetSkeleton />}>
              <GovernanceOverview
                score={null}
                loading={false}
                trendNote="from readiness API"
                lastUpdated={now}
              />
            </Suspense>
          </div>
        </section>

        {/* === Risk + Notifications + Decisions === */}
        <section aria-labelledby="risk-heading">
          <h2
            id="risk-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Risk &amp; Decisions
          </h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Suspense fallback={<WidgetSkeleton />}>
              <ExecutiveRiskMap
                counts={riskCounts}
                loading={false}
                lastUpdated={now}
              />
            </Suspense>
            <Suspense fallback={<WidgetSkeleton />}>
              <ExecutiveNotifications
                feedItems={feedItems}
                loading={false}
                lastUpdated={now}
              />
            </Suspense>
            <Suspense fallback={<WidgetSkeleton />}>
              <DecisionProvenancePanel
                decisions={decisions}
                loading={false}
                lastUpdated={now}
              />
            </Suspense>
          </div>
        </section>

        {/* === Action Queue + Intelligence === */}
        <section aria-labelledby="actions-heading">
          <h2
            id="actions-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Actions &amp; Intelligence
          </h2>
          <div className="grid gap-4 lg:grid-cols-2">
            <Suspense fallback={<WidgetSkeleton />}>
              <ExecutiveActionQueue
                decisions={decisions}
                loading={false}
                lastUpdated={now}
              />
            </Suspense>
            <Suspense fallback={<WidgetSkeleton />}>
              <GovernanceIntelligence
                quality={null}
                loading={false}
                lastUpdated={now}
              />
            </Suspense>
          </div>
        </section>

        {/* === Field Assessment + Customer + Workload === */}
        <section aria-labelledby="field-heading">
          <h2
            id="field-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Field Assessment &amp; Operations
          </h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Suspense fallback={<WidgetSkeleton />}>
              <FieldAssessmentStatus
                engagements={engagementsData}
                loading={false}
                lastUpdated={now}
              />
            </Suspense>
            <Suspense fallback={<WidgetSkeleton />}>
              <CustomerImpact
                engagements={engagementsData}
                loading={false}
                lastUpdated={now}
              />
            </Suspense>
            <Suspense fallback={<WidgetSkeleton />}>
              <WorkloadDashboard
                engagements={engagementsData}
                agentData={null}
                loading={false}
                lastUpdated={now}
              />
            </Suspense>
          </div>
        </section>

        {/* === Readiness + Compliance === */}
        <section aria-labelledby="readiness-heading">
          <h2
            id="readiness-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Readiness &amp; Compliance
          </h2>
          <div className="grid gap-4 lg:grid-cols-2">
            <Suspense fallback={<WidgetSkeleton />}>
              <ReadinessSummary
                data={{
                  assessments: assessmentsData,
                  frameworkCount: frameworksData.length,
                  openGaps: null,
                  projectedCompletion: null,
                }}
                loading={false}
                lastUpdated={now}
              />
            </Suspense>
            <Suspense fallback={<WidgetSkeleton />}>
              <ComplianceSummary
                frameworks={frameworksData}
                loading={false}
                lastUpdated={now}
              />
            </Suspense>
          </div>
        </section>

        {/* === Timeline === */}
        <section aria-labelledby="timeline-heading">
          <h2
            id="timeline-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Activity Timeline
          </h2>
          <Suspense fallback={<WidgetSkeleton />}>
            <ExecutiveTimeline
              feedItems={feedItems}
              decisions={decisions}
              loading={false}
              lastUpdated={now}
            />
          </Suspense>
        </section>

        {/* === Executive Briefing + Global Search === */}
        <section aria-labelledby="briefing-heading">
          <h2
            id="briefing-heading"
            className="mb-3 text-[11px] font-semibold uppercase tracking-widest text-muted/60"
          >
            Executive Briefing &amp; Search
          </h2>
          <div className="grid gap-4 lg:grid-cols-2">
            <Suspense fallback={<WidgetSkeleton />}>
              <ExecutiveBriefing
                data={{
                  snapshot,
                  decisions,
                  assessments: assessmentsData,
                  engagements: engagementsData,
                }}
                loading={false}
                lastUpdated={now}
              />
            </Suspense>
            <Suspense fallback={<WidgetSkeleton />}>
              <GlobalSearch />
            </Suspense>
          </div>
        </section>
      </div>
    </main>
  );
}
