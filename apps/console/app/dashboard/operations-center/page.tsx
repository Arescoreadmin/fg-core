'use client';

import { useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { ConsoleTopNav } from '@/components/ConsoleTopNav';
import ExecutiveOperationsQueue from '@/components/operations-center/ExecutiveOperationsQueue';
import GovernanceAutomationQueue from '@/components/operations-center/GovernanceAutomationQueue';
import DecisionExecutionPipeline from '@/components/operations-center/DecisionExecutionPipeline';
import OperationalRiskHeatmap from '@/components/operations-center/OperationalRiskHeatmap';
import EvidenceFreshnessMonitor from '@/components/operations-center/EvidenceFreshnessMonitor';
import PolicyConflictCenter from '@/components/operations-center/PolicyConflictCenter';
import GovernanceSLAMonitor from '@/components/operations-center/GovernanceSLAMonitor';
import AutomationSafetyCenter from '@/components/operations-center/AutomationSafetyCenter';
import CrossAuthorityTimeline from '@/components/operations-center/CrossAuthorityTimeline';
import ExecutiveOperationalBriefing from '@/components/operations-center/ExecutiveOperationalBriefing';

export default function OperationsCenterPage() {
  const [refreshKey, setRefreshKey] = useState(0);

  function refresh() {
    setRefreshKey((k) => k + 1);
  }

  return (
    <>
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-[100] focus:rounded focus:bg-background focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-foreground focus:outline focus:outline-2 focus:outline-primary"
      >
        Skip to content
      </a>

      <ConsoleTopNav
        crumbs={[
          { label: 'Dashboard', href: '/dashboard' },
          { label: 'Operations Center' },
        ]}
      />

      <div
        id="main-content"
        tabIndex={-1}
        className="focus-visible:outline-none"
        data-mcim="OPERATIONS-CENTER"
        data-authority="FrostGate Platform"
      >
        <div className="flex items-center justify-between border-b border-border px-6 py-4">
          <div>
            <h1 className="text-base font-semibold text-foreground">Operations Center</h1>
            <p className="mt-0.5 text-xs text-muted">
              Autonomous Governance Operations Center — MCIM: OPERATIONS-CENTER
            </p>
          </div>
          <button
            onClick={refresh}
            className="flex items-center gap-1.5 rounded border border-border px-3 py-1.5 text-xs text-muted hover:text-foreground"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>

        <div className="p-6 grid grid-cols-1 gap-4 md:grid-cols-2">
          <div data-section="executive-operations-queue" className="md:col-span-2">
            <ExecutiveOperationsQueue key={`exec-ops-queue-${refreshKey}`} />
          </div>

          <div data-section="governance-automation-queue">
            <GovernanceAutomationQueue key={`gov-auto-queue-${refreshKey}`} />
          </div>

          <div data-section="decision-execution-pipeline" className="md:col-span-2">
            <DecisionExecutionPipeline key={`decision-pipeline-${refreshKey}`} />
          </div>

          <div data-section="operational-risk-heatmap">
            <OperationalRiskHeatmap key={`risk-heatmap-${refreshKey}`} />
          </div>

          <div data-section="evidence-freshness-monitor">
            <EvidenceFreshnessMonitor key={`evidence-freshness-${refreshKey}`} />
          </div>

          <div data-section="policy-conflict-center">
            <PolicyConflictCenter key={`policy-conflict-${refreshKey}`} />
          </div>

          <div data-section="governance-sla-monitor">
            <GovernanceSLAMonitor key={`gov-sla-${refreshKey}`} />
          </div>

          <div data-section="automation-safety-center">
            <AutomationSafetyCenter key={`auto-safety-${refreshKey}`} />
          </div>

          <div data-section="cross-authority-timeline" className="md:col-span-2">
            <CrossAuthorityTimeline key={`cross-auth-timeline-${refreshKey}`} />
          </div>

          <div data-section="executive-operational-briefing" className="md:col-span-2">
            <ExecutiveOperationalBriefing key={`exec-op-briefing-${refreshKey}`} />
          </div>
        </div>
      </div>
    </>
  );
}
