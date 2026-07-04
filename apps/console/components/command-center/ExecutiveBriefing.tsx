'use client';

import { useState } from 'react';
import { AlertTriangle, Download, HelpCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import WidgetShell from './WidgetShell';
import type { ControlTowerSnapshotV1, DecisionOut } from '@/lib/coreApi';
import type { Assessment } from '@/lib/readinessApi';
import type { EngagementListPage } from '@/lib/fieldAssessmentApi';

// MCIM reference: MCIM-18.6-CMD-CENTER
const MCIM_ID = 'MCIM-18.6-CMD-CENTER';
const AUTHORITY = 'Executive Command Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard';

export interface BriefingData {
  snapshot: ControlTowerSnapshotV1 | null;
  decisions: DecisionOut[];
  assessments: Assessment[];
  engagements: EngagementListPage | null;
}

interface BriefingSection {
  id: string;
  label: string;
  content: string;
  confidence: number;
}

function isDataSufficient(data: BriefingData | null): boolean {
  if (!data) return false;
  if (!data.snapshot) return false;
  if (data.decisions.length === 0 && data.assessments.length === 0) return false;
  return true;
}

function buildBriefing(data: BriefingData): BriefingSection[] {
  if (!isDataSufficient(data)) return [];

  const snap = data.snapshot!;
  const chainOk = snap.chain_integrity.status === 'pass';
  const agentOk = snap.agents.quarantine_count === 0;
  const connectorOk = snap.connectors.errors.length === 0;
  const overallOk = chainOk && agentOk && connectorOk;

  const openDecisions = data.decisions.filter(
    (d) => d.threat_level === 'critical' || d.threat_level === 'high',
  );

  const criticalDecisions = data.decisions.filter(
    (d) => d.threat_level === 'critical',
  );

  const activeAssessments = data.assessments.filter(
    (a) => a.assessment_status === 'collecting' || a.assessment_status === 'partially_evaluated',
  );

  const finalizedCount = data.assessments.filter(
    (a) => a.assessment_status === 'finalized',
  ).length;

  const sections: BriefingSection[] = [
    {
      id: 'briefing-posture',
      label: 'Current Posture',
      content: overallOk
        ? `Platform operating normally. Chain integrity: ${snap.chain_integrity.status}. ${snap.agents.total} agent(s) active, ${snap.connectors.enabled} connector(s) enabled.`
        : `Attention required. Chain: ${snap.chain_integrity.status}, quarantined agents: ${snap.agents.quarantine_count}, connector errors: ${snap.connectors.errors.length}.`,
      confidence: 0.95,
    },
    {
      id: 'briefing-improved',
      label: 'Improved',
      content:
        finalizedCount > 0
          ? `${finalizedCount} assessment(s) finalized. Evidence chain active.`
          : 'No finalized assessments in current window.',
      confidence: 0.8,
    },
    {
      id: 'briefing-regressed',
      label: 'Regressed',
      content:
        !chainOk || !agentOk
          ? `Chain integrity: ${snap.chain_integrity.status}. Quarantined: ${snap.agents.quarantine_count}.`
          : 'No regressions detected in monitored indicators.',
      confidence: 0.85,
    },
    {
      id: 'briefing-decisions',
      label: 'Critical Decisions',
      content:
        criticalDecisions.length > 0
          ? `${criticalDecisions.length} critical decision(s) require review: ${criticalDecisions
              .slice(0, 2)
              .map((d) => d.explain_summary ?? d.event_type ?? d.id.slice(0, 8))
              .join('; ')}.`
          : 'No critical decisions pending.',
      confidence: 0.9,
    },
    {
      id: 'briefing-risks',
      label: 'Top Risks',
      content:
        openDecisions.length > 0
          ? `${openDecisions.length} high/critical decision(s) open. ${snap.connectors.errors.length > 0 ? `${snap.connectors.errors.length} connector error(s).` : ''}`
          : 'No elevated risks identified from available data.',
      confidence: 0.85,
    },
    {
      id: 'briefing-opportunities',
      label: 'Top Opportunities',
      content:
        activeAssessments.length > 0
          ? `${activeAssessments.length} active assessment(s) in progress — completing these will improve posture.`
          : 'Initiate new assessments to expand governance coverage.',
      confidence: 0.7,
    },
    {
      id: 'briefing-deadlines',
      label: 'Upcoming Deadlines',
      content: 'No deadlines sourced from available API data — check field assessments.',
      confidence: 0.5,
    },
    {
      id: 'briefing-actions',
      label: 'Recommended Actions',
      content: [
        !chainOk && 'Review chain integrity failures in Forensics.',
        !agentOk && `Unquarantine or review ${snap.agents.quarantine_count} agent(s).`,
        !connectorOk && `Resolve ${snap.connectors.errors.length} connector error(s).`,
        criticalDecisions.length > 0 && `Act on ${criticalDecisions.length} critical decision(s).`,
      ]
        .filter(Boolean)
        .join(' ')
        .trim() || 'Platform indicators are within normal operating range.',
      confidence: 0.9,
    },
  ];

  return sections;
}

interface ExecutiveBriefingProps {
  data: BriefingData | null;
  loading?: boolean;
  lastUpdated?: string;
}

export default function ExecutiveBriefing({
  data,
  loading = false,
  lastUpdated,
}: ExecutiveBriefingProps) {
  const [downloadDone, setDownloadDone] = useState(false);

  const sufficient = data !== null && isDataSufficient(data);
  const sections = sufficient && data !== null ? buildBriefing(data) : [];

  function handleExport() {
    if (!sections.length) return;
    const text = sections
      .map((s) => `## ${s.label}\n${s.content}\nConfidence: ${Math.round(s.confidence * 100)}%`)
      .join('\n\n');

    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `executive-briefing-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    setDownloadDone(true);
    setTimeout(() => setDownloadDone(false), 3000);
  }

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Executive Briefing"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Executive Briefing"
    >
      <div
        aria-label="executive-briefing"
        data-testid="executive-briefing-authority"
      >
        {loading ? (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-12 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : !sufficient ? (
          <div
            className="py-4 text-center text-sm text-muted"
            data-testid="briefing-low-confidence"
            aria-label="briefing-low-confidence"
          >
            <AlertTriangle className="mx-auto mb-2 h-6 w-6 text-muted/40" aria-hidden="true" />
            <p>Insufficient data for executive briefing.</p>
            <p className="mt-1 text-xs">
              Connect control tower snapshot and populate decisions and assessments to generate this briefing.
            </p>
            <p className="mt-2 text-[10px]">Authority: {AUTHORITY}</p>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Badge variant="secondary" className="text-[10px]" data-testid="briefing-confidence" aria-label="briefing-confidence">
                Evidence-backed
              </Badge>
              <Button
                variant="outline"
                size="sm"
                className="h-6 gap-1 text-[10px]"
                onClick={handleExport}
                data-testid="briefing-export"
                aria-label="briefing-export"
              >
                <Download className="h-3 w-3" aria-hidden="true" />
                {downloadDone ? 'Downloaded' : 'Export'}
              </Button>
            </div>

            {sections.map((section) => (
              <div
                key={section.id}
                data-testid={section.id}
                aria-label={section.id}
                className="rounded-md border border-border p-3"
              >
                <div className="flex items-center justify-between mb-1">
                  <h3 className="text-xs font-semibold text-foreground">{section.label}</h3>
                  <span className="text-[9px] text-muted">
                    {Math.round(section.confidence * 100)}% confidence
                  </span>
                </div>
                <p className="text-xs text-muted">{section.content}</p>
              </div>
            ))}

            <p className="text-[10px] text-muted/60">
              Authority: {AUTHORITY} · {MCIM_ID}
            </p>
          </div>
        )}
      </div>
    </WidgetShell>
  );
}
