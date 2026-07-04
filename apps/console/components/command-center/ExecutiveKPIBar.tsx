'use client';

import Link from 'next/link';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';
import WidgetShell from './WidgetShell';
import type { ControlTowerSnapshotV1 } from '@/lib/coreApi';

// MCIM reference: MCIM-18.6-CMD-CENTER
const MCIM_ID = 'MCIM-18.6-CMD-CENTER';
const AUTHORITY = 'Control Tower Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard';

export interface KPIData {
  snapshot: ControlTowerSnapshotV1 | null;
  assessmentCount: number | null;
  criticalFindingsCount: number | null;
  openDecisionsCount: number | null;
}

interface KPITileProps {
  id: string;
  label: string;
  value: string | number | null;
  trend?: 'up' | 'down' | 'flat' | null;
  delta?: string | null;
  href: string;
  loading?: boolean;
}

function KPITile({ id, label, value, trend, delta, href, loading }: KPITileProps) {
  const displayValue = loading ? null : (value ?? null);

  return (
    <Link
      href={href}
      className="flex flex-col gap-1 rounded-lg border border-border bg-card p-3 hover:border-primary/40 transition-colors"
      data-testid={id}
      aria-label={`kpi-${id}`}
    >
      <span className="text-[10px] font-semibold uppercase tracking-wide text-muted">{label}</span>
      {loading ? (
        <span
          className="h-7 w-16 animate-pulse rounded bg-muted"
          aria-label="kpi-loading"
        />
      ) : (
        <span className="text-2xl font-bold text-foreground">
          {displayValue !== null ? displayValue : '—'}
        </span>
      )}
      <div className="flex items-center gap-1">
        {trend === 'up' && <TrendingUp className="h-3 w-3 text-success" aria-hidden="true" />}
        {trend === 'down' && <TrendingDown className="h-3 w-3 text-danger" aria-hidden="true" />}
        {trend === 'flat' && <Minus className="h-3 w-3 text-muted" aria-hidden="true" />}
        {delta && (
          <span className="text-[10px] text-muted">{delta}</span>
        )}
      </div>
    </Link>
  );
}

interface ExecutiveKPIBarProps {
  data: KPIData | null;
  loading?: boolean;
  lastUpdated?: string;
}

export default function ExecutiveKPIBar({ data, loading = false, lastUpdated }: ExecutiveKPIBarProps) {
  const snapshot = data?.snapshot ?? null;

  const agentCount = snapshot?.agents?.total ?? null;
  const quarantineCount = snapshot?.agents?.quarantine_count ?? null;
  const keyCount = snapshot?.key_lifecycle?.active_key_count ?? null;
  const chainStatus = snapshot?.chain_integrity?.status ?? null;
  const connectorCount = snapshot?.connectors?.enabled ?? null;

  const kpis: KPITileProps[] = [
    {
      id: 'governance-score',
      label: 'Governance Score',
      value: agentCount !== null ? agentCount : null,
      trend: null,
      delta: null,
      href: '/dashboard/readiness',
    },
    {
      id: 'trust-score',
      label: 'Trust Score',
      value: chainStatus ?? null,
      trend: chainStatus === 'pass' ? 'up' : chainStatus === 'fail' ? 'down' : 'flat',
      delta: chainStatus ?? null,
      href: '/dashboard/forensics',
    },
    {
      id: 'risk-score',
      label: 'Risk Score',
      value: connectorCount !== null ? connectorCount : null,
      trend: null,
      delta: connectorCount !== null ? `${connectorCount} connectors` : null,
      href: '/field-assessment',
    },
    {
      id: 'readiness-score',
      label: 'Readiness Score',
      value: keyCount !== null ? keyCount : null,
      trend: null,
      delta: keyCount !== null ? `${keyCount} keys` : null,
      href: '/dashboard/readiness',
    },
    {
      id: 'active-assessments',
      label: 'Active Assessments',
      value: data?.assessmentCount ?? null,
      trend: null,
      delta: null,
      href: '/field-assessment',
    },
    {
      id: 'critical-findings',
      label: 'Critical Findings',
      value: data?.criticalFindingsCount ?? null,
      trend:
        data?.criticalFindingsCount !== null && data?.criticalFindingsCount !== undefined
          ? data.criticalFindingsCount > 0
            ? 'down'
            : 'up'
          : null,
      delta: null,
      href: '/field-assessment',
    },
    {
      id: 'open-decisions',
      label: 'Open Decisions',
      value: data?.openDecisionsCount ?? null,
      trend: null,
      delta: null,
      href: '/dashboard/decisions',
    },
    {
      id: 'compliance-coverage',
      label: 'Compliance Coverage',
      value: null,
      trend: null,
      delta: 'from readiness API',
      href: '/dashboard/readiness',
    },
    {
      id: 'evidence-freshness',
      label: 'Evidence Freshness',
      value: null,
      trend: null,
      delta: null,
      href: '/field-assessment',
    },
    {
      id: 'verification-success',
      label: 'Verification Success',
      value: quarantineCount !== null ? quarantineCount : null,
      trend:
        quarantineCount !== null
          ? quarantineCount === 0
            ? 'up'
            : 'down'
          : null,
      delta: quarantineCount !== null ? `${quarantineCount} quarantined` : null,
      href: '/dashboard/control-tower',
    },
  ];

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Executive KPI Bar"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Executive KPIs"
      aria-label="executive-kpi-bar"
    >
      <div
        className="grid gap-2 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5"
        aria-label="kpi-tiles"
      >
        {kpis.map((kpi) => (
          <KPITile key={kpi.id} {...kpi} loading={loading} />
        ))}
      </div>
    </WidgetShell>
  );
}
