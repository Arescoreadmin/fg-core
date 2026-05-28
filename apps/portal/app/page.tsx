'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  portalApi,
  type AttestationHealthSummary,
  type EngagementSummary,
} from '@/lib/portalApi';
import {
  getStoredEngagementId,
  setStoredEngagementId,
} from '@/lib/engagementStore';

const ACCENT_BORDER = {
  green: 'hover:border-green-500/40',
  amber: 'hover:border-amber-500/40',
  red: 'hover:border-red-500/40',
  default: 'hover:border-primary/40',
};
const ACCENT_VALUE = {
  green: 'text-green-300',
  amber: 'text-amber-200',
  red: 'text-red-300',
  default: 'text-foreground',
};

function DashboardCard({
  title,
  value,
  subtitle,
  href,
  accent = 'default',
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  href: string;
  accent?: 'green' | 'amber' | 'red' | 'default';
}) {
  return (
    <Link
      href={href}
      className={`rounded border border-border bg-surface-2 p-4 block space-y-1 transition-colors ${ACCENT_BORDER[accent]}`}
    >
      <p className="text-xs font-semibold text-muted uppercase tracking-wider">{title}</p>
      <p className={`text-2xl font-bold ${ACCENT_VALUE[accent]}`}>{value}</p>
      {subtitle && <p className="text-xs text-muted">{subtitle}</p>}
    </Link>
  );
}

const ENG_PAGE_LINKS = [
  { key: 'findings', label: 'Findings', path: '/findings' },
  { key: 'reports', label: 'Reports', path: '/reports' },
  { key: 'coverage', label: 'Coverage', path: '/coverage' },
  { key: 'remediation', label: 'Remediation', path: '/remediation' },
] as const;

function EngagementCard({
  eng,
  active,
  onSelect,
}: {
  eng: EngagementSummary;
  active: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <div
      className={`rounded border p-4 space-y-3 transition-colors ${
        active ? 'border-primary/40 bg-surface-2' : 'border-border bg-surface-2'
      }`}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="text-sm font-semibold text-foreground">{eng.client_name}</p>
          <p className="text-xs text-muted capitalize mt-0.5">
            {eng.assessment_type.replace(/_/g, ' ')} &middot;{' '}
            {eng.status.replace(/_/g, ' ')}
          </p>
        </div>
        {active && (
          <span className="text-[11px] px-1.5 py-0.5 rounded bg-primary/10 border border-primary/20 text-primary font-medium shrink-0">
            Active
          </span>
        )}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {ENG_PAGE_LINKS.map(({ key, label, path }) => (
          <Link
            key={key}
            href={`${path}?e=${eng.id}`}
            onClick={() => onSelect(eng.id)}
            className="rounded border border-border bg-surface-3 px-2.5 py-1 text-xs text-foreground hover:bg-surface-2 hover:border-primary/30 transition-colors"
          >
            {label}
          </Link>
        ))}
      </div>
    </div>
  );
}

export default function PortalHome() {
  const [health, setHealth] = useState<AttestationHealthSummary | null>(null);
  const [engagements, setEngagements] = useState<EngagementSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeId, setActiveId] = useState<string>('');

  useEffect(() => {
    setActiveId(getStoredEngagementId());
    Promise.allSettled([
      portalApi.getAttestationHealth(),
      portalApi.listEngagements({ limit: 20 }),
    ]).then(([healthRes, engRes]) => {
      if (healthRes.status === 'fulfilled') setHealth(healthRes.value);
      if (engRes.status === 'fulfilled') {
        const items = engRes.value.items;
        setEngagements(items);
        const storedId = getStoredEngagementId();
        const storedValid = storedId !== '' && items.some((e) => e.id === storedId);
        if (storedId && !storedValid) {
          setActiveId('');
          setStoredEngagementId('');
        }
        if (items.length === 1 && !storedValid) {
          setActiveId(items[0].id);
          setStoredEngagementId(items[0].id);
        }
      }
      setLoading(false);
    });
  }, []);

  function handleSelect(id: string) {
    setActiveId(id);
    setStoredEngagementId(id);
  }

  const healthPct = health ? Math.round(health.health_pct) : null;
  const overdueCount = health?.overdue ?? 0;
  const dueSoonCount = health?.due_soon ?? 0;

  const findingsHref = activeId ? `/findings?e=${activeId}` : '/findings';
  const reportsHref = activeId ? `/reports?e=${activeId}` : '/reports';

  return (
    <div className="space-y-8" aria-label="portal-overview">
      <div>
        <h1 className="text-xl font-bold text-foreground">AI Governance Portal</h1>
        <p className="mt-1 text-sm text-muted">
          View your assessment findings, reports, and compliance status.
        </p>
      </div>

      {/* Engagement selector — primary navigation hub */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <p className="text-xs font-semibold text-muted uppercase tracking-wider">
            {engagements.length === 1 ? 'Your Engagement' : 'Your Engagements'}
          </p>
          {loading && (
            <span className="text-xs text-muted">Loading…</span>
          )}
        </div>

        {loading && (
          <div className="space-y-2" aria-busy="true">
            {[1, 2].map((i) => (
              <div key={i} className="h-24 rounded border border-border bg-surface-2 animate-pulse" />
            ))}
          </div>
        )}

        {!loading && engagements.length === 0 && (
          <div className="rounded border border-border bg-surface-2 p-6 text-center space-y-1">
            <p className="text-sm font-medium text-foreground">No engagements available</p>
            <p className="text-xs text-muted">
              Your assessor will create an engagement and notify you when it is ready.
            </p>
          </div>
        )}

        {!loading && engagements.length > 0 && (
          <div className="space-y-2">
            {engagements.map((eng) => (
              <EngagementCard
                key={eng.id}
                eng={eng}
                active={eng.id === activeId}
                onSelect={handleSelect}
              />
            ))}
          </div>
        )}
      </div>

      {/* Attestation health dashboard */}
      {!loading && health && (
        <div className="space-y-3">
          <p className="text-xs font-semibold text-muted uppercase tracking-wider">
            Compliance Health
          </p>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <DashboardCard
              title="Health Score"
              value={`${healthPct}%`}
              subtitle="Attestation compliance"
              href="/continuity"
              accent={
                healthPct != null && healthPct >= 80
                  ? 'green'
                  : healthPct != null && healthPct >= 60
                  ? 'amber'
                  : 'red'
              }
            />
            <DashboardCard
              title="Overdue"
              value={overdueCount}
              subtitle="Assets past due"
              href="/attestation"
              accent={overdueCount > 0 ? 'red' : 'green'}
            />
            <DashboardCard
              title="Due Soon"
              value={dueSoonCount}
              subtitle="Upcoming attestations"
              href="/attestation"
              accent={dueSoonCount > 0 ? 'amber' : 'green'}
            />
            <DashboardCard
              title="Compliant"
              value={health.compliant}
              subtitle={`of ${health.total} total assets`}
              href="/continuity"
              accent="green"
            />
          </div>
        </div>
      )}

      {/* Quick links — use active engagement where applicable */}
      <div className="space-y-3">
        <p className="text-xs font-semibold text-muted uppercase tracking-wider">
          Quick Access
        </p>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Link
            href={findingsHref}
            className="rounded border border-border bg-surface-2 p-4 block hover:border-primary/40 transition-colors"
          >
            <p className="text-sm font-semibold text-foreground">Findings</p>
            <p className="mt-1 text-xs text-muted">
              Review assessment findings by severity and framework mapping.
            </p>
          </Link>
          <Link
            href={reportsHref}
            className="rounded border border-border bg-surface-2 p-4 block hover:border-primary/40 transition-colors"
          >
            <p className="text-sm font-semibold text-foreground">Reports</p>
            <p className="mt-1 text-xs text-muted">
              Download signed governance reports in JSON or PDF format.
            </p>
          </Link>
          <Link
            href="/attestation"
            className="rounded border border-border bg-surface-2 p-4 block hover:border-primary/40 transition-colors"
          >
            <p className="text-sm font-semibold text-foreground">Attestation</p>
            <p className="mt-1 text-xs text-muted">
              Submit asset attestations for operator review and track history.
            </p>
          </Link>
          <Link
            href="/continuity"
            className="rounded border border-border bg-surface-2 p-4 block hover:border-primary/40 transition-colors"
          >
            <p className="text-sm font-semibold text-foreground">Continuity</p>
            <p className="mt-1 text-xs text-muted">
              Track overdue attestations and asset governance gaps.
            </p>
          </Link>
        </div>
      </div>
    </div>
  );
}
