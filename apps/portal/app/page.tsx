'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { portalApi, type AttestationHealthSummary, type EngagementSummary } from '@/lib/portalApi';

interface DashboardCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  href: string;
  accent?: 'green' | 'amber' | 'red' | 'default';
}

function DashboardCard({ title, value, subtitle, href, accent = 'default' }: DashboardCardProps) {
  const accentBorder = {
    green: 'hover:border-green-500/40',
    amber: 'hover:border-amber-500/40',
    red: 'hover:border-red-500/40',
    default: 'hover:border-primary/40',
  }[accent];

  const valueColor = {
    green: 'text-green-300',
    amber: 'text-amber-200',
    red: 'text-red-300',
    default: 'text-foreground',
  }[accent];

  return (
    <Link
      href={href}
      className={`rounded border border-border bg-surface-2 p-4 block space-y-1 transition-colors ${accentBorder}`}
    >
      <p className="text-xs font-semibold text-muted uppercase tracking-wider">{title}</p>
      <p className={`text-2xl font-bold ${valueColor}`}>{value}</p>
      {subtitle && <p className="text-xs text-muted">{subtitle}</p>}
    </Link>
  );
}

export default function PortalHome() {
  const [health, setHealth] = useState<AttestationHealthSummary | null>(null);
  const [engagements, setEngagements] = useState<EngagementSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      portalApi.getAttestationHealth(),
      portalApi.listEngagements({ limit: 5 }),
    ]).then(([healthRes, engRes]) => {
      if (healthRes.status === 'fulfilled') setHealth(healthRes.value);
      if (engRes.status === 'fulfilled') setEngagements(engRes.value.items);
      setLoading(false);
    });
  }, []);

  const healthPct = health ? Math.round(health.health_pct) : null;
  const overdueCount = health?.overdue ?? 0;
  const dueSoonCount = health?.due_soon ?? 0;

  return (
    <div className="space-y-8" aria-label="portal-overview">
      <div>
        <h1 className="text-xl font-bold text-foreground">AI Governance Portal</h1>
        <p className="mt-1 text-sm text-muted">
          View your assessment findings, reports, and compliance status.
        </p>
      </div>

      {loading && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4" aria-busy="true">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-24 rounded border border-border bg-surface-2 animate-pulse" />
          ))}
        </div>
      )}

      {!loading && health && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <DashboardCard
            title="Health Score"
            value={`${healthPct}%`}
            subtitle="Attestation compliance"
            href="/continuity"
            accent={healthPct != null && healthPct >= 80 ? 'green' : healthPct != null && healthPct >= 60 ? 'amber' : 'red'}
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
      )}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Link
          href="/findings"
          className="rounded border border-border bg-surface-2 p-4 block hover:border-primary/40 transition-colors"
        >
          <p className="text-sm font-semibold text-foreground">Findings</p>
          <p className="mt-1 text-xs text-muted">
            Review assessment findings by severity and framework mapping.
          </p>
        </Link>
        <Link
          href="/reports"
          className="rounded border border-border bg-surface-2 p-4 block hover:border-primary/40 transition-colors"
        >
          <p className="text-sm font-semibold text-foreground">Reports</p>
          <p className="mt-1 text-xs text-muted">
            Download signed governance reports in JSON or PDF format.
          </p>
        </Link>
        <Link
          href="/remediation"
          className="rounded border border-border bg-surface-2 p-4 block hover:border-primary/40 transition-colors"
        >
          <p className="text-sm font-semibold text-foreground">Remediation</p>
          <p className="mt-1 text-xs text-muted">
            Track open findings with remediation guidance from your assessor.
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
      </div>

      {!loading && engagements.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-3">
            Your Engagements
          </p>
          <div className="space-y-2">
            {engagements.map((eng) => (
              <div key={eng.id} className="rounded border border-border bg-surface-2 p-3 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="text-sm font-medium text-foreground">{eng.name}</p>
                  <p className="text-xs text-muted capitalize">{eng.assessment_type.replace(/_/g, ' ')}</p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs capitalize text-muted">{eng.status.replace(/_/g, ' ')}</span>
                  <div className="flex gap-1">
                    <Link
                      href={`/findings?e=${eng.id}`}
                      className="rounded border border-border bg-surface-3 px-2 py-0.5 text-xs text-muted hover:text-foreground transition-colors"
                    >
                      Findings
                    </Link>
                    <Link
                      href={`/reports?e=${eng.id}`}
                      className="rounded border border-border bg-surface-3 px-2 py-0.5 text-xs text-muted hover:text-foreground transition-colors"
                    >
                      Reports
                    </Link>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
