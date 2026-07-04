'use client';

import { AlertTriangle, CheckCircle2, HelpCircle, Minus } from 'lucide-react';
import WidgetShell from './WidgetShell';
import type { Framework } from '@/lib/readinessApi';

// MCIM reference: MCIM-18.6-COMPLIANCE
const MCIM_ID = 'MCIM-18.6-COMPLIANCE';
const AUTHORITY = 'Compliance Authority';
const sourceOfTruth = '/api/core/control-plane/readiness/frameworks';
const drillDown = '/dashboard/readiness';

const KNOWN_FRAMEWORKS: Array<{ slug: string; id: string; label: string }> = [
  { slug: 'nist', id: 'compliance-nist', label: 'NIST' },
  { slug: 'iso', id: 'compliance-iso', label: 'ISO 27001' },
  { slug: 'soc2', id: 'compliance-soc2', label: 'SOC 2' },
  { slug: 'hipaa', id: 'compliance-hipaa', label: 'HIPAA' },
  { slug: 'pci', id: 'compliance-pci', label: 'PCI DSS' },
];

interface FrameworkRow {
  id: string;
  label: string;
  present: boolean;
  status: string;
  version: string | null;
  drift: boolean;
  upcomingDeadline: string | null;
  coveragePct: number | null;
  missingControls: number | null;
}

function buildRows(frameworks: Framework[]): FrameworkRow[] {
  const rows: FrameworkRow[] = KNOWN_FRAMEWORKS.map(({ slug, id, label }) => {
    const found = frameworks.find(
      (f) => f.framework_slug.toLowerCase().includes(slug) ||
              f.framework_name.toLowerCase().includes(slug),
    );

    return {
      id,
      label,
      present: !!found,
      status: found?.framework_status ?? 'not-configured',
      version: found?.framework_version ?? null,
      drift: found?.framework_status === 'stale' || found?.framework_status === 'deprecated',
      upcomingDeadline: null,
      coveragePct: found ? null : null,
      missingControls: null,
    };
  });

  // Add custom frameworks not matching known slugs
  const customFrameworks = frameworks.filter(
    (f) =>
      !KNOWN_FRAMEWORKS.some(
        ({ slug }) =>
          f.framework_slug.toLowerCase().includes(slug) ||
          f.framework_name.toLowerCase().includes(slug),
      ),
  );

  for (const cf of customFrameworks.slice(0, 3)) {
    rows.push({
      id: 'compliance-custom',
      label: cf.framework_name,
      present: true,
      status: cf.framework_status,
      version: cf.framework_version,
      drift: cf.framework_status === 'stale' || cf.framework_status === 'deprecated',
      upcomingDeadline: null,
      coveragePct: null,
      missingControls: null,
    });
  }

  return rows;
}

interface ComplianceSummaryProps {
  frameworks: Framework[];
  loading?: boolean;
  lastUpdated?: string;
}

export default function ComplianceSummary({
  frameworks,
  loading = false,
  lastUpdated,
}: ComplianceSummaryProps) {
  const rows = loading ? [] : buildRows(frameworks);

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Compliance Summary"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Compliance Frameworks"
    >
      <div aria-label="compliance-summary">
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-10 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : frameworks.length === 0 && rows.length === 0 ? (
          <div className="py-4 text-center text-sm text-muted">
            <HelpCircle className="mx-auto mb-2 h-6 w-6 text-muted/40" aria-hidden="true" />
            <p>No compliance frameworks configured.</p>
            <p className="mt-1 text-[10px]">Authority: {AUTHORITY}</p>
          </div>
        ) : (
          <table className="w-full text-xs" aria-label="compliance-table">
            <thead>
              <tr className="border-b border-border text-[10px] text-muted">
                <th className="pb-1.5 text-left font-semibold">Framework</th>
                <th className="pb-1.5 text-left font-semibold" data-testid="compliance-coverage" aria-label="compliance-coverage">Coverage</th>
                <th className="pb-1.5 text-left font-semibold" data-testid="compliance-drift" aria-label="compliance-drift">Drift</th>
                <th className="pb-1.5 text-left font-semibold">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr
                  key={`${row.id}-${i}`}
                  className="border-b border-border/50 last:border-0"
                  data-testid={row.id}
                  aria-label={row.id}
                >
                  <td className="py-1.5 font-medium text-foreground">
                    {row.label}
                    {row.version && (
                      <span className="ml-1 text-[9px] text-muted font-mono">v{row.version}</span>
                    )}
                  </td>
                  <td className="py-1.5 text-muted">
                    {row.present
                      ? row.coveragePct !== null
                        ? `${row.coveragePct}%`
                        : 'see score'
                      : '—'}
                  </td>
                  <td className="py-1.5">
                    {!row.present ? (
                      <Minus className="h-3.5 w-3.5 text-muted" aria-hidden="true" />
                    ) : row.drift ? (
                      <AlertTriangle className="h-3.5 w-3.5 text-warning" aria-hidden="true" />
                    ) : (
                      <CheckCircle2 className="h-3.5 w-3.5 text-success" aria-hidden="true" />
                    )}
                  </td>
                  <td className="py-1.5 text-muted">
                    {row.present ? row.status : 'not-configured'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </WidgetShell>
  );
}
