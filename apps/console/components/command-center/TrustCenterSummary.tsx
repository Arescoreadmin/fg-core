'use client';

import Link from 'next/link';
import { CheckCircle2, AlertTriangle, XCircle, HelpCircle } from 'lucide-react';
import WidgetShell from './WidgetShell';
import type { ControlTowerSnapshotV1 } from '@/lib/coreApi';

// MCIM reference: MCIM-18.6-TRUST-CENTER
const MCIM_ID = 'MCIM-18.6-TRUST-CENTER';
const AUTHORITY = 'Trust Center Authority';
const sourceOfTruth = '/api/core/control-tower/snapshot';
const drillDown = '/dashboard/forensics';

type StatusLevel = 'ok' | 'warning' | 'critical' | 'unknown';

function StatusIcon({ level }: { level: StatusLevel }) {
  if (level === 'ok') return <CheckCircle2 className="h-4 w-4 text-success shrink-0" aria-hidden="true" />;
  if (level === 'warning') return <AlertTriangle className="h-4 w-4 text-warning shrink-0" aria-hidden="true" />;
  if (level === 'critical') return <XCircle className="h-4 w-4 text-danger shrink-0" aria-hidden="true" />;
  return <HelpCircle className="h-4 w-4 text-muted shrink-0" aria-hidden="true" />;
}

interface TrustRow {
  id: string;
  label: string;
  value: string;
  level: StatusLevel;
  href: string;
}

interface TrustCenterSummaryProps {
  snapshot: ControlTowerSnapshotV1 | null;
  loading?: boolean;
  lastUpdated?: string;
}

export default function TrustCenterSummary({
  snapshot,
  loading = false,
  lastUpdated,
}: TrustCenterSummaryProps) {
  function buildRows(): TrustRow[] {
    if (!snapshot) return [];

    const chain = snapshot.chain_integrity;
    const keys = snapshot.key_lifecycle;
    const replay = snapshot.last_replay;
    const agents = snapshot.agents;
    const lockers = snapshot.lockers;

    const chainLevel: StatusLevel =
      chain.status === 'pass' ? 'ok' : chain.status === 'fail' ? 'critical' : 'unknown';

    const keyLevel: StatusLevel = keys.active_key_count > 0 ? 'ok' : 'warning';

    const verifyLevel: StatusLevel =
      replay.result === 'ok' || replay.result === 'success'
        ? 'ok'
        : replay.result
          ? 'warning'
          : 'unknown';

    const agentLevel: StatusLevel =
      agents.quarantine_count > 0 ? 'warning' : 'ok';

    const lockerLevel: StatusLevel =
      lockers.status === 'ok' || lockers.status === 'healthy'
        ? 'ok'
        : lockers.status
          ? 'warning'
          : 'unknown';

    const decisionLevel: StatusLevel =
      replay.event_id ? 'ok' : 'unknown';

    return [
      {
        id: 'trust-health',
        label: 'Trust Health',
        value: chainLevel === 'ok' ? 'Verified' : chainLevel === 'critical' ? 'Chain failure' : 'Unknown',
        level: chainLevel,
        href: '/dashboard/forensics',
      },
      {
        id: 'chain-integrity',
        label: 'Chain Integrity',
        value: chain.status ?? 'unknown',
        level: chainLevel,
        href: '/dashboard/forensics',
      },
      {
        id: 'key-lifecycle',
        label: 'Key Health',
        value: `${keys.active_key_count} active key${keys.active_key_count !== 1 ? 's' : ''}`,
        level: keyLevel,
        href: '/keys',
      },
      {
        id: 'verification-status',
        label: 'Verification Status',
        value: replay.result ?? 'no replay',
        level: verifyLevel,
        href: '/dashboard/provenance',
      },
      {
        id: 'transparency-health',
        label: 'Transparency Health',
        value: lockers.status ?? 'unknown',
        level: lockerLevel,
        href: '/dashboard/forensics',
      },
      {
        id: 'decision-provenance',
        label: 'Decision Provenance',
        value: decisionLevel === 'ok' ? `Last: ${replay.event_id?.slice(0, 8) ?? '—'}` : 'No replay event',
        level: decisionLevel,
        href: '/dashboard/decisions',
      },
    ];
  }

  const rows = loading ? [] : buildRows();

  return (
    <WidgetShell
      mcimId={MCIM_ID}
      authority={AUTHORITY}
      capability="Trust Center Summary"
      sourceOfTruth={sourceOfTruth}
      drillDown={drillDown}
      refreshPolicy="on-load"
      lastUpdated={lastUpdated}
      title="Trust Center"
    >
      <div aria-label="trust-center-summary">
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-8 w-full animate-pulse rounded bg-muted" />
            ))}
          </div>
        ) : snapshot === null ? (
          <div className="py-4 text-center text-sm text-muted">
            <HelpCircle className="mx-auto mb-2 h-6 w-6 text-muted/40" aria-hidden="true" />
            <p>Trust center data unavailable.</p>
            <p className="mt-1 text-[10px]">Authority: {AUTHORITY}</p>
          </div>
        ) : (
          <ul className="space-y-2" role="list">
            {rows.map((row) => (
              <li key={row.id} aria-label={row.id} data-testid={row.id}>
                <Link
                  href={row.href}
                  className="flex items-center justify-between gap-2 rounded-md border border-border px-3 py-2 hover:border-primary/40 transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <StatusIcon level={row.level} />
                    <span className="text-xs font-medium text-foreground">{row.label}</span>
                  </div>
                  <span className="text-xs text-muted truncate max-w-[120px]">{row.value}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </WidgetShell>
  );
}
