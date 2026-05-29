'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { portalApi, PortalApiError, type EngagementSummary } from '@/lib/portalApi';

const STATUS_CLASS: Record<string, string> = {
  scheduled:           'border-blue-500/30 bg-blue-500/5 text-blue-300',
  pre_visit:           'border-blue-500/30 bg-blue-500/5 text-blue-300',
  in_progress:         'border-amber-500/30 bg-amber-500/5 text-amber-200',
  evidence_collected:  'border-amber-500/30 bg-amber-500/5 text-amber-200',
  report_generation:   'border-purple-500/30 bg-purple-500/5 text-purple-300',
  delivered:           'border-green-500/30 bg-green-500/5 text-green-300',
  remediation:         'border-orange-500/30 bg-orange-500/5 text-orange-300',
  monitoring:          'border-teal-500/30 bg-teal-500/5 text-teal-300',
  closed:              'border-border bg-surface-3 text-muted',
  cancelled:           'border-border bg-surface-3 text-muted',
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_CLASS[status] ?? 'border-border bg-surface-3 text-muted';
  const label = status.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs border font-medium ${cls}`}>
      {label}
    </span>
  );
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

export default function EngagementListPage() {
  const [engagements, setEngagements] = useState<EngagementSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    portalApi
      .listEngagements({ limit: 50 })
      .then((r) => setEngagements(r.items))
      .catch((e) => {
        if (e instanceof PortalApiError) setError(`Error ${e.status}: ${e.code}`);
        else setError('Failed to load engagements.');
      })
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-foreground">Field Assessments</h1>
        <p className="mt-1 text-sm text-muted">
          Select an engagement to view scans, documents, observations, evidence, and audit history.
        </p>
      </div>

      {loading && (
        <div className="rounded border border-border bg-surface p-8 text-center text-sm text-muted">
          Loading engagements…
        </div>
      )}

      {error && (
        <div className="rounded border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {!loading && !error && engagements.length === 0 && (
        <div className="rounded border border-border bg-surface p-8 text-center text-sm text-muted">
          No engagements found for this account.
        </div>
      )}

      {!loading && engagements.length > 0 && (
        <div className="divide-y divide-border rounded border border-border bg-surface overflow-hidden">
          {engagements.map((eng) => (
            <Link
              key={eng.id}
              href={`/engagement/${eng.id}`}
              className="flex items-center justify-between gap-4 px-4 py-3 hover:bg-surface-2 transition-colors group"
            >
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-foreground group-hover:text-primary transition-colors truncate">
                  {eng.client_name}
                </p>
                <p className="text-xs text-muted mt-0.5">
                  {eng.assessment_type.replace(/_/g, ' ').toUpperCase()} · Created {fmtDate(eng.created_at)}
                </p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <StatusBadge status={eng.status} />
                <span className="text-xs text-muted">→</span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
