'use client';

import { useEffect, useState } from 'react';
import {
  getPolicyConflicts,
  type PolicyConflictResult,
  type ConflictType,
  type Severity,
} from '@/lib/operationsCenterApi';

const CONFLICT_TYPES: ConflictType[] = [
  'duplicate_policy',
  'conflicting_policy',
  'overlapping_authority',
  'missing_ownership',
  'contradicting_requirements',
  'dead_policy',
  'orphaned_control',
];

function severityClasses(severity: Severity): string {
  switch (severity) {
    case 'critical': return 'border-red-500/40 bg-red-500/10 text-red-400';
    case 'high': return 'border-orange-500/40 bg-orange-500/10 text-orange-400';
    case 'medium': return 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400';
    case 'low': return 'border-blue-500/40 bg-blue-500/10 text-blue-400';
    default: return 'border-border bg-surface text-muted';
  }
}

function severityDot(severity: Severity): string {
  switch (severity) {
    case 'critical': return 'bg-red-500';
    case 'high': return 'bg-orange-500';
    case 'medium': return 'bg-yellow-500';
    case 'low': return 'bg-blue-500';
    default: return 'bg-muted';
  }
}

export default function PolicyConflictCenter() {
  const [result, setResult] = useState<PolicyConflictResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getPolicyConflicts().then((res) => {
      if (res.ok) {
        setResult(res.data);
      } else {
        setError(res.error);
      }
      setLoading(false);
    });
  }, []);

  return (
    <div
      data-mcim="MCIM-18.7-POLICY-CONFLICT"
      className="rounded-lg border border-border bg-surface-2 p-4"
    >
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-widest text-muted/70">
        Policy Conflict Center
      </h2>

      {loading && (
        <p className="text-sm text-muted" aria-live="polite">Loading…</p>
      )}

      {!loading && error && (
        <p className="text-sm text-danger" role="alert" aria-label="Error loading policy conflicts">
          {error}
        </p>
      )}

      {!loading && !error && result && (
        <>
          <div className="mb-4 flex gap-4" aria-label="Policy conflict statistics">
            <div className="rounded border border-border bg-surface px-3 py-2 text-center" role="status" aria-label="Total conflicts">
              <p className="text-lg font-semibold text-foreground">{result.conflicts.length}</p>
              <p className="text-xs text-muted">Total Conflicts</p>
            </div>
            <div className="rounded border border-border bg-surface px-3 py-2 text-center" role="status" aria-label="Orphaned nodes">
              <p className="text-lg font-semibold text-foreground">{result.orphanedNodes}</p>
              <p className="text-xs text-muted">Orphaned Nodes</p>
            </div>
          </div>

          <div className="mb-4 flex flex-wrap gap-2" aria-label="Conflicts by type">
            {CONFLICT_TYPES.map((ct) => (
              <span
                key={ct}
                className="rounded border border-border bg-surface px-2 py-1 text-xs text-muted"
                aria-label={`${ct}: ${result.byType[ct] ?? 0}`}
              >
                {ct.replace(/_/g, ' ')}: <span className="text-foreground font-medium">{result.byType[ct] ?? 0}</span>
              </span>
            ))}
          </div>

          {result.conflicts.length === 0 ? (
            <p className="text-sm text-muted">No policy conflicts detected.</p>
          ) : (
            <ul className="space-y-2" role="list" aria-label="Policy conflict list">
              {result.conflicts.map((conflict) => (
                <li
                  key={conflict.id}
                  role="listitem"
                  aria-label={`${conflict.type} conflict, severity ${conflict.severity}`}
                  className={`rounded border px-3 py-2 ${severityClasses(conflict.severity)}`}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`inline-block h-2 w-2 rounded-full ${severityDot(conflict.severity)}`} aria-hidden="true" />
                    <span className="text-xs font-medium">{conflict.type.replace(/_/g, ' ')}</span>
                    <span className="text-xs text-muted">{conflict.description}</span>
                    <span className="ml-auto text-xs text-muted">{conflict.nodeIds.length} node{conflict.nodeIds.length !== 1 ? 's' : ''}</span>
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-muted">
                    <span aria-label="Detected at">{conflict.detectedAt}</span>
                    {conflict.resolved && (
                      <span className="rounded border border-green-500/30 bg-green-500/10 px-1.5 py-0.5 text-green-400" aria-label="Resolved">
                        resolved
                      </span>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}
