'use client';

import { useEffect, useState } from 'react';
import { CheckCircle2, XCircle, AlertTriangle, Loader2 } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  type AuditOverview,
  type AuditStatus,
  type AuditChainIntegrity,
  getAuditOverview,
  getAuditStatus,
  getAuditChainIntegrity,
} from '@/lib/evidenceApi';

function IntegrityIcon({ status }: { status: string }) {
  if (status === 'ok') return <CheckCircle2 className="h-4 w-4 shrink-0 text-success" aria-hidden="true" />;
  if (status === 'broken') return <XCircle className="h-4 w-4 shrink-0 text-risk-critical" aria-hidden="true" />;
  return <AlertTriangle className="h-4 w-4 shrink-0 text-risk-medium" aria-hidden="true" />;
}

function HashValue({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="italic text-muted-foreground text-xs">—</span>;
  return (
    <span className="font-mono text-xs break-all" title={value}>
      {value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-8)}` : value}
    </span>
  );
}

export function AuditChainPanel() {
  const [overview, setOverview] = useState<AuditOverview | null>(null);
  const [status, setStatus] = useState<AuditStatus | null>(null);
  const [integrity, setIntegrity] = useState<AuditChainIntegrity | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([getAuditOverview(), getAuditStatus(), getAuditChainIntegrity()]).then(
      ([ovRes, stRes, intRes]) => {
        if (cancelled) return;
        if (!ovRes.ok || !stRes.ok || !intRes.ok) {
          const msg = !ovRes.ok ? ovRes.error : !stRes.ok ? stRes.error : intRes.ok ? '' : intRes.error;
          setError(msg || 'Audit data unavailable');
        } else {
          setOverview(ovRes.data);
          setStatus(stRes.data);
          setIntegrity(intRes.data);
        }
        setLoading(false);
      },
    );

    return () => {
      cancelled = true;
    };
  }, []);

  const integrityStatus = integrity?.audit_chain_integrity ?? 'unknown';
  const failureRatio =
    status && status.records > 0
      ? ((status.failed_records / status.records) * 100).toFixed(1)
      : null;

  return (
    <Card aria-label="audit-chain-panel">
      <CardHeader>
        <CardTitle className="text-sm font-semibold">Audit Chain</CardTitle>
      </CardHeader>
      <CardContent>
        {loading && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground" aria-label="audit-chain-loading">
            <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            Loading audit chain…
          </div>
        )}

        {!loading && error && (
          <div
            className="flex items-center gap-2 rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2"
            aria-label="audit-chain-error"
          >
            <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-amber-600" aria-hidden="true" />
            <p className="text-xs text-amber-700 dark:text-amber-400">{error}</p>
          </div>
        )}

        {!loading && !error && (
          <div className="space-y-4">
            {/* Chain integrity */}
            <div
              className={`flex items-center gap-2 rounded border px-3 py-2 ${
                integrityStatus === 'ok'
                  ? 'border-success/30 bg-success/10'
                  : integrityStatus === 'broken'
                    ? 'border-risk-critical/30 bg-risk-critical/10'
                    : 'border-border bg-surface-2'
              }`}
              aria-label="audit-chain-integrity-status"
            >
              <IntegrityIcon status={integrityStatus} />
              <div>
                <p className="text-xs font-medium text-foreground">
                  Chain integrity:{' '}
                  <span className="font-mono">{integrityStatus}</span>
                </p>
                {integrityStatus === 'broken' && (
                  <p className="mt-0.5 text-xs text-risk-critical">
                    Audit chain continuity failure detected. Do not rely on this ledger for compliance
                    decisions until verified.
                  </p>
                )}
              </div>
            </div>

            {/* Record counts */}
            {status && (
              <div className="grid grid-cols-2 gap-2 text-xs" aria-label="audit-record-counts">
                <div className="flex flex-col gap-0.5">
                  <span className="text-muted-foreground">Total Records</span>
                  <span className="font-mono font-medium">{status.records.toLocaleString()}</span>
                </div>
                <div className="flex flex-col gap-0.5">
                  <span className="text-muted-foreground">Failed Records</span>
                  <span
                    className={`font-mono font-medium ${status.failed_records > 0 ? 'text-risk-critical' : 'text-foreground'}`}
                    aria-label="audit-failed-count"
                  >
                    {status.failed_records.toLocaleString()}
                    {failureRatio !== null && status.failed_records > 0 && (
                      <span className="ml-1 text-muted-foreground">({failureRatio}%)</span>
                    )}
                  </span>
                </div>
              </div>
            )}

            {/* Invariant + drift */}
            {overview && (
              <div className="space-y-1.5 text-xs" aria-label="audit-invariant-drift">
                <div className="flex flex-col gap-0.5">
                  <span className="text-muted-foreground">Invariant Status</span>
                  <span className="font-mono font-medium text-foreground">
                    {overview.current_invariant_status}
                  </span>
                </div>
                <div className="flex flex-col gap-0.5">
                  <span className="text-muted-foreground">Drift Status</span>
                  <span className="font-mono font-medium text-foreground">{overview.drift_status}</span>
                </div>
              </div>
            )}

            {/* Policy + config hashes */}
            {overview && (
              <div className="space-y-1.5 text-xs" aria-label="audit-hash-summary">
                <div className="flex flex-col gap-0.5">
                  <span className="text-muted-foreground">Policy Hash</span>
                  <HashValue value={overview.policy_hash} />
                </div>
                <div className="flex flex-col gap-0.5">
                  <span className="text-muted-foreground">Config Hash</span>
                  <HashValue value={overview.config_hash} />
                </div>
              </div>
            )}

            <p className="text-xs text-muted-foreground/70" aria-label="audit-chain-authority-note">
              Audit chain integrity is authoritative from the ledger API. Do not derive compliance
              posture from this panel alone.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
