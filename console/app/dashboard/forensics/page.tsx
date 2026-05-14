'use client';

import { useState } from 'react';
import { getChainVerifyWithMeta, getForensicsAuditTrailWithMeta, getForensicsSnapshotWithMeta } from '@/lib/coreApi';
import { toErrorDisplay } from '@/lib/errors';
import {
  TrustIndicator,
  EvidenceCard,
  AuditTimeline,
  AuditForensicsConsole,
} from '@/components/governance';
import type { EvidenceField, TimelineEvent } from '@/components/governance';

type ChainStatus = 'verified' | 'unverified' | 'unknown';

type UiError = {
  message: string;
  code: string;
  requestId: string;
};

type ChainProof = {
  requestId: string;
  timestamp: string;
  responseHash: string;
};

const SNAPSHOT_FIELDS = new Set<string>([
  'event_id',
  'tenant_id',
  'source',
  'threat_level',
  'created_at',
  'explain_summary',
  'severity',
  'action',
  'decision_type',
  'policy',
  'reason',
  'confidence',
]);

function stringifyValue(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);

  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function toTimelineEvents(data: unknown): TimelineEvent[] | null {
  if (!data || typeof data !== 'object') return null;

  const d = data as Record<string, unknown>;
  const arr = Array.isArray(d.events)
    ? d.events
    : Array.isArray(d.items)
      ? d.items
      : Array.isArray(d.audit_events)
        ? d.audit_events
        : null;

  if (!arr) return null;

  return arr.map((ev: unknown, i: number) => {
    const e = (ev && typeof ev === 'object' ? ev : {}) as Record<string, unknown>;

    return {
      id: stringifyValue(e.id ?? e.event_id ?? i),
      ts: stringifyValue(e.ts ?? e.timestamp ?? e.created_at),
      actor: e.actor ? stringifyValue(e.actor) : undefined,
      action: stringifyValue(e.action ?? e.event_type ?? 'event'),
      status: stringifyValue(e.status ?? e.action ?? 'info'),
      summary: e.summary ? stringifyValue(e.summary) : undefined,
      requestId: e.request_id ? stringifyValue(e.request_id) : undefined,
    };
  });
}

function toEvidenceFields(data: unknown, knownKeys?: Set<string>): EvidenceField[] {
  if (!data || typeof data !== 'object') return [];

  return Object.entries(data as Record<string, unknown>)
    .filter(([key]) => !knownKeys || knownKeys.has(key))
    .map(([key, value]) => ({
      label: key,
      value: stringifyValue(value),
    }));
}

function toExtraFields(data: unknown, knownKeys: Set<string>): EvidenceField[] {
  if (!data || typeof data !== 'object') return [];

  return Object.entries(data as Record<string, unknown>)
    .filter(([key]) => !knownKeys.has(key))
    .map(([key, value]) => ({
      label: key,
      value: stringifyValue(value),
    }));
}

function normalizeError(err: unknown): UiError {
  const display = toErrorDisplay(err) as Partial<UiError>;

  return {
    message: stringifyValue(display.message || 'Request failed'),
    code: stringifyValue(display.code || 'UNKNOWN_ERROR'),
    requestId: stringifyValue(display.requestId || 'n/a'),
  };
}

export default function ForensicsPage() {
  const [eventId, setEventId] = useState<string>('');
  const [snapshotData, setSnapshotData] = useState<unknown>(null);
  const [auditData, setAuditData] = useState<unknown>(null);
  const [chainStatus, setChainStatus] = useState<ChainStatus>('unknown');
  const [chainProof, setChainProof] = useState<ChainProof | null>(null);
  const [error, setError] = useState<UiError | null>(null);
  const [loading, setLoading] = useState<'snapshot' | 'audit' | 'chain' | null>(null);
  const [lookupOpen, setLookupOpen] = useState(false);

  async function run(kind: 'snapshot' | 'audit' | 'chain'): Promise<void> {
    try {
      setError(null);
      setLoading(kind);

      const response =
        kind === 'snapshot'
          ? await getForensicsSnapshotWithMeta(eventId)
          : kind === 'audit'
            ? await getForensicsAuditTrailWithMeta(eventId)
            : await getChainVerifyWithMeta();

      if (kind === 'snapshot') {
        setSnapshotData(response.data);
      }

      if (kind === 'audit') {
        setAuditData(response.data);
      }

      if (kind === 'chain') {
        const d = response.data as Record<string, unknown>;
        const verified = Boolean(d.verified ?? d.pass ?? d.ok);

        setChainStatus(verified ? 'verified' : 'unverified');
        setChainProof({
          requestId: stringifyValue(response.meta.requestId || 'n/a'),
          timestamp: stringifyValue(response.meta.receivedAt),
          responseHash: stringifyValue(response.meta.responseHash || 'n/a'),
        });
      }
    } catch (err) {
      setError(normalizeError(err));
      if (kind === 'chain') setChainStatus('unverified');
    } finally {
      setLoading(null);
    }
  }

  const auditTimeline = auditData ? toTimelineEvents(auditData) : null;
  const snapshotCore = snapshotData ? toEvidenceFields(snapshotData, SNAPSHOT_FIELDS) : [];
  const snapshotExtra = snapshotData ? toExtraFields(snapshotData, SNAPSHOT_FIELDS) : [];
  const auditFallbackFields = auditData
    ? toEvidenceFields(auditData)
    : [];

  return (
    <div className="flex flex-col">
      <div className="border-b border-border px-6 py-4">
        <h1 className="text-base font-semibold text-foreground">Forensics</h1>
        <p className="mt-0.5 text-xs text-muted">
          Investigate events, verify chain integrity, retrieve audit trails
        </p>
      </div>

      {/* Primary: Audit & Forensics Console */}
      <AuditForensicsConsole />

      {/* Secondary: Event Lookup (collapsible) */}
      <div className="border-t border-border">
        <button
          onClick={() => setLookupOpen((prev) => !prev)}
          aria-expanded={lookupOpen}
          aria-controls="event-lookup-section"
          className="flex w-full items-center justify-between px-6 py-3 text-left text-xs font-semibold uppercase tracking-widest text-muted/70 hover:text-foreground"
        >
          <span>Event Lookup (chain-verify, snapshot, audit-trail)</span>
          <span>{lookupOpen ? '▲' : '▼'}</span>
        </button>

        {lookupOpen && (
          <div id="event-lookup-section" className="space-y-4 p-6">
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-widest text-muted/60">
                  Chain Verify Status
                </span>
                {chainProof ? (
                  <button
                    onClick={() => {
                      void navigator.clipboard.writeText(
                        JSON.stringify({
                          requestId: chainProof.requestId,
                          responseHash: chainProof.responseHash,
                          timestamp: chainProof.timestamp,
                        }),
                      );
                    }}
                    className="rounded border border-border bg-surface-2 px-2.5 py-1 text-xs text-muted hover:text-foreground"
                  >
                    Copy proof
                  </button>
                ) : null}
              </div>

              <TrustIndicator
                status={chainStatus}
                requestId={chainProof?.requestId}
                hash={chainProof?.responseHash}
              />
            </div>

            <div className="flex flex-wrap gap-2">
              <input
                value={eventId}
                onChange={(e) => setEventId(e.target.value)}
                placeholder="event_id"
                className="rounded border border-border bg-surface-2 px-3 py-1.5 text-sm text-foreground placeholder:text-muted/40 focus:outline-none focus:ring-1 focus:ring-primary"
              />

              <button
                disabled={!eventId || loading === 'snapshot'}
                onClick={() => void run('snapshot')}
                className="rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
              >
                {loading === 'snapshot' ? 'Loading…' : 'Snapshot'}
              </button>

              <button
                disabled={!eventId || loading === 'audit'}
                onClick={() => void run('audit')}
                className="rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
              >
                {loading === 'audit' ? 'Loading…' : 'Audit trail'}
              </button>

              <button
                disabled={loading === 'chain'}
                onClick={() => void run('chain')}
                className="rounded bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-hover disabled:opacity-40"
              >
                {loading === 'chain' ? 'Verifying…' : 'Chain verify'}
              </button>
            </div>

            {error ? (
              <p className="rounded border border-danger/30 bg-danger/5 px-3 py-2 text-xs text-danger">
                {error.message} ({error.code}) · request_id: {error.requestId}
              </p>
            ) : null}

            {snapshotData ? (
              <div className="space-y-3">
                {snapshotCore.length > 0 ? (
                  <EvidenceCard title="Snapshot" fields={snapshotCore} highlight />
                ) : null}

                {snapshotExtra.length > 0 ? (
                  <EvidenceCard title="Additional fields" fields={snapshotExtra} />
                ) : null}
              </div>
            ) : null}

            {auditData ? (
              <div className="rounded-lg border border-border bg-surface-2 p-4">
                <p className="mb-3 text-xs font-semibold uppercase tracking-widest text-muted/70">
                  Audit Trail
                </p>

                {auditTimeline ? (
                  <AuditTimeline events={auditTimeline} />
                ) : (
                  <EvidenceCard title="Audit data" fields={auditFallbackFields} />
                )}
              </div>
            ) : null}
          </div>
        )}
      </div>
    </div>
  );
}
