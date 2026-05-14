'use client';

import { useState, useCallback } from 'react';
import {
  getForensicsEvents,
  getForensicsTrace,
  getForensicsExport,
  type ForensicsEvent,
  type ForensicsEventsPage,
  type ForensicsEventsQuery,
  type ForensicsTrace,
  type ForensicsExportPayload,
} from '@/lib/coreApi';
import { toErrorDisplay } from '@/lib/errors';

// ─── Severity helpers ─────────────────────────────────────────────────────────

function severityLabel(severity: string): string {
  switch (severity) {
    case 'info': return 'Info';
    case 'warning': return 'Warning';
    case 'error': return 'Error';
    case 'critical': return 'Critical';
    default: return severity;
  }
}

function severityClass(severity: string): string {
  switch (severity) {
    case 'info': return 'text-info';
    case 'warning': return 'text-warning';
    case 'error': return 'text-danger';
    case 'critical': return 'text-danger font-semibold';
    default: return 'text-muted';
  }
}

// ─── Error normalization ──────────────────────────────────────────────────────

function normalizeError(err: unknown): string {
  const display = toErrorDisplay(err) as Partial<{ message: string }>;
  return display?.message || (err instanceof Error ? err.message : 'An error occurred');
}

// ─── ForensicsSearchBar ───────────────────────────────────────────────────────

interface ForensicsSearchBarProps {
  value: string;
  onChange: (v: string) => void;
  onSearch: () => void;
  loading: boolean;
}

function ForensicsSearchBar({ value, onChange, onSearch, loading }: ForensicsSearchBarProps) {
  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') onSearch();
  }

  return (
    <form
      aria-label="forensics-search-bar"
      onSubmit={(e) => { e.preventDefault(); onSearch(); }}
      className="flex flex-wrap items-center gap-2"
    >
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="Search by request_id"
        aria-label="Search by request_id"
        className="rounded border border-border bg-surface-2 px-3 py-1.5 font-mono text-sm text-foreground placeholder:text-muted/40 focus:outline-none focus:ring-1 focus:ring-primary"
      />
      <button
        type="submit"
        disabled={loading}
        aria-label="Run search"
        className="rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
      >
        {loading ? 'Loading…' : 'Search'}
      </button>
    </form>
  );
}

// ─── ForensicsFilterPanel ─────────────────────────────────────────────────────

interface ForensicsFilterPanelProps {
  severity: string;
  eventType: string;
  success: string;
  onSeverityChange: (v: string) => void;
  onEventTypeChange: (v: string) => void;
  onSuccessChange: (v: string) => void;
}

function ForensicsFilterPanel({
  severity,
  eventType,
  success,
  onSeverityChange,
  onEventTypeChange,
  onSuccessChange,
}: ForensicsFilterPanelProps) {
  return (
    <div aria-label="forensics-filter-panel" className="flex flex-wrap gap-3">
      <div className="flex flex-col gap-1">
        <label htmlFor="filter-severity" className="text-xs text-muted">Severity</label>
        <select
          id="filter-severity"
          value={severity}
          onChange={(e) => onSeverityChange(e.target.value)}
          aria-label="Filter by severity"
          className="rounded border border-border bg-surface-2 px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
        >
          <option value="">All</option>
          <option value="info">Info</option>
          <option value="warning">Warning</option>
          <option value="error">Error</option>
          <option value="critical">Critical</option>
        </select>
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor="filter-event-type" className="text-xs text-muted">Event type</label>
        <select
          id="filter-event-type"
          value={eventType}
          onChange={(e) => onEventTypeChange(e.target.value)}
          aria-label="Filter by event type"
          className="rounded border border-border bg-surface-2 px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
        >
          <option value="">All</option>
          <option value="auth_success">auth_success</option>
          <option value="auth_failure">auth_failure</option>
          <option value="rate_limit_exceeded">rate_limit_exceeded</option>
          <option value="key_created">key_created</option>
          <option value="key_revoked">key_revoked</option>
          <option value="key_rotated">key_rotated</option>
          <option value="admin_action">admin_action</option>
          <option value="provider_baa_allowed">provider_baa_allowed</option>
          <option value="provider_baa_denied">provider_baa_denied</option>
          <option value="brute_force_detected">brute_force_detected</option>
        </select>
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor="filter-success" className="text-xs text-muted">Outcome</label>
        <select
          id="filter-success"
          value={success}
          onChange={(e) => onSuccessChange(e.target.value)}
          aria-label="Filter by outcome"
          className="rounded border border-border bg-surface-2 px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
        >
          <option value="">All</option>
          <option value="true">Success</option>
          <option value="false">Failure</option>
        </select>
      </div>
    </div>
  );
}

// ─── AuditEventCard ───────────────────────────────────────────────────────────

interface AuditEventCardProps {
  event: ForensicsEvent;
}

function AuditEventCard({ event }: AuditEventCardProps) {
  const truncatedRequestId = event.request_id
    ? event.request_id.length > 24
      ? `${event.request_id.slice(0, 12)}…${event.request_id.slice(-8)}`
      : event.request_id
    : null;

  return (
    <div
      aria-label="forensics-event-card"
      className="rounded border border-border bg-surface-2 px-4 py-3 space-y-1"
    >
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm font-medium text-foreground">{event.event_type}</span>
        <span aria-label="severity-label" className={`text-xs ${severityClass(event.severity)}`}>
          {severityLabel(event.severity)}
        </span>
        {event.request_method && (
          <span className="rounded bg-surface-3 px-1.5 py-0.5 font-mono text-xs text-muted">
            {event.request_method}
          </span>
        )}
        {event.success ? (
          <span className="text-xs text-success">Success</span>
        ) : (
          <span className="text-xs text-danger">Failure</span>
        )}
      </div>

      <div className="flex flex-wrap gap-4 text-xs text-muted">
        {event.created_at && (
          <span>
            <time dateTime={event.created_at}>
              {new Date(event.created_at).toLocaleString('en-US', { timeZoneName: 'short' })}
            </time>
          </span>
        )}
        {truncatedRequestId && (
          <span className="font-mono" title={event.request_id ?? undefined}>
            req: {truncatedRequestId}
          </span>
        )}
        {event.request_path && (
          <span className="font-mono">{event.request_path}</span>
        )}
      </div>

      {event.reason && (
        <p className="text-xs text-muted/80">{event.reason}</p>
      )}
    </div>
  );
}

// ─── AuditEventTimeline ───────────────────────────────────────────────────────

interface AuditEventTimelineProps {
  events: ForensicsEvent[];
}

function AuditEventTimeline({ events }: AuditEventTimelineProps) {
  if (events.length === 0) {
    return (
      <div
        aria-label="forensics-empty-state"
        className="rounded border border-border bg-surface-2 px-4 py-8 text-center text-sm text-muted"
      >
        No events found for the current filters.
      </div>
    );
  }

  return (
    <ol aria-label="forensics-timeline" className="space-y-2">
      {events.map((event) => (
        <li key={event.event_id}>
          <AuditEventCard event={event} />
        </li>
      ))}
    </ol>
  );
}

// ─── RequestTracePanel ────────────────────────────────────────────────────────

function RequestTracePanel() {
  const [traceId, setTraceId] = useState('');
  const [trace, setTrace] = useState<ForensicsTrace | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function runTrace() {
    if (!traceId.trim()) return;
    setLoading(true);
    setError(null);
    setTrace(null);
    try {
      const result = await getForensicsTrace(traceId.trim());
      setTrace(result);
    } catch (err) {
      setError(normalizeError(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div aria-label="forensics-trace-panel" className="rounded border border-border bg-surface-2 p-4 space-y-3">
      <p className="text-xs font-semibold uppercase tracking-widest text-muted/70">
        Request Trace Lookup
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <input
          type="text"
          value={traceId}
          onChange={(e) => setTraceId(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') void runTrace(); }}
          placeholder="request_id"
          aria-label="Trace lookup request_id"
          className="rounded border border-border bg-surface-3 px-3 py-1.5 font-mono text-sm text-foreground placeholder:text-muted/40 focus:outline-none focus:ring-1 focus:ring-primary"
        />
        <button
          onClick={() => void runTrace()}
          disabled={!traceId.trim() || loading}
          aria-label="Look up trace"
          className="rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
        >
          {loading ? 'Loading…' : 'Trace'}
        </button>
      </div>

      {error && (
        <p className="text-xs text-danger">{error}</p>
      )}

      {trace && !trace.trace_available && (
        <p className="text-xs text-muted">No trace found for request_id: {trace.request_id}</p>
      )}

      {trace && trace.trace_available && (
        <div className="space-y-1">
          <p className="text-xs text-muted">
            {trace.event_count} event{trace.event_count !== 1 ? 's' : ''} for request_id:{' '}
            <span className="font-mono">{trace.request_id}</span>
          </p>
          <ol className="space-y-2">
            {trace.events.map((event) => (
              <li key={event.event_id}>
                <AuditEventCard event={event} />
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}

// ─── ForensicsExportPanel ─────────────────────────────────────────────────────

interface ForensicsExportPanelProps {
  eventType: string;
  severity: string;
}

function ForensicsExportPanel({ eventType, severity }: ForensicsExportPanelProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [payload, setPayload] = useState<ForensicsExportPayload | null>(null);
  const [copied, setCopied] = useState(false);

  async function runExport() {
    setLoading(true);
    setError(null);
    setPayload(null);
    try {
      const result = await getForensicsExport({
        event_type: eventType || undefined,
        severity: severity || undefined,
      });
      setPayload(result);
    } catch (err) {
      setError(normalizeError(err));
    } finally {
      setLoading(false);
    }
  }

  async function copyToClipboard() {
    if (!payload) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API may be unavailable; silently fail
    }
  }

  return (
    <div aria-label="forensics-export-panel" className="rounded border border-border bg-surface-2 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-semibold uppercase tracking-widest text-muted/70">
          Export-Safe Audit Data
        </p>
        {payload && (
          <button
            onClick={() => void copyToClipboard()}
            aria-label="Copy export to clipboard"
            className="rounded border border-border bg-surface-3 px-2.5 py-1 text-xs text-muted hover:text-foreground"
          >
            {copied ? 'Copied!' : 'Copy to clipboard'}
          </button>
        )}
      </div>

      <div className="space-y-1">
        <p aria-label="forensics-export-safe-indicator" className="text-xs text-success font-medium">
          export_safe: true — No raw prompts, credentials, or vectors
        </p>
        <p className="text-xs text-muted">
          Excludes: key_prefix, client_ip, user_agent, prev_hash, entry_hash, chain_id, details_json
        </p>
      </div>

      <button
        onClick={() => void runExport()}
        disabled={loading}
        aria-label="Generate export"
        className="rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
      >
        {loading ? 'Generating…' : 'Generate export'}
      </button>

      {error && (
        <p className="text-xs text-danger">{error}</p>
      )}

      {payload && (
        <div className="space-y-1 text-xs text-muted">
          <p>Generated at: {payload.generated_at}</p>
          <p>{payload.event_count} event{payload.event_count !== 1 ? 's' : ''} exported</p>
          <p className="text-muted/60">{payload.limitation_note}</p>
        </div>
      )}
    </div>
  );
}

// ─── ReplayReadinessPanel ─────────────────────────────────────────────────────

function ReplayReadinessPanel() {
  return (
    <div
      aria-label="forensics-replay-panel"
      className="rounded border border-border bg-surface-2 p-4 space-y-2"
    >
      <p className="text-xs font-semibold uppercase tracking-widest text-muted/70">
        Incident Reconstruction
      </p>
      <p className="text-xs text-muted font-medium">
        Replay mode — not yet available
      </p>
      <p className="text-xs text-muted/60">
        Future capability: request re-execution, provider replay, and incident reconstruction scaffolding. No mutations are performed here.
      </p>
    </div>
  );
}

// ─── AuditForensicsConsole ────────────────────────────────────────────────────

export function AuditForensicsConsole() {
  const [page, setPage] = useState<ForensicsEventsPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filter state
  const [searchRequestId, setSearchRequestId] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterEventType, setFilterEventType] = useState('');
  const [filterSuccess, setFilterSuccess] = useState('');

  const LIMIT = 50;
  const [offset, setOffset] = useState(0);

  const buildQuery = useCallback(
    (currentOffset: number): ForensicsEventsQuery => {
      const q: ForensicsEventsQuery = { limit: LIMIT, offset: currentOffset };
      if (searchRequestId.trim()) q.request_id = searchRequestId.trim();
      if (filterSeverity) q.severity = filterSeverity;
      if (filterEventType) q.event_type = filterEventType;
      if (filterSuccess !== '') q.success = filterSuccess === 'true';
      return q;
    },
    [searchRequestId, filterSeverity, filterEventType, filterSuccess],
  );

  const loadEvents = useCallback(
    async (currentOffset: number) => {
      setLoading(true);
      setError(null);
      try {
        const result = await getForensicsEvents(buildQuery(currentOffset));
        setPage(result);
        setOffset(currentOffset);
      } catch (err) {
        setError(normalizeError(err));
        setPage(null);
      } finally {
        setLoading(false);
      }
    },
    [buildQuery],
  );

  // Load on mount
  const [initialized, setInitialized] = useState(false);
  if (!initialized) {
    setInitialized(true);
    void loadEvents(0);
  }

  function handleSearch() {
    void loadEvents(0);
  }

  function handlePrev() {
    const newOffset = Math.max(0, offset - LIMIT);
    void loadEvents(newOffset);
  }

  function handleNext() {
    if (!page) return;
    const newOffset = offset + LIMIT;
    if (newOffset < page.total) {
      void loadEvents(newOffset);
    }
  }

  const currentPage = page ? Math.floor(offset / LIMIT) + 1 : 1;
  const totalPages = page ? Math.ceil(page.total / LIMIT) : 0;
  const hasPrev = offset > 0;
  const hasNext = page ? offset + LIMIT < page.total : false;

  return (
    <div aria-label="forensics-console" className="flex flex-col space-y-4 p-6">
      <div>
        <h2 className="text-base font-semibold text-foreground">Audit &amp; Forensics Console</h2>
        <p className="mt-0.5 text-xs text-muted">
          SOC investigation layer — search and filter security audit events for this tenant
        </p>
      </div>

      <ForensicsSearchBar
        value={searchRequestId}
        onChange={setSearchRequestId}
        onSearch={handleSearch}
        loading={loading}
      />

      <ForensicsFilterPanel
        severity={filterSeverity}
        eventType={filterEventType}
        success={filterSuccess}
        onSeverityChange={(v) => { setFilterSeverity(v); }}
        onEventTypeChange={(v) => { setFilterEventType(v); }}
        onSuccessChange={(v) => { setFilterSuccess(v); }}
      />

      <div className="flex flex-wrap items-center justify-between gap-2">
        <button
          onClick={handleSearch}
          disabled={loading}
          aria-label="Apply filters"
          className="rounded bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-hover disabled:opacity-40"
        >
          {loading ? 'Loading…' : 'Apply filters'}
        </button>

        {page && (
          <span className="text-xs text-muted">
            {page.total} total event{page.total !== 1 ? 's' : ''} — page {currentPage} of {totalPages || 1}
          </span>
        )}
      </div>

      {error && (
        <div
          aria-label="forensics-error-state"
          className="rounded border border-danger/30 bg-danger/5 px-3 py-2 text-xs text-danger"
        >
          {error}
        </div>
      )}

      {!error && page && page.events.length === 0 && !loading && (
        <AuditEventTimeline events={[]} />
      )}

      {!error && page && page.events.length > 0 && (
        <AuditEventTimeline events={page.events} />
      )}

      {page && page.total > LIMIT && (
        <div className="flex items-center gap-2">
          <button
            onClick={handlePrev}
            disabled={!hasPrev || loading}
            aria-label="Previous page"
            className="rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
          >
            Previous
          </button>
          <button
            onClick={handleNext}
            disabled={!hasNext || loading}
            aria-label="Next page"
            className="rounded border border-border bg-surface-2 px-3 py-1.5 text-xs text-muted hover:text-foreground disabled:opacity-40"
          >
            Next
          </button>
        </div>
      )}

      <RequestTracePanel />

      <ForensicsExportPanel eventType={filterEventType} severity={filterSeverity} />

      <ReplayReadinessPanel />
    </div>
  );
}
