'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import {
  exportAuditEvents,
  fetchAuditEvents,
  type AuditEvent,
  type AuditSearchParams,
} from '@/lib/api';

const DEFAULT_PAGE_SIZE = 100;

export default function AuditPage() {
  const [tenantId, setTenantId] = useState('');
  const [action, setAction] = useState('');
  const [actor, setActor] = useState('');
  const [status, setStatus] = useState('');
  const [fromTs, setFromTs] = useState('');
  const [toTs, setToTs] = useState('');
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toIsoString = (value: string) =>
    value ? new Date(value).toISOString() : undefined;

  const params: AuditSearchParams = useMemo(
    () => ({
      tenantId: tenantId || undefined,
      action: action || undefined,
      actor: actor || undefined,
      status: status || undefined,
      fromTs: toIsoString(fromTs),
      toTs: toIsoString(toTs),
      pageSize,
    }),
    [tenantId, action, actor, status, fromTs, toTs, pageSize]
  );

  const isTenantValid = Boolean(tenantId);

  const handleSearch = async () => {
    setError(null);
    setLoading(true);
    try {
      const data = await fetchAuditEvents(params);
      setEvents(data.items || []);
      setNextCursor(data.next_cursor || null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit events');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadMore = async () => {
    if (!nextCursor) return;
    setError(null);
    setLoading(true);
    try {
      const data = await fetchAuditEvents({ ...params, cursor: nextCursor });
      setEvents((prev) => [...prev, ...(data.items || [])]);
      setNextCursor(data.next_cursor || null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load more events');
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async (format: 'csv' | 'json') => {
    setError(null);
    try {
      const blob = await exportAuditEvents({ ...params, format });
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `audit-events.${format}`;
      anchor.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to export audit data');
    }
  };

  const failureCount = events.filter((event) => event.status !== 'success').length;
  const canaryCount = events.filter((event) =>
    event.action.toLowerCase().startsWith('canary')
  ).length;

  return (
    <main style={styles.main}>
      <header style={styles.header}>
        <div style={styles.headerLeft}>
          <Link href="/" style={styles.backLink}>
            Back to Dashboard
          </Link>
          <h1 style={styles.title}>Audit Search</h1>
          <p style={styles.subtitle}>Search and export tenant-scoped audit logs.</p>
        </div>
        <div style={styles.headerActions}>
          <button
            style={styles.secondaryButton}
            onClick={() => handleExport('csv')}
            disabled={!isTenantValid}
          >
            Export CSV
          </button>
          <button
            style={styles.secondaryButton}
            onClick={() => handleExport('json')}
            disabled={!isTenantValid}
          >
            Export JSON
          </button>
        </div>
      </header>

      <section style={styles.filters}>
        <label style={styles.filterLabel}>
          Tenant ID
          <input
            style={styles.input}
            value={tenantId}
            onChange={(event) => setTenantId(event.target.value)}
            placeholder="tenant-id"
          />
        </label>
        <label style={styles.filterLabel}>
          Action
          <input
            style={styles.input}
            value={action}
            onChange={(event) => setAction(event.target.value)}
            placeholder="auth_success"
          />
        </label>
        <label style={styles.filterLabel}>
          Actor
          <input
            style={styles.input}
            value={actor}
            onChange={(event) => setActor(event.target.value)}
            placeholder="user-123"
          />
        </label>
        <label style={styles.filterLabel}>
          Status
          <select
            style={styles.select}
            value={status}
            onChange={(event) => setStatus(event.target.value)}
          >
            <option value="">Any</option>
            <option value="success">Success</option>
            <option value="deny">Deny</option>
            <option value="error">Error</option>
          </select>
        </label>
        <label style={styles.filterLabel}>
          From
          <input
            style={styles.input}
            type="datetime-local"
            value={fromTs}
            onChange={(event) => setFromTs(event.target.value)}
          />
        </label>
        <label style={styles.filterLabel}>
          To
          <input
            style={styles.input}
            type="datetime-local"
            value={toTs}
            onChange={(event) => setToTs(event.target.value)}
          />
        </label>
        <label style={styles.filterLabel}>
          Page size
          <input
            style={styles.input}
            type="number"
            min={1}
            max={1000}
            value={pageSize}
            onChange={(event) => setPageSize(Number(event.target.value))}
          />
        </label>
        <button
          style={styles.primaryButton}
          onClick={handleSearch}
          disabled={!isTenantValid || loading}
        >
          {loading ? 'Searching...' : 'Search'}
        </button>
      </section>

      {!isTenantValid ? (
        <div style={styles.notice}>
          Provide a tenant ID to search or export.
        </div>
      ) : null}

      {error ? <div style={styles.error}>{error}</div> : null}

      <section style={styles.section}>
        <div style={styles.sectionHeader}>
          <h2 style={styles.sectionTitle}>Results</h2>
          <span style={styles.count}>{events.length} events</span>
        </div>
        <div style={styles.highlights}>
          <div style={styles.highlightCard}>
            <p style={styles.highlightLabel}>Recent failures</p>
            <p style={styles.highlightValue}>{failureCount}</p>
          </div>
          <div style={styles.highlightCard}>
            <p style={styles.highlightLabel}>Canary trips</p>
            <p style={styles.highlightValue}>{canaryCount}</p>
          </div>
        </div>
        <div style={styles.tableWrapper}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Time</th>
                <th style={styles.th}>Tenant</th>
                <th style={styles.th}>Actor</th>
                <th style={styles.th}>Action</th>
                <th style={styles.th}>Status</th>
                <th style={styles.th}>Request</th>
                <th style={styles.th}>Resource</th>
                <th style={styles.th}>IP</th>
                <th style={styles.th}>User Agent</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td style={styles.td} colSpan={10}>
                    No audit events loaded.
                  </td>
                </tr>
              ) : (
                events.map((event) => (
                  <tr key={`${event.id}-${event.ts}`}>
                    <td style={styles.td}>{event.ts}</td>
                    <td style={styles.td}>{event.tenant_id}</td>
                    <td style={styles.td}>{event.actor || '—'}</td>
                    <td style={styles.td}>{event.action}</td>
                    <td style={styles.td}>{event.status}</td>
                    <td style={styles.td}>{event.request_id || '—'}</td>
                    <td style={styles.td}>
                      {event.resource_type || '—'} {event.resource_id || ''}
                    </td>
                    <td style={styles.td}>{event.ip || '—'}</td>
                    <td style={styles.td}>{event.user_agent || '—'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        <div style={styles.pagination}>
          <button
            style={styles.secondaryButton}
            onClick={handleLoadMore}
            disabled={!nextCursor || loading}
          >
            {loading ? 'Loading...' : 'Load more'}
          </button>
        </div>
      </section>
    </main>
  );
}

const styles: { [key: string]: React.CSSProperties } = {
  main: {
    minHeight: '100vh',
    padding: '2rem',
    maxWidth: '1400px',
    margin: '0 auto',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    gap: '1.5rem',
    marginBottom: '2rem',
    paddingBottom: '1rem',
    borderBottom: '1px solid var(--border)',
  },
  headerLeft: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem',
  },
  headerActions: {
    display: 'flex',
    gap: '0.75rem',
  },
  backLink: {
    fontSize: '0.875rem',
    color: 'var(--muted)',
    textDecoration: 'none',
  },
  title: {
    fontSize: '1.5rem',
    fontWeight: 600,
  },
  subtitle: {
    color: 'var(--muted)',
  },
  filters: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
    gap: '1rem',
    alignItems: 'end',
    marginBottom: '1.5rem',
  },
  filterLabel: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
    fontSize: '0.75rem',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    color: 'var(--muted)',
  },
  input: {
    padding: '0.5rem 0.75rem',
    borderRadius: '6px',
    border: '1px solid var(--border)',
  },
  select: {
    padding: '0.5rem 0.75rem',
    borderRadius: '6px',
    border: '1px solid var(--border)',
  },
  primaryButton: {
    padding: '0.6rem 1.1rem',
    borderRadius: '6px',
    border: 'none',
    backgroundColor: 'var(--primary)',
    color: 'white',
    cursor: 'pointer',
    fontWeight: 600,
  },
  secondaryButton: {
    padding: '0.5rem 0.9rem',
    borderRadius: '6px',
    border: '1px solid var(--border)',
    backgroundColor: 'transparent',
    cursor: 'pointer',
  },
  notice: {
    padding: '1rem',
    backgroundColor: 'rgba(59, 130, 246, 0.08)',
    borderRadius: '8px',
    marginBottom: '1rem',
    color: '#1d4ed8',
  },
  error: {
    padding: '1rem',
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderRadius: '8px',
    marginBottom: '1rem',
    color: '#b91c1c',
  },
  section: {
    backgroundColor: 'var(--background)',
    borderRadius: '8px',
    border: '1px solid var(--border)',
    padding: '1rem',
  },
  sectionHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '0.75rem',
  },
  highlights: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
    gap: '0.75rem',
    marginBottom: '1rem',
  },
  highlightCard: {
    padding: '0.75rem',
    borderRadius: '8px',
    border: '1px solid var(--border)',
    backgroundColor: 'rgba(15, 23, 42, 0.03)',
  },
  highlightLabel: {
    fontSize: '0.7rem',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    color: 'var(--muted)',
    marginBottom: '0.35rem',
  },
  highlightValue: {
    fontSize: '1.25rem',
    fontWeight: 600,
  },
  sectionTitle: {
    fontSize: '1.1rem',
    fontWeight: 600,
  },
  count: {
    fontSize: '0.875rem',
    color: 'var(--muted)',
  },
  tableWrapper: {
    overflowX: 'auto',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
  },
  th: {
    textAlign: 'left',
    padding: '0.6rem',
    borderBottom: '1px solid var(--border)',
    fontSize: '0.75rem',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    color: 'var(--muted)',
  },
  td: {
    padding: '0.6rem',
    borderBottom: '1px solid var(--border)',
    fontSize: '0.85rem',
  },
  pagination: {
    display: 'flex',
    justifyContent: 'flex-end',
    marginTop: '1rem',
  },
};
