'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import {
  exportAuditEvents,
  fetchAuditEvents,
  type AuditEvent,
  type AuditSearchParams,
} from '@/lib/api';

const DEFAULT_LIMIT = 100;

export default function AuditPage() {
  const [tenantId, setTenantId] = useState('');
  const [tenantIds, setTenantIds] = useState('');
  const [eventType, setEventType] = useState('');
  const [severity, setSeverity] = useState('');
  const [success, setSuccess] = useState('');
  const [queryText, setQueryText] = useState('');
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [limit, setLimit] = useState(DEFAULT_LIMIT);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const derivedTenantIds = useMemo(
    () =>
      tenantIds
        .split(',')
        .map((id) => id.trim())
        .filter(Boolean),
    [tenantIds]
  );

  const params: AuditSearchParams = useMemo(
    () => ({
      tenantId: tenantId || undefined,
      tenantIds: derivedTenantIds.length ? derivedTenantIds : undefined,
      eventType: eventType || undefined,
      severity: severity || undefined,
      success: success ? success === 'true' : undefined,
      queryText: queryText || undefined,
      limit,
      offset,
    }),
    [
      tenantId,
      derivedTenantIds,
      eventType,
      severity,
      success,
      queryText,
      limit,
      offset,
    ]
  );

  const isTenantValid = Boolean(tenantId || derivedTenantIds.length);

  const handleSearch = async () => {
    setError(null);
    setLoading(true);
    try {
      const data = await fetchAuditEvents(params);
      setEvents(data.events || []);
      setTotal(data.total || 0);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit events');
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async (format: 'csv' | 'jsonl') => {
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
            onClick={() => handleExport('jsonl')}
            disabled={!isTenantValid}
          >
            Export JSONL
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
          Tenant IDs (comma-separated)
          <input
            style={styles.input}
            value={tenantIds}
            onChange={(event) => setTenantIds(event.target.value)}
            placeholder="tenant-a, tenant-b"
          />
        </label>
        <label style={styles.filterLabel}>
          Event type
          <input
            style={styles.input}
            value={eventType}
            onChange={(event) => setEventType(event.target.value)}
            placeholder="auth_success"
          />
        </label>
        <label style={styles.filterLabel}>
          Severity
          <input
            style={styles.input}
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
            placeholder="info"
          />
        </label>
        <label style={styles.filterLabel}>
          Success
          <select
            style={styles.select}
            value={success}
            onChange={(event) => setSuccess(event.target.value)}
          >
            <option value="">Any</option>
            <option value="true">True</option>
            <option value="false">False</option>
          </select>
        </label>
        <label style={styles.filterLabel}>
          Search
          <input
            style={styles.input}
            value={queryText}
            onChange={(event) => setQueryText(event.target.value)}
            placeholder="request_id, path, reason"
          />
        </label>
        <label style={styles.filterLabel}>
          Limit
          <input
            style={styles.input}
            type="number"
            min={1}
            max={1000}
            value={limit}
            onChange={(event) => setLimit(Number(event.target.value))}
          />
        </label>
        <label style={styles.filterLabel}>
          Offset
          <input
            style={styles.input}
            type="number"
            min={0}
            value={offset}
            onChange={(event) => setOffset(Number(event.target.value))}
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
          Provide a tenant ID or a tenant list to search or export.
        </div>
      ) : null}

      {error ? <div style={styles.error}>{error}</div> : null}

      <section style={styles.section}>
        <div style={styles.sectionHeader}>
          <h2 style={styles.sectionTitle}>Results</h2>
          <span style={styles.count}>{total} events</span>
        </div>
        <div style={styles.tableWrapper}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Time</th>
                <th style={styles.th}>Tenant</th>
                <th style={styles.th}>Event</th>
                <th style={styles.th}>Severity</th>
                <th style={styles.th}>Success</th>
                <th style={styles.th}>Request</th>
                <th style={styles.th}>Reason</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td style={styles.td} colSpan={7}>
                    No audit events loaded.
                  </td>
                </tr>
              ) : (
                events.map((event) => (
                  <tr key={`${event.id}-${event.created_at}`}>
                    <td style={styles.td}>{event.created_at}</td>
                    <td style={styles.td}>{event.tenant_id || '—'}</td>
                    <td style={styles.td}>{event.event_type}</td>
                    <td style={styles.td}>{event.severity}</td>
                    <td style={styles.td}>{event.success ? 'yes' : 'no'}</td>
                    <td style={styles.td}>
                      {event.request_method} {event.request_path}
                    </td>
                    <td style={styles.td}>{event.reason || '—'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
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
};
