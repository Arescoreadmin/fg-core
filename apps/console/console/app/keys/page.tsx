'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  ApiKeyInfo,
  ApiKeyCreateResponse,
  ApiKeyRotateResponse,
  createApiKey,
  fetchApiKeys,
  revokeApiKey,
  rotateApiKey,
} from '@/lib/api';

const DEFAULT_TENANT = 'default';

function formatTimestamp(value?: string | number | null): string {
  if (value === null || value === undefined || value === '') {
    return '—';
  }
  const date =
    typeof value === 'number' ? new Date(value * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return date.toLocaleString();
}

export default function KeysPage() {
  const [tenantId, setTenantId] = useState(DEFAULT_TENANT);
  const [keys, setKeys] = useState<ApiKeyInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [createdKey, setCreatedKey] = useState<ApiKeyCreateResponse | null>(null);
  const [rotatedKey, setRotatedKey] = useState<ApiKeyRotateResponse | null>(null);
  const [formName, setFormName] = useState('');
  const [formScopes, setFormScopes] = useState('keys:read');
  const [formTtl, setFormTtl] = useState(86400);

  const ttlHours = useMemo(() => Math.round(formTtl / 3600), [formTtl]);

  async function loadKeys() {
    setLoading(true);
    setError(null);
    try {
      const response = await fetchApiKeys(tenantId);
      setKeys(response.keys ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load keys');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadKeys();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenantId]);

  async function handleCreate() {
    setError(null);
    try {
      const scopes = formScopes
        .split(',')
        .map((scope) => scope.trim())
        .filter(Boolean);
      const response = await createApiKey({
        name: formName || undefined,
        scopes,
        tenant_id: tenantId,
        ttl_seconds: formTtl,
      });
      setCreatedKey(response);
      setRotatedKey(null);
      setShowCreate(false);
      await loadKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create key');
    }
  }

  async function handleRotate(prefix: string) {
    setError(null);
    try {
      const response = await rotateApiKey(prefix, tenantId, formTtl);
      setRotatedKey(response);
      setCreatedKey(null);
      await loadKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to rotate key');
    }
  }

  async function handleRevoke(prefix: string) {
    setError(null);
    try {
      await revokeApiKey(prefix, tenantId);
      await loadKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke key');
    }
  }

  return (
    <main style={styles.main}>
      <header style={styles.header}>
        <div>
          <h1 style={styles.title}>API Keys</h1>
          <p style={styles.subtitle}>Manage tenant-scoped API keys</p>
        </div>
        <button style={styles.primaryButton} onClick={() => setShowCreate(true)}>
          Create key
        </button>
      </header>

      <section style={styles.filters}>
        <label style={styles.filterLabel}>
          Tenant
          <input
            style={styles.input}
            value={tenantId}
            onChange={(event) => setTenantId(event.target.value)}
          />
        </label>
        <label style={styles.filterLabel}>
          TTL (seconds)
          <input
            style={styles.input}
            type="number"
            min={60}
            value={formTtl}
            onChange={(event) => setFormTtl(Number(event.target.value))}
          />
          <span style={styles.helperText}>~{ttlHours}h</span>
        </label>
      </section>

      {error ? <div style={styles.error}>{error}</div> : null}

      {createdKey ? (
        <div style={styles.notice}>
          <strong>New key created.</strong>
          <p style={styles.noticeText}>
            Copy this key now; it will only be shown once.
          </p>
          <code style={styles.codeBlock}>{createdKey.key}</code>
        </div>
      ) : null}

      {rotatedKey ? (
        <div style={styles.notice}>
          <strong>Key rotated.</strong>
          <p style={styles.noticeText}>
            Old key revoked: {rotatedKey.old_key_revoked ? 'yes' : 'no'}
          </p>
          <code style={styles.codeBlock}>{rotatedKey.new_key}</code>
        </div>
      ) : null}

      <section style={styles.section}>
        {loading ? (
          <p style={styles.loading}>Loading keys…</p>
        ) : (
          <div style={styles.tableWrapper}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>Prefix</th>
                  <th style={styles.th}>Name</th>
                  <th style={styles.th}>Scopes</th>
                  <th style={styles.th}>Last used</th>
                  <th style={styles.th}>Use count</th>
                  <th style={styles.th}>Expires</th>
                  <th style={styles.th}>Status</th>
                  <th style={styles.th}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {keys.length === 0 ? (
                  <tr>
                    <td style={styles.td} colSpan={8}>
                      No keys found for this tenant.
                    </td>
                  </tr>
                ) : (
                  keys.map((key) => (
                    <tr key={key.prefix}>
                      <td style={styles.td}>{key.prefix}</td>
                      <td style={styles.td}>{key.name || '—'}</td>
                      <td style={styles.td}>{key.scopes?.join(', ') || '—'}</td>
                      <td style={styles.td}>{formatTimestamp(key.last_used_at)}</td>
                      <td style={styles.td}>{key.use_count ?? 0}</td>
                      <td style={styles.td}>{formatTimestamp(key.expires_at)}</td>
                      <td style={styles.td}>
                        {key.enabled ? 'Active' : 'Revoked'}
                      </td>
                      <td style={styles.td}>
                        <div style={styles.actionGroup}>
                          <button
                            style={styles.secondaryButton}
                            onClick={() => handleRotate(key.prefix)}
                          >
                            Rotate
                          </button>
                          <button
                            style={styles.dangerButton}
                            onClick={() => handleRevoke(key.prefix)}
                          >
                            Revoke
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {showCreate ? (
        <div style={styles.modalBackdrop} role="dialog" aria-modal="true">
          <div style={styles.modal}>
            <h2 style={styles.modalTitle}>Create API key</h2>
            <label style={styles.modalField}>
              Name
              <input
                style={styles.input}
                value={formName}
                onChange={(event) => setFormName(event.target.value)}
                placeholder="Production ingestion key"
              />
            </label>
            <label style={styles.modalField}>
              Scopes (comma separated)
              <input
                style={styles.input}
                value={formScopes}
                onChange={(event) => setFormScopes(event.target.value)}
                placeholder="keys:read,decisions:write"
              />
            </label>
            <label style={styles.modalField}>
              Expiry (seconds)
              <input
                style={styles.input}
                type="number"
                min={60}
                value={formTtl}
                onChange={(event) => setFormTtl(Number(event.target.value))}
              />
            </label>
            <div style={styles.placeholder}>
              Plan &amp; entitlements (placeholder for future billing controls)
            </div>
            <div style={styles.modalActions}>
              <button style={styles.secondaryButton} onClick={() => setShowCreate(false)}>
                Cancel
              </button>
              <button style={styles.primaryButton} onClick={handleCreate}>
                Create key
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </main>
  );
}

const styles: { [key: string]: React.CSSProperties } = {
  main: {
    minHeight: '100vh',
    padding: '2rem',
    maxWidth: '1200px',
    margin: '0 auto',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '1.5rem',
  },
  title: {
    fontSize: '1.5rem',
    fontWeight: 600,
    marginBottom: '0.25rem',
  },
  subtitle: {
    color: 'var(--muted)',
    fontSize: '0.875rem',
  },
  filters: {
    display: 'flex',
    gap: '1rem',
    marginBottom: '1.5rem',
  },
  filterLabel: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
    fontSize: '0.75rem',
    textTransform: 'uppercase',
    color: 'var(--muted)',
  },
  input: {
    padding: '0.5rem',
    borderRadius: '6px',
    border: '1px solid var(--border)',
    minWidth: '220px',
  },
  helperText: {
    fontSize: '0.75rem',
    color: 'var(--muted)',
  },
  error: {
    padding: '0.75rem 1rem',
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderRadius: '8px',
    marginBottom: '1rem',
  },
  notice: {
    padding: '1rem',
    backgroundColor: 'rgba(34, 197, 94, 0.1)',
    borderRadius: '8px',
    marginBottom: '1rem',
  },
  noticeText: {
    marginTop: '0.5rem',
  },
  codeBlock: {
    display: 'block',
    marginTop: '0.75rem',
    padding: '0.75rem',
    backgroundColor: 'var(--background)',
    border: '1px solid var(--border)',
    borderRadius: '6px',
    overflowX: 'auto',
  },
  section: {
    border: '1px solid var(--border)',
    borderRadius: '8px',
    backgroundColor: 'var(--background)',
    padding: '1rem',
  },
  loading: {
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
    padding: '0.75rem',
    borderBottom: '1px solid var(--border)',
    fontSize: '0.75rem',
    textTransform: 'uppercase',
    color: 'var(--muted)',
  },
  td: {
    padding: '0.75rem',
    borderBottom: '1px solid var(--border)',
    fontSize: '0.875rem',
  },
  actionGroup: {
    display: 'flex',
    gap: '0.5rem',
  },
  primaryButton: {
    padding: '0.5rem 1rem',
    borderRadius: '6px',
    border: 'none',
    backgroundColor: '#2563eb',
    color: '#fff',
    cursor: 'pointer',
  },
  secondaryButton: {
    padding: '0.4rem 0.75rem',
    borderRadius: '6px',
    border: '1px solid var(--border)',
    backgroundColor: 'transparent',
    cursor: 'pointer',
  },
  dangerButton: {
    padding: '0.4rem 0.75rem',
    borderRadius: '6px',
    border: '1px solid rgba(239, 68, 68, 0.5)',
    color: '#ef4444',
    backgroundColor: 'transparent',
    cursor: 'pointer',
  },
  modalBackdrop: {
    position: 'fixed',
    inset: 0,
    backgroundColor: 'rgba(0,0,0,0.4)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '1rem',
  },
  modal: {
    backgroundColor: '#fff',
    borderRadius: '12px',
    padding: '1.5rem',
    width: '100%',
    maxWidth: '480px',
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
  },
  modalTitle: {
    fontSize: '1.125rem',
    fontWeight: 600,
  },
  modalField: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
  },
  placeholder: {
    padding: '0.75rem',
    borderRadius: '8px',
    backgroundColor: 'rgba(59, 130, 246, 0.08)',
    fontSize: '0.875rem',
    color: '#1e3a8a',
  },
  modalActions: {
    display: 'flex',
    justifyContent: 'flex-end',
    gap: '0.75rem',
  },
};
